#!/usr/bin/env python3
"""Generate the shared, deterministically ordered security-scan file inventory."""

from __future__ import annotations

import argparse
import io
import os
import re
import stat
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path, PurePosixPath

IGNORE_FILE_NAMES = (".gitignore", ".ignore", ".rgignore")


class InventoryError(ValueError):
    """Raised when the repository, scope, or inventory cannot be used safely."""


def symbolic_metadata(metadata: os.stat_result) -> bool:
    reparse_point = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & reparse_point
    )


def git_metadata_path(parent: Path, name: str) -> bool:
    if name == ".git":
        return True
    if name.casefold().rstrip(". ") != ".git":
        return False
    try:
        return (parent / name).samefile(parent / ".git")
    except OSError:
        return False


def resolve_repository(value: str) -> Path:
    """Resolve the repository once so every scope is bound to its real root."""
    try:
        repository = Path(value).expanduser().resolve(strict=True)
    except (OSError, ValueError) as error:
        raise InventoryError(f"--repo: cannot resolve repository: {value}") from error
    if not repository.is_dir():
        raise InventoryError(f"--repo: expected a directory: {repository}")
    return repository


def resolve_scope(repository: Path, value: str) -> str:
    """Preserve ripgrep's relative path spelling while rejecting escaped scopes."""
    if not value or "\0" in value:
        raise InventoryError("--scope: expected a non-empty file or directory")

    requested = Path(value).expanduser()
    scope = requested if requested.is_absolute() else repository / requested
    try:
        resolved = scope.resolve(strict=True)
    except (OSError, ValueError) as error:
        raise InventoryError(f"--scope: path does not exist: {value}") from error

    try:
        relative = resolved.relative_to(repository)
    except ValueError as error:
        raise InventoryError(f"--scope: path must remain inside --repo: {value}") from error
    parent = repository
    for component in relative.parts:
        if git_metadata_path(parent, component):
            raise InventoryError("--scope: Git metadata paths are not supported")
        parent /= component

    current = scope
    while current != repository:
        if current == current.parent:
            raise InventoryError("--scope: symbolic links are not supported")
        metadata = current.stat(follow_symlinks=False)
        if symbolic_metadata(metadata):
            raise InventoryError("--scope: symbolic links are not supported")
        current = current.parent

    if not resolved.is_dir() and not resolved.is_file():
        raise InventoryError(f"--scope: expected a file or directory: {value}")

    canonical = relative.as_posix() if relative.parts else "."
    return f"./{canonical}" if value.startswith("./") and canonical != "." else canonical


def resolve_output(value: str) -> Path:
    """Reject direct symlink outputs without constraining the artifact root."""
    if not value or "\0" in value:
        raise InventoryError("--out: expected an inventory file path")
    requested = Path(value).expanduser()
    if requested.is_symlink():
        raise InventoryError("--out: refusing to replace a symbolic link")
    try:
        output = requested.resolve(strict=False)
    except (OSError, ValueError) as error:
        raise InventoryError(f"--out: cannot resolve inventory path: {value}") from error
    if output.exists() and not output.is_file():
        raise InventoryError(f"--out: expected a regular file path: {output}")
    return output


def generate_in_scope_files(repository: Path, scope: str, output: Path) -> int:
    """Atomically inventory visible files and ignored files tracked by Git."""
    selected = (repository / scope).resolve(strict=True)
    selected_directory = selected if selected.is_dir() else selected.parent
    ancestors: list[Path] = []
    current = selected_directory
    while True:
        ancestors.append(current)
        if current == repository:
            break
        current = current.parent
    ancestors.reverse()

    def reject_symbolic_ignore(directory: Path, *, allow_ignored: bool = False) -> None:
        for name in IGNORE_FILE_NAMES:
            try:
                metadata = (directory / name).stat(follow_symlinks=False)
            except FileNotFoundError:
                continue
            if not symbolic_metadata(metadata) and stat.S_ISREG(metadata.st_mode):
                continue
            if allow_ignored and directory != repository:
                ignored = subprocess.run(
                    [
                        "git",
                        "-c",
                        "core.fsmonitor=false",
                        "-C",
                        str(repository),
                        "check-ignore",
                        "--quiet",
                        "--no-index",
                        "--",
                        directory.relative_to(repository).as_posix(),
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
                ripgrep_overrides = any(
                    (repository / parent / ignore).is_file()
                    for parent in directory.relative_to(repository).parents
                    for ignore in (".ignore", ".rgignore")
                )
                if ignored.returncode == 0 and not ripgrep_overrides:
                    continue
            if symbolic_metadata(metadata):
                raise InventoryError("symbolic ignore files are not supported")
            raise InventoryError("non-regular ignore files are not supported")

    def directory_identity(path: Path) -> tuple[int, int]:
        metadata = path.stat()
        return metadata.st_dev, metadata.st_ino

    discovered_roots: dict[tuple[int, int], Path] = {}
    metadata_aliases: set[tuple[str, ...]] = set()
    for ancestor in ancestors:
        reject_symbolic_ignore(ancestor)
    if selected.is_dir():
        for directory, children, files in os.walk(selected, followlinks=False):
            directory_path = Path(directory)
            if directory_path != repository and (directory_path / ".git").exists():
                discovered_roots[directory_identity(directory_path)] = directory_path
            for name in (*children, *files):
                if name != ".git" and git_metadata_path(directory_path, name):
                    metadata_aliases.add(
                        (directory_path / name).relative_to(repository).parts
                    )
            children[:] = [
                name
                for name in children
                if not git_metadata_path(directory_path, name)
                and not symbolic_metadata((directory_path / name).stat(follow_symlinks=False))
            ]
            reject_symbolic_ignore(directory_path, allow_ignored=True)

    command = [
        "rg",
        "--no-config",
        "--files",
        "--null",
        "--hidden",
        "--no-require-git",
        "--no-ignore-parent",
        "--no-ignore-global",
        "--glob",
        "!.git",
        "--glob",
        "!.git/**",
    ]

    def ripgrep_inventory(
        directory: Path, requested_scope: str, *, directory_guard: bool = False
    ) -> set[bytes]:
        arguments = command.copy()
        directory_parts = directory.relative_to(repository).parts
        ignored_aliases = []
        for alias in sorted(metadata_aliases):
            if alias[: len(directory_parts)] != directory_parts:
                continue
            relative_alias = "/".join(re.escape(part) for part in alias[len(directory_parts) :])
            if relative_alias and "\n" not in relative_alias and "\r" not in relative_alias:
                ignored_aliases.append(f"/{relative_alias}\n")
        for name in IGNORE_FILE_NAMES:
            ignore = directory / name
            if ignore.is_file() and not ignore.is_symlink():
                arguments.extend(["--ignore-file", str(ignore)])
        with tempfile.TemporaryDirectory() as temporary_directory, tempfile.TemporaryFile(
            mode="w+b"
        ) as inventory:
            if ignored_aliases:
                alias_file = Path(temporary_directory) / "git-metadata.ignore"
                alias_file.write_bytes(b"".join(os.fsencode(alias) for alias in ignored_aliases))
                arguments.extend(["--ignore-file", str(alias_file)])
            if directory_guard:
                relative_scope = requested_scope.removeprefix("./")
                arguments.extend(
                    ["--quiet", "--glob", f"/{re.escape(relative_scope)}/**", "--", "."]
                )
            else:
                arguments.extend(["--", requested_scope])
            try:
                result = subprocess.run(
                    arguments,
                    cwd=directory,
                    stdout=inventory,
                    stderr=subprocess.PIPE,
                    check=False,
                )
            except OSError as error:
                raise InventoryError(f"could not run ripgrep: {error}") from error

            if result.returncode not in (0, 1):
                detail = result.stderr.decode("utf-8", errors="replace").strip()
                message = f"ripgrep exited with status {result.returncode}"
                if detail:
                    message = f"{message}: {detail}"
                raise InventoryError(message)

            if directory_guard:
                return {b""} if result.returncode == 0 else set()
            inventory.seek(0)
            rows = set()

            def inventory_paths() -> Iterator[bytes]:
                remainder = b""
                while chunk := inventory.read(io.DEFAULT_BUFFER_SIZE):
                    paths = chunk.split(b"\0")
                    paths[0] = remainder + paths[0]
                    remainder = paths.pop()
                    yield from paths
                if remainder:
                    raise InventoryError("ripgrep returned an unterminated inventory path")

            for path in inventory_paths():
                if not path:
                    continue
                if b"\n" in path or b"\r" in path:
                    raise InventoryError("line separators are not supported in inventory paths")
                row = path + b"\n"
                if not metadata_aliases:
                    rows.add(row)
                    continue
                parts = (
                    *directory_parts,
                    *Path(os.fsdecode(row.removesuffix(b"\n"))).parts,
                )
                if not any(parts[: len(alias)] == alias for alias in metadata_aliases):
                    rows.add(row)
            return rows

    def normalized(path: bytes) -> bytes:
        return path.replace(b"\\", b"/") if os.name == "nt" else path

    rows = ripgrep_inventory(repository, scope)
    if selected.is_dir() and scope not in (".", "./") and not ripgrep_inventory(
        repository, scope, directory_guard=True
    ):
        rows.clear()
    for ancestor in ancestors[1:]:
        if not any((ancestor / name).is_file() for name in IGNORE_FILE_NAMES):
            continue
        ancestor_scope = selected.relative_to(ancestor).as_posix() or "."
        ancestor_prefix = os.fsencode(ancestor.relative_to(repository).as_posix()) + b"/"
        visible = {
            normalized(
                ancestor_prefix + normalized(row.removesuffix(b"\n")).removeprefix(b"./")
            )
            for row in ripgrep_inventory(ancestor, ancestor_scope)
        }
        rows = {
            row
            for row in rows
            if normalized(row.removesuffix(b"\n")).removeprefix(b"./") in visible
        }

    environment = os.environ.copy()
    for name in (
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_CEILING_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_DIR",
        "GIT_DISCOVERY_ACROSS_FILESYSTEM",
        "GIT_INDEX_FILE",
        "GIT_ICASE_PATHSPECS",
        "GIT_GLOB_PATHSPECS",
        "GIT_NAMESPACE",
        "GIT_NOGLOB_PATHSPECS",
        "GIT_OBJECT_DIRECTORY",
        "GIT_WORK_TREE",
    ):
        environment.pop(name, None)
    environment["GIT_LITERAL_PATHSPECS"] = "1"
    environment["LC_ALL"] = "C"
    git = [
        "git",
        "-c",
        "core.fsmonitor=false",
        "-c",
        f"core.excludesFile={os.devnull}",
        "--literal-pathspecs",
    ]

    def run_git(
        arguments: list[str], *, directory: Path = repository, literal: bool = True
    ) -> subprocess.CompletedProcess[bytes]:
        command = git if literal else git[:-1]
        git_environment = environment if literal else environment.copy()
        if not literal:
            git_environment.pop("GIT_LITERAL_PATHSPECS", None)
        try:
            return subprocess.run(
                [*command, *arguments],
                cwd=directory,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=git_environment,
                check=False,
            )
        except OSError as error:
            raise InventoryError(f"could not run Git: {error}") from error

    def resolve_git_root(value: bytes) -> Path:
        root_path = value.removesuffix(b"\n")
        if os.name == "nt":
            root_path = root_path.removesuffix(b"\r")
        return Path(os.fsdecode(root_path)).resolve(strict=True)

    worktree = (
        run_git(["rev-parse", "--show-toplevel"])
        if (repository / ".git").exists()
        else None
    )
    if worktree is not None and worktree.returncode:
        detail = worktree.stderr.decode("utf-8", errors="replace").strip()
        if any(
            reason in detail.lower()
            for reason in (
                "not a git repository",
                "gitfile does not point to a valid repository",
                "invalid gitfile format",
            )
        ):
            worktree = None
        else:
            message = f"git rev-parse exited with status {worktree.returncode}"
            if detail:
                message = f"{message}: {detail}"
            raise InventoryError(message)

    if worktree is not None:
        try:
            worktree_root = resolve_git_root(worktree.stdout)
        except (OSError, ValueError) as error:
            raise InventoryError(f"could not resolve Git worktree root: {error}") from error
        if worktree_root != repository:
            worktree = None

    if worktree is not None or discovered_roots:
        prefix = b"./" if scope == "." or scope.startswith("./") else b""
        listed: list[list[bytes]] = [[], []]
        cached_by_root: dict[tuple[int, int], tuple[Path, list[bytes]]] = {}

        def listed_paths(index: int) -> Iterator[bytes]:
            for chunk in listed[index]:
                for relative in chunk.split(b"\0"):
                    if not relative:
                        continue
                    if b"\n" in relative or b"\r" in relative:
                        raise InventoryError("line separators are not supported in inventory paths")
                    yield relative

        if worktree is not None:
            for index, arguments in enumerate(
                (["--cached"], ["--others", "--exclude-standard"])
            ):
                result = run_git(["ls-files", *arguments, "-z", "--", scope])
                if result.returncode:
                    detail = result.stderr.decode("utf-8", errors="replace").strip()
                    message = f"git ls-files exited with status {result.returncode}"
                    if detail:
                        message = f"{message}: {detail}"
                    raise InventoryError(message)
                listed[index].append(result.stdout)
                if index == 0:
                    cached_by_root[directory_identity(repository)] = (
                        repository,
                        [relative for relative in result.stdout.split(b"\0") if relative],
                    )

        visible_paths = {
            normalized(row.removesuffix(b"\n")).removeprefix(b"./") for row in rows
        }
        outer_tracked_paths = set(listed_paths(0))

        def visible_nested_root(root: Path) -> bool:
            relative = os.fsencode(root.relative_to(repository).as_posix())
            if selected != repository and (selected == root or selected.is_relative_to(root)):
                return True
            return any(
                path == relative or path.startswith(relative + b"/")
                for paths in (visible_paths, outer_tracked_paths)
                for path in paths
            )

        nested_roots = {
            identity: root
            for identity, root in discovered_roots.items()
            if visible_nested_root(root)
        }
        current = selected if selected.is_dir() else selected.parent
        while current != repository:
            if (current / ".git").exists():
                nested_roots[directory_identity(current)] = current
            current = current.parent
        for index in range(len(listed)):
            for relative in listed_paths(index):
                candidate = repository / os.fsdecode(relative)
                if candidate.is_symlink() or not candidate.is_dir():
                    continue
                if not (candidate / ".git").exists():
                    continue
                try:
                    discovered = candidate.resolve(strict=True)
                    discovered.relative_to(repository)
                except (OSError, ValueError):
                    continue
                if index != 0 and not visible_nested_root(discovered):
                    continue
                nested_roots[directory_identity(discovered)] = discovered

        pending_roots = sorted(nested_roots.values())
        inspected_roots: dict[tuple[int, int], Path] = {}
        while pending_roots:
            nested = pending_roots.pop(0)
            nested_identity = directory_identity(nested)
            if nested_identity in inspected_roots:
                continue
            nested_worktree = run_git(
                ["rev-parse", "--show-toplevel"], directory=nested
            )
            if nested_worktree.returncode:
                detail = nested_worktree.stderr.decode("utf-8", errors="replace").strip()
                if any(
                    reason in detail.lower()
                    for reason in (
                        "not a git repository",
                        "gitfile does not point to a valid repository",
                        "invalid gitfile format",
                    )
                ):
                    continue
                raise InventoryError(
                    f"nested git rev-parse exited with status {nested_worktree.returncode}: {detail}"
                )
            try:
                if resolve_git_root(nested_worktree.stdout) != nested:
                    continue
            except (OSError, ValueError):
                continue
            inspected_roots[nested_identity] = nested
            try:
                nested_scope = selected.relative_to(nested).as_posix() or "."
            except ValueError:
                nested_scope = "."
            nested_prefix = os.fsencode(nested.relative_to(repository).as_posix()) + b"/"
            for index, arguments in enumerate(
                (["--cached"], ["--others", "--exclude-standard"])
            ):
                result = run_git(
                    ["ls-files", *arguments, "-z", "--", nested_scope],
                    directory=nested,
                )
                if result.returncode:
                    detail = result.stderr.decode("utf-8", errors="replace").strip()
                    raise InventoryError(
                        f"nested git ls-files exited with status {result.returncode}: {detail}"
                    )
                listed[index].append(
                    b"".join(
                        nested_prefix + relative + b"\0"
                        for relative in result.stdout.split(b"\0")
                        if relative
                    )
                )
                if index == 0:
                    cached_by_root[nested_identity] = (
                        nested,
                        [relative for relative in result.stdout.split(b"\0") if relative],
                    )
                for relative in result.stdout.split(b"\0"):
                    if not relative:
                        continue
                    candidate = nested / os.fsdecode(relative)
                    if candidate.is_symlink() or not candidate.is_dir():
                        continue
                    if not (candidate / ".git").exists():
                        continue
                    try:
                        discovered = candidate.resolve(strict=True)
                        discovered.relative_to(repository)
                    except (OSError, ValueError):
                        continue
                    if directory_identity(discovered) not in inspected_roots:
                        pending_roots.append(discovered)

        allowed = {
            normalized(prefix + relative)
            for index in range(len(listed))
            for relative in listed_paths(index)
        }
        if scope not in (".", "./"):
            for identity, (root, _) in list(cached_by_root.items()):
                tracked = run_git(["ls-files", "--cached", "-z"], directory=root)
                if tracked.returncode:
                    detail = tracked.stderr.decode("utf-8", errors="replace").strip()
                    raise InventoryError(
                        f"git ls-files exited with status {tracked.returncode}: {detail}"
                    )
                cached_by_root[identity] = (
                    root,
                    [relative for relative in tracked.stdout.split(b"\0") if relative],
                )
        case_insensitive_roots: dict[tuple[int, int], bool] = {}
        for identity, (root, _) in cached_by_root.items():
            setting = run_git(["config", "--bool", "core.ignoreCase"], directory=root)
            if setting.returncode not in (0, 1):
                detail = setting.stderr.decode("utf-8", errors="replace").strip()
                raise InventoryError(
                    f"git config exited with status {setting.returncode}: {detail}"
                )
            case_insensitive_roots[identity] = setting.stdout.strip().lower() == b"true"
        inspected_prefixes = tuple(
            normalized(prefix + os.fsencode(root.relative_to(repository).as_posix()) + b"/")
            for root in inspected_roots.values()
        )
        nested_worktrees = tuple(
            path
            for path in allowed
            if path.endswith(b"/") and path not in inspected_prefixes
        )
        explicitly_ignored = False
        enclosing_roots = list(inspected_roots.values())
        if worktree is not None:
            enclosing_roots.append(repository)
        if scope not in (".", "./") and any(
            selected.is_relative_to(root) for root in enclosing_roots
        ):
            enclosing = max(
                (root for root in enclosing_roots if selected.is_relative_to(root)),
                key=lambda root: len(root.parts),
            )
            explicit_relative = selected.relative_to(enclosing).as_posix()
            explicit_path = f"./{explicit_relative}"
            ignored = run_git(
                ["check-ignore", "--quiet", "--no-index", "--", explicit_path],
                directory=enclosing,
                literal=False,
            )
            if ignored.returncode not in (0, 1):
                detail = ignored.stderr.decode("utf-8", errors="replace").strip()
                message = f"git check-ignore exited with status {ignored.returncode}"
                if detail:
                    message = f"{message}: {detail}"
                raise InventoryError(message)
            explicitly_ignored = ignored.returncode == 0 and selected.is_file()

        if not explicitly_ignored:
            rows = {
                row
                for row in rows
                if (path := normalized(row.removesuffix(b"\n"))) in allowed
                or (
                    worktree is None
                    and not any(path.startswith(root) for root in inspected_prefixes)
                )
                or any(path.startswith(worktree) for worktree in nested_worktrees)
            }
        recorded = {normalized(row.removesuffix(b"\n")) for row in rows}
        directory_entries: dict[tuple[int, int], dict[str, list[Path]]] = {}
        selected_parts = tuple(
            os.fsencode(part) for part in selected.relative_to(repository).parts
        )
        selected_is_directory = selected.is_dir()

        def tracked_variants(
            root_identity: tuple[int, int], root: Path, relative: bytes
        ) -> Iterator[Path]:
            components = PurePosixPath(os.fsdecode(relative)).parts
            if not components or any(part in (".", "..") for part in components):
                return
            root_parts = tuple(os.fsencode(part) for part in root.relative_to(repository).parts)
            indexed_parts = root_parts + tuple(os.fsencode(part) for part in components)
            if (not selected_is_directory and len(indexed_parts) != len(selected_parts)) or (
                selected_is_directory and len(indexed_parts) <= len(selected_parts)
            ):
                return
            for index, requested in enumerate(selected_parts):
                indexed = indexed_parts[index]
                if index < len(root_parts) or not case_insensitive_roots[root_identity]:
                    if indexed != requested:
                        return
                elif os.fsdecode(indexed).casefold() != os.fsdecode(requested).casefold():
                    return

            def descend(parent: Path, index: int) -> list[Path]:
                try:
                    parent_identity = directory_identity(parent)
                except OSError:
                    return []
                if parent_identity not in directory_entries:
                    grouped: dict[str, list[Path]] = {}
                    try:
                        with os.scandir(parent) as entries:
                            for entry in entries:
                                if not git_metadata_path(parent, entry.name):
                                    grouped.setdefault(entry.name.casefold(), []).append(
                                        parent / entry.name
                                    )
                    except OSError:
                        return []
                    directory_entries[parent_identity] = grouped
                component = components[index]
                variants = directory_entries[parent_identity].get(component.casefold(), [])
                exact = [candidate for candidate in variants if candidate.name == component]
                alternatives = [candidate for candidate in variants if candidate.name != component]
                groups = [exact]
                if case_insensitive_roots[root_identity]:
                    groups.append(alternatives)
                for group in groups:
                    matches: list[Path] = []
                    for candidate in group:
                        try:
                            metadata = candidate.stat(follow_symlinks=False)
                        except OSError:
                            continue
                        if symbolic_metadata(metadata):
                            continue
                        if index + 1 < len(components):
                            if not stat.S_ISDIR(metadata.st_mode):
                                continue
                            owner_identity = (metadata.st_dev, metadata.st_ino)
                            if owner_identity in inspected_roots and owner_identity != root_identity:
                                continue
                            matches.extend(descend(candidate, index + 1))
                        elif stat.S_ISREG(metadata.st_mode):
                            matches.append(candidate)
                    if matches:
                        return matches
                return []

            for candidate in descend(root, 0):
                try:
                    resolved = candidate.resolve(strict=True)
                    resolved.relative_to(repository)
                except (OSError, ValueError):
                    continue
                candidate_parts = tuple(
                    os.fsencode(part) for part in candidate.relative_to(repository).parts
                )
                if selected_is_directory:
                    if candidate_parts[: len(selected_parts)] != selected_parts:
                        continue
                elif candidate_parts != selected_parts:
                    continue
                yield candidate

        for root_identity, (root, tracked_paths) in cached_by_root.items():
            for relative in tracked_paths:
                for candidate in tracked_variants(root_identity, root, relative):
                    relative_path = prefix + os.fsencode(
                        candidate.relative_to(repository).as_posix()
                    )
                    key = normalized(relative_path)
                    if key not in recorded:
                        rows.add(relative_path + b"\n")
                        recorded.add(key)

    rows = sorted(rows)

    output.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=output.parent,
            prefix=f".{output.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.writelines(rows)
        temporary.replace(output)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)

    return len(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="Repository root.")
    parser.add_argument("--scope", required=True, help="File or directory within the repository.")
    parser.add_argument("--out", required=True, help="Destination for the file inventory.")
    args = parser.parse_args()

    try:
        repository = resolve_repository(args.repo)
        scope = resolve_scope(repository, args.scope)
        output = resolve_output(args.out)
        count = generate_in_scope_files(repository, scope, output)
    except (OSError, ValueError) as error:
        print(f"generate_in_scope_files: {error}", file=sys.stderr)
        raise SystemExit(2) from error

    print(f"Recorded {count} in-scope files.")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Generate the shared, deterministically ordered security-scan file inventory."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path

IGNORE_FILE_NAMES = (".gitignore", ".ignore", ".rgignore")


class InventoryError(ValueError):
    """Raised when the repository, scope, or inventory cannot be used safely."""


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

    current = scope
    while current != repository:
        if current == current.parent:
            raise InventoryError("--scope: symbolic links are not supported")
        if current.is_symlink():
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

    def reject_symbolic_ignore(directory: Path) -> None:
        if any((directory / name).is_symlink() for name in IGNORE_FILE_NAMES):
            raise InventoryError("symbolic ignore files are not supported")

    discovered_roots: set[Path] = set()
    for ancestor in ancestors:
        reject_symbolic_ignore(ancestor)
    if selected.is_dir():
        for directory, children, _ in os.walk(selected, followlinks=False):
            directory_path = Path(directory)
            if directory_path != repository and (directory_path / ".git").exists():
                discovered_roots.add(directory_path)
            children[:] = [name for name in children if name != ".git"]
            reject_symbolic_ignore(directory_path)

    command = [
        "rg",
        "--no-config",
        "--files",
        "--hidden",
        "--no-require-git",
        "--no-ignore-parent",
        "--no-ignore-global",
        "--glob",
        "!.git/**",
    ]

    def ripgrep_inventory(directory: Path, requested_scope: str) -> set[bytes]:
        arguments = command.copy()
        for name in IGNORE_FILE_NAMES:
            ignore = directory / name
            if ignore.is_file() and not ignore.is_symlink():
                arguments.extend(["--ignore-file", str(ignore)])
        arguments.extend(["--", requested_scope])
        with tempfile.TemporaryFile(mode="w+b") as inventory:
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

            inventory.seek(0)
            return set(inventory)

    def normalized(path: bytes) -> bytes:
        return path.replace(b"\\", b"/") if os.name == "nt" else path

    rows = ripgrep_inventory(repository, scope)
    for ancestor in ancestors[1:]:
        if not any((ancestor / name).is_file() for name in IGNORE_FILE_NAMES):
            continue
        ancestor_scope = selected.relative_to(ancestor).as_posix() or "."
        ancestor_prefix = os.fsencode(ancestor.relative_to(repository).as_posix()) + b"/"
        visible = {
            normalized(ancestor_prefix + row.removesuffix(b"\n").removeprefix(b"./"))
            for row in ripgrep_inventory(ancestor, ancestor_scope)
        }
        rows = {
            row
            for row in rows
            if normalized(row.removesuffix(b"\n").removeprefix(b"./")) in visible
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

        def listed_paths(index: int) -> Iterator[bytes]:
            for chunk in listed[index]:
                yield from (relative for relative in chunk.split(b"\0") if relative)

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

        nested_roots = discovered_roots.copy()
        current = selected if selected.is_dir() else selected.parent
        while current != repository:
            if (current / ".git").exists():
                nested_roots.add(current)
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
                nested_roots.add(discovered)

        pending_roots = sorted(nested_roots)
        inspected_roots: set[Path] = set()
        while pending_roots:
            nested = pending_roots.pop(0)
            if nested in inspected_roots:
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
            inspected_roots.add(nested)
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
                    if discovered not in inspected_roots:
                        pending_roots.append(discovered)

        allowed = {
            normalized(prefix + relative)
            for index in range(len(listed))
            for relative in listed_paths(index)
        }
        inspected_prefixes = tuple(
            normalized(prefix + os.fsencode(root.relative_to(repository).as_posix()) + b"/")
            for root in inspected_roots
        )
        nested_worktrees = tuple(
            path
            for path in allowed
            if path.endswith(b"/") and path not in inspected_prefixes
        )
        explicitly_ignored = False
        enclosing_roots = inspected_roots.copy()
        if worktree is not None:
            enclosing_roots.add(repository)
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

        for relative in listed_paths(0):
            candidate = repository / os.fsdecode(relative)
            if candidate.is_symlink() or not candidate.is_file():
                continue
            try:
                candidate.resolve(strict=True).relative_to(repository)
            except (OSError, ValueError):
                continue
            relative_path = prefix + relative
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

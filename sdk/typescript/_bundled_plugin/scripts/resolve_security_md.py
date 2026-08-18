#!/usr/bin/env python3
"""Concatenate the SECURITY.md files that apply to a scan path."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

MAX_SECURITY_MD_BYTES = 1024 * 1024


class ResolutionError(ValueError):
    """Raised when a SECURITY.md chain cannot be resolved."""


def _inside(path: Path, root: Path, label: str) -> Path:
    try:
        return path.relative_to(root)
    except ValueError as exc:
        raise ResolutionError(f"{label} is outside the scan root: {path}") from exc


def _resolve_root(repo: Path) -> Path:
    try:
        root = repo.expanduser().resolve(strict=True)
    except OSError as exc:
        raise ResolutionError(f"scan root does not exist: {repo}") from exc
    if not root.is_dir():
        raise ResolutionError(f"scan root is not a directory: {root}")
    return root


def _scope_directory(root: Path, scope: Path, *, require_directory: bool = False) -> Path:
    requested = scope.expanduser()
    if not requested.is_absolute():
        requested = root / requested
    try:
        resolved = requested.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ResolutionError(f"scan scope does not exist: {requested}") from exc
    _inside(resolved, root, "scan scope")
    if require_directory and not resolved.is_dir():
        raise ResolutionError(f"policy scope must be a directory: {requested}")
    return resolved if resolved.is_dir() else resolved.parent


def _git_metadata(path: Path, root: Path, git_dirs: tuple[Path, ...]) -> bool:
    relative = _inside(path, root, "policy path")
    for directory in git_dirs:
        if path.is_relative_to(directory):
            return True
        # resolve() preserves case aliases on some case-insensitive filesystems.
        for ancestor in (path, *path.parents):
            try:
                if ancestor.samefile(directory):
                    return True
            except (FileNotFoundError, NotADirectoryError):
                pass
            if ancestor == root:
                break
    current = root
    for part in relative.parts:
        current /= part
        if part == ".git":
            return True
        if part.lower() == ".git":
            marker = current.with_name(".git")
            try:
                if current.samefile(marker):
                    return True
            except (FileNotFoundError, NotADirectoryError):
                pass
    return False


def _read_policy(policy: Path, root: Path, git_dirs: tuple[Path, ...] = ()) -> str | None:
    try:
        resolved = policy.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise ResolutionError(f"could not resolve SECURITY.md: {policy}") from exc
    _inside(resolved, root, "SECURITY.md")
    if _git_metadata(policy, root, git_dirs) or _git_metadata(resolved, root, git_dirs):
        raise ResolutionError(f"SECURITY.md points into Git metadata: {policy}")
    try:
        metadata = resolved.stat(follow_symlinks=False)
    except (FileNotFoundError, NotADirectoryError):
        return None
    if not stat.S_ISREG(metadata.st_mode):
        raise ResolutionError(f"SECURITY.md must be a regular file: {policy}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(resolved, flags), "rb") as policy_file:
        metadata = os.fstat(policy_file.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise ResolutionError(f"SECURITY.md must be a regular file: {policy}")
        if metadata.st_nlink > 1:
            raise ResolutionError(f"SECURITY.md must not be hard-linked: {policy}")
        policy_bytes = policy_file.read(MAX_SECURITY_MD_BYTES + 1)
    if len(policy_bytes) > MAX_SECURITY_MD_BYTES:
        raise ResolutionError(f"SECURITY.md exceeds 1 MiB: {policy}")
    try:
        return policy_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ResolutionError(f"SECURITY.md is not valid UTF-8: {policy}") from exc


def list_security_md(
    repo: Path, scope: Path | None = None, git_dirs: tuple[Path, ...] = ()
) -> list[str]:
    """Return a stable, safely framed inventory without traversing Git metadata."""
    root = _resolve_root(repo)

    def raise_walk_error(error: OSError) -> None:
        raise error

    policies: list[str] = []
    selected = root if scope is None else _scope_directory(root, scope, require_directory=True)
    if _git_metadata(selected, root, git_dirs):
        raise ResolutionError(f"policy scope is inside Git metadata: {selected}")
    for directory, subdirectories, _filenames in os.walk(
        selected, onerror=raise_walk_error, followlinks=False
    ):
        safe_subdirectories: list[str] = []
        for name in sorted(subdirectories):
            child = Path(directory) / name
            if _git_metadata(child, root, git_dirs):
                continue
            directory_stat = child.stat(follow_symlinks=False)
            if not stat.S_ISDIR(directory_stat.st_mode):
                continue
            reparse_point = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
            if getattr(directory_stat, "st_file_attributes", 0) & reparse_point:
                continue
            safe_subdirectories.append(name)
        subdirectories[:] = safe_subdirectories
        policy = Path(directory) / "SECURITY.md"
        if policy.is_file() or policy.is_symlink():
            policies.append(policy.relative_to(root).as_posix())
    return sorted(policies)


def resolve_security_md(repo: Path, scope: Path, git_dirs: tuple[Path, ...] = ()) -> str:
    """Return applicable SECURITY.md files, concatenated root to leaf."""
    root = _resolve_root(repo)

    target_directory = _scope_directory(root, scope)
    if _git_metadata(target_directory, root, git_dirs):
        raise ResolutionError(f"policy scope is inside Git metadata: {target_directory}")
    relative_directory = _inside(target_directory, root, "scan scope")
    directories = [root]
    current = root
    for part in relative_directory.parts:
        current /= part
        directories.append(current)

    sections: list[str] = []
    for directory in directories:
        policy = directory / "SECURITY.md"
        content = _read_policy(policy, root, git_dirs)
        if content is None:
            continue
        if not content.strip():
            continue

        source = policy.relative_to(root).as_posix()
        section = f"## SECURITY.md source: {json.dumps(source)}\n\n{content}"
        if not section.endswith("\n"):
            section += "\n"
        sections.append(section)

    return "\n".join(sections)


def inspect_security_policy(
    repo: Path, scope: Path, git_dirs: tuple[Path, ...] = ()
) -> dict[str, object]:
    """Return checked drafting evidence without interpreting policy as instructions."""
    root = _resolve_root(repo)
    directory = _scope_directory(root, scope, require_directory=True)
    selected = directory / "SECURITY.md"
    if selected.is_symlink():
        raise ResolutionError(f"selected SECURITY.md must not be a symbolic link: {selected}")
    previous = _read_policy(selected, root, git_dirs)
    paths = set(list_security_md(root, directory, git_dirs))
    current = directory
    while True:
        paths.add((current / "SECURITY.md").relative_to(root).as_posix())
        if current == root:
            break
        current = current.parent
    paths.update((".github/SECURITY.md", "docs/SECURITY.md"))
    checked = [
        path for path in sorted(paths) if _read_policy(root / path, root, git_dirs) is not None
    ]
    return {
        "previousContent": previous,
        "guidance": resolve_security_md(root, directory, git_dirs),
        "policyPaths": checked,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path, help="scan root directory")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--list",
        action="store_true",
        help="write a JSON inventory of repository policy paths",
    )
    mode.add_argument(
        "--inspect",
        action="store_true",
        help="write checked drafting inputs as JSON",
    )
    parser.add_argument(
        "--scope",
        type=Path,
        help="existing file or directory within the scan root",
    )
    parser.add_argument("--out", default=Path("-"), type=Path, help="output path, or - for stdout")
    parser.add_argument(
        "--git-dir",
        action="append",
        default=[],
        type=Path,
        help="exclude a Git metadata directory identified by the caller",
    )
    args = parser.parse_args()
    if not args.list and args.scope is None:
        parser.error("--scope is required unless --list is specified")
    return args


def main() -> int:
    args = parse_args()
    try:
        git_dirs = tuple(path.resolve(strict=True) for path in args.git_dir)
        if args.inspect:
            guidance = (
                json.dumps(
                    inspect_security_policy(args.repo, args.scope, git_dirs), ensure_ascii=True
                )
                + "\n"
            )
        elif args.list:
            guidance = (
                json.dumps(list_security_md(args.repo, args.scope, git_dirs), ensure_ascii=True)
                + "\n"
            )
        else:
            guidance = resolve_security_md(args.repo, args.scope, git_dirs)
        if args.out == Path("-"):
            sys.stdout.buffer.write(guidance.encode("utf-8"))
        else:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(guidance, encoding="utf-8")
    except (OSError, ResolutionError) as exc:
        print(f"resolve_security_md.py: error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

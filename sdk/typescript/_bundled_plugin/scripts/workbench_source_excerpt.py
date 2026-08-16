"""Read bounded finding source excerpts from sealed Git revisions."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from functools import cache
from pathlib import Path, PurePosixPath
from typing import Any
from unicodedata import normalize

# Some plugin hosts launch Python with safe-path isolation enabled.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from workbench_target import (
    clean_worktree_content_digest,
    git_bytes,
    git_worktree_context,
)
from workbench_validation import path_within_scope

CONTEXT_LINES = 3
MAX_BYTES = 16_000
MAX_LINES = 60


def normalized_path_component(value: str) -> str:
    return normalize("NFC", normalize("NFD", value).casefold())


def finding_source_excerpt(
    scan: sqlite3.Row,
    target: Path | None,
    locations: list[dict[str, Any]],
    scopes: list[str],
) -> str | None:
    if target is None or not locations or scan["target_revision"] == "unversioned":
        return None
    snapshot_digest = scan["target_snapshot_digest"]
    if snapshot_digest is not None and snapshot_digest != clean_worktree_content_digest():
        return None
    indexed_scopes: dict[tuple[str, ...], list[str]] = {}
    for scope in scopes:
        parts = tuple(normalized_path_component(part) for part in PurePosixPath(scope).parts)
        indexed_scopes.setdefault(parts, []).append(scope)
    scope_lengths = sorted({len(parts) for parts in indexed_scopes})
    location_scopes: dict[str, str] = {}

    def location_is_in_scope(path: str) -> bool:
        parts = tuple(normalized_path_component(part) for part in PurePosixPath(path).parts)
        for length in scope_lengths:
            if length > len(parts):
                break
            matching_scopes = indexed_scopes.get(parts[:length], [])
            if matching_scopes and safe_source_path(target, path) is None:
                return False
            for scope in matching_scopes:
                if source_path_in_scope(scan, target, path, scope):
                    location_scopes[path] = scope
                    return True
        return False

    def matching_location(priority: int) -> dict[str, Any] | None:
        for candidate in locations:
            path = candidate.get("path")
            role = candidate.get("role")
            if (
                not isinstance(path, str)
                or priority == 0 and role != "root_control"
                or priority == 1 and "root_control" not in str(role or "").lower()
            ):
                continue
            if location_is_in_scope(path):
                return candidate
        return None

    location = next(
        (candidate for priority in range(3) if (candidate := matching_location(priority))),
        None,
    )
    if location is None:
        return None
    path = location.get("path")
    start_line = location.get("startLine")
    end_line = location.get("endLine")
    if not isinstance(path, str) or not isinstance(start_line, int):
        return None
    source = scanned_source_text(scan, target, path, scope=location_scopes[path])
    if not source or "\0" in source:
        return None
    lines = source.splitlines()
    if start_line < 1 or start_line > len(lines):
        return None
    last_affected_line = end_line if isinstance(end_line, int) else start_line
    excerpt_start = max(1, start_line - CONTEXT_LINES)
    excerpt_end = min(
        len(lines),
        max(start_line, last_affected_line) + CONTEXT_LINES,
        excerpt_start + MAX_LINES - 1,
    )
    width = len(str(excerpt_end))
    excerpt = "\n".join(
        f"{line_number:>{width}}  {lines[line_number - 1]}"
        for line_number in range(excerpt_start, excerpt_end + 1)
    )
    encoded = excerpt.encode("utf-8")[:MAX_BYTES]
    return encoded.decode("utf-8", errors="ignore")


def scanned_source_text(
    scan: sqlite3.Row,
    target: Path,
    path: str,
    scopes: list[str] | None = None,
    *,
    scope: str | None = None,
) -> str | None:
    source_path = safe_source_path(target, path)
    if source_path is None or (
        scopes is not None
        and not any(source_path_in_scope(scan, target, path, scope) for scope in scopes)
    ):
        return None
    if scope is not None:
        selected = safe_source_path(target, scope)
        if selected is None:
            return None
        candidate_parts = source_path.relative_to(target).parts
        selected_parts = selected.relative_to(target).parts
        candidate_prefix = candidate_parts[: len(selected_parts)]
        if tuple(map(normalized_path_component, candidate_prefix)) != tuple(
            map(normalized_path_component, selected_parts)
        ):
            return None
    revision = scan["target_revision"]
    if revision == "unversioned":
        return None
    snapshot_digest = scan["target_snapshot_digest"]
    if snapshot_digest is not None and snapshot_digest != clean_worktree_content_digest():
        return None
    try:
        repository, object_name = committed_object(scan, target, path, scope)
        content = offline_git_bytes(repository, "cat-file", "blob", object_name)
        if content is None:
            repository, object_name = committed_object(
                scan, target, path, scope, canonicalize=True
            )
            content = offline_git_bytes(repository, "cat-file", "blob", object_name)
    except (OSError, RuntimeError, SystemExit):
        return None
    return content.decode("utf-8", errors="replace") if content is not None else None


def source_path_in_scope(scan: sqlite3.Row, target: Path, path: str, scope: str) -> bool:
    try:
        recipe = scan["recipe_json"]
    except (KeyError, IndexError):
        recipe = None
    if recipe is not None:
        file_scopes = recorded_file_scopes(recipe)
        if scope in file_scopes and len(PurePosixPath(path).parts) > len(
            PurePosixPath(scope).parts
        ):
            return False
    if path_within_scope(path, scope):
        try:
            if PurePosixPath(path) == PurePosixPath(scope) or not (target / scope).is_file():
                return True
            return bool(committed_tree_entries(target, scan["target_revision"], scope))
        except (KeyError, IndexError, OSError, RuntimeError, SystemExit):
            return False
    requested = PurePosixPath(scope)
    actual = PurePosixPath(path)
    if len(requested.parts) > len(actual.parts):
        return False
    for index, (selected_name, actual_name) in enumerate(
        zip(requested.parts, actual.parts), start=1
    ):
        if selected_name == actual_name:
            continue
        if normalized_path_component(selected_name) != normalized_path_component(actual_name):
            return False
        try:
            selected_path = target / PurePosixPath(*requested.parts[:index])
            actual_path = target / PurePosixPath(*actual.parts[:index])
            if not filesystem_case_alias(target, selected_path, actual_path):
                return False
            entries = committed_tree_entries(
                target,
                scan["target_revision"],
                str(PurePosixPath(*actual.parts[: index - 1])),
            )
            if entries is None:
                return False
            aliases = [
                entry
                for entry in entries
                if normalized_path_component(entry)
                == normalized_path_component(selected_name)
            ]
            if len(aliases) != 1:
                return False
        except (OSError, RuntimeError, SystemExit):
            return False
    try:
        if len(requested.parts) == len(actual.parts) or not (target / scope).is_file():
            return True
        committed_scope = str(PurePosixPath(*actual.parts[: len(requested.parts)]))
        return bool(committed_tree_entries(target, scan["target_revision"], committed_scope))
    except (KeyError, IndexError, OSError, RuntimeError, SystemExit):
        return False


def filesystem_case_alias(target: Path, selected: Path, actual: Path) -> bool:
    try:
        if selected.is_symlink() or actual.is_symlink() or not selected.samefile(actual):
            return False
    except OSError:
        for directory in (target, *target.parents):
            alternative = next(
                (
                    directory.name[:index]
                    + character.swapcase()
                    + directory.name[index + 1 :]
                    for index, character in enumerate(directory.name)
                    if character.isascii() and character.isalpha()
                ),
                None,
            )
            if alternative is None:
                continue
            try:
                if directory.samefile(directory.with_name(alternative)):
                    return True
            except OSError:
                continue
        return False
    try:
        normalized = normalized_path_component(selected.name)
        with os.scandir(selected.parent) as entries:
            return (
                sum(normalized_path_component(entry.name) == normalized for entry in entries) == 1
            )
    except OSError:
        return False


@cache
def recorded_file_scopes(recipe: str) -> frozenset[str]:
    return frozenset(json.loads(recipe).get("_codexSecurityFileScopes", []))


@cache
def committed_tree_entries(target: Path, revision: str, parent: str) -> tuple[str, ...] | None:
    repository, prefix = committed_worktree_context(target)
    if prefix != ".":
        _, object_name = committed_object(
            {"target_revision": revision}, repository, prefix, scope=prefix, canonicalize=True
        )
        prefix = object_name.partition(":")[2]
    selected = PurePosixPath(prefix, parent)
    tree = revision if selected == PurePosixPath(".") else f"{revision}:{selected}"
    entries = offline_git_bytes(repository, "ls-tree", "-z", tree)
    if entries is None:
        return None
    return tuple(
        os.fsdecode(entry.partition(b"\t")[2]) for entry in entries.split(b"\0") if entry
    )


def offline_git_bytes(repository: Path, *arguments: str) -> bytes | None:
    names = ("GIT_NO_LAZY_FETCH", "GIT_ALLOW_PROTOCOL")
    previous = {name: os.environ.get(name) for name in names}
    os.environ["GIT_NO_LAZY_FETCH"] = "1"
    os.environ["GIT_ALLOW_PROTOCOL"] = ""
    try:
        return git_bytes(repository, *arguments)
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


@cache
def committed_worktree_context(target: Path) -> tuple[Path, str]:
    return git_worktree_context(target)


def committed_object(
    scan: sqlite3.Row,
    target: Path,
    path: str,
    scope: str | None = None,
    *,
    canonicalize: bool = False,
) -> tuple[Path, str]:
    repository, prefix = committed_worktree_context(target)
    selected = PurePosixPath(prefix, path)
    revision = scan["target_revision"]
    boundary = (
        len(selected.parts)
        if canonicalize
        else len(PurePosixPath(prefix).parts)
        + len(PurePosixPath(scope or ".").parts)
    )
    canonical: list[str] = []
    for index, name in enumerate(selected.parts):
        if index >= boundary:
            canonical.extend(selected.parts[index:])
            break
        parent = PurePosixPath(*canonical)
        entries = committed_tree_entries(repository, revision, str(parent))
        if entries is None:
            raise OSError("Committed source tree is unavailable.")
        aliases = [
            entry
            for entry in entries
            if normalized_path_component(entry) == normalized_path_component(name)
        ]
        if len(aliases) > 1:
            actual = repository / parent / name
            for entry in aliases:
                if entry == name:
                    continue
                try:
                    if actual.samefile(repository / parent / entry):
                        raise OSError("Committed source path has an ambiguous case alias.")
                except FileNotFoundError:
                    continue
        if len(aliases) == 1 and aliases[0] != name:
            selected_path = repository / parent / name
            committed_alias = repository / parent / aliases[0]
            if not filesystem_case_alias(repository, selected_path, committed_alias):
                raise OSError("Committed source path is not a filesystem case alias.")
        canonical.append(aliases[0] if len(aliases) == 1 else name)
    committed = PurePosixPath(*canonical)
    return repository, revision if committed == PurePosixPath(".") else f"{revision}:{committed}"


def safe_source_path(target: Path, relative_path: str) -> Path | None:
    if "\\" in relative_path:
        return None
    parsed = PurePosixPath(relative_path)
    if parsed.is_absolute() or ".." in parsed.parts:
        return None
    try:
        path = (target / parsed.as_posix()).resolve()
        path.relative_to(target)
    except (OSError, RuntimeError, ValueError):
        return None
    return path


def main() -> None:
    argparse.ArgumentParser(description=__doc__).parse_args()


if __name__ == "__main__":
    main()

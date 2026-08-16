"""Persist stable Codex Security target identities."""

from __future__ import annotations

import argparse
import hashlib
import os
import sqlite3
import stat
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

# Some plugin hosts launch Python with safe-path isolation enabled.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from filesystem_identity import (
    serialize_filesystem_identity,
    stored_filesystem_identity_matches,
)
from workbench_target import git_output


def stable_target_id(target: Path) -> str:
    digest = hashlib.sha256(f"local-workspace\0{target}".encode()).hexdigest()
    return f"target_sha256_{digest}"


def repository_relative_path(target: Path) -> str | None:
    """Return the target's normalized location within its own Git worktree."""
    worktree = _repository_worktree(target)
    return worktree[1] if worktree is not None else None


def _repository_worktree(target: Path) -> tuple[Path, str] | None:
    worktree_root = git_output(target, "rev-parse", "--show-toplevel")
    if worktree_root is None:
        return None
    try:
        canonical_root = Path(os.path.realpath(worktree_root))
        relative = Path(os.path.realpath(target)).relative_to(canonical_root)
    except (OSError, ValueError):
        return None
    return canonical_root, relative.as_posix()


def _repository_birth_time_ns(path: str, metadata: os.stat_result) -> int | None:
    birth_time_ns = getattr(metadata, "st_birthtime_ns", None)
    if birth_time_ns is not None:
        return birth_time_ns if birth_time_ns > 0 else None
    if os.name == "nt":
        return metadata.st_ctime_ns if metadata.st_ctime_ns > 0 else None
    birth_time = getattr(metadata, "st_birthtime", None)
    if birth_time is not None:
        return int(birth_time * 1_000_000_000) if birth_time > 0 else None
    if not sys.platform.startswith("linux"):
        return None
    try:
        result = subprocess.run(
            ["stat", "--format=%.9W", "--", path],
            check=False,
            capture_output=True,
            text=True,
            env={**os.environ, "LC_ALL": "C"},
        )
    except OSError:
        return None
    seconds, separator, nanoseconds = result.stdout.strip().partition(".")
    if (
        result.returncode != 0
        or separator != "."
        or not seconds.isdecimal()
        or len(nanoseconds) != 9
        or not nanoseconds.isdecimal()
    ):
        return None
    birth_time_ns = int(seconds) * 1_000_000_000 + int(nanoseconds)
    return birth_time_ns if birth_time_ns > 0 else None


@dataclass(frozen=True)
class GitRepositoryIdentity:
    value: str
    relative_path: str
    common_directory: str
    device: int | str
    inode: int | str
    birth_time_ns: int


def _identity_digest(material: str) -> str:
    return f"repository_sha256_{hashlib.sha256(material.encode()).hexdigest()}"


def _repository_identity_details(target: Path | str) -> GitRepositoryIdentity | None:
    target = Path(target)
    common_directory = git_output(
        target, "rev-parse", "--path-format=absolute", "--git-common-dir"
    )
    if common_directory is None:
        return None
    worktree = _repository_worktree(target)
    if worktree is None:
        return None
    worktree_root, relative = worktree
    registered = git_output(target, "worktree", "list", "--porcelain", "-z")
    if registered is None:
        return None
    canonical_root = os.fspath(worktree_root)
    if not any(
        os.path.realpath(record.removeprefix("worktree ")) == canonical_root
        for record in registered.split("\0")
        if record.startswith("worktree ")
    ):
        return None
    canonical_directory = os.path.realpath(common_directory)
    try:
        metadata = Path(canonical_directory).stat()
    except OSError:
        return None
    birth_time_ns = _repository_birth_time_ns(canonical_directory, metadata)
    if birth_time_ns is None:
        return None
    device = serialize_filesystem_identity(metadata.st_dev)
    inode = serialize_filesystem_identity(metadata.st_ino)
    material = (
        f"git-common-dir\0{canonical_directory}\0{device}\0{inode}\0"
        f"{birth_time_ns}\0{relative}"
    )
    return GitRepositoryIdentity(
        _identity_digest(material), relative, canonical_directory, device, inode, birth_time_ns
    )


def repository_identity(target: Path | str) -> str | None:
    """Identify matching Git worktree targets without storing remote credentials."""
    identity = _repository_identity_details(target)
    return identity.value if identity is not None else None


def repository_origin(target: Path) -> tuple[str, str] | None:
    remote = git_output(target, "remote", "get-url", "origin")
    if remote is None:
        return None
    if "://" in remote:
        try:
            parsed = urlsplit(remote)
            port = parsed.port
        except ValueError:
            return None
        if parsed.scheme not in {"https", "ssh"} or parsed.hostname is None:
            return None
        if parsed.query or parsed.fragment:
            return None
        host = parsed.hostname
        if port is not None and port != {"https": 443, "ssh": 22}[parsed.scheme]:
            host = f"{host}:{port}"
        path = parsed.path
    else:
        authority, separator, path = remote.partition(":")
        if not separator or "?" in path or "#" in path:
            return None
        host = authority.rsplit("@", 1)[-1]
    path = path.strip("/").removesuffix(".git")
    return (host.lower(), path) if host and path else None


def supports_repository_identity(connection: sqlite3.Connection) -> bool:
    return any(
        row["name"] == "repository_identity"
        for row in connection.execute("PRAGMA table_info(security_targets)")
    )


@dataclass(frozen=True)
class RepositoryTargetState:
    target_id: str
    target_path: str
    stored_identity: str | None
    resolved_path: str | None = None
    metadata: os.stat_result | None = None
    repository: GitRepositoryIdentity | None = None
    ownership_matches: bool = False
    strict_owner_matches: bool = False
    generation_matches_history: bool = False
    missing: bool = False

    @property
    def live_identity(self) -> str | None:
        return self.repository.value if self.repository is not None else None

    @property
    def verified_identity(self) -> str | None:
        if not self.ownership_matches or self.repository is None:
            return None
        if self.stored_identity is None:
            return (
                self.live_identity
                if self.strict_owner_matches and self.generation_matches_history
                else None
            )
        return self.live_identity if self.live_identity == self.stored_identity else None

    @property
    def relaxed_directory_ownership(self) -> bool:
        return (
            self.stored_identity is not None
            and self.verified_identity == self.stored_identity
            and self.repository is not None
            and self.repository.relative_path != "."
        )

    def require_owner(self) -> None:
        if not self.ownership_matches:
            raise SystemExit(
                f"The repository checkout at {self.target_path} no longer matches its recorded "
                "security scan history; refusing to reuse its target."
            )


def _inspect_repository_target(
    connection: sqlite3.Connection,
    target_id: str,
    target_path: str,
    stored_identity: str | None,
    *,
    scan_columns: set[str] | None = None,
) -> RepositoryTargetState:
    target = Path(target_path)
    try:
        resolved_path = str(target.resolve())
    except (OSError, RuntimeError):
        return RepositoryTargetState(target_id, target_path, stored_identity)
    try:
        metadata = target.stat()
    except (FileNotFoundError, NotADirectoryError):
        return RepositoryTargetState(
            target_id, target_path, stored_identity,
            resolved_path=resolved_path, ownership_matches=True, missing=True,
        )
    except OSError:
        return RepositoryTargetState(
            target_id, target_path, stored_identity, resolved_path=resolved_path
        )
    repository = _repository_identity_details(target)
    if scan_columns is None:
        scan_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(scans)")
        }
    historical_scan = False
    recorded_owner = False
    malformed_owner = False
    mismatch = False
    strict_owner_matches = False
    generation_matches_history = False
    ownership_matches = True
    if {"target_id", "target_path"} <= scan_columns:
        if not {"target_device", "target_inode"} <= scan_columns:
            historical_scan = connection.execute(
                "SELECT 1 FROM scans WHERE target_id = ? OR target_path = ? LIMIT 1",
                (target_id, target_path),
            ).fetchone() is not None
            strict_owner_matches = not historical_scan
            generation_matches_history = repository is not None and not historical_scan
        else:
            strict_owner_matches = True
            timestamps = ", started_at, created_at" if {
                "started_at", "created_at"
            } <= scan_columns else ""
            scans = connection.execute(
                f"""
                SELECT target_device, target_inode{timestamps} FROM scans
                WHERE target_id = ? OR target_path = ?
                """,
                (target_id, target_path),
            ).fetchall()
            generation_matches_history = (
                repository is not None and _repository_predates_history(repository, scans)
            )
            for scan in scans:
                historical_scan = True
                device, inode = scan["target_device"], scan["target_inode"]
                if device is None and inode is None:
                    strict_owner_matches = False
                    continue
                if device is None or inode is None:
                    malformed_owner = True
                    strict_owner_matches = False
                    continue
                recorded_owner = True
                if not stored_filesystem_identity_matches(
                    device, metadata.st_dev
                ) or not stored_filesystem_identity_matches(inode, metadata.st_ino):
                    mismatch = True
                    strict_owner_matches = False
            verified_repository = (
                stored_identity is not None
                and repository is not None
                and repository.value == stored_identity
            )
            ownership_matches = not (
                malformed_owner
                or mismatch
                and (
                    not verified_repository
                    or repository is None
                    or repository.relative_path == "."
                )
                or stored_identity is not None
                and (
                    not verified_repository or historical_scan and not recorded_owner
                )
                or stored_identity is None
                and repository is not None
                and historical_scan
                and not generation_matches_history
            )
    return RepositoryTargetState(
        target_id, target_path, stored_identity, resolved_path, metadata, repository,
        ownership_matches, strict_owner_matches, generation_matches_history,
    )


def verified_repository_identity(
    connection: sqlite3.Connection,
    target_id: str,
    target_path: str,
    *,
    stored_identity: str | None = None,
) -> str | None:
    return _inspect_repository_target(
        connection, target_id, target_path, stored_identity
    ).verified_identity


class RepositoryIdentityCache:
    """One request's saved identities and verified live aliases."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection
        self.supports_identity = supports_repository_identity(connection)
        self.scan_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(scans)")
        }
        identity_column = "repository_identity" if self.supports_identity else "NULL"
        self.targets = {
            row["target_id"]: row
            for row in connection.execute(
                "SELECT id AS target_id, current_path AS target_path, "
                f"{identity_column} AS repository_identity FROM security_targets"
            )
        }
        self.targets_by_path = {
            row["target_path"]: row for row in self.targets.values()
        }
        self._states: dict[tuple[str, str, str | None], RepositoryTargetState] = {}
        self._origins: dict[str, tuple[str, str] | None] = {}

    def for_row(self, row: sqlite3.Row | dict) -> RepositoryTargetState:
        key = (
            row["target_id"] or "",
            row["target_path"],
            row["repository_identity"] if "repository_identity" in row.keys() else None,
        )
        if key not in self._states:
            self._states[key] = _inspect_repository_target(
                self.connection, *key, scan_columns=self.scan_columns
            )
        return self._states[key]

    def for_path(self, target_path: str) -> RepositoryTargetState:
        row = self.targets_by_path.get(target_path)
        return self.for_row(
            row if row is not None else {
                "target_id": "", "target_path": target_path, "repository_identity": None,
            }
        )

    def group(self, target_id: str) -> tuple[str, str]:
        target = self.targets.get(target_id)
        identity = target["repository_identity"] if target is not None else None
        if identity is None and target is not None:
            identity = self.for_row(target).verified_identity
        return ("target", target_id) if identity is None else ("repository", identity)

    def target_ids(self, target_id: str) -> set[str]:
        target = self.targets.get(target_id)
        if not self.supports_identity or target is None:
            return {target_id}
        return self._target_ids_for_state(self.for_row(target))

    def target_ids_for_path(self, target_path: str) -> set[str]:
        return self._target_ids_for_state(self.for_path(target_path))

    def _target_ids_for_state(self, requested: RepositoryTargetState) -> set[str]:
        if not requested.ownership_matches:
            return set()
        identity = (
            requested.stored_identity or requested.verified_identity
            if self.supports_identity else None
        )
        if identity is None:
            return {requested.target_id} if requested.target_id else set()
        group = ("repository", identity)
        return {candidate for candidate in self.targets if self.group(candidate) == group}

    def origin(self, state: RepositoryTargetState) -> tuple[str, str] | None:
        if state.target_path not in self._origins:
            self._origins[state.target_path] = repository_origin(Path(state.target_path))
        return self._origins[state.target_path]


def _pre_release_repository_identities(identity: GitRepositoryIdentity) -> set[str]:
    directory = os.path.normcase(identity.common_directory)
    relative = os.path.normcase(os.fspath(Path(identity.relative_path))).replace(os.sep, "/")
    prefix = f"git-common-dir\0{directory}\0{identity.device}\0{identity.inode}\0"
    identities = {_identity_digest(f"{prefix}{relative}")}
    try:
        generation = (Path(identity.common_directory) / "description").lstat()
    except OSError:
        return identities
    if stat.S_ISREG(generation.st_mode):
        identities.add(_identity_digest(
            f"{prefix}git-description\0"
            f"{serialize_filesystem_identity(generation.st_dev)}\0"
            f"{serialize_filesystem_identity(generation.st_ino)}\0"
            f"{generation.st_ctime_ns}\0{relative}"
        ))
    return identities


def _timestamp_ns(value: str) -> int | None:
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None
    if timestamp.tzinfo is None:
        return None
    delta = timestamp - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days * 86400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000


def _repository_predates_history(
    identity: GitRepositoryIdentity,
    scans: list[sqlite3.Row],
    *,
    empty_timestamp: str | None = None,
) -> bool:
    if not scans and empty_timestamp is None:
        return True
    if any(not {"started_at", "created_at"} <= set(scan.keys()) for scan in scans):
        return False
    timestamps = (
        [_timestamp_ns(scan[column]) for scan in scans for column in ("started_at", "created_at")]
        if scans else [_timestamp_ns(empty_timestamp)]
    )
    return (
        all(value is not None for value in timestamps)
        and identity.birth_time_ns <= min(timestamps)
    )


def normalize_pre_release_repository_identities(connection: sqlite3.Connection) -> None:
    """Retain only individually established pre-release identity bindings."""
    if not supports_repository_identity(connection):
        return
    identities = RepositoryIdentityCache(connection)
    targets = connection.execute(
        "SELECT id AS target_id, current_path AS target_path, created_at, repository_identity "
        "FROM security_targets WHERE repository_identity IS NOT NULL"
    ).fetchall()
    states = {target["target_id"]: identities.for_row(target) for target in targets}
    anchors = {
        state.stored_identity: state.repository
        for state in states.values()
        if state.repository is not None
        and state.verified_identity == state.stored_identity
    }
    for target in targets:
        stored = target["repository_identity"]
        state = states[target["target_id"]]
        scans = connection.execute(
            "SELECT started_at, created_at FROM scans WHERE target_id = ? OR target_path = ?",
            (target["target_id"], target["target_path"]),
        ).fetchall()
        anchor = anchors.get(stored)
        identity = state.repository
        replacement = None
        if anchor is not None:
            if _repository_predates_history(
                anchor, scans, empty_timestamp=target["created_at"]
            ):
                replacement = stored
        elif (
            identity is not None
            and state.strict_owner_matches
            and stored in _pre_release_repository_identities(identity)
            and _repository_predates_history(
                identity, scans, empty_timestamp=target["created_at"]
            )
        ):
            replacement = identity.value
        if replacement != stored:
            connection.execute(
                "UPDATE security_targets SET repository_identity = ? "
                "WHERE id = ? AND repository_identity = ?",
                (replacement, target["target_id"], stored),
            )


def backfill_repository_identities(connection: sqlite3.Connection) -> None:
    if not supports_repository_identity(connection):
        return
    targets = connection.execute(
        """
        SELECT id, current_path
        FROM security_targets
        WHERE repository_identity IS NULL
        """
    ).fetchall()
    for target in targets:
        identity = verified_repository_identity(
            connection, str(target["id"]), target["current_path"]
        )
        if identity is not None:
            connection.execute(
                """
                UPDATE security_targets
                SET repository_identity = ?
                WHERE id = ? AND repository_identity IS NULL
                """,
                (identity, target["id"]),
            )


def backfill_security_targets(connection: sqlite3.Connection) -> None:
    rows = connection.execute(
        """
        SELECT target_path FROM workspaces WHERE target_path IS NOT NULL
        UNION
        SELECT target_path FROM scans
        """
    ).fetchall()
    for row in rows:
        target_path = row["target_path"]
        target_id = ensure_security_target(connection, target_path, verify_ownership=False)
        connection.execute(
            "UPDATE workspaces SET target_id = ? WHERE target_path = ? AND target_id IS NULL",
            (target_id, target_path),
        )
        connection.execute(
            "UPDATE scans SET target_id = ? WHERE target_path = ? AND target_id IS NULL",
            (target_id, target_path),
        )
    backfill_repository_identities(connection)


def ensure_security_target(
    connection: sqlite3.Connection, target_path: str, *, verify_ownership: bool = True
) -> str:
    supports_identity = supports_repository_identity(connection)
    existing = connection.execute(
        "SELECT id, repository_identity FROM security_targets WHERE current_path = ?"
        if supports_identity
        else "SELECT id FROM security_targets WHERE current_path = ?",
        (target_path,),
    ).fetchone()
    if existing is not None:
        target_id = str(existing["id"])
        if supports_identity:
            state = _inspect_repository_target(
                connection, target_id, target_path, existing["repository_identity"]
            )
            if verify_ownership:
                state.require_owner()
        if supports_identity and existing["repository_identity"] is None:
            identity = state.verified_identity
            if identity is not None:
                connection.execute(
                    """
                    UPDATE security_targets
                    SET repository_identity = ?
                    WHERE id = ? AND repository_identity IS NULL
                    """,
                    (identity, target_id),
                )
        return target_id
    target_id = stable_target_id(Path(target_path))
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    if supports_identity:
        identity = verified_repository_identity(connection, target_id, target_path)
        connection.execute(
            """
            INSERT OR IGNORE INTO security_targets (
                id, current_path, display_name, created_at, updated_at, repository_identity
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (target_id, target_path, Path(target_path).name, timestamp, timestamp, identity),
        )
    else:
        connection.execute(
            """
            INSERT OR IGNORE INTO security_targets (
                id, current_path, display_name, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (target_id, target_path, Path(target_path).name, timestamp, timestamp),
        )
    return target_id


def main() -> None:
    argparse.ArgumentParser(description=__doc__).parse_args()


if __name__ == "__main__":
    main()

"""Persist stable Codex Security target identities."""

from __future__ import annotations

import argparse
import hashlib
import os
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

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


def repository_identity(target: Path | str) -> str | None:
    """Identify matching Git worktree targets without storing remote credentials."""
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
    return f"repository_sha256_{hashlib.sha256(material.encode()).hexdigest()}"


def _supports_repository_identity(connection: sqlite3.Connection) -> bool:
    return any(
        row["name"] == "repository_identity"
        for row in connection.execute("PRAGMA table_info(security_targets)")
    )


def _verified_repository_identity(
    connection: sqlite3.Connection, target_id: str, target_path: str
) -> str | None:
    target = Path(target_path)
    try:
        metadata = target.stat()
    except OSError:
        return None

    scan_columns = {
        row["name"] for row in connection.execute("PRAGMA table_info(scans)")
    }
    if not {"target_id", "target_path"} <= scan_columns:
        return None
    if not {"target_device", "target_inode"} <= scan_columns:
        historical_scan = connection.execute(
            "SELECT 1 FROM scans WHERE target_id = ? OR target_path = ? LIMIT 1",
            (target_id, target_path),
        ).fetchone()
        return None if historical_scan is not None else repository_identity(target)

    scans = connection.execute(
        """
        SELECT target_device, target_inode
        FROM scans
        WHERE target_id = ? OR target_path = ?
        """,
        (target_id, target_path),
    )
    if any(
        not stored_filesystem_identity_matches(scan["target_device"], metadata.st_dev)
        or not stored_filesystem_identity_matches(scan["target_inode"], metadata.st_ino)
        for scan in scans
    ):
        return None
    return repository_identity(target)


def _require_current_target_owner(
    connection: sqlite3.Connection,
    target_id: str,
    target_path: str,
    stored_identity: str | None,
) -> None:
    target = Path(target_path)
    try:
        metadata = target.stat()
    except OSError:
        return
    scan_columns = {
        row["name"] for row in connection.execute("PRAGMA table_info(scans)")
    }
    if not {"target_id", "target_path", "target_device", "target_inode"} <= scan_columns:
        return
    scans = connection.execute(
        """
        SELECT target_device, target_inode
        FROM scans
        WHERE target_id = ? OR target_path = ?
        """,
        (target_id, target_path),
    )
    historical_scan = False
    verified_owner = False
    mismatch = False
    for scan in scans:
        historical_scan = True
        device, inode = scan["target_device"], scan["target_inode"]
        if device is None and inode is None:
            continue
        if not stored_filesystem_identity_matches(
            device, metadata.st_dev
        ) or not stored_filesystem_identity_matches(inode, metadata.st_ino):
            mismatch = True
            break
        verified_owner = True
    if (
        mismatch
        or stored_identity is not None
        and (
            repository_identity(target) != stored_identity
            or historical_scan and not verified_owner
        )
    ):
        raise SystemExit(
            f"The repository checkout at {target_path} no longer matches its recorded "
            "security scan history; refusing to reuse its target."
        )


def backfill_repository_identities(connection: sqlite3.Connection) -> None:
    if not _supports_repository_identity(connection):
        return
    targets = connection.execute(
        """
        SELECT id, current_path
        FROM security_targets
        WHERE repository_identity IS NULL
        """
    ).fetchall()
    for target in targets:
        identity = _verified_repository_identity(
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
    supports_identity = _supports_repository_identity(connection)
    existing = connection.execute(
        "SELECT id, repository_identity FROM security_targets WHERE current_path = ?"
        if supports_identity
        else "SELECT id FROM security_targets WHERE current_path = ?",
        (target_path,),
    ).fetchone()
    if existing is not None:
        target_id = str(existing["id"])
        if verify_ownership and supports_identity:
            _require_current_target_owner(
                connection, target_id, target_path, existing["repository_identity"]
            )
        if supports_identity and existing["repository_identity"] is None:
            identity = _verified_repository_identity(connection, target_id, target_path)
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
        identity = _verified_repository_identity(connection, target_id, target_path)
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

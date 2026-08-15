"""Read-only native findings and repository indexes for the Security workbench."""

import argparse
import sqlite3
import sys
from collections import Counter
from collections.abc import Iterator
from itertools import islice
from pathlib import Path
from typing import Any

# Some plugin hosts launch Python with safe-path isolation enabled.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import workbench_scan_history as scan_history
from workbench_constants import FINDING_SUMMARY_BYTES, FINDING_TITLE_BYTES, FINDINGS_PAGE_MAX
from workbench_target_state import _require_current_target_owner
from workbench_validation import bounded_output_text


def repository_target_ids(connection: sqlite3.Connection, target_id: str) -> set[str]:
    if not _has_repository_identities(connection):
        return {target_id}

    requested_target = connection.execute(
        "SELECT current_path, repository_identity FROM security_targets WHERE id = ?",
        (target_id,),
    ).fetchone()
    if requested_target is None:
        return {target_id}
    try:
        _require_current_target_owner(
            connection,
            target_id,
            requested_target["current_path"],
            requested_target["repository_identity"],
        )
    except SystemExit:
        return set()

    rows = connection.execute(
        """
        SELECT id
        FROM security_targets
        WHERE id = ?
            OR (
                repository_identity IS NOT NULL
                AND repository_identity = ?
            )
        """,
        (target_id, requested_target["repository_identity"]),
    )
    return {row["id"] for row in rows} or {target_id}


def _has_repository_identities(connection: sqlite3.Connection) -> bool:
    return any(
        column["name"] == "repository_identity"
        for column in connection.execute("PRAGMA table_info(security_targets)")
    )


def list_global_findings(
    connection: sqlite3.Connection,
    args: argparse.Namespace,
) -> dict[str, Any]:
    limit = min(args.limit, FINDINGS_PAGE_MAX)
    query = args.query.strip().casefold() if args.query else ""
    target_ids = (
        None if args.target_id is None else repository_target_ids(connection, args.target_id)
    )
    findings = (
        row
        for row in _indexed_findings(connection)
        if (target_ids is None or row["target_id"] in target_ids)
        and (args.severity is None or row["severity"] == args.severity)
        and (args.status is None or row["status"] == args.status)
        and (
            not query
            or any(
                query in value.casefold()
                for value in (
                    row["title"],
                    row["summary"],
                    row["target_path"],
                    row["location_path"],
                )
                if value is not None
            )
        )
    )
    rows = list(islice(findings, args.offset, args.offset + limit + 1))
    has_more = len(rows) > limit
    return {
        "findings": [
            {
                "confirmedInLatestScan": row["confirmed_in_latest_scan"],
                "createdAt": row["created_at"],
                "findingId": row["finding_id"],
                "knownSince": row["known_since"],
                "knownScanIds": row["known_scan_ids"],
                "locationPath": row["location_path"],
                "matchedFindingIds": row["matched_finding_ids"],
                "occurrenceCount": row["occurrence_count"],
                "occurrenceId": row["occurrence_id"],
                "scanId": row["scan_id"],
                "scope": row["scope"],
                "severity": {"level": row["severity"]},
                "status": row["status"],
                "summary": bounded_output_text(row["summary"], FINDING_SUMMARY_BYTES),
                "targetId": row["target_id"],
                "targetPath": row["target_path"],
                "title": bounded_output_text(row["title"], FINDING_TITLE_BYTES),
                "updatedAt": row["updated_at"],
            }
            for row in rows[:limit]
        ],
        "limit": limit,
        "nextOffset": args.offset + limit if has_more else None,
        "offset": args.offset,
    }


def _indexed_findings(connection: sqlite3.Connection) -> Iterator[dict[str, Any]]:
    parents: dict[
        tuple[tuple[str, str], str], tuple[tuple[str, str], str]
    ] = {}
    has_repository_identities = _has_repository_identities(connection)
    identity_column = "targets.repository_identity" if has_repository_identities else "NULL"
    before_identity_column = (
        "before_targets.repository_identity" if has_repository_identities else "NULL"
    )
    after_identity_column = (
        "after_targets.repository_identity" if has_repository_identities else "NULL"
    )
    alias_condition = (
        "before_targets.repository_identity IS NOT NULL "
        "AND before_targets.repository_identity = after_targets.repository_identity"
        if has_repository_identities
        else "0"
    )

    def repository_identity(target_id: str, identity: str | None) -> tuple[str, str]:
        return ("target", target_id) if identity is None else ("repository", identity)

    def group(identity: tuple[tuple[str, str], str]) -> tuple[tuple[str, str], str]:
        while identity in parents:
            identity = parents[identity]
        return identity

    for match in connection.execute(
        f"""
        SELECT before_scans.target_id AS before_target_id,
            after_scans.target_id AS after_target_id,
            {before_identity_column} AS before_repository_identity,
            {after_identity_column} AS after_repository_identity,
            before.finding_id AS before_finding_id,
            after.finding_id AS after_finding_id
        FROM scan_comparison_matches AS matches
        JOIN finding_occurrences AS before ON before.id = matches.before_occurrence_id
        JOIN scans AS before_scans ON before_scans.id = before.scan_id
        JOIN security_targets AS before_targets ON before_targets.id = before_scans.target_id
        JOIN finding_occurrences AS after ON after.id = matches.after_occurrence_id
        JOIN scans AS after_scans ON after_scans.id = after.scan_id
        JOIN security_targets AS after_targets ON after_targets.id = after_scans.target_id
        WHERE before_scans.target_id = after_scans.target_id OR ({alias_condition})
        """
    ):
        before = group(
            (
                repository_identity(
                    match["before_target_id"], match["before_repository_identity"]
                ),
                match["before_finding_id"],
            )
        )
        after = group(
            (
                repository_identity(
                    match["after_target_id"], match["after_repository_identity"]
                ),
                match["after_finding_id"],
            )
        )
        if before != after:
            parents[after] = before

    latest_scan_by_repository = {
        repository_identity(row["target_id"], row["repository_identity"]): row["id"]
        for row in connection.execute(
            f"""
            SELECT scans.target_id, scans.id, {identity_column} AS repository_identity
            FROM scans
            JOIN security_targets AS targets ON targets.id = scans.target_id
            WHERE scans.status = 'complete'
            ORDER BY scans.started_at, scans.id
            """
        )
    }

    grouped: dict[tuple[tuple[str, str], str], list[sqlite3.Row]] = {}
    for row in connection.execute(
        f"""
        SELECT
            occurrences.id AS occurrence_id,
            occurrences.finding_id,
            occurrences.severity,
            occurrences.created_at,
            scans.id AS scan_id,
            scans.started_at AS scan_started_at,
            scans.target_id,
            targets.current_path AS target_path,
            {identity_column} AS repository_identity,
            scans.scope,
            MAX(scans.updated_at, COALESCE(triage.updated_at, '')) AS updated_at,
            triage.status AS decision_status,
            triage.close_reason,
            triage.updated_at AS decision_updated_at,
            occurrences.title,
            occurrences.summary,
            (
                SELECT locations.relative_path
                FROM finding_locations AS locations
                WHERE locations.occurrence_id = occurrences.id
                ORDER BY
                    CASE WHEN locations.role = 'root_control' THEN 0 ELSE 1 END,
                    locations.sort_order
                LIMIT 1
            ) AS location_path
        FROM finding_occurrences AS occurrences
        JOIN scans ON scans.id = occurrences.scan_id
        JOIN security_targets AS targets ON targets.id = scans.target_id
        LEFT JOIN finding_triage AS triage ON triage.occurrence_id = occurrences.id
        """,
    ):
        grouped.setdefault(
            group(
                (
                    repository_identity(row["target_id"], row["repository_identity"]),
                    row["finding_id"],
                )
            ),
            [],
        ).append(row)

    findings = []
    for occurrences in grouped.values():
        latest = max(occurrences, key=lambda row: (row["created_at"], row["occurrence_id"]))
        decision = max(
            (row for row in occurrences if row["decision_status"] is not None),
            key=lambda row: (row["decision_updated_at"], row["occurrence_id"]),
            default=None,
        )
        status = decision["decision_status"] if decision is not None else "open"
        if (
            status == "closed"
            and decision["close_reason"] == "already_fixed"
            and latest["created_at"] > decision["decision_updated_at"]
        ):
            status = "open"
        scans = sorted({(row["scan_started_at"], row["scan_id"]) for row in occurrences})
        findings.append(
            {
                **dict(latest),
                "close_reason": decision["close_reason"] if decision is not None else None,
                "confirmed_in_latest_scan": latest_scan_by_repository.get(
                    repository_identity(latest["target_id"], latest["repository_identity"])
                )
                == latest["scan_id"],
                "known_since": scans[0][0],
                "known_scan_ids": [scan_id for _, scan_id in scans],
                "matched_finding_ids": sorted({row["finding_id"] for row in occurrences}),
                "occurrence_count": len(occurrences),
                "status": status,
                "updated_at": max(
                    latest["updated_at"],
                    decision["decision_updated_at"] if decision is not None else "",
                ),
            }
        )

    findings.sort(key=lambda finding: finding["occurrence_id"])
    findings.sort(
        key=lambda finding: (
            finding["status"] == "open",
            -scan_history.SEVERITY_ORDER.get(finding["severity"], 5),
            finding["created_at"],
        ),
        reverse=True,
    )
    yield from findings


def list_repositories(
    connection: sqlite3.Connection,
    args: argparse.Namespace | None = None,
) -> dict[str, Any]:
    scans = scan_history.list_scans(connection)["scans"]
    scans_by_id = {scan["scanId"]: scan for scan in scans}
    scan_count_by_target: dict[str, int] = {}
    for scan in scans:
        target_id = scan["targetId"]
        scan_count_by_target[target_id] = scan_count_by_target.get(target_id, 0) + 1

    latest_scan_by_target: dict[str, dict[str, Any]] = {}
    for row in connection.execute(
        "SELECT id, target_id FROM scans ORDER BY started_at DESC, id DESC"
    ):
        latest_scan_by_target.setdefault(row["target_id"], scans_by_id[row["id"]])

    targets = {row["id"]: row for row in connection.execute("SELECT * FROM security_targets")}

    def repository_group(target_id: str) -> tuple[str, str]:
        target = targets[target_id]
        identity = (
            target["repository_identity"] if "repository_identity" in target.keys() else None
        )
        return ("target", target_id) if identity is None else ("repository", identity)

    open_findings_by_repository = Counter(
        repository_group(row["target_id"])
        for row in _indexed_findings(connection)
        if row["status"] == "open"
    )
    repositories = [
        {
            "checkoutAvailable": Path(target["current_path"]).is_dir(),
            "displayName": target["display_name"],
            "latestScan": latest_scan,
            "openFindingsCount": open_findings_by_repository.get(
                repository_group(target_id), 0
            ),
            "scanCount": scan_count_by_target[target_id],
            "targetId": target_id,
            "targetPath": target["current_path"],
        }
        for target_id, latest_scan in latest_scan_by_target.items()
        if (target := targets.get(target_id)) is not None
    ]
    if args is None:
        return {"repositories": repositories}

    query = args.query.strip().casefold() if args.query else ""
    repositories = [
        repository
        for repository in repositories
        if (args.target_id is None or repository["targetId"] == args.target_id)
        and args.status != "not_scanned"
        and (args.status != "open_findings" or repository["openFindingsCount"] > 0)
        and (
            not query
            or query in repository["displayName"].casefold()
            or query in repository["targetPath"].casefold()
        )
    ]
    if args.limit is None and args.offset == 0:
        return {"repositories": repositories}

    limit = min(args.limit or FINDINGS_PAGE_MAX, FINDINGS_PAGE_MAX)
    page = repositories[args.offset : args.offset + limit]
    next_offset = args.offset + len(page)
    return {
        "repositories": page,
        "limit": limit,
        "nextOffset": next_offset if next_offset < len(repositories) else None,
        "offset": args.offset,
    }


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()

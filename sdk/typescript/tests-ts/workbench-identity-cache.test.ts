import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const probe = String.raw`
import argparse
import hashlib
import json
import os
import sqlite3
import stat
import sys
from collections import Counter
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, sys.argv[1])
import workbench_scan_history as history
import workbench_native_indexes as indexes
import workbench_target_state as state
import workbench_feedback as feedback_module
import workbench_db as workbench
from workbench_feedback import get_scan_feedback
from workbench_schema import MIGRATIONS, apply_migrations

scenario = sys.argv[2]
timestamp = "2026-08-01T00:00:00Z"
root = Path.cwd() / "synthetic-identity-fixture"
connection = sqlite3.connect(":memory:")
connection.row_factory = sqlite3.Row
connection.execute("PRAGMA foreign_keys = ON")
identity_migration = next(item for item in MIGRATIONS if item[0] == 31)
initial = (
    (*tuple(item for item in MIGRATIONS if item[0] <= 28), (30, *identity_migration[1:]))
    if scenario in ("migration", "v30-current") else
    tuple(item for item in MIGRATIONS if item[0] <= 30)
    if scenario == "null-history" else MIGRATIONS
)
apply_migrations(connection, initial, lambda: timestamp, lambda database: None)
paths = {}
details = {}
metadata = {}
missing = set()
resolution_errors = {}
probes = Counter()
origins = Counter()
description = SimpleNamespace(
    st_mode=stat.S_IFREG, st_dev=44, st_ino=55, st_ctime_ns=66
)


def add_target(name, stored, live=None, relative=".", birth=1_000_000_000):
    path = str(root / name)
    paths[name] = path
    metadata[path] = SimpleNamespace(st_mode=stat.S_IFDIR, st_dev=7, st_ino=100 + len(paths))
    details[path] = state.GitRepositoryIdentity(
        live or stored or "repository-current", relative, str(root / "common"), 11, 22, birth
    )
    if state.supports_repository_identity(connection):
        connection.execute(
            "INSERT INTO security_targets "
            "(id, current_path, display_name, created_at, updated_at, repository_identity) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (name, path, name, timestamp, timestamp, stored),
        )
    else:
        connection.execute(
            "INSERT INTO security_targets "
            "(id, current_path, display_name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (name, path, name, timestamp, timestamp),
        )
    return details[path]


def add_scan(scan_id, target, owner="current", started=timestamp, created=timestamp):
    path = paths[target]
    device, inode = metadata[path].st_dev, metadata[path].st_ino
    if owner == "missing":
        device, inode = None, None
    elif owner == "mismatch":
        inode += 1
    connection.execute(
        "INSERT INTO workspaces (id, target_path, target_id, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?)",
        ("workspace-" + scan_id, path, target, timestamp, timestamp),
    )
    connection.execute(
        "INSERT INTO scans (id, workspace_id, target_path, target_id, target_device, "
        "target_inode, target_revision, scope, mode, scan_dir, status, phase, "
        "started_at, completed_at, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (scan_id, "workspace-" + scan_id, path, target, device, inode, "synthetic",
         ".", "standard", str(root / "scans" / scan_id), "complete", "reporting",
         started, created, created, created),
    )
    connection.execute(
        "INSERT INTO scan_progress (scan_id, updated_at) VALUES (?, ?)",
        (scan_id, timestamp),
    )


def add_finding(scan_id, finding_id, closed=False):
    occurrence = scan_id + ":" + finding_id
    connection.execute(
        "INSERT OR IGNORE INTO findings "
        "(id, fingerprint, rule_id, identity_anchor, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (finding_id, "fingerprint-" + finding_id, "synthetic-rule", finding_id, timestamp, timestamp),
    )
    connection.execute(
        "INSERT INTO finding_occurrences "
        "(id, finding_id, scan_id, title, summary, severity, confidence, remediation, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (occurrence, finding_id, scan_id, finding_id, "Synthetic summary", "high",
         "high", "Synthetic remediation", timestamp),
    )
    connection.execute(
        "INSERT INTO finding_locations "
        "(occurrence_id, relative_path, start_line, end_line, role, sort_order) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (occurrence, "src/example.py", 1, 1, "root_control", 0),
    )
    if closed:
        connection.execute(
            "INSERT INTO finding_triage VALUES (?, ?, ?, ?, ?)",
            (occurrence, "closed", "false_positive", "Synthetic review", timestamp),
        )
    return occurrence


original_resolve, original_stat, original_lstat = Path.resolve, Path.stat, Path.lstat


def resolve_path(path, *args, **kwargs):
    value = str(path)
    if value in resolution_errors:
        raise resolution_errors[value]("Synthetic path resolution failure")
    return path if value in metadata else original_resolve(path, *args, **kwargs)


def stat_path(path, *args, **kwargs):
    value = str(path)
    if value in missing:
        raise FileNotFoundError(value)
    return metadata[value] if value in metadata else original_stat(path, *args, **kwargs)


def lstat_path(path, *args, **kwargs):
    if path.name == "description" and path.parent == root / "common":
        return description
    return original_lstat(path, *args, **kwargs)


def identity_details(path):
    value = str(path)
    probes[value] += 1
    return details.get(value)


def origin(path):
    value = str(path)
    origins[value] += 1
    identity = details.get(value)
    return ("example.test", identity.value) if identity is not None else None


def listed(target):
    args = argparse.Namespace(
        repository=paths[target], scan_root=None, target_id=None, mode=None,
        status=None, query=None, limit=None, offset=0,
    )
    return sorted(row["scanId"] for row in history.list_scans(connection, args)["scans"])


def findings(target):
    return indexes.list_global_findings(
        connection,
        argparse.Namespace(target_id=target, limit=50, offset=0, query=None, severity=None, status=None),
    )["findings"]


def legacy_hash(identity, with_description=False):
    directory = os.path.normcase(identity.common_directory)
    relative = os.path.normcase(os.fspath(Path(identity.relative_path))).replace(os.sep, "/")
    material = f"git-common-dir\0{directory}\0{identity.device}\0{identity.inode}\0"
    if with_description:
        material += f"git-description\0{description.st_dev}\0{description.st_ino}\0{description.st_ctime_ns}\0"
    return "repository_sha256_" + hashlib.sha256((material + relative).encode()).hexdigest()


with ExitStack() as stack:
    stack.enter_context(patch.object(Path, "resolve", resolve_path))
    stack.enter_context(patch.object(Path, "stat", stat_path))
    stack.enter_context(patch.object(Path, "lstat", lstat_path))
    stack.enter_context(patch.object(state, "_repository_identity_details", identity_details))
    stack.enter_context(patch.object(state, "repository_origin", origin))
    if scenario == "cache":
        for name, stored, live in [
            ("requested", "repository-current", None),
            ("persisted", "repository-current", None),
            ("legacy", None, "repository-current"),
            ("unverified", None, "repository-current"),
            ("unrelated", "repository-other", None),
            ("unresolvable-runtime", None, "repository-current"),
            ("unresolvable-os", None, "repository-current"),
            ("removed", "repository-current", None),
            ("changed", "repository-previous", "repository-current"),
        ]:
            add_target(name, stored, live)
        for name in paths:
            add_scan(name + "-scan", name, "missing" if name == "unverified" else "current")
        for number in range(5):
            add_scan("unrelated-extra-" + str(number), "unrelated")
        add_scan("legacy-second", "legacy")
        missing.add(paths["removed"])
        resolution_errors[paths["unresolvable-runtime"]] = RuntimeError
        resolution_errors[paths["unresolvable-os"]] = OSError
        before = add_finding("persisted-scan", "before-review")
        after = add_finding("legacy-scan", "after-review", closed=True)
        add_finding("legacy-second", "legacy-open")
        add_finding("unrelated-scan", "unrelated-finding", closed=True)
        connection.execute(
            "INSERT INTO scan_comparisons VALUES (?, ?, ?, ?, ?)",
            ("persisted-scan", "legacy-scan", "{}", timestamp, timestamp),
        )
        connection.execute(
            "INSERT INTO scan_comparison_matches VALUES (?, ?, ?, ?, ?)",
            ("persisted-scan", "legacy-scan", before, after, "Synthetic match"),
        )
        scans = listed("requested")
        listing_probes = dict(probes)
        probes.clear()
        origins.clear()
        matching = history.list_unmatched_scan_pairs(
            connection, argparse.Namespace(repository=paths["requested"], force=False),
            backfill_finding_details=lambda database, scan: None,
            read_coverage=lambda scan: {},
        )
        matching_probes = dict(probes)
        matching_origins = dict(origins)
        probes.clear()
        indexed = findings("requested")
        indexing_probes = dict(probes)
        probes.clear()
        feedback_scope = []
        feedback_queries = []
        def scoped_index(database, **kwargs):
            feedback_scope.extend(sorted(kwargs["target_ids"]))
            return indexes._indexed_findings(database, **kwargs)
        connection.set_trace_callback(feedback_queries.append)
        with patch.object(feedback_module, "_indexed_findings", side_effect=scoped_index):
            feedback = get_scan_feedback(
                connection, connection.execute("SELECT * FROM scans WHERE id = 'requested-scan'").fetchone()
            )
        connection.set_trace_callback(None)
        index_queries = [query for query in feedback_queries if any(marker in query for marker in (
            "SELECT before_scans.target_id AS before_target_id",
            "SELECT scans.target_id, scans.id",
            "occurrences.id AS occurrence_id",
        ))]
        feedback_probes = dict(probes)
        print(json.dumps({
            "scans": scans,
            "removedExact": listed("removed"),
            "matchingCount": matching["scanCount"],
            "aliases": sorted(indexes.repository_target_ids(connection, "requested")),
            "findings": indexed,
            "feedback": [row["findingId"] for row in feedback["falsePositives"]],
            "feedbackScope": feedback_scope,
            "feedbackIndexQueriesScoped": len(index_queries) == 3 and all(
                "target_id IN (" in query for query in index_queries
            ),
            "listingRequestedProbes": listing_probes.get(paths["requested"], 0),
            "matchingRequestedProbes": matching_probes.get(paths["requested"], 0),
            "matchingUnrelatedProbes": matching_probes.get(paths["unrelated"], 0),
            "matchingUnrelatedOrigins": matching_origins.get(paths["unrelated"], 0),
            "indexingMaxProbes": max(indexing_probes.values(), default=0),
            "feedbackMaxProbes": max(feedback_probes.values(), default=0),
            "legacyStored": connection.execute(
                "SELECT repository_identity FROM security_targets WHERE id = 'legacy'"
            ).fetchone()[0],
            "changedStored": connection.execute(
                "SELECT repository_identity FROM security_targets WHERE id = 'changed'"
            ).fetchone()[0],
        }))
    elif scenario == "persisted-alias":
        for name, stored, live in [
            ("requested", "repository-current", None),
            ("reused", "repository-current", "repository-other"),
            ("legacy", None, "repository-current"),
            ("unverified", None, "repository-current"),
            ("unrelated", "repository-other", None),
        ]:
            add_target(name, stored, live)
            add_scan(name + "-scan", name, "missing" if name == "unverified" else "current")
        metadata[paths["reused"]].st_ino += 1000
        add_finding("requested-scan", "current-finding")
        add_finding("reused-scan", "historical-finding", closed=True)
        scans = listed("requested")
        reused_listing_probes = probes[paths["reused"]]
        matching = history.list_unmatched_scan_pairs(
            connection, argparse.Namespace(repository=paths["requested"], force=False),
            backfill_finding_details=lambda *_: None, read_coverage=lambda _: {},
        )
        feedback = get_scan_feedback(
            connection, connection.execute("SELECT * FROM scans WHERE id = 'requested-scan'").fetchone()
        )
        print(json.dumps({
            "scans": scans,
            "replacementRequest": listed("reused"),
            "aliases": sorted(indexes.repository_target_ids(connection, "requested")),
            "findings": sorted(row["findingId"] for row in findings("requested")),
            "feedback": [row["findingId"] for row in feedback["falsePositives"]],
            "matchingCount": matching["scanCount"],
            "reusedListingProbes": reused_listing_probes,
            "stored": connection.execute(
                "SELECT repository_identity FROM security_targets WHERE id = 'reused'"
            ).fetchone()[0],
        }))
    elif scenario == "v30-current":
        generation_birth = state._timestamp_ns("2026-08-02T00:00:00Z")
        later = "2026-08-03T00:00:00Z"
        for name in ("current-owner", "old-owner", "removed-old", "removed-valid", "invalid-time"):
            add_target(name, "current-generation", birth=generation_birth)
            recorded = later if name in ("current-owner", "removed-valid") else timestamp
            add_scan(name + "-scan", name, started="invalid" if name == "invalid-time" else recorded, created=recorded)
        add_target("unverified-anchor", "unverified-current")
        add_scan("unverified-anchor-scan", "unverified-anchor", owner="missing")
        add_target("opaque-missing", "opaque-current")
        add_scan("opaque-missing-scan", "opaque-missing")
        add_target("valid-scope", "scope-current", relative="service")
        add_scan("valid-scope-scan", "valid-scope")
        missing.update(paths[name] for name in ("removed-old", "removed-valid", "opaque-missing"))
        for name in ("current-owner", "old-owner", "removed-old", "removed-valid"):
            add_finding(name + "-scan", name + "-finding", closed=name != "current-owner")
            connection.execute(
                "INSERT INTO scan_artifacts VALUES (?, ?, ?, ?)",
                (name + "-scan", "findings", str(root / name / "findings.json"), timestamp),
            )
        tables = ("scans", "findings", "finding_occurrences", "finding_triage", "scan_artifacts")
        retained = {table: [tuple(row) for row in connection.execute("SELECT * FROM " + table)] for table in tables}
        target_ids = sorted(paths)
        apply_migrations(connection, MIGRATIONS, lambda: timestamp, state.backfill_security_targets)
        state.backfill_repository_identities(connection)
        try:
            state.ensure_security_target(connection, paths["old-owner"])
        except SystemExit:
            old_registration_rejected = True
        else:
            old_registration_rejected = False
        print(json.dumps({
            "stored": {row["id"]: row["repository_identity"] for row in connection.execute(
                "SELECT id, repository_identity FROM security_targets"
            )},
            "recordsPreserved": retained == {table: [tuple(row) for row in connection.execute("SELECT * FROM " + table)] for table in tables},
            "targetIdsPreserved": target_ids == sorted(row["id"] for row in connection.execute("SELECT id FROM security_targets")),
            "aliases": sorted(indexes.repository_target_ids(connection, "current-owner")),
            "removedExact": listed("removed-old"),
            "visibleFindings": sorted(row["findingId"] for row in findings("current-owner")),
            "oldRegistrationRejected": old_registration_rejected,
        }))
    elif scenario == "lineage":
        for name, stored, live in [
            ("requested", "repository-current", None),
            ("removed", "repository-current", None),
            ("legacy", None, "repository-current"),
            ("unverified", None, "repository-current"),
            ("clone", "repository-other", None),
            ("scope", "repository-current-scope", None),
            ("changed", "repository-previous", "repository-current"),
        ]:
            add_target(name, stored, live, relative="service" if name == "scope" else ".")
            add_scan(name + "-scan", name, "missing" if name == "unverified" else "current")
        missing.add(paths["removed"])
        scan_dir = root / "scan-output"
        original_iterdir = Path.iterdir
        stack.enter_context(patch.object(Path, "iterdir", lambda path: iter(()) if path == scan_dir else original_iterdir(path)))
        stack.enter_context(patch.object(workbench, "require_target", return_value=Path(paths["requested"])))
        stack.enter_context(patch.object(workbench, "require_scannable_target"))
        stack.enter_context(patch.object(workbench, "require_canonical_scan_directory", return_value=scan_dir))
        stack.enter_context(patch.object(workbench, "directory_snapshot_regular_file_count", return_value=0))
        stack.enter_context(patch.object(workbench, "scan_target_identity", return_value={}))
        stack.enter_context(patch.object(workbench, "require_uuid", side_effect=lambda value, label: value))
        stack.enter_context(patch.object(workbench, "archive_scan"))
        class LineageAccepted(Exception):
            pass
        stack.enter_context(patch.object(workbench, "insert_running_scan", side_effect=LineageAccepted))
        connection.commit()
        accepted = {}
        for name in paths:
            args = argparse.Namespace(
                repository=paths["requested"], scan_dir=str(scan_dir), parent_scan_id=name + "-scan",
                recipe_json=json.dumps({"repository": paths["requested"], "mode": "standard", "config": {}, "target": {"kind": "repository", "paths": []}}),
            )
            try:
                workbench.register_cli_scan(connection, args)
            except LineageAccepted:
                accepted[name] = True
            except SystemExit:
                accepted[name] = False
        print(json.dumps({"accepted": accepted, "scanCount": connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0]}))
    elif scenario == "null-history":
        newer_birth = state._timestamp_ns("2026-08-02T00:00:00Z")
        for name, birth in [
            ("unchanged", 1_000_000_000), ("newer", newer_birth),
            ("invalid-time", 1_000_000_000), ("no-history", newer_birth),
        ]:
            add_target(name, None, "current-" + name, birth=birth)
            if name != "no-history":
                add_scan(name + "-scan", name, started="invalid" if name == "invalid-time" else timestamp)
        apply_migrations(connection, MIGRATIONS, lambda: timestamp, state.backfill_security_targets)
        add_target("replacement-alias", "current-newer", birth=newer_birth)
        add_scan("replacement-alias-scan", "replacement-alias", started="2026-08-03T00:00:00Z")
        errors = {}
        for name in ("unchanged", "newer", "invalid-time", "no-history"):
            try:
                state.ensure_security_target(connection, paths[name])
            except SystemExit as error:
                errors[name] = str(error)
        print(json.dumps({
            "stored": {row["id"]: row["repository_identity"] for row in connection.execute(
                "SELECT id, repository_identity FROM security_targets"
            )},
            "registrationErrors": sorted(errors),
            "aliases": sorted(indexes.repository_target_ids(connection, "replacement-alias")),
            "sameCheckoutMetadata": connection.execute(
                "SELECT target_inode FROM scans WHERE id = 'newer-scan'"
            ).fetchone()[0] == metadata[paths["newer"]].st_ino,
        }))
    else:
        stack.enter_context(patch.object(os.path, "normcase", lambda value: os.fspath(value).lower()))
        originals = {}
        expected = {}
        for name in [
            "old-basic", "old-description", "current", "unknown", "newer-generation",
            "unverified", "changed-owner", "unavailable", "invalid-time", "no-scans",
            "scope-upper", "scope-lower",
        ]:
            relative = "Service" if name == "scope-upper" else "service" if name == "scope-lower" else "."
            birth = state._timestamp_ns("2026-08-02T00:00:00Z") if name == "newer-generation" else 1_000_000_000
            identity = add_target(name, None, "current-" + name, relative, birth)
            stored = (
                identity.value if name == "current" else
                "unknown-identity" if name == "unknown" else
                legacy_hash(identity, name == "old-description")
            )
            originals[name] = stored
            connection.execute(
                "UPDATE security_targets SET repository_identity = ? WHERE id = ?", (stored, name)
            )
            if name != "no-scans":
                owner = "missing" if name == "unverified" else "mismatch" if name == "changed-owner" else "current"
                add_scan(name + "-scan", name, owner, "invalid" if name == "invalid-time" else timestamp)
            if name == "unavailable":
                missing.add(paths[name])
            expected[name] = identity.value if name in {
                "old-basic", "old-description", "current", "no-scans", "scope-upper", "scope-lower"
            } else None
        apply_migrations(connection, MIGRATIONS, lambda: timestamp, state.backfill_security_targets)
        first = {
            row["id"]: row["repository_identity"]
            for row in connection.execute("SELECT id, repository_identity FROM security_targets")
        }
        apply_migrations(connection, MIGRATIONS, lambda: timestamp, state.backfill_security_targets)
        second = {
            row["id"]: row["repository_identity"]
            for row in connection.execute("SELECT id, repository_identity FROM security_targets")
        }
        print(json.dumps({
            "identities": first,
            "expected": expected,
            "idempotent": first == second,
            "foldedLegacyScopesEqual": originals["scope-upper"] == originals["scope-lower"],
            "currentScopesDistinct": first["scope-upper"] != first["scope-lower"],
            "targetCount": len(first),
            "migrations": [row["version"] for row in connection.execute("SELECT version FROM schema_migrations ORDER BY version")],
        }))
`;

function run(scenario: string): Record<string, unknown> {
  const python = (Bun.which("python3") ?? Bun.which("python"))!;
  const execution = spawnSync(
    python,
    ["-I", "-B", "-c", probe, join(PLUGIN_ROOT, "scripts"), scenario],
    { encoding: "utf8", timeout: 10_000 },
  );
  expect(execution.status, execution.stderr).toBe(0);
  return JSON.parse(execution.stdout) as Record<string, unknown>;
}

test("reuses verified legacy aliases and probes each saved target once per request", () => {
  const result = run("cache");

  expect(result["scans"]).toEqual([
    "legacy-scan",
    "legacy-second",
    "persisted-scan",
    "removed-scan",
    "requested-scan",
  ]);
  expect(result["removedExact"]).toEqual(["removed-scan"]);
  expect(result["matchingCount"]).toBe(5);
  expect(result["aliases"]).toEqual([
    "legacy",
    "persisted",
    "removed",
    "requested",
  ]);
  const findings = result["findings"] as Array<Record<string, unknown>>;
  expect(
    findings.find((finding) => finding["status"] === "closed"),
  ).toMatchObject({
    occurrenceCount: 2,
    matchedFindingIds: ["after-review", "before-review"],
  });
  expect(
    findings.find((finding) => finding["findingId"] === "legacy-open"),
  ).toBeDefined();
  expect(result["feedback"]).toEqual(["after-review"]);
  expect(result["feedbackScope"]).toEqual(result["aliases"]);
  expect(result["feedbackIndexQueriesScoped"]).toBe(true);
  expect(result["listingRequestedProbes"]).toBe(1);
  expect(result["matchingRequestedProbes"]).toBe(1);
  expect(result["matchingUnrelatedProbes"]).toBe(1);
  expect(result["matchingUnrelatedOrigins"]).toBe(1);
  expect(result["indexingMaxProbes"]).toBe(1);
  expect(result["feedbackMaxProbes"]).toBe(1);
  expect(result["legacyStored"]).toBeNull();
  expect(result["changedStored"]).toBe("repository-previous");
});

test("keeps authenticated historical aliases visible without trusting a replacement checkout", () => {
  const result = run("persisted-alias");

  expect(result["scans"]).toEqual([
    "legacy-scan",
    "requested-scan",
    "reused-scan",
  ]);
  expect(result["replacementRequest"]).toEqual([]);
  expect(result["aliases"]).toEqual(["legacy", "requested", "reused"]);
  expect(result["findings"]).toEqual(["current-finding", "historical-finding"]);
  expect(result["feedback"]).toEqual(["historical-finding"]);
  expect(result["matchingCount"]).toBe(3);
  expect(result["reusedListingProbes"]).toBe(0);
  expect(result["stored"]).toBe("repository-current");
});

test("upgrades only independently verified pre-release repository hashes", () => {
  const result = run("migration");

  expect(result["identities"]).toEqual(result["expected"]);
  expect(result["idempotent"]).toBe(true);
  expect(result["foldedLegacyScopesEqual"]).toBe(true);
  expect(result["currentScopesDistinct"]).toBe(true);
  expect(result["targetCount"]).toBe(12);
  expect(result["migrations"]).toEqual(
    Array.from({ length: 31 }, (_, index) => index + 1),
  );
});

test("does not assign legacy history to a newer or indeterminate Git generation", () => {
  const result = run("null-history");

  expect(result["sameCheckoutMetadata"]).toBe(true);
  expect(result["stored"]).toEqual({
    unchanged: "current-unchanged",
    newer: null,
    "invalid-time": null,
    "no-history": "current-no-history",
    "replacement-alias": "current-newer",
  });
  expect(result["registrationErrors"]).toEqual(["invalid-time", "newer"]);
  expect(result["aliases"]).toEqual(["replacement-alias"]);
});

test("admits rerun lineage only through the verified repository and exact scope", () => {
  const result = run("lineage");

  expect(result["accepted"]).toEqual({
    requested: true,
    removed: true,
    legacy: true,
    unverified: false,
    clone: false,
    scope: false,
    changed: false,
  });
  expect(result["scanCount"]).toBe(7);
});

test("quarantines unproved public-v30 bindings without discarding historical records", () => {
  const result = run("v30-current");

  expect(result["stored"]).toEqual({
    "current-owner": "current-generation",
    "old-owner": null,
    "removed-old": null,
    "removed-valid": "current-generation",
    "invalid-time": null,
    "unverified-anchor": null,
    "opaque-missing": null,
    "valid-scope": "scope-current",
  });
  expect(result["recordsPreserved"]).toBe(true);
  expect(result["targetIdsPreserved"]).toBe(true);
  expect(result["aliases"]).toEqual(["current-owner", "removed-valid"]);
  expect(result["removedExact"]).toEqual(["removed-old-scan"]);
  expect(result["visibleFindings"]).toEqual([
    "current-owner-finding",
    "removed-valid-finding",
  ]);
  expect(result["oldRegistrationRejected"]).toBe(true);
});

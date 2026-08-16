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
    if scenario == "migration" else MIGRATIONS
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
    connection.execute(
        "INSERT INTO security_targets "
        "(id, current_path, display_name, created_at, updated_at, repository_identity) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (name, path, name, timestamp, timestamp, stored),
    )
    return details[path]


def add_scan(scan_id, target, owner="current", started=timestamp):
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
         started, timestamp, timestamp, timestamp),
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
        feedback = get_scan_feedback(
            connection, connection.execute("SELECT * FROM scans WHERE id = 'requested-scan'").fetchone()
        )
        feedback_probes = dict(probes)
        print(json.dumps({
            "scans": scans,
            "removedExact": listed("removed"),
            "matchingCount": matching["scanCount"],
            "aliases": sorted(indexes.repository_target_ids(connection, "requested")),
            "findings": indexed,
            "feedback": [row["findingId"] for row in feedback["falsePositives"]],
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
            } else stored
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
  expect(result["listingRequestedProbes"]).toBe(1);
  expect(result["matchingRequestedProbes"]).toBe(1);
  expect(result["matchingUnrelatedProbes"]).toBe(1);
  expect(result["matchingUnrelatedOrigins"]).toBe(1);
  expect(result["indexingMaxProbes"]).toBe(1);
  expect(result["feedbackMaxProbes"]).toBe(1);
  expect(result["legacyStored"]).toBeNull();
  expect(result["changedStored"]).toBe("repository-previous");
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

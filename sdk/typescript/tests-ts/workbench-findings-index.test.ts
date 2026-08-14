import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const findingsIndexProbe = [
  "import argparse, json, os, sqlite3, sys",
  "sys.path.insert(0, sys.argv[1])",
  "import workbench_native_indexes as indexes",
  "from filesystem_identity import serialize_filesystem_identity",
  "settings = json.loads(sys.argv[2])",
  "connection = sqlite3.connect(':memory:')",
  "connection.row_factory = sqlite3.Row",
  "connection.executescript('''",
  "CREATE TABLE security_targets (id TEXT PRIMARY KEY, current_path TEXT NOT NULL, display_name TEXT NOT NULL);",
  "CREATE TABLE scans (id TEXT PRIMARY KEY, target_id TEXT, target_path TEXT, status TEXT, seal_manifest_digest TEXT, started_at TEXT, updated_at TEXT, scope TEXT, scan_dir TEXT);",
  "CREATE TABLE finding_occurrences (id TEXT PRIMARY KEY, finding_id TEXT, scan_id TEXT, severity TEXT, created_at TEXT, title TEXT, summary TEXT);",
  "CREATE TABLE finding_triage (occurrence_id TEXT, status TEXT, updated_at TEXT, close_reason TEXT);",
  "CREATE TABLE finding_locations (occurrence_id TEXT, relative_path TEXT, role TEXT, sort_order INTEGER);",
  "CREATE TABLE scan_comparison_matches (before_occurrence_id TEXT, after_occurrence_id TEXT);",
  "''')",
  "connection.executemany('INSERT INTO security_targets VALUES (?, ?, ?)', [('current-target', '/current/repository', 'current'), ('stale-target', '/stale/repository', 'stale')])",
  "stale_directory = sys.argv[1] if settings.get('coverageFailure') in ('noncanonical', 'pruned') else '/private/tmp/codex-security-findings-index-missing-stale'",
  "connection.executemany('INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', [",
  "    ('current-old', 'current-target', '/current/repository', 'complete', 'sealed', '2026-01-01', '2026-01-01', '.', '/private/tmp/current-old'),",
  "    ('current-new', 'current-target', '/current/repository', 'complete', 'sealed', '2026-02-01', '2026-02-01', '.', '/private/tmp/current-new'),",
  "    ('reused-legacy', None, '/current/repository', 'complete', 'sealed', '2026-03-01', '2026-03-01', '.', '/private/tmp/reused-legacy'),",
  "    ('stale-old', 'stale-target', '/stale/repository', 'complete', 'sealed', '2026-01-01', '2026-01-01', '.', '/private/tmp/stale-old'),",
  "    ('stale-new', 'stale-target', '/stale/repository', 'complete', 'sealed', '2026-02-01', '2026-02-01', '.', stale_directory),",
  "    ('orphan-old', None, '/orphan/repository', 'complete', 'sealed', '2026-01-01', '2026-01-01', '.', '/private/tmp/orphan-old'),",
  "    ('orphan-new', None, '/orphan/repository', 'complete', 'sealed', '2026-02-01', '2026-02-01', '.', '/private/tmp/orphan-new'),",
  "])",
  "if settings.get('clockRollback'):",
  "    connection.execute(\"UPDATE scans SET started_at = '2025-12-01' WHERE id = 'current-new'\")",
  "if settings.get('mixedLegacyOwnership'):",
  "    connection.execute('ALTER TABLE scans ADD COLUMN target_device INTEGER')",
  "    connection.execute('ALTER TABLE scans ADD COLUMN target_inode INTEGER')",
  "    connection.execute(\"UPDATE scans SET target_device = 7, target_inode = 9 WHERE id = 'current-new'\")",
  "if settings.get('replacedCheckout'):",
  "    connection.execute('ALTER TABLE scans ADD COLUMN target_device INTEGER')",
  "    connection.execute('ALTER TABLE scans ADD COLUMN target_inode INTEGER')",
  "    connection.execute('ALTER TABLE scans ADD COLUMN target_revision TEXT')",
  "    connection.execute(\"UPDATE scans SET target_device = -1, target_inode = -1 WHERE target_id = 'current-target'\")",
  "    connection.execute(\"UPDATE security_targets SET current_path = ? WHERE id = 'current-target'\", (sys.argv[1],))",
  "if settings.get('ownershipTransition') or settings.get('ownershipReuse'):",
  "    connection.execute('ALTER TABLE scans ADD COLUMN target_device INTEGER')",
  "    connection.execute('ALTER TABLE scans ADD COLUMN target_inode INTEGER')",
  "    connection.execute('ALTER TABLE scans ADD COLUMN target_revision TEXT')",
  "    connection.execute(\"UPDATE security_targets SET current_path = ? WHERE id = 'current-target'\", (sys.argv[1],))",
  "    connection.execute(\"UPDATE scans SET target_path = ? WHERE target_id = 'current-target'\", (sys.argv[1],))",
  "    metadata = os.stat(sys.argv[1])",
  "    if settings.get('ownershipReuse'):",
  "        connection.execute(\"UPDATE scans SET target_device = ?, target_inode = ?, started_at = '2027-01-01' WHERE id = 'current-old'\", (serialize_filesystem_identity(metadata.st_dev), serialize_filesystem_identity(metadata.st_ino)))",
  "    connection.execute(\"INSERT INTO scans (id, target_id, target_path, status, seal_manifest_digest, started_at, updated_at, scope, scan_dir, target_device, target_inode) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)\", ('previous-owner-identity', 'current-target', sys.argv[1], 'complete', 'sealed', '2026-01-15', '2026-01-15', '.', '/private/tmp/previous-owner', -1, -1))",
  "    connection.execute(\"DELETE FROM scans WHERE id = 'current-new'\")",
  "    connection.execute(\"INSERT INTO scans (id, target_id, target_path, status, seal_manifest_digest, started_at, updated_at, scope, scan_dir, target_device, target_inode) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)\", ('current-new', 'current-target', sys.argv[1], 'complete', 'sealed', '2026-02-01', '2026-02-01', '.', '/private/tmp/current-new', serialize_filesystem_identity(metadata.st_dev), serialize_filesystem_identity(metadata.st_ino)))",
  "connection.executemany('INSERT INTO finding_occurrences VALUES (?, ?, ?, ?, ?, ?, ?)', [",
  "    ('current-old-occurrence', 'current-old-finding', 'current-old', 'high', '2026-01-01', 'Resolved current finding', 'Older issue'),",
  "    ('current-new-occurrence', 'current-new-finding', 'current-new', 'critical', '2026-02-01', 'Current CLI finding', 'Latest issue'),",
  "    ('reused-legacy-occurrence', 'previous-owner-finding', 'reused-legacy', 'critical', '2026-03-01', 'Previous owner secret', 'Must never cross checkout owners'),",
  "    ('stale-old-occurrence', 'stale-finding', 'stale-old', 'medium', '2026-01-01', 'Unavailable follow-up', 'Coverage is unavailable'),",
  "    ('orphan-old-occurrence', 'orphan-old-finding', 'orphan-old', 'high', '2026-01-01', 'Older orphan finding', 'Still outside follow-up coverage'),",
  "    ('orphan-new-occurrence', 'orphan-new-finding', 'orphan-new', 'medium', '2026-02-01', 'Latest orphan finding', 'Target row does not exist'),",
  "])",
  "if settings.get('legacyPriority'):",
  "    connection.execute(\"UPDATE finding_occurrences SET severity = 'low' WHERE id = 'current-new-occurrence'\")",
  "    connection.execute(\"UPDATE finding_occurrences SET severity = 'critical' WHERE id = 'orphan-old-occurrence'\")",
  "if settings.get('lateCompletion'):",
  "    connection.execute(\"UPDATE finding_occurrences SET finding_id = 'current-new-finding', created_at = '2026-03-01' WHERE id = 'current-old-occurrence'\")",
  "connection.executemany('INSERT INTO finding_locations VALUES (?, ?, ?, ?)', [",
  "    ('current-old-occurrence', 'src/old.py', 'root_control', 0),",
  "    ('current-new-occurrence', 'src/new.py', 'root_control', 0),",
  "    ('current-new-occurrence', 'src/secondary.py', 'sink', 1),",
  "    ('current-new-occurrence', 'src/ÄUTH-Straße.py', 'sink', 2),",
  "    ('reused-legacy-occurrence', 'src/previous-owner.py', 'root_control', 0),",
  "    ('stale-old-occurrence', 'src/stale.py', 'root_control', 0),",
  "    ('orphan-old-occurrence', 'src/orphan-old.py', 'root_control', 0),",
  "    ('orphan-new-occurrence', 'src/orphan-new.py', 'root_control', 0),",
  "])",
  "if settings.get('indexedAliases') and settings.get('ownershipReuse'):",
  "    connection.execute('INSERT INTO scan_comparison_matches VALUES (?, ?)', ('current-old-occurrence', 'current-new-occurrence'))",
  "coverage_reads = []",
  "def coverage(scan):",
  "    coverage_reads.append(scan['id'])",
  "    if settings.get('mixedLegacyOwnership') and scan['id'] == 'current-new':",
  "        return {'completeness': 'partial', 'includePaths': ['src/new.py'], 'excludePaths': [], 'explicitExclusions': []}",
  "    if scan['id'] == 'stale-new':",
  "        if settings.get('coverageFailure') == 'tampered':",
  "            raise SystemExit('The sealed scan manifest changed after completion.')",
  "        if settings.get('coverageFailure') == 'sealedArtifact':",
  "            raise SystemExit('coverage.json: sealed artifact changed or is missing')",
  "        if settings.get('coverageFailure') == 'pruned':",
  "            raise SystemExit('coverage.json: expected a regular file inside the scan directory.')",
  "        raise SystemExit('Scan directory must be an existing canonical non-symlink directory.')",
  "    if scan['id'] == 'orphan-new':",
  "        return {'completeness': 'partial', 'includePaths': ['src/orphan-new.py'], 'excludePaths': [], 'explicitExclusions': []}",
  "    return {'completeness': 'complete', 'includePaths': ['.'], 'excludePaths': [], 'explicitExclusions': []}",
  "args = argparse.Namespace(query=settings.get('query'), severity=None, status=None, target_id=settings.get('targetIds') or settings.get('targetId'), target_path=settings.get('targetPaths') or settings.get('targetPath'), include_resolved=settings.get('includeResolved', False), offset=0, limit=20)",
  "if settings.get('repositories'):",
  "    indexes.scan_history.list_scans = lambda connection: {'scans': [{'scanId': row['id'], 'targetId': row['target_id']} for row in connection.execute('SELECT id, target_id FROM scans')]}",
  "    result = indexes.list_repositories(connection, read_coverage=coverage)",
  "else:",
  "    result = indexes.list_global_findings(connection, args, read_coverage=coverage)",
  "scoped_scan_ids = []",
  "matching_scan_count = None",
  "old_owner_matches = None",
  "if settings.get('ownershipTransition') or settings.get('ownershipReuse'):",
  "    clauses, values, _, _ = indexes.scan_history.repository_scan_scope(connection, sys.argv[1])",
  "    scoped_scan_ids = [row['id'] for row in connection.execute('SELECT scans.id FROM scans WHERE ' + ' AND '.join(clauses), values)]",
  "if settings.get('ownershipReuse'):",
  "    connection.execute('CREATE TABLE scan_comparisons (before_scan_id TEXT, after_scan_id TEXT)')",
  "    matching = indexes.scan_history.list_unmatched_scan_pairs(connection, argparse.Namespace(repository=sys.argv[1], force=False), backfill_finding_details=lambda _connection, _scan: None, read_coverage=coverage)",
  "    matching_scan_count = matching['scanCount']",
  "    scans = [connection.execute('SELECT * FROM scans WHERE id = ?', (scan,)).fetchone() for scan in ('current-old', 'current-new')]",
  "    old_owner_matches = indexes.scan_history._same_registered_repository(connection, *scans)",
  "print(json.dumps({'findings': result.get('findings', []), 'repositories': result.get('repositories', []), 'coverageReads': coverage_reads, 'scopedScanIds': scoped_scan_ids, 'matchingScanCount': matching_scan_count, 'oldOwnerMatches': old_owner_matches}))",
].join("\n");

function runFindingsIndex(
  targetId: string | null,
  settings: {
    targetIds?: string[];
    targetPath?: string;
    targetPaths?: string[];
    query?: string;
    clockRollback?: boolean;
    coverageFailure?: "tampered" | "sealedArtifact" | "noncanonical" | "pruned";
    includeResolved?: boolean;
    indexedAliases?: boolean;
    lateCompletion?: boolean;
    legacyPriority?: boolean;
    mixedLegacyOwnership?: boolean;
    ownershipReuse?: boolean;
    ownershipTransition?: boolean;
    replacedCheckout?: boolean;
    repositories?: boolean;
  } = {},
) {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  expect(python).not.toBeNull();
  if (python === null) {
    throw new Error(
      "A Python interpreter is required for findings-index tests.",
    );
  }
  return Bun.spawnSync(
    [
      python,
      "-I",
      "-B",
      "-c",
      findingsIndexProbe,
      join(PLUGIN_ROOT, "scripts"),
      JSON.stringify({ targetId, ...settings }),
    ],
    { stdout: "pipe", stderr: "pipe" },
  );
}

function probeFindingsIndex(
  targetId: string | null,
  settings: {
    targetIds?: string[];
    targetPath?: string;
    targetPaths?: string[];
    query?: string;
    clockRollback?: boolean;
    coverageFailure?: "pruned";
    includeResolved?: boolean;
    indexedAliases?: boolean;
    lateCompletion?: boolean;
    legacyPriority?: boolean;
    mixedLegacyOwnership?: boolean;
    ownershipReuse?: boolean;
    ownershipTransition?: boolean;
    replacedCheckout?: boolean;
    repositories?: boolean;
  } = {},
): {
  findings: Array<{
    occurrenceId: string;
    scanId: string;
    targetId: string | null;
    targetPath: string;
  }>;
  repositories: Array<{ targetId: string; openFindingsCount: number }>;
  coverageReads: string[];
  matchingScanCount: number | null;
  oldOwnerMatches: boolean | null;
  scopedScanIds: string[];
} {
  const result = runFindingsIndex(targetId, settings);
  expect(new TextDecoder().decode(result.stderr)).toBe("");
  expect(result.exitCode).toBe(0);
  return JSON.parse(new TextDecoder().decode(result.stdout));
}

describe("workbench findings index", () => {
  test("isolates targetless previous-owner findings and coverage reads", () => {
    const result = probeFindingsIndex("current-target");

    expect(result.findings).toEqual([
      expect.objectContaining({
        occurrenceId: "current-new-occurrence",
        scanId: "current-new",
        targetId: "current-target",
      }),
    ]);
    expect(result.coverageReads).toEqual(["current-new"]);
    expect(result.findings).not.toContainEqual(
      expect.objectContaining({ occurrenceId: "reused-legacy-occurrence" }),
    );
  });

  test("keeps legacy findings after newer scans record filesystem ownership", () => {
    const result = probeFindingsIndex("current-target", {
      mixedLegacyOwnership: true,
    });

    expect(result.findings).toEqual([
      expect.objectContaining({ occurrenceId: "current-new-occurrence" }),
      expect.objectContaining({ occurrenceId: "current-old-occurrence" }),
    ]);
    expect(result.findings).not.toContainEqual(
      expect.objectContaining({ occurrenceId: "reused-legacy-occurrence" }),
    );
  });

  test("counts only active findings when listing repositories", () => {
    const result = probeFindingsIndex(null, { repositories: true });

    expect(result.repositories).toContainEqual(
      expect.objectContaining({
        targetId: "current-target",
        openFindingsCount: 1,
      }),
    );
  });

  test("uses scan insertion order when the system clock moves backward", () => {
    const result = probeFindingsIndex("current-target", {
      clockRollback: true,
    });

    expect(result.findings).toEqual([
      expect.objectContaining({
        confirmedInLatestScan: true,
        occurrenceId: "current-new-occurrence",
      }),
    ]);
    expect(result.coverageReads).toEqual(["current-new"]);
  });

  test("keeps rediscovered findings active when the system clock moves backward", () => {
    const result = probeFindingsIndex("current-target", {
      clockRollback: true,
      lateCompletion: true,
    });

    expect(result.findings).toEqual([
      expect.objectContaining({ occurrenceId: "current-new-occurrence" }),
    ]);
  });

  test("retains covered same-owner findings while preparing semantic matching", () => {
    const result = probeFindingsIndex("current-target", {
      includeResolved: true,
    });

    expect(result.findings).toEqual([
      expect.objectContaining({ occurrenceId: "current-new-occurrence" }),
      expect.objectContaining({ occurrenceId: "current-old-occurrence" }),
    ]);
    expect(result.findings).not.toContainEqual(
      expect.objectContaining({ occurrenceId: "reused-legacy-occurrence" }),
    );
    expect(
      probeFindingsIndex("current-target", {
        includeResolved: true,
        ownershipReuse: true,
      }).findings,
    ).toEqual([
      expect.objectContaining({ occurrenceId: "current-new-occurrence" }),
    ]);
  });

  test("excludes replaced checkout owners from findings and repository counts", () => {
    expect(
      probeFindingsIndex("current-target", { replacedCheckout: true }).findings,
    ).toEqual([]);
    expect(
      probeFindingsIndex(null, { replacedCheckout: true }).findings,
    ).not.toContainEqual(
      expect.objectContaining({ targetId: "current-target" }),
    );

    expect(
      probeFindingsIndex(null, {
        replacedCheckout: true,
        repositories: true,
      }).repositories,
    ).toContainEqual(
      expect.objectContaining({
        targetId: "current-target",
        openFindingsCount: 0,
      }),
    );
  });

  test("drops ambiguous legacy history after checkout ownership changes", () => {
    const result = probeFindingsIndex("current-target", {
      ownershipTransition: true,
    });

    expect(result.findings).toEqual([
      expect.objectContaining({ occurrenceId: "current-new-occurrence" }),
    ]);
    expect(result.scopedScanIds).toContain("current-new");
    expect(result.scopedScanIds).not.toContain("current-old");
    expect(
      probeFindingsIndex(null, {
        ownershipTransition: true,
        repositories: true,
      }).repositories,
    ).toContainEqual(
      expect.objectContaining({
        targetId: "current-target",
        openFindingsCount: 1,
      }),
    );
  });

  test("rejects recycled filesystem identities after the system clock moves backward", () => {
    const result = probeFindingsIndex("current-target", {
      ownershipReuse: true,
    });

    expect(result.findings).toEqual([
      expect.objectContaining({ occurrenceId: "current-new-occurrence" }),
    ]);
    expect(result.scopedScanIds).toContain("current-new");
    expect(result.scopedScanIds).not.toContain("current-old");
    expect(result.matchingScanCount).toBe(1);
    expect(result.oldOwnerMatches).toBe(false);
  });

  test("never combines indexed finding aliases across checkout owners", () => {
    const result = probeFindingsIndex("current-target", {
      indexedAliases: true,
      ownershipReuse: true,
    });

    expect(result.findings).toEqual([
      expect.objectContaining({
        occurrenceId: "current-new-occurrence",
        knownScanIds: ["current-new"],
        matchedFindingIds: ["current-new-finding"],
      }),
    ]);
  });

  test("keeps active findings when a later scan artifact was pruned", () => {
    const result = probeFindingsIndex("stale-target", {
      coverageFailure: "pruned",
    });

    expect(result.findings).toEqual([
      expect.objectContaining({ occurrenceId: "stale-old-occurrence" }),
    ]);
    expect(result.coverageReads).toEqual(["stale-new"]);
  });

  test.each(["tampered", "sealedArtifact"] as const)(
    "rejects %s sealed scan artifacts",
    (coverageFailure) => {
      const result = runFindingsIndex("stale-target", { coverageFailure });

      expect(result.exitCode).not.toBe(0);
      expect(new TextDecoder().decode(result.stderr)).toContain("changed");
    },
  );

  test("indexes every targetless scan even without a saved target", () => {
    const result = probeFindingsIndex(null, {
      targetPath: "/orphan/repository",
    });

    expect(result.findings).toEqual([
      expect.objectContaining({
        occurrenceId: "orphan-old-occurrence",
        targetId: null,
        targetPath: "/orphan/repository",
      }),
      expect.objectContaining({
        occurrenceId: "orphan-new-occurrence",
        targetId: null,
        targetPath: "/orphan/repository",
      }),
    ]);
    expect(result.coverageReads).toEqual(["orphan-new"]);
  });

  test("keeps multi-target repository queries inside the selected checkout", () => {
    const scoped = probeFindingsIndex(null, {
      targetPaths: ["/current/repository", "/orphan/repository"],
    });
    expect(scoped.findings.map((finding) => finding.occurrenceId)).toEqual([
      "current-new-occurrence",
      "orphan-old-occurrence",
      "orphan-new-occurrence",
    ]);
    expect(scoped.coverageReads).toEqual(["current-new", "orphan-new"]);

    const siblingPrefix = probeFindingsIndex(null, {
      targetPaths: ["/current/repositor"],
    });
    expect(siblingPrefix.findings).toEqual([]);
    expect(siblingPrefix.coverageReads).toEqual([]);
  });

  test("orders registered and legacy findings together by severity", () => {
    const result = probeFindingsIndex(null, {
      legacyPriority: true,
      targetPaths: ["/current/repository", "/orphan/repository"],
    });

    expect(result.findings.map((finding) => finding.occurrenceId)).toEqual([
      "orphan-old-occurrence",
      "orphan-new-occurrence",
      "current-new-occurrence",
    ]);
  });

  test("combines exact target identities with legacy checkout paths", () => {
    const identified = probeFindingsIndex(null, {
      targetIds: ["current-target", "stale-target"],
    });
    expect(identified.findings.map((finding) => finding.occurrenceId)).toEqual([
      "current-new-occurrence",
      "stale-old-occurrence",
    ]);

    const mixed = probeFindingsIndex(null, {
      targetIds: ["current-target"],
      targetPaths: ["/orphan/repository"],
    });
    expect(mixed.findings.map((finding) => finding.occurrenceId)).toEqual([
      "current-new-occurrence",
      "orphan-old-occurrence",
      "orphan-new-occurrence",
    ]);
  });

  test("searches secondary finding source locations", () => {
    for (const query of ["SECONDARY.PY", "äuth-strasse.py"]) {
      const result = probeFindingsIndex("current-target", { query });

      expect(result.findings).toEqual([
        expect.objectContaining({ occurrenceId: "current-new-occurrence" }),
      ]);
    }
  });
});

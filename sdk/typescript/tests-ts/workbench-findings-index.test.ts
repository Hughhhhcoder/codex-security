import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const findingsIndexProbe = [
  "import argparse, json, sqlite3, sys",
  "sys.path.insert(0, sys.argv[1])",
  "import workbench_native_indexes as indexes",
  "settings = json.loads(sys.argv[2])",
  "connection = sqlite3.connect(':memory:')",
  "connection.row_factory = sqlite3.Row",
  "connection.executescript('''",
  "CREATE TABLE security_targets (id TEXT PRIMARY KEY, current_path TEXT NOT NULL);",
  "CREATE TABLE scans (id TEXT PRIMARY KEY, target_id TEXT, target_path TEXT, status TEXT, seal_manifest_digest TEXT, started_at TEXT, updated_at TEXT, scope TEXT, scan_dir TEXT);",
  "CREATE TABLE finding_occurrences (id TEXT PRIMARY KEY, finding_id TEXT, scan_id TEXT, severity TEXT, created_at TEXT, title TEXT, summary TEXT);",
  "CREATE TABLE finding_triage (occurrence_id TEXT, status TEXT, updated_at TEXT);",
  "CREATE TABLE finding_locations (occurrence_id TEXT, relative_path TEXT, role TEXT, sort_order INTEGER);",
  "''')",
  "connection.executemany('INSERT INTO security_targets VALUES (?, ?)', [('current-target', '/current/repository'), ('stale-target', '/stale/repository')])",
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
  "if settings.get('mixedLegacyOwnership'):",
  "    connection.execute('ALTER TABLE scans ADD COLUMN target_device INTEGER')",
  "    connection.execute('ALTER TABLE scans ADD COLUMN target_inode INTEGER')",
  "    connection.execute(\"UPDATE scans SET target_device = 7, target_inode = 9 WHERE id = 'current-new'\")",
  "connection.executemany('INSERT INTO finding_occurrences VALUES (?, ?, ?, ?, ?, ?, ?)', [",
  "    ('current-old-occurrence', 'current-old-finding', 'current-old', 'high', '2026-01-01', 'Resolved current finding', 'Older issue'),",
  "    ('current-new-occurrence', 'current-new-finding', 'current-new', 'critical', '2026-02-01', 'Current CLI finding', 'Latest issue'),",
  "    ('reused-legacy-occurrence', 'previous-owner-finding', 'reused-legacy', 'critical', '2026-03-01', 'Previous owner secret', 'Must never cross checkout owners'),",
  "    ('stale-old-occurrence', 'stale-finding', 'stale-old', 'medium', '2026-01-01', 'Unavailable follow-up', 'Coverage is unavailable'),",
  "    ('orphan-old-occurrence', 'orphan-old-finding', 'orphan-old', 'high', '2026-01-01', 'Older orphan finding', 'Still outside follow-up coverage'),",
  "    ('orphan-new-occurrence', 'orphan-new-finding', 'orphan-new', 'medium', '2026-02-01', 'Latest orphan finding', 'Target row does not exist'),",
  "])",
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
  "coverage_reads = []",
  "def coverage(scan):",
  "    coverage_reads.append(scan['id'])",
  "    if settings.get('mixedLegacyOwnership') and scan['id'] == 'current-new':",
  "        return {'completeness': 'partial', 'includePaths': ['src/new.py'], 'excludePaths': [], 'explicitExclusions': []}",
  "    if scan['id'] == 'stale-new':",
  "        if settings.get('coverageFailure') == 'tampered':",
  "            raise SystemExit('The sealed scan manifest changed after completion.')",
  "        if settings.get('coverageFailure') == 'pruned':",
  "            raise SystemExit('coverage.json: expected a regular file inside the scan directory.')",
  "        raise SystemExit('Scan directory must be an existing canonical non-symlink directory.')",
  "    if scan['id'] == 'orphan-new':",
  "        return {'completeness': 'partial', 'includePaths': ['src/orphan-new.py'], 'excludePaths': [], 'explicitExclusions': []}",
  "    return {'completeness': 'complete', 'includePaths': ['.'], 'excludePaths': [], 'explicitExclusions': []}",
  "location_queries = []",
  "connection.set_trace_callback(lambda statement: location_queries.append(statement) if 'finding_locations' in statement else None)",
  "args = argparse.Namespace(query=settings.get('query'), severity=None, status=None, target_id=settings.get('targetIds') or settings.get('targetId'), target_path=settings.get('targetPaths') or settings.get('targetPath'), offset=0, limit=20)",
  "result = indexes.list_global_findings(connection, args, read_coverage=coverage)",
  "print(json.dumps({'findings': result['findings'], 'coverageReads': coverage_reads, 'locationQueryCount': len(location_queries)}))",
].join("\n");

function runFindingsIndex(
  targetId: string | null,
  settings: {
    targetIds?: string[];
    targetPath?: string;
    targetPaths?: string[];
    query?: string;
    coverageFailure?: "tampered" | "noncanonical" | "pruned";
    lateCompletion?: boolean;
    mixedLegacyOwnership?: boolean;
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
    coverageFailure?: "pruned";
    lateCompletion?: boolean;
    mixedLegacyOwnership?: boolean;
  } = {},
): {
  findings: Array<{
    occurrenceId: string;
    scanId: string;
    targetId: string | null;
    targetPath: string;
  }>;
  coverageReads: string[];
  locationQueryCount: number;
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

  test("keeps active findings when a later scan artifact was pruned", () => {
    const result = probeFindingsIndex("stale-target", {
      coverageFailure: "pruned",
    });

    expect(result.findings).toEqual([
      expect.objectContaining({ occurrenceId: "stale-old-occurrence" }),
    ]);
    expect(result.coverageReads).toEqual(["stale-new"]);
  });

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
      expect(result.locationQueryCount).toBe(1);
    }
  });
});

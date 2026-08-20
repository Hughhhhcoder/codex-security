import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

test("loads each scan's matching findings once across historical batches", () => {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  expect(python).not.toBeNull();
  if (python === null) throw new Error("A Python interpreter is required.");

  const probe = [
    "import argparse, json, sqlite3, sys",
    "sys.path.insert(0, sys.argv[1])",
    "import workbench_scan_history as history",
    "connection = sqlite3.connect(':memory:')",
    "connection.row_factory = sqlite3.Row",
    "connection.executescript('''",
    "CREATE TABLE security_targets (id TEXT, current_path TEXT);",
    "CREATE TABLE scans (id TEXT, target_path TEXT, target_id TEXT, status TEXT, started_at TEXT);",
    "CREATE TABLE scan_comparisons (before_scan_id TEXT, after_scan_id TEXT);",
    "CREATE TABLE finding_occurrences (id TEXT, finding_id TEXT, scan_id TEXT, details_json TEXT, remediation TEXT, severity TEXT, summary TEXT, title TEXT);",
    "CREATE TABLE finding_triage (occurrence_id TEXT, status TEXT, close_reason TEXT);",
    "CREATE TABLE finding_locations (occurrence_id TEXT, relative_path TEXT, role TEXT, sort_order INTEGER);",
    "''')",
    "for index in range(3):",
    "    scan = f'scan-{index}'",
    "    connection.execute('INSERT INTO scans VALUES (?, ?, NULL, ?, ?)', (scan, sys.argv[2], 'complete', str(index)))",
    "    connection.execute('INSERT INTO finding_occurrences VALUES (?, ?, ?, ?, ?, ?, ?, ?)', (scan, scan, scan, '{}', 'fix', 'high', 'summary', 'title'))",
    "queries = []",
    "connection.set_trace_callback(queries.append)",
    "backfilled = []",
    "result = history.list_unmatched_scan_pairs(connection, argparse.Namespace(repository=sys.argv[2], force=False), backfill_finding_details=lambda _connection, scan: backfilled.append(scan['id']), read_coverage=lambda _scan: {})",
    "print(json.dumps({'result': result, 'backfilled': backfilled, 'findingQueries': sum('FROM finding_occurrences AS occurrences' in query for query in queries)}))",
  ].join("\n");

  const result = spawnSync(
    python,
    [
      "-I",
      "-B",
      "-c",
      probe,
      join(PLUGIN_ROOT, "scripts"),
      join(tmpdir(), "codex-security-matching-fixture"),
    ],
    { encoding: "utf8", timeout: 10_000 },
  );

  expect(result.status).toBe(0);
  expect(result.stderr).toBe("");
  expect(JSON.parse(result.stdout)).toMatchObject({
    backfilled: ["scan-0", "scan-1", "scan-2"],
    findingQueries: 3,
    result: {
      scanCount: 3,
      batches: [
        { afterScanId: "scan-1", beforeScans: [{ scanId: "scan-0" }] },
        {
          afterScanId: "scan-2",
          beforeScans: [{ scanId: "scan-0" }, { scanId: "scan-1" }],
        },
      ],
    },
  });
});

test("resolves missing findings only inside a complete later scope", () => {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  expect(python).not.toBeNull();
  const probe = [
    "import argparse, json, sqlite3, sys",
    "sys.path.insert(0, sys.argv[1])",
    "import workbench_scan_history as history",
    "db = sqlite3.connect(':memory:')",
    "db.row_factory = sqlite3.Row",
    "db.executescript('''",
    "CREATE TABLE scan_comparisons (before_scan_id TEXT, after_scan_id TEXT, result_json TEXT);",
    "CREATE TABLE finding_occurrences (id TEXT, finding_id TEXT, scan_id TEXT, severity TEXT, title TEXT);",
    "CREATE TABLE finding_triage (occurrence_id TEXT, status TEXT, close_reason TEXT);",
    "CREATE TABLE finding_locations (occurrence_id TEXT, relative_path TEXT, role TEXT, sort_order INTEGER);",
    "''')",
    "scans = {name: {'id': name, 'status': 'complete', 'target_id': 'target', 'target_path': '/synthetic/repository'} for name in ('before', 'after')}",
    "paths = ['src/parser/input.ts', 'src/parser-other/input.ts', 'src/parser/generated/code.ts', 'src/parser/test_fixture.ts']",
    "for index, path in enumerate(paths):",
    "    key = str(index)",
    "    db.execute('INSERT INTO finding_occurrences VALUES (?, ?, ?, ?, ?)', (key, key, 'before', 'high', 'Synthetic finding'))",
    "    db.execute('INSERT INTO finding_locations VALUES (?, ?, ?, ?)', (key, path, 'root_control', 0))",
    "coverage = {'mode': 'scoped_path', 'completeness': 'complete', 'includePaths': ['src/parser'], 'excludePaths': ['src/parser/generated'], 'explicitExclusions': [{'pattern': 'src/parser/test_*', 'reason': 'Excluded test fixtures'}]}",
    "args = argparse.Namespace(before_scan_id='before', after_scan_id='after')",
    "def compare():",
    "    result = history.compare_scans(db, args, require_scan=lambda _, key: scans[key], read_coverage=lambda _: coverage)",
    "    return {item['path']: item['status'] for item in result['findings']}",
    "complete = compare()",
    "coverage['completeness'] = 'partial'",
    "print(json.dumps({'complete': complete, 'partial': compare()}))",
  ].join("\n");
  const result = spawnSync(
    python!,
    ["-I", "-B", "-c", probe, join(PLUGIN_ROOT, "scripts")],
    { encoding: "utf8" },
  );
  expect(result.status, result.stderr).toBe(0);
  const output = JSON.parse(result.stdout);
  expect(output.complete).toEqual({
    "src/parser/input.ts": "resolved",
    "src/parser-other/input.ts": "unknown",
    "src/parser/generated/code.ts": "unknown",
    "src/parser/test_fixture.ts": "unknown",
  });
  expect(Object.values(output.partial)).toEqual([
    "unknown",
    "unknown",
    "unknown",
    "unknown",
  ]);
});

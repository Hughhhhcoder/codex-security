import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

test("loads each scan once and scopes saved links to uncached history", () => {
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
    "CREATE TABLE scan_comparison_matches (before_scan_id TEXT, after_scan_id TEXT, before_occurrence_id TEXT, after_occurrence_id TEXT);",
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
    "finding_queries = sum('FROM finding_occurrences AS occurrences' in query for query in queries)",
    "connection.executemany('INSERT INTO scan_comparisons VALUES (?, ?)', [('scan-0', 'scan-1'), ('scan-0', 'scan-2'), ('scan-1', 'scan-2')])",
    "queries.clear()",
    "cached = history.list_unmatched_scan_pairs(connection, argparse.Namespace(repository=sys.argv[2], force=False), backfill_finding_details=lambda *_: None, read_coverage=lambda _scan: {})",
    "cached_link_queries = sum('FROM scan_comparison_matches' in query for query in queries)",
    "for name in ('foreign-a', 'foreign-b'):",
    "    connection.execute('INSERT INTO finding_occurrences VALUES (?, ?, ?, ?, ?, ?, ?, ?)', (name, name, name, '{}', 'fix', 'high', 'summary', 'title'))",
    "connection.executemany('INSERT INTO scan_comparison_matches VALUES (?, ?, ?, ?)', [('scan-0', 'scan-1', 'scan-0', 'scan-1'), ('foreign-a', 'foreign-b', 'foreign-a', 'foreign-b')])",
    "queries.clear()",
    "scoped = history._saved_finding_links(connection, {'scan-0', 'scan-1'})",
    "link_queries = [query for query in queries if 'FROM scan_comparison_matches' in query]",
    "print(json.dumps({'result': result, 'backfilled': backfilled, 'findingQueries': finding_queries, 'cached': cached, 'cachedLinkQueries': cached_link_queries, 'scopedLinks': [dict(row) for row in scoped], 'scopedQueryCount': len(link_queries), 'unscopedQueries': sum('WHERE matches.before_scan_id' not in query for query in link_queries)}))",
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
    cached: { batches: [], skippedPairs: 3 },
    cachedLinkQueries: 0,
    scopedLinks: [{ before_finding_id: "scan-0", after_finding_id: "scan-1" }],
    scopedQueryCount: 2,
    unscopedQueries: 0,
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

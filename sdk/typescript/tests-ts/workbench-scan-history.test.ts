import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

test("keeps inline and stdin comparison transports compatible", () => {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  if (python === null) throw new Error("A Python interpreter is required.");
  const probe = [
    "import json, sys",
    "sys.path.insert(0, sys.argv.pop(1))",
    "from workbench_cli import parse_args",
    "args = parse_args('Synthetic comparison transport')",
    "print(json.dumps(json.loads(args.matches_json)))",
  ].join("\n");
  const args = [
    "-I",
    "-B",
    "-c",
    probe,
    join(PLUGIN_ROOT, "scripts"),
    "save-scan-comparison",
    "--before-scan-id",
    "before",
    "--after-scan-id",
    "after",
  ];
  const payload = JSON.stringify({
    matches: [
      {
        beforeOccurrenceIds: ["before"],
        afterOccurrenceIds: ["after"],
        confidence: "high",
        reason: "Synthetic comparison 🙂",
      },
    ],
    uncertain: [],
  });
  for (const transport of [
    ["--matches-json", payload],
    ["--matches-json-stdin"],
  ]) {
    const result = spawnSync(python, [...args, ...transport], {
      input: payload,
      encoding: "utf8",
      timeout: 10_000,
    });
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual(JSON.parse(payload));
  }
  const conflicting = spawnSync(
    python,
    [...args, "--matches-json", payload, "--matches-json-stdin"],
    { input: payload, encoding: "utf8", timeout: 10_000 },
  );
  expect(conflicting.status).toBe(2);
  expect(conflicting.stderr).toContain("not allowed with argument");
});

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
    "for index in (3, 4):",
    "    scan = f'scan-{index}'",
    "    connection.execute('INSERT INTO scans VALUES (?, ?, NULL, ?, ?)', (scan, sys.argv[2], 'complete', str(index)))",
    "    connection.execute('INSERT INTO finding_occurrences VALUES (?, ?, ?, ?, ?, ?, ?, ?)', (scan, f'scan-{index - 3}', scan, '{}', 'fix', 'high', 'summary', 'title'))",
    "def coverage(scan):",
    "    if scan['id'] in {'scan-0', 'scan-1', 'scan-2'}:",
    "        raise SystemExit('Synthetic unavailable artifacts')",
    "    return {}",
    "unavailable = history.list_unmatched_scan_pairs(connection, argparse.Namespace(repository=sys.argv[2], force=False), backfill_finding_details=lambda *_: None, read_coverage=coverage)",
    "forced = history.list_unmatched_scan_pairs(connection, argparse.Namespace(repository=sys.argv[2], force=True), backfill_finding_details=lambda *_: None, read_coverage=coverage)",
    "print(json.dumps({'result': result, 'backfilled': backfilled, 'findingQueries': finding_queries, 'cached': cached, 'cachedLinkQueries': cached_link_queries, 'scopedLinks': [dict(row) for row in scoped], 'scopedQueryCount': len(link_queries), 'unscopedQueries': sum('WHERE matches.before_scan_id' not in query for query in link_queries), 'unavailable': unavailable, 'forcedKnownGroups': [batch.get('knownFindingGroups') for batch in forced['batches']]}))",
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
    unavailable: {
      scanCount: 5,
      unavailableScans: 3,
      batches: [
        {
          afterScanId: "scan-4",
          beforeScans: [{ scanId: "scan-3" }],
          knownFindingGroups: [["scan-0", "scan-1"]],
        },
      ],
    },
    forcedKnownGroups: [null],
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

test("loads displayed relations in bulk and follows current confirmed identities", () => {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  if (python === null) throw new Error("A Python interpreter is required.");
  const probe = `
import json, sqlite3, sys
sys.path.insert(0, sys.argv[1])
import workbench_scan_history as history
connection = sqlite3.connect(':memory:')
connection.row_factory = sqlite3.Row
connection.executescript('''
CREATE TABLE scans (id TEXT PRIMARY KEY, target_id TEXT);
CREATE INDEX scans_by_target ON scans(target_id, id);
CREATE TABLE finding_occurrences (
    id TEXT PRIMARY KEY, finding_id TEXT, scan_id TEXT, title TEXT,
    UNIQUE(scan_id, finding_id)
);
CREATE TABLE scan_comparisons (before_scan_id TEXT, after_scan_id TEXT, result_json TEXT);
CREATE TABLE scan_comparison_matches (
    before_scan_id TEXT, after_scan_id TEXT, before_occurrence_id TEXT, after_occurrence_id TEXT
);
CREATE INDEX matches_before ON scan_comparison_matches(before_occurrence_id);
CREATE INDEX matches_after ON scan_comparison_matches(after_occurrence_id);
''')
connection.executemany('INSERT INTO scans VALUES (?, ?)', [
    ('one', 'target'), ('two', 'target'), ('three', 'clone'),
    ('four', 'target'), ('foreign-one', 'unrelated-target'),
    ('foreign-two', 'unrelated-target')
])
connection.executemany('INSERT INTO finding_occurrences VALUES (?, ?, ?, ?)', (
    (f'{side}-{index}', f'{side}-identity-{index}', scan, f'Synthetic {side} {index}')
    for index in range(10_000)
    for side, scan in [('left', 'one'), ('right', 'two')]
))
payload = json.dumps({'matches': [], 'uncertain': [], 'related': [
    {'beforeOccurrenceId': f'left-{index}', 'afterOccurrenceId': f'right-{index}',
     'reason': 'Separate synthetic controls.'}
    for index in range(10_000)
]})
connection.execute('INSERT INTO scan_comparisons VALUES (?, ?, ?)', ('one', 'two', payload))
queries = []
connection.set_trace_callback(queries.append)
scoped = history.finding_relations(connection, 'one', ['left-0'])
scoped_queries = len(queries)
queries.clear()
empty = history.finding_relations(connection, 'one', [])
empty_queries = len(queries)
connection.executemany('INSERT INTO finding_occurrences VALUES (?, ?, ?, ?)', [
    ('recurring-left', 'left-identity-0', 'four', 'Recurring control'),
    ('bridge', 'bridge-identity', 'three', 'Renamed control'),
    ('foreign-a', 'foreign-identity-a', 'foreign-one', 'Unrelated A'),
    ('foreign-b', 'foreign-identity-b', 'foreign-two', 'Unrelated B')
])
connection.executemany('INSERT INTO scan_comparison_matches VALUES (?, ?, ?, ?)', [
    ('four', 'three', 'recurring-left', 'bridge'),
    ('two', 'three', 'right-0', 'bridge'),
    ('foreign-one', 'foreign-two', 'foreign-a', 'foreign-b')
])
aliases = history._confirmed_finding_aliases(connection, ['left-0'])
forward = history.finding_relations(connection, 'one', ['left-0'])
reverse = history.finding_relations(connection, 'two', ['right-0'])
remaining = history.finding_relations(connection, 'one', ['left-1'])
unchanged = connection.execute('SELECT result_json FROM scan_comparisons').fetchone()[0] == payload
connection.execute('DELETE FROM scan_comparison_matches WHERE before_occurrence_id = ?', ('right-0',))
restored = history.finding_relations(connection, 'one', ['left-0']) == scoped

limited = hasattr(connection, 'setlimit')
if limited:
    old_limit = connection.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 8)
queries.clear()
batched = history.finding_relations(connection, 'one', [f'left-{index}' for index in range(1, 11)])
batched_queries = len(queries)
if limited:
    connection.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, old_limit)

class LegacyConnection:
    def execute(self, *args):
        return connection.execute(*args)

queries.clear()
legacy_rows = list(history._rows_for_ids(
    LegacyConnection(), 'SELECT id FROM finding_occurrences WHERE id IN ({placeholders})',
    (f'left-{index}' for index in range(1001))
))
print(json.dumps({
    'scoped': scoped, 'scopedQueries': scoped_queries, 'empty': empty,
    'emptyQueries': empty_queries, 'aliases': sorted(aliases), 'forward': forward,
    'reverse': reverse, 'remaining': sorted(remaining), 'unchanged': unchanged,
    'restoredAfterUnlink': restored,
    'batchedCount': len(batched), 'batchedQueries': batched_queries,
    'expectedBatchedQueries': 6 if limited else 3,
    'legacyCount': len(legacy_rows), 'legacyQueries': len(queries)
}))
`;
  const result = spawnSync(
    python,
    ["-I", "-B", "-c", probe, join(PLUGIN_ROOT, "scripts")],
    { encoding: "utf8", timeout: 10_000 },
  );
  expect(result.status, result.stderr).toBe(0);
  const observed = JSON.parse(result.stdout) as Record<string, unknown>;
  expect(observed).toMatchObject({
    scoped: {
      "left-0": [{ occurrenceId: "right-0", scanId: "two" }],
    },
    scopedQueries: 3,
    empty: {},
    emptyQueries: 0,
    aliases: ["bridge-identity", "left-identity-0", "right-identity-0"],
    forward: {},
    reverse: {},
    remaining: ["left-1"],
    unchanged: true,
    restoredAfterUnlink: true,
    batchedCount: 10,
    legacyCount: 1001,
    legacyQueries: 2,
  });
  expect(observed["batchedQueries"]).toBe(observed["expectedBatchedQueries"]);
});

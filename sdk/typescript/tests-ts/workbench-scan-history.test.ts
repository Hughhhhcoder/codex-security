import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

test("loads each scan's matching findings once in insertion order after clock rollback", () => {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  expect(python).not.toBeNull();
  if (python === null) throw new Error("A Python interpreter is required.");

  const probe = [
    "import argparse, json, os, sqlite3, sys, tempfile",
    "sys.path.insert(0, sys.argv[1])",
    "import workbench_scan_history as history",
    "from filesystem_identity import serialize_filesystem_identity",
    "directory = tempfile.TemporaryDirectory(prefix='codex-security-matching-fixture-')",
    "repository = os.path.realpath(directory.name)",
    "connection = sqlite3.connect(':memory:')",
    "connection.row_factory = sqlite3.Row",
    "connection.executescript('''",
    "CREATE TABLE security_targets (id TEXT, current_path TEXT);",
    "CREATE TABLE scans (id TEXT, target_path TEXT, target_id TEXT, target_device INTEGER, target_inode INTEGER, target_revision TEXT, status TEXT, started_at TEXT);",
    "CREATE TABLE scan_comparisons (before_scan_id TEXT, after_scan_id TEXT);",
    "CREATE TABLE finding_occurrences (id TEXT, finding_id TEXT, scan_id TEXT, details_json TEXT, remediation TEXT, severity TEXT, summary TEXT, title TEXT);",
    "CREATE TABLE finding_triage (occurrence_id TEXT, status TEXT, close_reason TEXT);",
    "CREATE TABLE finding_locations (occurrence_id TEXT, relative_path TEXT, role TEXT, sort_order INTEGER);",
    "''')",
    "metadata = os.stat(repository)",
    "identity = (serialize_filesystem_identity(metadata.st_dev), serialize_filesystem_identity(metadata.st_ino))",
    "connection.execute('INSERT INTO security_targets VALUES (?, ?)', ('owned-target', repository))",
    "for index in range(3):",
    "    scan = f'scan-{index}'",
    "    connection.execute('INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?, ?)', (scan, repository, 'owned-target', *identity, 'unversioned', 'complete', str(2 - index)))",
    "    connection.execute('INSERT INTO finding_occurrences VALUES (?, ?, ?, ?, ?, ?, ?, ?)', (scan, scan, scan, '{}', 'fix', 'high', 'summary', 'title'))",
    "queries = []",
    "connection.set_trace_callback(queries.append)",
    "backfilled = []",
    "result = history.list_unmatched_scan_pairs(connection, argparse.Namespace(repository=repository, force=False), backfill_finding_details=lambda _connection, scan: backfilled.append(scan['id']), read_coverage=lambda _scan: {})",
    "print(json.dumps({'result': result, 'backfilled': backfilled, 'findingQueries': sum('FROM finding_occurrences AS occurrences' in query for query in queries)}))",
  ].join("\n");

  const result = spawnSync(
    python,
    ["-I", "-B", "-c", probe, join(PLUGIN_ROOT, "scripts")],
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

test("lists completed scans in insertion order after clock rollback", () => {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  if (python === null) throw new Error("A Python interpreter is required.");

  const probe = [
    "import json, sqlite3, sys",
    "sys.path.insert(0, sys.argv[1])",
    "import workbench_scan_history as history",
    "import workbench_schema as schema",
    "connection = sqlite3.connect(':memory:')",
    "connection.row_factory = sqlite3.Row",
    "schema.apply_migrations(connection, schema.MIGRATIONS, lambda: '2026-01-01', lambda _connection: None)",
    "connection.execute(\"INSERT INTO workspaces (id, created_at, updated_at) VALUES ('workspace', '2026-01-01', '2026-01-01')\")",
    "for scan, status, started in [('older', 'complete', '2026-02-01'), ('newer', 'complete', '2026-01-01'), ('running', 'running', '2025-12-01')]:",
    "    connection.execute('INSERT INTO scans (id, workspace_id, target_path, target_revision, scope, mode, scan_dir, status, phase, started_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', (scan, 'workspace', '/repository', 'revision', '.', 'standard', '/scans/' + scan, status, 'reporting', started, started, started))",
    "    connection.execute('INSERT INTO scan_progress (scan_id, updated_at) VALUES (?, ?)', (scan, started))",
    "print(json.dumps([scan['scanId'] for scan in history.list_scans(connection)['scans']]))",
  ].join("\n");

  const result = spawnSync(
    python,
    ["-I", "-B", "-c", probe, join(PLUGIN_ROOT, "scripts")],
    { encoding: "utf8", timeout: 10_000 },
  );

  expect(result.status, result.stderr).toBe(0);
  expect(JSON.parse(result.stdout)).toEqual(["running", "newer", "older"]);
});

test("orders finding-detail history by scan insertion after clock rollback", () => {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  if (python === null) throw new Error("A Python interpreter is required.");

  const probe = [
    "import json, sqlite3, sys",
    "sys.path.insert(0, sys.argv[1])",
    "import workbench_scan_history as history",
    "connection = sqlite3.connect(':memory:')",
    "connection.row_factory = sqlite3.Row",
    "connection.executescript('''",
    "CREATE TABLE scans (id TEXT, started_at TEXT);",
    "CREATE TABLE finding_occurrences (id TEXT, finding_id TEXT, scan_id TEXT, title TEXT);",
    "CREATE TABLE scan_comparison_matches (before_scan_id TEXT, after_scan_id TEXT, before_occurrence_id TEXT, after_occurrence_id TEXT, reason TEXT);",
    "''')",
    "connection.executemany('INSERT INTO scans VALUES (?, ?)', [('older-scan', '2026-02-01'), ('newer-scan', '2026-01-01')])",
    "connection.executemany('INSERT INTO finding_occurrences VALUES (?, ?, ?, ?)', [('older-occurrence', 'finding', 'older-scan', 'Older'), ('newer-occurrence', 'finding', 'newer-scan', 'Newer')])",
    "connection.execute(\"INSERT INTO scan_comparison_matches VALUES ('older-scan', 'newer-scan', 'older-occurrence', 'newer-occurrence', 'Same finding')\")",
    "matches, known_since, scan_ids = history.finding_matches(connection, 'newer-occurrence', 'newer-scan', '2026-01-01')",
    "print(json.dumps({'knownSince': known_since, 'knownScanIds': scan_ids, 'matches': matches}))",
  ].join("\n");

  const result = spawnSync(
    python,
    ["-I", "-B", "-c", probe, join(PLUGIN_ROOT, "scripts")],
    { encoding: "utf8", timeout: 10_000 },
  );

  expect(result.status, result.stderr).toBe(0);
  expect(JSON.parse(result.stdout)).toMatchObject({
    knownSince: "2026-02-01",
    knownScanIds: ["older-scan", "newer-scan"],
  });
});

test("compares registered scan history after its checkout moves", () => {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  if (python === null) throw new Error("A Python interpreter is required.");

  const probe = [
    "import json, os, pathlib, sqlite3, sys, tempfile",
    "sys.path.insert(0, sys.argv[1])",
    "import workbench_scan_history as history",
    "from filesystem_identity import serialize_filesystem_identity",
    "with tempfile.TemporaryDirectory() as temporary:",
    "    old = pathlib.Path(temporary) / 'old-checkout'",
    "    old.mkdir()",
    "    identity = os.stat(old)",
    "    moved = pathlib.Path(temporary) / 'moved-checkout'",
    "    old.rename(moved)",
    "    connection = sqlite3.connect(':memory:')",
    "    connection.row_factory = sqlite3.Row",
    "    connection.execute('CREATE TABLE security_targets (id TEXT, current_path TEXT)')",
    "    connection.execute('INSERT INTO security_targets VALUES (?, ?)', ('owned-target', str(moved)))",
    "    rows = [connection.execute('SELECT ? AS target_id, ? AS target_path, ? AS target_device, ? AS target_inode', ('owned-target', str(path), serialize_filesystem_identity(identity.st_dev), serialize_filesystem_identity(identity.st_ino))).fetchone() for path in (old, moved)]",
    "    print(json.dumps(history._same_registered_repository(connection, *rows)))",
  ].join("\n");

  const result = spawnSync(
    python,
    ["-I", "-B", "-c", probe, join(PLUGIN_ROOT, "scripts")],
    { encoding: "utf8" },
  );

  expect(result.status).toBe(0);
  expect(result.stderr).toBe("");
  expect(JSON.parse(result.stdout)).toBe(true);
});

test("includes linked worktrees and recognizes separately verified clones", () => {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  if (python === null) throw new Error("A Python interpreter is required.");

  const probe = [
    "import json, os, pathlib, sqlite3, subprocess, sys, tempfile",
    "sys.path.insert(0, sys.argv[1])",
    "import workbench_scan_history as history",
    "from filesystem_identity import serialize_filesystem_identity",
    "with tempfile.TemporaryDirectory() as temporary:",
    "    root = pathlib.Path(temporary).resolve() / 'repository'",
    "    linked = pathlib.Path(temporary).resolve() / 'linked-worktree'",
    "    clone = pathlib.Path(temporary).resolve() / 'repository-clone'",
    "    unregistered = pathlib.Path(temporary).resolve() / 'unregistered-clone'",
    "    subprocess.run(['git', 'init', '-q', '-b', 'main', str(root)], check=True)",
    "    (root / 'source.py').write_text('print(1)\\n')",
    "    subprocess.run(['git', '-C', str(root), 'add', 'source.py'], check=True)",
    "    subprocess.run(['git', '-C', str(root), '-c', 'user.name=Inventory Test', '-c', 'user.email=inventory@example.test', 'commit', '-qm', 'initial'], check=True)",
    "    subprocess.run(['git', '-C', str(root), 'worktree', 'add', '-q', '-b', 'linked', str(linked)], check=True)",
    "    subprocess.run(['git', '-C', str(root), 'remote', 'add', 'origin', 'https://github.com/example/project.git'], check=True)",
    "    subprocess.run(['git', 'clone', '-q', str(root), str(clone)], check=True)",
    "    subprocess.run(['git', '-C', str(clone), 'remote', 'set-url', 'origin', 'git@github.com:example/project.git'], check=True)",
    "    subprocess.run(['git', 'clone', '-q', str(root), str(unregistered)], check=True)",
    "    subprocess.run(['git', '-C', str(unregistered), 'remote', 'set-url', 'origin', 'git@github.com:example/project.git'], check=True)",
    "    nested = root / 'src'",
    "    nested.mkdir()",
    "    connection = sqlite3.connect(':memory:')",
    "    connection.row_factory = sqlite3.Row",
    "    connection.executescript('CREATE TABLE security_targets (id TEXT, current_path TEXT); CREATE TABLE scans (id TEXT, target_id TEXT, target_path TEXT, target_device INTEGER, target_inode INTEGER, target_revision TEXT, started_at TEXT);')",
    "    for target_id, target in [('main', root), ('linked', linked), ('clone', clone)]:",
    "        metadata = target.stat()",
    "        connection.execute('INSERT INTO security_targets VALUES (?, ?)', (target_id, str(target)))",
    "        connection.execute('INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?)', (target_id, target_id, str(target), serialize_filesystem_identity(metadata.st_dev), serialize_filesystem_identity(metadata.st_ino), 'revision', '2026-01-01'))",
    "    connection.execute('INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?)', ('local-legacy', None, str(nested), None, None, 'revision', '2026-01-02'))",
    "    _, _, target_ids, _ = history.repository_scan_scope(connection, nested)",
    "    scans = [connection.execute('SELECT * FROM scans WHERE id = ?', (target_id,)).fetchone() for target_id in ('main', 'clone')]",
    "    untrusted = connection.execute(\"SELECT '' AS target_id, ? AS target_path\", (str(unregistered),)).fetchone()",
    "    _, _, unregistered_targets, _ = history.repository_scan_scope(connection, unregistered)",
    "    print(json.dumps({'targets': sorted(target_ids), 'clone': history._same_repository(*scans, require_ownership=True), 'untrusted': history._same_repository(scans[0], untrusted), 'unregistered': unregistered_targets}))",
  ].join("\n");

  const result = spawnSync(
    python,
    ["-I", "-B", "-c", probe, join(PLUGIN_ROOT, "scripts")],
    { encoding: "utf8" },
  );

  expect(result.status).toBe(0);
  expect(result.stderr).toBe("");
  expect(JSON.parse(result.stdout)).toEqual({
    targets: ["linked", "main"],
    clone: true,
    untrusted: false,
    unregistered: [],
  });
});

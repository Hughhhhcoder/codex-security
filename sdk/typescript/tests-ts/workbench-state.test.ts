import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import {
  chmod,
  mkdir,
  mkdtemp,
  readdir,
  realpath,
  rm,
  stat,
  symlink,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const temporaryDirectories: string[] = [];
const testPosix = process.platform === "win32" ? test.skip : test;

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function temporaryDirectory(): Promise<string> {
  const path = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-workbench-state-")),
  );
  temporaryDirectories.push(path);
  return path;
}

function runPython(stateDirectory: string, args: string[]) {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  if (python === null) throw new Error("A Python interpreter is required.");
  return spawnSync(python, ["-I", "-B", ...args], {
    encoding: "utf8",
    timeout: 30_000,
    env: {
      PATH: process.env["PATH"],
      SystemRoot: process.env["SystemRoot"],
      CODEX_SECURITY_STATE_DIR: stateDirectory,
    },
  });
}

test("direct workbench initialization creates and pins private state", async () => {
  const root = await temporaryDirectory();
  const actual = join(root, "actual");
  const alias = join(root, "alias");
  await mkdir(actual, { mode: 0o700 });
  await symlink(
    actual,
    alias,
    process.platform === "win32" ? "junction" : "dir",
  );
  for (const mask of [0o002, 0o700]) {
    const nested = `nested-${mask.toString(8)}`;
    const state = `${alias}${sep}.${sep}${nested}${sep}state`;
    const canonical = join(actual, nested, "state");
    const result = runPython(state, [
      "-c",
      [
        "import json, os, sys",
        "os.umask(int(sys.argv[2], 8))",
        "sys.path.insert(0, sys.argv[1])",
        "import workbench_db as workbench",
        "workbench.connect().close()",
        'print(json.dumps({"state": str(workbench.state_dir()), "configured": os.environ["CODEX_SECURITY_STATE_DIR"]}))',
      ].join("\n"),
      join(PLUGIN_ROOT, "scripts"),
      mask.toString(8),
    ]);

    expect(result.status).toBe(0);
    expect(result.stderr).toBe("");
    const paths = JSON.parse(result.stdout) as {
      state: string;
      configured: string;
    };
    expect(paths.configured).toBe(paths.state);
    expect(await realpath(paths.state)).toBe(await realpath(canonical));
    expect(existsSync(join(canonical, "workbench.sqlite3"))).toBe(true);
    if (process.platform !== "win32") {
      expect((await stat(join(actual, nested))).mode & 0o777).toBe(0o700);
      expect((await stat(canonical)).mode & 0o777).toBe(0o700);
      expect(
        (await stat(join(canonical, "workbench.sqlite3"))).mode & 0o777,
      ).toBe(0o600);
    }
  }
});

test("direct workbench validates a competing private initializer", async () => {
  const root = await temporaryDirectory();
  const component = join(root, "nested");
  const state = join(component, "state");
  const result = runPython(state, [
    "-c",
    [
      "import json, sys",
      "from pathlib import Path",
      "from unittest.mock import patch",
      "sys.path.insert(0, sys.argv[1])",
      "import workbench_db as workbench",
      "component = Path(sys.argv[2])",
      "original_mkdir = Path.mkdir",
      "def competing_mkdir(path, *args, **kwargs):",
      "    if path == component and not path.exists():",
      "        original_mkdir(path, *args, **kwargs)",
      "        raise FileExistsError(str(path))",
      "    return original_mkdir(path, *args, **kwargs)",
      'with patch.object(Path, "mkdir", competing_mkdir), patch.object(workbench, "require_canonical_scan_directory", wraps=workbench.require_canonical_scan_directory) as validate:',
      "    workbench.connect().close()",
      "    print(json.dumps([str(call.args[0]) for call in validate.call_args_list]))",
    ].join("\n"),
    join(PLUGIN_ROOT, "scripts"),
    component,
  ]);

  expect(result.status).toBe(0);
  expect(result.stderr).toBe("");
  expect(JSON.parse(result.stdout)).toContain(component);
  expect(existsSync(join(state, "workbench.sqlite3"))).toBe(true);
});

testPosix(
  "direct workbench rejects unsafe state before opening its database",
  async () => {
    const root = await temporaryDirectory();
    const state = join(root, "state");
    const shared = join(root, "shared");
    const nestedState = join(shared, "state");
    const missingState = join(shared, "missing", "state");
    await mkdir(state, { mode: 0o700 });
    await mkdir(nestedState, { recursive: true, mode: 0o700 });
    await chmod(shared, 0o775);
    const command = [
      join(PLUGIN_ROOT, "scripts", "workbench_db.py"),
      "list-scans",
      "--repository",
      root,
    ];

    for (const mode of [0o755, 0o1777]) {
      await chmod(state, mode);
      const actualMode = (await stat(state)).mode & 0o7777;
      const result = runPython(state, command);
      expect(result.status).not.toBe(0);
      expect(result.stderr).toContain("state directory");
      expect((await stat(state)).mode & 0o7777).toBe(actualMode);
      expect(existsSync(join(state, "workbench.sqlite3"))).toBe(false);
    }

    const nested = runPython(nestedState, command);
    expect(nested.status).not.toBe(0);
    expect(nested.stderr).toContain("group- or world-writable");
    expect((await stat(shared)).mode & 0o7777).toBe(0o775);
    expect((await stat(nestedState)).mode & 0o7777).toBe(0o700);
    expect(existsSync(join(nestedState, "workbench.sqlite3"))).toBe(false);
    const missing = runPython(missingState, command);
    expect(missing.status).not.toBe(0);
    expect(missing.stderr).toContain("group- or world-writable");
    expect(existsSync(join(shared, "missing"))).toBe(false);
  },
);

testPosix(
  "direct workbench rejects unsafe lexical and chained state aliases",
  async () => {
    const root = await temporaryDirectory();
    const state = join(root, "state");
    const shared = join(root, "shared");
    const trusted = join(root, "trusted");
    const unsafeLink = join(shared, "state-link");
    const nextLink = join(trusted, "next-link");
    const alias = join(root, "alias");
    const dottedAlias = join(root, "dotted-alias");
    const dottedState = `${shared}${sep}..${sep}state`;
    const missing = join(alias, "missing", "state");
    await mkdir(state, { mode: 0o700 });
    await mkdir(shared, { mode: 0o700 });
    await mkdir(trusted, { mode: 0o700 });
    await chmod(shared, 0o775);
    await symlink(state, unsafeLink, "dir");
    await symlink(unsafeLink, nextLink, "dir");
    await symlink(`${nextLink}${sep}`, alias, "dir");
    await symlink(dottedState, dottedAlias, "dir");
    const command = [
      join(PLUGIN_ROOT, "scripts", "workbench_db.py"),
      "list-scans",
      "--repository",
      root,
    ];

    for (const path of [
      unsafeLink,
      nextLink,
      alias,
      dottedAlias,
      dottedState,
      missing,
    ]) {
      const result = runPython(path, command);
      expect(result.status).not.toBe(0);
      expect(result.stdout).toBe("");
      expect(result.stderr).toContain("state directory is unsafe");
      expect(result.stderr).toContain("group- or world-writable");
    }
    expect((await stat(shared)).mode & 0o7777).toBe(0o775);
    expect((await stat(state)).mode & 0o7777).toBe(0o700);
    expect(await readdir(state)).toEqual([]);
    expect(await readdir(shared)).toEqual(["state-link"]);
    expect(await readdir(trusted)).toEqual(["next-link"]);
    expect(existsSync(missing)).toBe(false);
  },
);

testPosix(
  "direct workbench rejects untrusted state-link ownership before creation",
  async () => {
    const root = await temporaryDirectory();
    const state = join(root, "state");
    const alias = join(root, "alias");
    await mkdir(state, { mode: 0o700 });
    await symlink(state, alias, "dir");
    const result = runPython(alias, [
      "-c",
      [
        "import os, sys",
        "from pathlib import Path",
        "from unittest.mock import patch",
        "sys.path.insert(0, sys.argv[1])",
        "import workbench_db as workbench",
        "original_lstat = os.lstat",
        "def synthetic_lstat(path, *args, **kwargs):",
        "    metadata = original_lstat(path, *args, **kwargs)",
        "    if os.fspath(path) == sys.argv[2]:",
        "        values = list(metadata)",
        "        values[4] = os.geteuid() + 1",
        "        return os.stat_result(values)",
        "    return metadata",
        "with (",
        '    patch.object(os, "lstat", synthetic_lstat),',
        '    patch.object(Path, "mkdir", side_effect=AssertionError("unexpected creation")),',
        '    patch.object(workbench.sqlite3, "connect", side_effect=AssertionError("unexpected database access")),',
        "):",
        "    try:",
        "        workbench.connect()",
        "    except SystemExit as error:",
        "        print(error)",
        "    else:",
        '        raise AssertionError("untrusted state link was accepted")',
      ].join("\n"),
      join(PLUGIN_ROOT, "scripts"),
      alias,
    ]);

    expect(result.status).toBe(0);
    expect(result.stderr).toBe("");
    expect(result.stdout).toContain("state directory is unsafe");
    expect(result.stdout).toContain("trusted owner");
    expect((await stat(state)).mode & 0o7777).toBe(0o700);
    expect(await readdir(state)).toEqual([]);
  },
);

test("direct workbench preserves unresolved home expansion failures", () => {
  const result = runPython("", [
    "-c",
    [
      "import json, os, sys",
      "from pathlib import Path",
      "from unittest.mock import patch",
      "sys.path.insert(0, sys.argv[1])",
      "import workbench_db as workbench",
      "errors = []",
      "with (",
      '    patch.object(os.path, "expanduser", side_effect=lambda path: path),',
      '    patch.object(Path, "mkdir", side_effect=AssertionError("unexpected creation")),',
      '    patch.object(workbench.sqlite3, "connect", side_effect=AssertionError("unexpected database access")),',
      "):",
      "    for environment in (",
      '        {"CODEX_SECURITY_STATE_DIR": "~unresolved/state"},',
      '        {"CODEX_SECURITY_STATE_DIR": "", "CODEX_HOME": "~/home"},',
      "    ):",
      "        with patch.dict(os.environ, environment, clear=True):",
      "            for select in (workbench.state_dir, workbench.connect):",
      "                try:",
      "                    select()",
      "                except RuntimeError as error:",
      "                    errors.append(str(error))",
      "                else:",
      '                    raise AssertionError("unresolved home was accepted")',
      "print(json.dumps(errors))",
    ].join("\n"),
    join(PLUGIN_ROOT, "scripts"),
  ]);

  expect(result.status).toBe(0);
  expect(result.stderr).toBe("");
  expect(JSON.parse(result.stdout)).toEqual(
    Array(4).fill("Could not determine home directory."),
  );
});

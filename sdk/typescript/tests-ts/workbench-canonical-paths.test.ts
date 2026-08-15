import {
  chmod,
  mkdir,
  mkdtemp,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const temporaryDirectories: string[] = [];
const testCaseSensitive = process.platform === "linux" ? test : test.skip;
const testPosix = process.platform === "win32" ? test.skip : test;
const testWindows = process.platform === "win32" ? test : test.skip;

const simulatedPathProbe = [
  "import json, ntpath, os, posixpath, sys",
  "from pathlib import PurePosixPath, PureWindowsPath",
  "from types import SimpleNamespace",
  "sys.path.insert(0, sys.argv[1])",
  "import deep_scan_workbench as deep_scan",
  "mode = sys.argv[2]",
  "if mode == 'windows':",
  "    path_type, path_module = PureWindowsPath, ntpath",
  "    root, supplied, resolved = 'D:/Scan', 'd:/sCaN/pRoMpT', 'D:/Scan/Prompt'",
  "else:",
  "    path_type, path_module = PurePosixPath, posixpath",
  "    root, supplied, resolved = '/scan', '/scan/prompt', '/scan/Prompt'",
  "class SimulatedPath(path_type):",
  "    def expanduser(self):",
  "        return self",
  "    def absolute(self):",
  "        return self",
  "    def resolve(self, strict=False):",
  "        return type(self)(resolved)",
  "    def is_file(self):",
  "        return True",
  "deep_scan.Path = SimulatedPath",
  "deep_scan.os = SimpleNamespace(path=path_module)",
  "deep_scan.require_canonical_scan_directory = lambda path: path",
  "try:",
  "    result = deep_scan.deep_scan_path({'scan_dir': root}, supplied, 'Worker prompt path', kind='file')",
  "except SystemExit:",
  "    accepted = False",
  "    result = None",
  "else:",
  "    accepted = True",
  "print(json.dumps({'accepted': accepted, 'nativePathEquality': path_type(supplied) == path_type(resolved), 'resolvedPath': result}))",
].join("\n");

const realFilesystemProbe = [
  "import json, sys",
  "from pathlib import Path",
  "sys.path.insert(0, sys.argv[1])",
  "import deep_scan_workbench as deep_scan",
  "import finalize_scan_contract as finalizer",
  "import workbench_db as workbench",
  "mode = sys.argv[2]",
  "scan_dir = Path(sys.argv[3])",
  "if mode == 'windows':",
  "    alias_scan_dir = Path(str(scan_dir).swapcase())",
  "    alias_directory = alias_scan_dir / 'pRoMpTs'",
  "    artifact_name = 'pRoMpTs/PrOmPt.TxT'",
  "    candidate_name = 'PrOmPt.TxT'",
  "else:",
  "    alias_scan_dir = Path(sys.argv[4])",
  "    alias_directory = scan_dir / 'prompts'",
  "    artifact_name = 'prompts/prompt.txt'",
  "    candidate_name = 'prompt.txt'",
  "deep_scan.require_canonical_scan_directory = workbench.require_canonical_scan_directory",
  "def accepted(action):",
  "    try:",
  "        action()",
  "    except (SystemExit, finalizer.ContractError):",
  "        return False",
  "    return True",
  "checks = {",
  "    'deepScanPath': accepted(lambda: deep_scan.deep_scan_path({'scan_dir': str(scan_dir)}, str(alias_directory / candidate_name), 'Worker prompt path', kind='file')),",
  "    'finalizerScanDirectory': accepted(lambda: finalizer._require_scan_directory(alias_scan_dir)),",
  "    'finalizerOutputParent': accepted(lambda: finalizer._validate_scan_local_output_path(scan_dir, alias_directory / 'output.json', f'{alias_directory.name}/output.json')),",
  "    'workbenchArtifact': accepted(lambda: workbench.artifact_path(scan_dir, artifact_name, required=True)),",
  "    'workbenchScanDirectory': accepted(lambda: workbench.require_canonical_scan_directory(alias_scan_dir)),",
  "}",
  "print(json.dumps(checks))",
].join("\n");

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

async function temporaryDirectory(): Promise<string> {
  const directory = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-canonical-paths-")),
  );
  temporaryDirectories.push(directory);
  return directory;
}

function runPythonProbe(
  program: string,
  ...args: string[]
): Record<string, unknown> {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  expect(python).not.toBeNull();
  if (python === null) {
    throw new Error(
      "A Python interpreter is required for workbench path tests.",
    );
  }

  const result = Bun.spawnSync(
    [python, "-I", "-B", "-c", program, join(PLUGIN_ROOT, "scripts"), ...args],
    { stdout: "pipe", stderr: "pipe" },
  );
  expect(new TextDecoder().decode(result.stderr)).toBe("");
  expect(result.exitCode).toBe(0);
  return JSON.parse(new TextDecoder().decode(result.stdout)) as Record<
    string,
    unknown
  >;
}

describe("bundled workbench canonical paths", () => {
  test("does not follow repository parent symlinks during inventory or snapshots", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const outside = join(root, "outside");
    await mkdir(repository);
    await mkdir(outside);
    await writeFile(join(outside, "private.py"), "private = True\n");
    await symlink(
      outside,
      join(repository, "linked"),
      process.platform === "win32" ? "junction" : "dir",
    );

    const result = runPythonProbe(
      [
        "import json, sys",
        "from pathlib import Path",
        "sys.path.insert(0, sys.argv[1])",
        "import generate_in_scope_files as inventory",
        "import generate_rank_input as ranking",
        "import rank_preview as previews",
        "import workbench_target as workbench",
        "repository = Path(sys.argv[2])",
        "output = Path(sys.argv[3])",
        "candidate = repository / 'linked' / 'private.py'",
        "ranking.git_changed_paths = lambda *_: [(candidate, 'M')]",
        "reads = []",
        "def preview(path, *_):",
        "    reads.append(path.read_text())",
        "    return '', False",
        "previews.preview_for = preview",
        "inventory.generate_diff_in_scope_files(repository, 'base', 'head', 'local-patch', output)",
        "workbench.git_output = lambda *_: str(repository)",
        "workbench.git_worktree_context = lambda _: (repository, '.')",
        "workbench.git_bytes = lambda *_: b'linked/private.py\\0'",
        "try:",
        "    workbench.git_directory_snapshot_paths(repository)",
        "except SystemExit:",
        "    snapshot_rejected = True",
        "else:",
        "    snapshot_rejected = False",
        "print(json.dumps({'inventory': output.read_text(), 'externalReads': reads, 'snapshotRejected': snapshot_rejected}))",
      ].join("\n"),
      repository,
      join(root, "inventory.txt"),
    );

    expect(result).toEqual({
      inventory: "",
      externalReads: [],
      snapshotRejected: true,
    });
  });

  testPosix(
    "rejects private scan directories under insecure shared parents",
    async () => {
      const root = await temporaryDirectory();
      const scanDirectory = join(root, "scan");
      await mkdir(scanDirectory, { mode: 0o700 });
      await chmod(root, 0o777);

      try {
        expect(
          runPythonProbe(
            [
              "import json, sys",
              "from pathlib import Path",
              "sys.path.insert(0, sys.argv[1])",
              "import workbench_db as workbench",
              "try:",
              "    workbench.require_canonical_scan_directory(Path(sys.argv[2]))",
              "except SystemExit as error:",
              "    print(json.dumps({'accepted': False, 'error': str(error)}))",
              "else:",
              "    print(json.dumps({'accepted': True}))",
            ].join("\n"),
            scanDirectory,
          ),
        ).toMatchObject({
          accepted: false,
          error: expect.stringContaining("sticky bit"),
        });
      } finally {
        await chmod(root, 0o700);
      }
    },
  );

  test("preserves native Windows case-insensitive path comparison", () => {
    expect(runPythonProbe(simulatedPathProbe, "windows")).toMatchObject({
      accepted: true,
      nativePathEquality: true,
    });
  });

  test("rejects case-differing POSIX symlink resolution", () => {
    expect(runPythonProbe(simulatedPathProbe, "posix")).toMatchObject({
      accepted: false,
      nativePathEquality: false,
    });
  });

  testCaseSensitive(
    "rejects case-differing symlinks at every workbench and finalizer boundary",
    async () => {
      const root = await temporaryDirectory();
      const parent = join(root, "Scans");
      const aliasParent = join(root, "scans");
      const scanDirectory = join(parent, "Scan");
      const promptDirectory = join(scanDirectory, "Prompts");
      await mkdir(promptDirectory, { recursive: true });
      await writeFile(join(promptDirectory, "prompt.txt"), "worker prompt\n");
      await symlink(parent, aliasParent, "dir");
      await symlink(promptDirectory, join(scanDirectory, "prompts"), "dir");

      expect(
        runPythonProbe(
          realFilesystemProbe,
          "posix",
          scanDirectory,
          join(aliasParent, "Scan"),
        ),
      ).toEqual({
        deepScanPath: false,
        finalizerScanDirectory: false,
        finalizerOutputParent: false,
        workbenchArtifact: false,
        workbenchScanDirectory: false,
      });
    },
  );

  testWindows(
    "accepts mixed-case Windows paths at every workbench and finalizer boundary",
    async () => {
      const root = await temporaryDirectory();
      const scanDirectory = join(root, "ScanRoot");
      const promptDirectory = join(scanDirectory, "Prompts");
      await mkdir(promptDirectory, { recursive: true });
      await writeFile(join(promptDirectory, "prompt.txt"), "worker prompt\n");

      expect(
        runPythonProbe(realFilesystemProbe, "windows", scanDirectory),
      ).toEqual({
        deepScanPath: true,
        finalizerScanDirectory: true,
        finalizerOutputParent: true,
        workbenchArtifact: true,
        workbenchScanDirectory: true,
      });
    },
  );
});

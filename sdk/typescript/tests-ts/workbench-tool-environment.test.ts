import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "bun:test";
import { inspectTrustedExecutable } from "../src/trusted-executable.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

function childEnvironment(path: string): NodeJS.ProcessEnv {
  return {
    PATH: path,
    ...(process.env["SystemRoot"] === undefined
      ? {}
      : { SystemRoot: process.env["SystemRoot"] }),
  };
}

function inspectPlatformEnvironment(
  platform: "linux" | "win32",
  environment: Record<string, string>,
) {
  const result = spawnSync(
    process.execPath,
    [
      "-e",
      `
        Object.defineProperty(process, "platform", { value: process.argv[1] });
        const { inspectTrustedExecutable } = await import(process.argv[2]);
        console.log(JSON.stringify(await inspectTrustedExecutable(
          "rg", JSON.parse(process.argv[3]), process.argv[4],
        )));
      `,
      platform,
      fileURLToPath(new URL("../src/trusted-executable.ts", import.meta.url)),
      JSON.stringify(environment),
      process.cwd(),
    ],
    {
      encoding: "utf8",
      env: childEnvironment(process.env["PATH"] ?? ""),
    },
  );
  expect(result.status, result.stderr).toBe(0);
  return JSON.parse(result.stdout) as {
    executable: string | null;
    environment: Record<string, string>;
  };
}

function runPythonMocks(source: string): void {
  const python = Bun.which("python3") ?? Bun.which("python");
  expect(python).not.toBeNull();
  const result = spawnSync(
    python!,
    [
      "-I",
      "-B",
      "-c",
      `
import argparse, io, json, os, subprocess, sys
from pathlib import Path
from unittest.mock import patch
os.environ.clear()
os.environ.update(json.loads(sys.argv[2]))
sys.path.insert(0, sys.argv[1])
import workbench_target as workbench
${source}
`,
      join(PLUGIN_ROOT, "scripts"),
      JSON.stringify(childEnvironment(dirname(python!))),
    ],
    { encoding: "utf8" },
  );
  expect(result.status, result.stderr).toBe(0);
}

describe("workbench tool environments", () => {
  test("preserves case-distinct POSIX environment keys", () => {
    const environment = {
      Path: "case-distinct value",
      pAtH: "another value",
      PATH: "",
      KEEP: "yes",
    };
    expect(inspectPlatformEnvironment("linux", environment)).toEqual({
      executable: null,
      environment,
    });
  });

  test("normalizes Windows PATH aliases using the effective key", () => {
    expect(
      inspectPlatformEnvironment("win32", {
        Path: "other value",
        pAtH: "another value",
        PATH: "",
        KEEP: "yes",
      }),
    ).toEqual({
      executable: null,
      environment: { KEEP: "yes", PATH: "" },
    });
  });

  test("keeps default lookup separate from an explicitly empty PATH", async () => {
    const defaultPath =
      process.platform === "win32"
        ? process.env["PATH"] ?? ""
        : "/usr/bin:/bin";
    const expected = await inspectTrustedExecutable(
      "rg",
      { KEEP: "yes", PATH: defaultPath },
      process.cwd(),
    );
    expect(
      await inspectTrustedExecutable("rg", { KEEP: "yes" }, process.cwd()),
    ).toEqual(expected);
    expect(
      await inspectTrustedExecutable(
        "rg",
        { KEEP: "yes", PATH: "" },
        process.cwd(),
      ),
    ).toEqual({
      executable: null,
      environment: { KEEP: "yes", PATH: "" },
    });
  });

  test("accepts extensionless bindings and quoted Windows tool paths", () => {
    runPythonMocks(`
import tempfile
with tempfile.TemporaryDirectory(prefix="workbench-tool-paths-") as temporary:
    root = Path(temporary).resolve()
    repository = root / "repository"
    directory = root / "tools with spaces"
    repository.mkdir()
    directory.mkdir()
    for name in ("git", "rg"):
        (directory / (name + ".exe")).write_bytes(b"synthetic native executable")
    (directory / "missing.com").write_bytes(b"synthetic native executable")
    with (
        patch.object(workbench.sys, "platform", "win32"),
        patch.object(workbench.subprocess, "run") as run,
    ):
        for name in ("git", "rg"):
            invocation = str(directory / name)
            setting = "CODEX_SECURITY_" + name.upper()
            assert workbench._trusted_executable(
                repository, {"PATH": "", setting: invocation}, name,
            ) == invocation
            environment = {"PATH": '"' + str(directory) + '"'}
            assert workbench._trusted_executable(
                repository, environment, name,
            ) == str(directory / (name + ".exe"))
            assert environment["PATH"] == str(directory)
            try:
                workbench._trusted_executable(
                    repository, {setting: str(directory / "missing")}, name,
                )
            except SystemExit:
                pass
            else:
                raise AssertionError("extensionless invocation incorrectly selected a .com file")
        run.assert_not_called()
`);
  });

  test("treats stale target roots as unavailable without hiding other errors", () => {
    runPythonMocks(`
import stat
from types import SimpleNamespace
repository = Path.cwd()
directory = SimpleNamespace(st_mode=stat.S_IFDIR)
with (
    patch.object(Path, "resolve", autospec=True, return_value=repository) as resolve,
    patch.object(Path, "stat", return_value=directory) as metadata,
    patch.object(Path, "lstat", side_effect=FileNotFoundError) as marker,
):
    assert workbench._protected_git_root(repository) == repository
    resolve.assert_called_once_with(repository, strict=True)

    metadata.return_value = SimpleNamespace(st_mode=stat.S_IFREG)
    marker.reset_mock()
    assert workbench._protected_git_root(repository) is None
    marker.assert_not_called()
    metadata.return_value = directory

    for error in (FileNotFoundError, NotADirectoryError):
        for operation in (resolve, metadata):
            operation.side_effect = error
            assert workbench._protected_git_root(repository) is None
            operation.side_effect = None
    marker.side_effect = NotADirectoryError
    assert workbench._protected_git_root(repository) is None

    for operation in (resolve, metadata, marker):
        marker.side_effect = FileNotFoundError
        failure = PermissionError("target metadata is unavailable")
        operation.side_effect = failure
        try:
            workbench._protected_git_root(repository)
        except PermissionError as error:
            assert error is failure
        else:
            raise AssertionError("unrelated filesystem error was hidden")
        operation.side_effect = None
`);
  });

  test("keeps stale history probes unavailable without spawning a tool", () => {
    runPythonMocks(`
import workbench_scan_history as history
repository = Path.cwd()
before = {"target_id": "historical", "target_path": str(repository)}
after = {"target_id": "selected", "target_path": str(repository.parent)}
with (
    patch.object(workbench, "_protected_git_root", return_value=None),
    patch.object(workbench, "_inside_protected_git_root") as inside,
    patch.object(workbench.os, "get_exec_path") as lookup,
    patch.object(workbench.subprocess, "run") as run,
):
    for environment in (
        {"PATH": ""},
        {"PATH": "", "CODEX_SECURITY_GIT": sys.executable, "CODEX_SECURITY_RG": sys.executable},
    ):
        with patch.dict(workbench.os.environ, environment, clear=True):
            completed = workbench.git_command(repository, "rev-parse", "--show-toplevel", text=True)
            assert (completed.returncode, completed.stdout, completed.stderr) == (127, "", "")
            assert workbench.git_output(repository, "rev-parse", "--git-common-dir") is None
            assert workbench.git_bytes(repository, "rev-parse", "--git-common-dir") is None
            assert not history._same_repository(before, after, after_identity=(None, None))
            try:
                workbench.ripgrep_command(repository, "--files")
            except FileNotFoundError:
                pass
            else:
                raise AssertionError("unavailable target was accepted")
    inside.assert_not_called()
    lookup.assert_not_called()
    run.assert_not_called()
`);
  });

  test("uses only a resolved ripgrep command and never spawns when unavailable", () => {
    runPythonMocks(`
repository = Path.cwd()
directory = Path(sys.executable).parent
executable = directory / ("rg.exe" if sys.platform == "win32" else "rg")
completed = subprocess.CompletedProcess([str(executable)], 0, b"", b"")
with (
    patch.object(workbench, "_protected_git_root", return_value=repository),
    patch.object(Path, "resolve", autospec=True, side_effect=lambda path, strict=False: path),
    patch.object(workbench, "_inside_protected_git_root", return_value=False),
    patch.object(workbench, "_is_native_executable", side_effect=lambda path, canonical: path == executable),
    patch.object(workbench.subprocess, "run", return_value=completed) as run,
):
    for environment in (
        {"PATH": str(directory)},
        {"PATH": "", "CODEX_SECURITY_RG": str(executable)},
    ):
        with patch.dict(workbench.os.environ, environment, clear=True):
            assert workbench.ripgrep_command(repository, "--files") is completed
        assert run.call_args.args[0] == [str(executable), "--files"]
        assert Path(run.call_args.args[0][0]).is_absolute()
        assert run.call_args.kwargs["cwd"] == repository
        assert run.call_args.kwargs["env"]["PATH"] == environment["PATH"]

    run.reset_mock()
    for environment in (
        {"PATH": ""},
        {"PATH": str(directory), "CODEX_SECURITY_RG": ""},
    ):
        with patch.dict(workbench.os.environ, environment, clear=True):
            try:
                workbench.ripgrep_command(repository, "--files")
            except FileNotFoundError:
                pass
            else:
                raise AssertionError("unavailable ripgrep was accepted")
    run.assert_not_called()
`);
  });

  test("applies platform-specific PATH names in the Python resolver", () => {
    runPythonMocks(`
repository = Path.cwd()
original = {"Path": "case-distinct value", "pAtH": "another value", "PATH": "", "KEEP": "yes"}
with patch.object(workbench, "_protected_git_root", return_value=repository):
    for platform in ("linux", "win32"):
        environment = dict(original)
        with patch.object(workbench.sys, "platform", platform):
            assert workbench._trusted_executable(repository, environment, "rg") is None
        expected = original if platform == "linux" else {"PATH": "", "KEEP": "yes"}
        assert environment == expected
`);
  });

  test("routes inventory and scoped ranking through the unavailable-tool guard", () => {
    runPythonMocks(`
import generate_in_scope_files as inventory
import generate_rank_input as ranking
repository = Path.cwd().resolve()
with (
    patch.object(workbench, "_trusted_executable", return_value=None) as resolve,
    patch.object(workbench.subprocess, "run") as run,
    patch.dict(workbench.os.environ, {"PATH": ""}, clear=True),
):
    with patch.object(inventory.tempfile, "TemporaryFile", return_value=io.BytesIO()):
        try:
            inventory.generate_in_scope_files(repository, ".", Path("unused-inventory"))
        except inventory.InventoryError:
            pass
        else:
            raise AssertionError("unavailable inventory tool was accepted")

    with (
        patch.object(Path, "is_dir", return_value=True),
        patch.object(Path, "is_file", return_value=False),
        patch.object(Path, "exists", return_value=False),
        patch.object(Path, "rglob", return_value=()),
        patch.object(ranking, "load_scopes_file", return_value=["."]),
        patch.object(ranking, "resolve_scope", return_value=repository),
        patch.object(ranking, "git_directory_snapshot_paths", return_value=None),
        patch.object(ranking, "write_jsonl") as write,
        patch("builtins.print"),
    ):
        ranking.make_repo_scope_input(argparse.Namespace(
            repo=str(repository), scopes_file="unused-scopes", out="unused-ranking",
        ))
        write.assert_called_once_with(Path("unused-ranking"), [])
    assert resolve.call_count == 2
    run.assert_not_called()
`);
  });

  test("forwards both trusted tool bindings to the MCP host", () => {
    const configuration = JSON.parse(
      readFileSync(join(PLUGIN_ROOT, ".mcp.json"), "utf8"),
    ) as { mcpServers: Record<string, { env_vars: string[] }> };
    expect(configuration.mcpServers["codex-security"]!.env_vars).toEqual(
      expect.arrayContaining(["CODEX_SECURITY_GIT", "CODEX_SECURITY_RG"]),
    );
  });
});

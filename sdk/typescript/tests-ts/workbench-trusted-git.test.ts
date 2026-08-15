import { execFileSync, spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import type { CodexOptions } from "@openai/codex-sdk";
import { afterEach, describe, expect, test } from "bun:test";
import { CodexSecurity } from "../src/api.js";
import { resolvePluginPython, runWorkbench } from "../src/runtime.js";
import { trustedExecutableEnvironment } from "../src/trusted-executable.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { preparedRuntime } from "./support/api-events.js";

const roots: string[] = [];
const testPosix = process.platform === "win32" ? test.skip : test;
const statusProbe = ["git_command(Path(sys.argv[2]), 'status', text=True)"];
const unsafeExecutable = "must stay outside the protected repository";
const TestClient = CodexSecurity as unknown as new (
  config: Record<string, unknown>,
  dependencies: Record<string, unknown>,
) => CodexSecurity;

afterEach(() => {
  for (const root of roots.splice(0)) {
    const exfiltrated = existsSync(join(root, "exfiltrated-credential"));
    rmSync(root, { recursive: true, force: true });
    expect(exfiltrated).toBe(false);
  }
});

function fixture() {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "trusted-git-")));
  roots.push(root);
  const repository = join(root, "repository");
  const shimDirectory = join(repository, "node_modules", ".bin");
  mkdirSync(shimDirectory, { recursive: true });
  const shim = join(
    shimDirectory,
    process.platform === "win32" ? "git.exe" : "git",
  );
  writeFileSync(
    shim,
    '#!/bin/sh\nprintf "%s" "$GITHUB_TOKEN" > "$CODEX_SECURITY_TEST_MARKER"\nexit 1\n',
    { mode: 0o700 },
  );
  const git = Bun.which("git");
  const python = Bun.which("python3") ?? Bun.which("python");
  expect(git).not.toBeNull();
  expect(python).not.toBeNull();
  return {
    root,
    repository,
    shim,
    git: git!,
    python: python!,
    environment: {
      HOME: root,
      USERPROFILE: root,
      ...(process.env["SystemRoot"] === undefined
        ? {}
        : { SystemRoot: process.env["SystemRoot"] }),
      PATH: `${shimDirectory}${delimiter}${dirname(git!)}`,
      GITHUB_TOKEN: "synthetic-github-credential",
      CODEX_SECURITY_TEST_MARKER: join(root, "exfiltrated-credential"),
      GIT_CONFIG_COUNT: "1",
      GIT_CONFIG_KEY_0: "codexsecurity.synthetic",
      GIT_CONFIG_VALUE_0: "operator-config-preserved",
      PYTHONDONTWRITEBYTECODE: "1",
    },
  };
}

function git(
  target: ReturnType<typeof fixture>,
  directory: string,
  ...args: string[]
) {
  return execFileSync(
    target.git,
    ["-C", directory, "-c", "user.name=x", "-c", "user.email=x@y", ...args],
    { encoding: "utf8" },
  ).trim();
}

function probe(
  target: ReturnType<typeof fixture>,
  source: readonly string[],
  options: {
    repository?: string;
    environment?: NodeJS.ProcessEnv;
  } = {},
) {
  return spawnSync(
    target.python,
    [
      "-I",
      "-B",
      "-c",
      [
        "import json, sys; from pathlib import Path",
        "sys.path.insert(0, sys.argv[1]); from workbench_target import git_command",
        ...source,
      ].join("\n"),
      join(PLUGIN_ROOT, "scripts"),
      options.repository ?? target.repository,
    ],
    {
      encoding: "utf8",
      env: { ...target.environment, ...options.environment },
      cwd: target.repository,
    },
  );
}

describe("bundled workbench trusted Git", () => {
  testPosix("avoids repository shims and preserves user Git settings", () => {
    const target = fixture();
    git(target, target.repository, "init", "-q");
    const nested = join(target.repository, "src", "nested");
    mkdirSync(nested, { recursive: true });

    for (const [repository, environment] of [
      [target.repository, { CODEX_SECURITY_GIT: target.git }],
      [nested, {}],
    ] as const) {
      const result = probe(
        target,
        [
          "result = git_command(Path(sys.argv[2]), 'config', '--get', 'codexsecurity.synthetic', text=True)",
          "print(json.dumps({'git': result.args[0], 'value': result.stdout.strip(), 'status': result.returncode}))",
        ],
        { repository, environment },
      );
      expect(result.status, result.stderr).toBe(0);
      expect(JSON.parse(result.stdout)).toMatchObject({
        value: "operator-config-preserved",
        status: 0,
      });
      expect(realpathSync(JSON.parse(result.stdout).git)).toBe(
        realpathSync(target.git),
      );
    }

    const uppercaseRepository = join(target.root, "REPOSITORY");
    if (existsSync(uppercaseRepository)) {
      const repositoryIdentity = statSync(target.repository);
      const uppercaseIdentity = statSync(uppercaseRepository);
      if (
        repositoryIdentity.dev === uppercaseIdentity.dev &&
        repositoryIdentity.ino === uppercaseIdentity.ino
      ) {
        const unsafeDirectory = join(
          uppercaseRepository,
          "node_modules",
          ".bin",
        );
        const externalAlias = join(target.root, "casefold-alias-bin");
        mkdirSync(externalAlias);
        symlinkSync(join(unsafeDirectory, "git"), join(externalAlias, "git"));
        const result = probe(
          target,
          [
            "import os, workbench_target",
            "environment = dict(os.environ)",
            "selected = workbench_target._trusted_git_executable(Path(sys.argv[2]), environment)",
            "result = git_command(Path(sys.argv[2]), 'config', '--get', 'codexsecurity.synthetic', text=True)",
            "print(json.dumps({'configured': 'CODEX_SECURITY_GIT' in os.environ, 'git': result.args[0], 'selected': selected, 'path': environment['PATH'], 'status': result.returncode, 'value': result.stdout.strip()}))",
          ],
          {
            environment: {
              PATH: [unsafeDirectory, externalAlias, dirname(target.git)].join(
                delimiter,
              ),
            },
          },
        );
        expect(result.status, result.stderr).toBe(0);
        expect(JSON.parse(result.stdout)).toEqual({
          configured: false,
          git: target.git,
          selected: target.git,
          path: dirname(target.git),
          status: 0,
          value: "operator-config-preserved",
        });
      }
    }
  });

  test("keeps Git optional when no trusted executable exists", () => {
    const target = fixture();
    const result = probe(
      target,
      [
        "result = git_command(Path(sys.argv[2]), 'status', text=True)",
        "print(json.dumps({'status': result.returncode, 'output': result.stdout}))",
      ],
      { environment: { CODEX_SECURITY_GIT: "" } },
    );
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({ status: 127, output: "" });
  });

  test("preserves absent PATH while clearing explicitly unsafe PATH", async () => {
    const target = fixture();
    const missing = await trustedExecutableEnvironment(
      "git",
      { HOME: target.root },
      target.repository,
    );
    expect(missing).not.toHaveProperty("PATH");

    const undefinedPath = await trustedExecutableEnvironment(
      "git",
      { HOME: target.root, PATH: undefined },
      target.repository,
    );
    expect(undefinedPath["PATH"]).toBeUndefined();

    const unsafe = await trustedExecutableEnvironment(
      "git",
      { HOME: target.root, PATH: dirname(target.shim) },
      target.repository,
    );
    expect(unsafe["PATH"]).toBe("");
  });

  test("rejects explicitly selected repository-controlled Git", () => {
    const target = fixture();
    const result = probe(target, statusProbe, {
      environment: { CODEX_SECURITY_GIT: target.shim },
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(unsafeExecutable);
  });

  testPosix("preserves trusted multicall Git symlink invocation", () => {
    const target = fixture();
    const trustedDirectory = join(target.root, "trusted-bin");
    mkdirSync(trustedDirectory);
    const multicall = join(trustedDirectory, "multicall");
    const invocation = join(trustedDirectory, "git");
    writeFileSync(
      multicall,
      '#!/bin/sh\ncase "$0" in */git) printf "%s" "$0";; *) exit 23;; esac\n',
      { mode: 0o700 },
    );
    symlinkSync(multicall, invocation);

    const result = probe(
      target,
      [
        "result = git_command(Path(sys.argv[2]), 'status', text=True)",
        "print(json.dumps({'git': result.args[0], 'invocation': result.stdout, 'status': result.returncode}))",
      ],
      { environment: { CODEX_SECURITY_GIT: invocation } },
    );
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({
      git: invocation,
      invocation,
      status: 0,
    });
  });

  testPosix("rejects repository symlinks and aliased parents", () => {
    const target = fixture();
    const linkedGit = join(target.repository, "safe-looking-git");
    const repositoryAlias = join(target.root, "repository-alias");
    const externalAlias = join(target.root, "external-git");
    const repositoryOwnedLink = join(target.repository, "trusted-link");
    const outside = join(target.root, "outside");
    mkdirSync(outside);
    symlinkSync(target.git, linkedGit);
    symlinkSync(target.repository, repositoryAlias, "junction");
    symlinkSync(target.shim, externalAlias);
    symlinkSync(dirname(target.git), repositoryOwnedLink, "junction");
    const rawRepositoryAlias = join(outside, "repo-alias");
    symlinkSync(target.repository, rawRepositoryAlias, "junction");
    for (const directory of [target.root, outside]) {
      symlinkSync(
        dirname(target.git),
        join(directory, "escaped-bin"),
        "junction",
      );
    }

    const aliases = [
      linkedGit,
      join(repositoryAlias, "safe-looking-git"),
      externalAlias,
      join(repositoryOwnedLink, "git"),
      join(repositoryAlias, "trusted-link", "git"),
      `${outside}/../repository/trusted-link/git`,
      `${rawRepositoryAlias}/../escaped-bin/git`,
    ];
    const mixedCaseAlias = join(
      target.root,
      "REPOSITORY",
      "trusted-link",
      "git",
    );
    if (existsSync(mixedCaseAlias)) {
      const repositoryIdentity = statSync(target.repository);
      const aliasIdentity = statSync(join(target.root, "REPOSITORY"));
      if (
        repositoryIdentity.dev === aliasIdentity.dev &&
        repositoryIdentity.ino === aliasIdentity.ino
      ) {
        aliases.push(mixedCaseAlias);
        const mixedCaseExternal = join(outside, "case-git");
        symlinkSync(
          join(target.root, "REPOSITORY", "node_modules", ".bin", "git"),
          mixedCaseExternal,
        );
        aliases.push(mixedCaseExternal);
        const nested = join(target.repository, "nested");
        mkdirSync(nested);
        symlinkSync(dirname(target.git), join(nested, "escape"), "junction");
        const nestedAlias = join(outside, "nested-alias");
        symlinkSync(join(target.root, "REPOSITORY", "nested"), nestedAlias);
        aliases.push(join(nestedAlias, "escape", "git"));
      }
    }
    for (const executable of aliases) {
      const result = probe(target, statusProbe, {
        environment: { CODEX_SECURITY_GIT: executable },
      });
      expect(result.status).toBe(1);
      expect(result.stderr).toContain(unsafeExecutable);
    }
  });

  test("ignores Windows batch shims, PATHEXT order, and the working directory", () => {
    const target = fixture();
    const trustedDirectory = join(target.root, "trusted-bin");
    mkdirSync(trustedDirectory);
    const executable = join(trustedDirectory, "git.exe");
    writeFileSync(executable, "synthetic native executable\n");
    for (const directory of [trustedDirectory, target.repository]) {
      writeFileSync(join(directory, "git.cmd"), "synthetic batch shim\n");
    }
    const result = probe(
      target,
      [
        "import os, workbench_target",
        "workbench_target.sys.platform = 'win32'",
        "selected = workbench_target._trusted_git_executable(Path(sys.argv[2]), dict(os.environ))",
        "batch = Path(sys.argv[2]).parent / 'trusted-bin' / 'git.cmd'",
        "try: workbench_target._trusted_git_executable(Path(sys.argv[2]), {**os.environ, 'CODEX_SECURITY_GIT': str(batch)})",
        "except SystemExit: batch_rejected = True",
        "else: batch_rejected = False",
        "print(json.dumps({'executable': selected, 'batchRejected': batch_rejected}))",
      ],
      {
        environment: { PATH: trustedDirectory, PATHEXT: ".CMD;.BAT;.EXE;.COM" },
      },
    );
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({
      executable,
      batchRejected: true,
    });
  });

  testPosix(
    "accepts Windows Git aliases to extensionless executables, not batch files",
    () => {
      const target = fixture();
      const trustedDirectory = join(target.root, "trusted-bin");
      mkdirSync(trustedDirectory);
      const multicall = join(trustedDirectory, "multicall");
      const executable = join(trustedDirectory, "git.exe");
      const batch = join(trustedDirectory, "git.cmd");
      const batchAlias = join(trustedDirectory, "batch.exe");
      writeFileSync(multicall, "synthetic native executable\n");
      writeFileSync(batch, "synthetic batch shim\n");
      symlinkSync(multicall, executable);
      symlinkSync(batch, batchAlias);

      const result = probe(
        target,
        [
          "import os, workbench_target",
          "workbench_target.sys.platform = 'win32'",
          "root = Path(sys.argv[2]).parent / 'trusted-bin'",
          "selected = workbench_target._trusted_git_executable(Path(sys.argv[2]), dict(os.environ))",
          "configured = workbench_target._trusted_git_executable(Path(sys.argv[2]), {**os.environ, 'CODEX_SECURITY_GIT': str(root / 'git.exe')})",
          "try: workbench_target._trusted_git_executable(Path(sys.argv[2]), {**os.environ, 'CODEX_SECURITY_GIT': str(root / 'batch.exe')})",
          "except SystemExit: batch_rejected = True",
          "else: batch_rejected = False",
          "print(json.dumps({'executable': selected, 'configured': configured, 'batchRejected': batch_rejected}))",
        ],
        { environment: { PATH: trustedDirectory } },
      );
      expect(result.status, result.stderr).toBe(0);
      expect(JSON.parse(result.stdout)).toEqual({
        executable,
        configured: executable,
        batchRejected: true,
      });
    },
  );

  testPosix(
    "uses trusted Git for real diff ranking and committed inventory",
    () => {
      const target = fixture();
      git(target, target.repository, "init", "-q");
      writeFileSync(join(target.repository, "source.py"), "before = True\n");
      git(target, target.repository, "add", "source.py");
      git(target, target.repository, "commit", "-qm", "base");
      const revision = git(target, target.repository, "rev-parse", "HEAD");
      writeFileSync(join(target.repository, "source.py"), "after = True\n");
      const output = join(target.root, "rank-input.jsonl");
      const revisionArgs = ["--base", revision, "--head", revision];
      const environment = {
        ...target.environment,
        CODEX_SECURITY_GIT: target.git,
      };
      const result = spawnSync(
        target.python,
        [
          "-I",
          "-B",
          join(PLUGIN_ROOT, "scripts", "generate_rank_input.py"),
          "make-diff-rank-input",
          "--repo",
          target.repository,
          ...revisionArgs,
          "--mode",
          "local-patch",
          "--out",
          output,
        ],
        { encoding: "utf8", env: environment },
      );
      expect(result.status, result.stderr).toBe(0);
      expect(JSON.parse(readFileSync(output, "utf8"))).toMatchObject({
        path: "source.py",
      });

      git(target, target.repository, "add", "source.py");
      git(target, target.repository, "commit", "-qm", "head");
      const inventoryPath = join(target.root, "in-scope-files.txt");
      const inventory = spawnSync(
        target.python,
        [
          "-I",
          "-B",
          join(PLUGIN_ROOT, "scripts", "generate_in_scope_files.py"),
          "--repo",
          target.repository,
          "--scope",
          ".",
          "--diff-base",
          revision,
          "--diff-head",
          "HEAD",
          "--out",
          inventoryPath,
        ],
        { encoding: "utf8", env: environment },
      );
      expect(inventory.status, inventory.stderr).toBe(0);
      expect(readFileSync(inventoryPath, "utf8")).toBe("source.py\n");
    },
  );

  testPosix(
    "keeps core.worktree redirection from trusting scanned repository aliases",
    async () => {
      const target = fixture();
      git(target, target.repository, "init", "-q");
      const redirectedRoot = join(target.root, "redirected-worktree");
      mkdirSync(redirectedRoot);
      git(target, target.repository, "config", "core.worktree", redirectedRoot);
      expect(
        git(target, target.repository, "rev-parse", "--show-toplevel"),
      ).toBe(redirectedRoot);
      writeFileSync(join(target.repository, "source.py"), "value = 1\n");

      const unsafeDirectory = dirname(target.shim);
      const repositoryRipgrep = join(unsafeDirectory, "rg");
      const repositoryPython = join(unsafeDirectory, "python");
      writeFileSync(repositoryRipgrep, readFileSync(target.shim), {
        mode: 0o700,
      });
      writeFileSync(repositoryPython, readFileSync(target.shim), {
        mode: 0o700,
      });
      const gitAlias = join(target.root, "git-alias-bin");
      const ripgrepAlias = join(target.root, "rg-alias-bin");
      const safeRipgrep = join(target.root, "trusted-rg-bin");
      const codexHome = join(target.root, "codex-home");
      for (const directory of [
        gitAlias,
        ripgrepAlias,
        safeRipgrep,
        codexHome,
      ]) {
        mkdirSync(directory);
      }
      symlinkSync(target.shim, join(gitAlias, "git"));
      symlinkSync(repositoryRipgrep, join(ripgrepAlias, "rg"));
      writeFileSync(
        join(safeRipgrep, "rg"),
        '#!/bin/sh\nprintf "source.py\\n"\n',
        { mode: 0o700 },
      );
      const environment = {
        ...target.environment,
        CODEX_SECURITY_STATE_DIR: join(target.root, "state"),
        PATH: [
          unsafeDirectory,
          gitAlias,
          ripgrepAlias,
          safeRipgrep,
          dirname(target.git),
        ].join(delimiter),
      };
      const observed: Array<Record<string, string | undefined>> = [];
      let pythonProtectedRoot: string | undefined;
      const client = new TestClient(
        {},
        {
          environment,
          prepareRuntime: async () => ({
            ...preparedRuntime(codexHome),
            environment,
          }),
          resolvePluginPython: async (options: { protectedRoot?: string }) => {
            pythonProtectedRoot = options.protectedRoot;
            return target.python;
          },
          repositoryRevision: async () => null,
          runWorkbench: async (...args: Parameters<typeof runWorkbench>) => {
            observed.push(args[0].environment);
            throw new Error("captured redirected-worktree environment");
          },
        },
      );
      try {
        await expect(
          client.preflight(target.repository, {
            outputDir: join(target.repository, "scan-output"),
          }),
        ).rejects.toThrow("outside");
        await expect(
          client.run(target.repository, {
            outputDir: join(target.root, "scan"),
          }),
        ).rejects.toThrow("captured redirected-worktree environment");
      } finally {
        await client.close();
      }

      expect(observed.length).toBe(1);
      expect(pythonProtectedRoot).toBe(target.repository);
      await expect(
        resolvePluginPython({
          configuredPath: repositoryPython,
          environment,
          protectedRoot: pythonProtectedRoot,
        }),
      ).rejects.toThrow();
      for (const candidate of observed) {
        expect(candidate["CODEX_SECURITY_GIT"]).toBe(target.git);
        expect(candidate["PATH"]?.split(delimiter)).toEqual([
          safeRipgrep,
          dirname(target.git),
        ]);
      }
      const trustedGit = spawnSync("git", ["--version"], {
        encoding: "utf8",
        env: observed[0],
      });
      expect(trustedGit.status, trustedGit.stderr).toBe(0);

      const inventoryPath = join(target.root, "inventory.txt");
      const inventory = spawnSync(
        target.python,
        [
          "-I",
          "-B",
          join(PLUGIN_ROOT, "scripts", "generate_in_scope_files.py"),
          "--repo",
          target.repository,
          "--scope",
          ".",
          "--out",
          inventoryPath,
        ],
        { encoding: "utf8", env: observed[0] },
      );
      expect(inventory.status, inventory.stderr).toBe(0);
      expect(readFileSync(inventoryPath, "utf8")).toBe("source.py\n");
    },
  );

  testPosix(
    "keeps optional-Git scans safe from repository Git and ripgrep aliases",
    async () => {
      const target = fixture();
      writeFileSync(join(target.repository, "source.py"), "value = 1\n");
      const unsafeDirectory = dirname(target.shim);
      const repositoryRipgrep = join(unsafeDirectory, "rg");
      writeFileSync(repositoryRipgrep, readFileSync(target.shim), {
        mode: 0o700,
      });
      const gitAliasDirectory = join(target.root, "git-alias-bin");
      const aliasDirectory = join(target.root, "alias-bin");
      const safeDirectory = join(target.root, "trusted-bin");
      const codexHome = join(target.root, "codex-home");
      for (const directory of [
        gitAliasDirectory,
        aliasDirectory,
        safeDirectory,
        codexHome,
      ]) {
        mkdirSync(directory);
      }
      symlinkSync(target.shim, join(gitAliasDirectory, "git"));
      symlinkSync(repositoryRipgrep, join(aliasDirectory, "rg"));
      writeFileSync(
        join(safeDirectory, "rg"),
        '#!/bin/sh\nprintf "source.py\\n"\n',
        { mode: 0o700 },
      );
      const environment = {
        ...target.environment,
        CODEX_SECURITY_STATE_DIR: join(target.root, "state"),
        PATH: [
          unsafeDirectory,
          gitAliasDirectory,
          aliasDirectory,
          safeDirectory,
        ].join(delimiter),
      };
      const observed: Array<Record<string, string | undefined>> = [];
      const client = new TestClient(
        {},
        {
          environment,
          prepareRuntime: async () => ({
            ...preparedRuntime(codexHome),
            environment,
          }),
          resolvePluginPython: async () => target.python,
          repositoryRevision: async () => null,
          runWorkbench: async (...args: Parameters<typeof runWorkbench>) => {
            observed.push(args[0].environment);
            return await runWorkbench(...args);
          },
          createCodex: (options: CodexOptions) => {
            observed.push(options.env ?? {});
            throw new Error("captured optional-Git environment");
          },
        },
      );
      try {
        await expect(
          client.run(target.repository, {
            outputDir: join(target.root, "scan"),
          }),
        ).rejects.toThrow("captured optional-Git environment");
      } finally {
        await client.close();
      }

      expect(observed.length).toBeGreaterThan(1);
      const unexpectedGit = spawnSync("git", ["--version"], {
        encoding: "utf8",
        env: observed[0],
      });
      expect(unexpectedGit.error).toMatchObject({ code: "ENOENT" });
      for (const candidate of observed) {
        expect(candidate["CODEX_SECURITY_GIT"]).toBe("");
        expect(candidate["PATH"]?.split(delimiter)).toEqual([safeDirectory]);
      }
      const output = join(target.root, "inventory.txt");
      const inventory = spawnSync(
        target.python,
        [
          "-I",
          "-B",
          join(PLUGIN_ROOT, "scripts", "generate_in_scope_files.py"),
          "--repo",
          target.repository,
          "--scope",
          ".",
          "--out",
          output,
        ],
        { encoding: "utf8", env: observed[0] },
      );
      expect(inventory.status, inventory.stderr).toBe(0);
      expect(readFileSync(output, "utf8")).toBe("source.py\n");
    },
  );

  testPosix(
    "propagates outermost-root trusted Git through SDK, workbench, and MCP",
    async () => {
      const target = fixture();
      git(target, target.repository, "init", "-q");
      const nested = join(target.repository, "submodule");
      mkdirSync(nested);
      git(target, nested, "init", "-q");
      writeFileSync(join(nested, "source.py"), "value = 1\n");
      git(target, nested, "add", "source.py");
      git(target, nested, "commit", "-qm", "base");
      const revision = git(target, nested, "rev-parse", "HEAD");
      const codexHome = join(target.root, "codex-home");
      mkdirSync(codexHome);
      const aliasDirectory = join(target.root, "alias-bin");
      mkdirSync(aliasDirectory);
      symlinkSync(target.shim, join(aliasDirectory, "rg"));
      const environment = {
        ...target.environment,
        CODEX_SECURITY_STATE_DIR: join(target.root, "state"),
        PATH: [dirname(target.shim), aliasDirectory, dirname(target.git)].join(
          delimiter,
        ),
      };
      const environments: Array<Record<string, string | undefined>> = [];
      const client = new TestClient(
        {},
        {
          environment,
          prepareRuntime: async () => ({
            ...preparedRuntime(codexHome),
            environment,
          }),
          resolvePluginPython: async () => target.python,
          repositoryRevision: async () => revision,
          runWorkbench: async (...args: Parameters<typeof runWorkbench>) => {
            environments.push(args[0].environment);
            return await runWorkbench(...args);
          },
          createCodex: (options: CodexOptions) => {
            environments.push(options.env ?? {});
            throw new Error("captured scan environment");
          },
        },
      );

      try {
        await expect(
          client.run(nested, { outputDir: join(target.root, "scan") }),
        ).rejects.toThrow("captured scan environment");
      } finally {
        await client.close();
      }

      expect(environments.length).toBeGreaterThan(1);
      for (const observed of environments) {
        expect(observed).toMatchObject({
          CODEX_SECURITY_GIT: target.git,
          GIT_CONFIG_COUNT: "1",
          GIT_CONFIG_KEY_0: "codexsecurity.synthetic",
          GIT_CONFIG_VALUE_0: "operator-config-preserved",
        });
        expect(observed?.["PATH"]?.split(delimiter)).not.toContain(
          dirname(target.shim),
        );
        expect(observed?.["PATH"]?.split(delimiter)).not.toContain(
          aliasDirectory,
        );
      }

      const configuration = JSON.parse(
        readFileSync(join(PLUGIN_ROOT, ".mcp.json"), "utf8"),
      ) as {
        mcpServers: Record<string, { env_vars: string[] }>;
      };
      const allowed = configuration.mcpServers["codex-security"]!.env_vars;
      const mcpEnvironment = Object.fromEntries(
        Object.entries(environments.at(-1) ?? {}).filter(([name]) =>
          allowed.includes(name),
        ),
      );
      expect(mcpEnvironment).toMatchObject({ CODEX_SECURITY_GIT: target.git });
    },
  );
});

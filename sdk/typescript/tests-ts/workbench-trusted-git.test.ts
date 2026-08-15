import { execFileSync, spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import type { CodexOptions } from "@openai/codex-sdk";
import { afterEach, describe, expect, test } from "bun:test";
import { CodexSecurity } from "../src/api.js";
import { runWorkbench } from "../src/runtime.js";
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

  test("rejects explicitly selected repository-controlled Git", () => {
    const target = fixture();
    const result = probe(target, statusProbe, {
      environment: { CODEX_SECURITY_GIT: target.shim },
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(unsafeExecutable);
  });

  testPosix("rejects repository symlinks and aliased parents", () => {
    const target = fixture();
    const linkedGit = join(target.repository, "safe-looking-git");
    const repositoryAlias = join(target.root, "repository-alias");
    symlinkSync(target.git, linkedGit);
    symlinkSync(target.repository, repositoryAlias, "junction");

    const aliases = [linkedGit, join(repositoryAlias, "safe-looking-git")];
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
    "keeps optional-Git scans and real inventory safe from repository ripgrep",
    async () => {
      const target = fixture();
      writeFileSync(join(target.repository, "source.py"), "value = 1\n");
      const unsafeDirectory = dirname(target.shim);
      const repositoryRipgrep = join(unsafeDirectory, "rg");
      writeFileSync(repositoryRipgrep, readFileSync(target.shim), {
        mode: 0o700,
      });
      const aliasDirectory = join(target.root, "alias-bin");
      const safeDirectory = join(target.root, "trusted-bin");
      const codexHome = join(target.root, "codex-home");
      for (const directory of [aliasDirectory, safeDirectory, codexHome]) {
        mkdirSync(directory);
      }
      symlinkSync(repositoryRipgrep, join(aliasDirectory, "rg"));
      writeFileSync(
        join(safeDirectory, "rg"),
        '#!/bin/sh\nprintf "source.py\\n"\n',
        { mode: 0o700 },
      );
      const environment = {
        ...target.environment,
        CODEX_SECURITY_STATE_DIR: join(target.root, "state"),
        PATH: [unsafeDirectory, aliasDirectory, safeDirectory].join(delimiter),
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

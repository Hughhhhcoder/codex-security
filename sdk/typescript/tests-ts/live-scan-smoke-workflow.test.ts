import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "bun:test";

const workflow = readFileSync(
  new URL("../../../.github/workflows/node-ci.yml", import.meta.url),
  "utf8",
);
const smokeWorkflow = readFileSync(
  new URL("../../../.github/workflows/live-scan-smoke.yml", import.meta.url),
  "utf8",
);

const gateMatch = /^\s{10}script: \|\n([\s\S]*?)(?=^  test:)/mu.exec(workflow);

if (gateMatch?.[1] === undefined) {
  throw new Error("The bundled MCP smoke-test gate is missing.");
}

const gateScript = gateMatch[1]
  .split("\n")
  .map((line) => (line.startsWith("            ") ? line.slice(12) : line))
  .join("\n");

const runGate = new Function(
  "github",
  "core",
  "context",
  `return (async () => {\n${gateScript}\n})();`,
) as (
  github: MockGithub,
  core: MockCore,
  context: MockContext,
) => Promise<void>;

interface ChangedFile {
  filename: string;
  previous_filename?: string;
}

interface CommitStatus {
  context: string;
  state: string;
}

interface MockGithub {
  rest: {
    pulls: { listFiles: symbol };
    repos: { listCommitStatusesForRef: symbol };
  };
  paginate: (
    endpoint: symbol,
    options: Record<string, unknown>,
  ) => Promise<ChangedFile[] | CommitStatus[]>;
}

interface MockCore {
  info: (message: string) => void;
  error: (message: string) => void;
  setFailed: (message: string) => void;
}

interface MockContext {
  repo: { owner: string; repo: string };
  payload: {
    pull_request: { number: number; head: { sha: string } };
  };
}

async function inspectGate(
  files: ChangedFile[],
  statuses: CommitStatus[] = [],
): Promise<{
  calls: { endpoint: symbol; options: Record<string, unknown> }[];
  errors: string[];
  failures: string[];
  infos: string[];
}> {
  const calls: { endpoint: symbol; options: Record<string, unknown> }[] = [];
  const errors: string[] = [];
  const failures: string[] = [];
  const infos: string[] = [];
  const filesEndpoint = Symbol("pull request files");
  const statusesEndpoint = Symbol("commit statuses");
  const github: MockGithub = {
    rest: {
      pulls: { listFiles: filesEndpoint },
      repos: { listCommitStatusesForRef: statusesEndpoint },
    },
    paginate: async (endpoint, options) => {
      calls.push({ endpoint, options });
      return endpoint === filesEndpoint ? files : statuses;
    },
  };
  const core: MockCore = {
    info: (message) => infos.push(message),
    error: (message) => errors.push(message),
    setFailed: (message) => failures.push(message),
  };
  const context: MockContext = {
    repo: { owner: "example", repo: "codex-security" },
    payload: {
      pull_request: {
        number: 123,
        head: { sha: "0123456789abcdef0123456789abcdef01234567" },
      },
    },
  };

  await runGate(github, core, context);

  return { calls, errors, failures, infos };
}

const bundledMcpFile = {
  filename: "sdk/typescript/_bundled_plugin/mcp/server.mjs",
};

const passingLinux = {
  context: "codex-security/live-smoke-linux",
  state: "success",
};

const passingWindows = {
  context: "codex-security/live-smoke-windows",
  state: "success",
};

describe("manually initiated bundled MCP smoke gate", () => {
  test("keeps credential isolation and workload identity exchange covered", () => {
    const result = spawnSync(
      process.execPath,
      [
        fileURLToPath(
          new URL(
            "../../../.github/scripts/live-scan-smoke.mjs",
            import.meta.url,
          ),
        ),
        "--self-test",
      ],
      {
        encoding: "utf8",
        timeout: 10_000,
        windowsHide: true,
      },
    );

    expect(result.status).toBe(0);
    expect(result.stderr).toBe("");
    expect(result.stdout).toContain(
      "Live scan smoke helper self-tests passed.",
    );
  });

  test("does not require a live scan for unrelated plugin or SDK changes", async () => {
    const result = await inspectGate([
      { filename: "sdk/typescript/src/api.ts" },
      {
        filename:
          "sdk/typescript/_bundled_plugin/skills/security-scan/SKILL.md",
      },
    ]);

    expect(result.failures).toEqual([]);
    expect(result.calls).toHaveLength(1);
    expect(result.infos[0]).toContain("not required");
  });

  test("requires both platform results when a bundled MCP file changes", async () => {
    const result = await inspectGate([bundledMcpFile]);

    expect(result.calls).toHaveLength(2);
    expect(result.calls[0]?.options).toEqual({
      owner: "example",
      repo: "codex-security",
      pull_number: 123,
      per_page: 100,
    });
    expect(result.calls[1]?.options).toEqual({
      owner: "example",
      repo: "codex-security",
      ref: "0123456789abcdef0123456789abcdef01234567",
      per_page: 100,
    });
    expect(result.errors).toEqual([
      "codex-security/live-smoke-linux: not run",
      "codex-security/live-smoke-windows: not run",
    ]);
    expect(result.failures[0]).toContain(
      "gh workflow run live-scan-smoke.yml --repo example/codex-security --ref main --field pull_request=123",
    );
  });

  test("requires a scan when an MCP file is renamed out of its directory", async () => {
    const result = await inspectGate([
      {
        filename: "sdk/typescript/_bundled_plugin/renamed.mjs",
        previous_filename: bundledMcpFile.filename,
      },
    ]);

    expect(result.failures).toHaveLength(1);
    expect(result.calls).toHaveLength(2);
  });

  test("rejects a missing, failed, or pending platform result", async () => {
    for (const statuses of [
      [passingLinux],
      [passingLinux, { ...passingWindows, state: "failure" }],
      [{ ...passingLinux, state: "pending" }, passingWindows],
    ]) {
      const result = await inspectGate([bundledMcpFile], statuses);

      expect(result.failures).toHaveLength(1);
    }
  });

  test("uses only the newest status for each platform", async () => {
    const failedRetry = await inspectGate(
      [bundledMcpFile],
      [{ ...passingLinux, state: "failure" }, passingLinux, passingWindows],
    );
    const successfulRetry = await inspectGate(
      [bundledMcpFile],
      [passingLinux, { ...passingLinux, state: "failure" }, passingWindows],
    );

    expect(failedRetry.failures).toHaveLength(1);
    expect(successfulRetry.failures).toEqual([]);
  });

  test("passes only when Linux and Windows succeeded for the exact PR head", async () => {
    const result = await inspectGate(
      [bundledMcpFile],
      [
        { context: "unrelated/context", state: "failure" },
        passingLinux,
        passingWindows,
      ],
    );

    expect(result.failures).toEqual([]);
    expect(result.infos[0]).toContain(
      "0123456789abcdef0123456789abcdef01234567",
    );
  });

  test("makes the existing protected Windows check depend on the gate", () => {
    expect(workflow).toContain(
      "needs: [bundled-mcp-live-smoke, windows-test, windows-verify]",
    );
    expect(workflow).toContain(
      "needs.bundled-mcp-live-smoke.result != 'success'",
    );
  });
});

describe("manual live scan workflow security boundaries", () => {
  test("only runs when a user explicitly dispatches the trusted workflow", () => {
    const triggers = /^on:\n([\s\S]*?)(?=^permissions:)/mu.exec(
      smokeWorkflow,
    )?.[1];

    expect(triggers).toBeDefined();
    expect(triggers).toContain("  workflow_dispatch:");
    expect(triggers).not.toMatch(
      /^  (?:push|pull_request|schedule|workflow_run):/mu,
    );
    expect(smokeWorkflow).toContain(
      "github.repository != 'openai/codex-security' || github.ref != 'refs/heads/main'",
    );
  });

  test("refuses forks and freezes the exact trusted pull request commit", () => {
    expect(smokeWorkflow).toContain(
      "pullRequest.head?.repo?.full_name !== expectedRepository",
    );
    expect(smokeWorkflow).toContain(
      'new Set(["OWNER", "MEMBER", "COLLABORATOR"])',
    );
    expect(smokeWorkflow).toContain(
      "ref: ${{ needs.prepare.outputs.head-sha }}",
    );
    expect(smokeWorkflow).toContain(
      "CODEX_SECURITY_EXPECTED_GIT_HEAD: ${{ needs.prepare.outputs.head-sha }}",
    );
  });

  test("runs a protected real scan on both Linux and Windows", () => {
    expect(smokeWorkflow).toContain("environment: security-live-smoke");
    expect(smokeWorkflow).toContain("id-token: write");
    expect(smokeWorkflow).toContain("platform: linux");
    expect(smokeWorkflow).toContain("runner: ubuntu-latest");
    expect(smokeWorkflow).toContain("platform: windows");
    expect(smokeWorkflow).toContain("runner: windows-latest");
    expect(smokeWorkflow).toContain("--effort low");
    expect(smokeWorkflow).toContain("--timeout-seconds 240");
    expect(smokeWorkflow).toContain("--max-cost 0.25");
  });

  test("reports immutable platform statuses and refreshes the required gate", () => {
    expect(smokeWorkflow).toContain(
      '"repos/$GITHUB_REPOSITORY/statuses/$HEAD_SHA"',
    );
    expect(smokeWorkflow).toContain(
      '"context=codex-security/live-smoke-$platform"',
    );
    expect(smokeWorkflow).toContain(
      '"repos/$GITHUB_REPOSITORY/actions/runs/$run_id/rerun-failed-jobs"',
    );
  });
});

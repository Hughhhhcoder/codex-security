import { readFileSync } from "node:fs";
import { describe, expect, test } from "bun:test";

const workflow = readFileSync(
  new URL("../../../.github/workflows/node-release-pr.yml", import.meta.url),
  "utf8",
);

describe("patch release PR workflow", () => {
  test("runs only for trusted successful main workflows or manual dispatch", () => {
    expect(workflow).toContain("workflow_run:");
    expect(workflow).toContain('workflows: ["node-ci", "node-github-release"]');
    expect(workflow).toContain("types: [completed]");
    expect(workflow).toContain("workflow_dispatch:");
    expect(workflow).toContain("github.repository == 'openai/codex-security'");
    expect(workflow).toContain("github.ref == 'refs/heads/main'");
    expect(workflow).toContain(
      "github.event.workflow_run.conclusion == 'success'",
    );
    expect(workflow).toContain(
      "github.event.workflow_run.head_repository.full_name == github.repository",
    );
    expect(workflow).toContain(
      "github.event.workflow_run.head_branch == 'main'",
    );
    expect(workflow).toContain("github.event.workflow_run.event == 'push'");
    expect(workflow).not.toMatch(/^  (?:pull_request_target|push):/mu);
  });

  test("serializes proposals independently of the protected publisher", () => {
    expect(workflow).toContain("group: node-release-pr");
    expect(workflow).toContain("queue: max");
    expect(workflow).not.toContain("cancel-in-progress: true");
    expect(workflow).not.toContain("group: node-release-cut");
    expect(workflow).not.toContain("group: node-release\n");
  });

  test("checks out trusted automation with pinned first-party actions", () => {
    const uses = [...workflow.matchAll(/^\s+uses:\s+([^\s#]+)/gmu)].map(
      (match) => match[1],
    );
    expect(uses.length).toBeGreaterThan(0);
    for (const action of uses) {
      expect(action).toMatch(/^actions\/[a-z0-9-]+@[a-f0-9]{40}$/u);
    }
    expect(workflow).toContain("ref: refs/heads/main");
    expect(workflow).toContain("fetch-depth: 0");
    expect(workflow).toContain("persist-credentials: false");
    expect(workflow).toContain("package-manager-cache: false");
    expect(workflow).toContain("sdk/typescript/scripts/patch-release-pr.mjs");
    expect(workflow).not.toContain("download-artifact@");
    expect(workflow).not.toContain("github.event.pull_request.head");
  });

  test("can create a PR but cannot publish a package or bypass release gates", () => {
    expect(workflow).toMatch(/^permissions: \{\}$/mu);
    expect(workflow).toContain("actions: read");
    expect(workflow).toContain("contents: write");
    expect(workflow).toContain("pull-requests: write");
    expect(workflow).not.toMatch(
      /^\s+(?:id-token|packages|attestations):\s+write\s*$/mu,
    );
    expect(workflow).not.toMatch(/^\s+environment:/mu);
    expect(workflow).not.toMatch(/\b(?:npm|pnpm)\s+publish\b/u);
    expect(workflow).not.toMatch(/\bgh\s+(?:release|workflow\s+run)\b/u);
    expect(workflow).not.toMatch(/\bgit\s+(?:tag|push)\b/u);
  });

  test("keeps App credentials optional and supports a write-free dry run", () => {
    expect(workflow).toContain("RELEASE_APP_CLIENT_ID");
    expect(workflow).toContain("RELEASE_APP_PRIVATE_KEY");
    expect(workflow).toContain("steps.release-app-token.outputs.token");
    expect(workflow).toContain("github.token");
    expect(workflow).toMatch(/dry_run:\s*\n[\s\S]*?type: boolean/u);
    expect(workflow).toContain("inputs.dry_run || false");
    expect(workflow).toContain("--dry-run");
    expect(workflow).not.toMatch(/permission-actions:\s*write/u);
  });
});

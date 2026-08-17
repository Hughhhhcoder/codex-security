import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  resolveSecurityPolicyTarget,
  runSecurityPolicyStages,
  type SecurityPolicyDraft,
  type SecurityPolicyStage,
  type SecurityPolicyStageResult,
} from "../../src/security-policy.js";
import { PLUGIN_ROOT } from "../plugin-root.js";

export const POLICY =
  "# Security Policy\n\n## Security Invariants\n\nRequests must be authorized before reading another account's records.\n";
export const PYTHON = execFileSync(
  process.env["PYTHON"] ??
    (process.platform === "win32" ? "python" : "python3"),
  ["-c", "import sys; print(sys.executable)"],
  { encoding: "utf8" },
).trim();

export function stageResult(
  stage: SecurityPolicyStage,
): SecurityPolicyStageResult {
  return {
    markdown:
      stage === "policy" ? POLICY : `# ${stage}\n\nSource: src/service.ts:1\n`,
    questions:
      stage === "architecture" ? ["Is this service internet-facing?"] : [],
    reviewNotes:
      stage === "policy" ? ["Confirm the deployment's exposure."] : [],
    blockedReason: null,
  };
}

export async function policyFixture(): Promise<{
  root: string;
  repository: string;
  outputDir: string;
  generate(options?: {
    path?: string;
    run?: (
      stage: SecurityPolicyStage,
      prompt: string,
    ) => Promise<SecurityPolicyStageResult>;
    answerQuestions?: (
      questions: readonly string[],
    ) => Promise<string | undefined>;
    signal?: AbortSignal;
  }): Promise<SecurityPolicyDraft>;
  cleanup(): Promise<void>;
}> {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-policy-")),
  );
  const repository = join(root, "repository");
  const outputDir = join(root, "policy");
  await mkdir(repository);
  await mkdir(outputDir, { mode: 0o700 });
  return {
    root,
    repository,
    outputDir,
    generate: async (options = {}) =>
      runSecurityPolicyStages({
        target: await resolveSecurityPolicyTarget(repository, options.path),
        outputDir,
        pluginRoot: PLUGIN_ROOT,
        guidance: "Synthetic inherited guidance",
        revision: null,
        model: "gpt-5.6-sol",
        reasoningEffort: "high",
        pluginVersion: "0.1.0",
        signal: options.signal ?? new AbortController().signal,
        run: options.run ?? (async (stage) => stageResult(stage)),
        answerQuestions: options.answerQuestions,
        cost: () => null,
      }),
    cleanup: async () => rm(root, { recursive: true, force: true }),
  };
}

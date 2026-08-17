import type { CodexSecurity } from "./api.js";
import type { BulkScanPrompt } from "./bulk-scan-discovery.js";
import type { CodexSecurityConfig } from "./config.js";
import { formatUsd, type ScanCost } from "./cost.js";
import { safeErrorMessage } from "./errors.js";
import {
  applySecurityPolicy,
  loadSecurityPolicyDraft,
  securityPolicyDiff,
  type SecurityPolicyDraft,
  type SecurityPolicyOptions,
  type SecurityPolicyStage,
} from "./security-policy.js";
import { resolvePluginPython } from "./runtime.js";

type SignalName = "SIGINT" | "SIGTERM";
type Output = { write(value: string): unknown };
export type PolicyPrompt = Pick<
  BulkScanPrompt,
  "isInteractive" | "input" | "confirm"
>;
export type PolicySecurity = Pick<
  CodexSecurity,
  "generatePolicy" | "preflightPolicy" | "close"
>;

export interface PolicyCommandOptions {
  repository: string;
  config: CodexSecurityConfig;
  generation: SecurityPolicyOptions;
  apply?: string;
  write: boolean;
  headless: boolean;
  dryRun: boolean;
  format: string;
}

export interface PolicyCommandDependencies {
  createSecurity(config: CodexSecurityConfig): PolicySecurity;
  prompt: PolicyPrompt;
  environment: NodeJS.ProcessEnv;
  errorOutput: Output;
  writePreview(value: string): Promise<void>;
  now(): number;
  addSignalListener(signal: SignalName, listener: () => void): void;
  removeSignalListener(signal: SignalName, listener: () => void): void;
  resolvePython?: typeof resolvePluginPython;
}

const STAGES: Record<SecurityPolicyStage, string> = {
  architecture: "[1/3] Understanding the system and its security boundaries",
  threat_model: "[2/3] Building the source-backed threat model",
  policy: "[3/3] Drafting SECURITY.md",
};

export async function runPolicyCommand(
  options: PolicyCommandOptions,
  dependencies: PolicyCommandDependencies,
): Promise<{
  exitCode: number;
  data?: Record<string, unknown>;
  markdown?: string;
}> {
  const { errorOutput, prompt } = dependencies;
  const controller = new AbortController();
  const interrupt = () => controller.abort("SIGINT");
  const terminate = () => controller.abort("SIGTERM");
  dependencies.addSignalListener("SIGINT", interrupt);
  dependencies.addSignalListener("SIGTERM", terminate);
  const interactive =
    !options.headless &&
    options.format === "toon" &&
    dependencies.environment["CI"] === undefined &&
    prompt.isInteractive();
  const started = dependencies.now();
  let security: PolicySecurity | undefined;
  let outputDir: string | undefined;
  let cost: Readonly<ScanCost> | null = null;
  const write = (message: string): void => {
    try {
      errorOutput.write(`${message}\n`);
    } catch {}
  };
  try {
    let draft: SecurityPolicyDraft;
    if (options.apply !== undefined) {
      draft = await loadSecurityPolicyDraft(options.repository, options.apply, {
        path: options.generation.path,
        signal: controller.signal,
      });
      outputDir = draft.outputDir;
    } else {
      security = dependencies.createSecurity(options.config);
      if (options.dryRun) {
        return {
          exitCode: 0,
          data: {
            ...(await security.preflightPolicy(
              options.repository,
              options.generation,
            )),
            dryRun: true,
          },
        };
      }
      draft = await security.generatePolicy(options.repository, {
        ...options.generation,
        signal: controller.signal,
        onOutputDirReady: (directory) => {
          outputDir = directory;
          write(`Policy artifacts: ${display(directory)}`);
        },
        onStage: (stage) => write(STAGES[stage]),
        onCost: (current) => {
          cost = current;
        },
        onWarning: (warning) =>
          write(`codex-security: ${display(safeErrorMessage(warning))}`),
        ...(interactive
          ? {
              answerQuestions: async (questions: readonly string[]) => {
                write(
                  "A few details could change this policy. Leave an answer blank to keep it unresolved.",
                );
                const answers: string[] = [];
                for (const question of questions) {
                  controller.signal.throwIfAborted();
                  const answer = await prompt.input(
                    display(question),
                    undefined,
                    controller.signal,
                  );
                  if (answer.trim()) answers.push(`${question}\n${answer}`);
                }
                return answers.join("\n\n");
              },
            }
          : {}),
      });
    }
    controller.signal.throwIfAborted();
    cost = draft.cost ?? cost;
    const changed = draft.content !== draft.previousContent;
    const python = changed
      ? await (dependencies.resolvePython ?? resolvePluginPython)({
          configuredPath: options.config.pythonPath,
          environment: dependencies.environment,
          protectedRoot: draft.repository,
          signal: controller.signal,
        })
      : undefined;
    const diff = await securityPolicyDiff(draft, python, controller.signal);
    const shouldPreview = options.format === "toon" || options.write;
    if (shouldPreview) {
      const preview = [
        `\nPolicy target: ${display(draft.targetPath)}`,
        changed
          ? display(diff, true).trimEnd()
          : "SECURITY.md is already up to date.",
        ...(draft.reviewNotes.length === 0
          ? []
          : [
              "\nOwner review:",
              ...draft.reviewNotes.map((note) => `- ${display(note)}`),
            ]),
      ].join("\n");
      if (interactive && !options.write)
        await dependencies.writePreview(`${preview}\n`);
      else write(preview);
    }
    const approved =
      changed &&
      (options.write ||
        (interactive &&
          (await prompt.confirm(
            `Write this policy to ${display(draft.targetPath)}?`,
            false,
            controller.signal,
          ))));
    controller.signal.throwIfAborted();
    let status: "draft" | "written" | "unchanged" = changed
      ? "draft"
      : "unchanged";
    if (approved) {
      await applySecurityPolicy(draft, {
        pythonPath: python,
        environment: dependencies.environment,
        signal: controller.signal,
      });
      status = "written";
      write(`Wrote and verified ${display(draft.targetPath)}`);
    } else if (options.format === "toon") {
      write(`\nDraft: ${display(draft.draftPath)}`);
      write(`Threat model: ${display(draft.threatModelPath)}`);
      if (changed)
        write(
          "No repository files changed. Review the draft, then run policy with --apply <artifact-directory> --write.",
        );
    }
    if (options.apply === undefined) {
      const seconds = Math.max(0, (dependencies.now() - started) / 1000);
      write(
        `Policy generation finished in ${seconds.toFixed(1)}s${cost === null ? "" : ` (${formatUsd(cost.estimatedUsd)} estimated)`}.`,
      );
    }
    return {
      exitCode: 0,
      markdown: draft.content,
      data: {
        status,
        repository: draft.repository,
        scope: draft.scope,
        targetPath: draft.targetPath,
        outputDir: draft.outputDir,
        draftPath: draft.draftPath,
        specificationPath: draft.specificationPath,
        threatModelPath: draft.threatModelPath,
        reviewNotes: draft.reviewNotes,
        cost,
      },
    };
  } catch (error) {
    const signal =
      controller.signal.reason ??
      (error instanceof Error && error.name === "ExitPromptError"
        ? "SIGINT"
        : undefined);
    const exitCode = signal === "SIGINT" ? 130 : signal === "SIGTERM" ? 143 : 2;
    write(
      `codex-security: ${signal === "SIGINT" ? "Policy generation canceled by Ctrl-C." : signal === "SIGTERM" ? "Policy generation terminated by SIGTERM." : display(safeErrorMessage(error))}`,
    );
    if (outputDir !== undefined)
      write(`Saved artifacts: ${display(outputDir)}`);
    return { exitCode };
  } finally {
    dependencies.removeSignalListener("SIGINT", interrupt);
    dependencies.removeSignalListener("SIGTERM", terminate);
    await security?.close();
  }
}

function display(value: string, multiline = false): string {
  return value.replaceAll(
    multiline
      ? /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u2028-\u202e\u2066-\u2069]/gu
      : /[\u0000-\u001f\u007f-\u009f\u2028-\u202e\u2066-\u2069]/gu,
    (character) =>
      `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
}

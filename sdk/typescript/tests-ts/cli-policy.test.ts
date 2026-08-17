import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Writable } from "node:stream";
import { afterEach, describe, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import type {
  SecurityPolicyDraft,
  SecurityPolicyOptions,
} from "../src/index.js";
import type { PolicyPrompt } from "../src/security-policy-cli.js";
import { capture, dependencies, FakeSignals } from "./cli-fixtures.js";
import {
  POLICY,
  PYTHON,
  policyFixture,
  stageResult,
} from "./support/security-policy.js";

const fixtures: Awaited<ReturnType<typeof policyFixture>>[] = [];
async function fixture() {
  const f = await policyFixture();
  fixtures.push(f);
  return f;
}
afterEach(async () => {
  await Promise.all(fixtures.splice(0).map((f) => f.cleanup()));
});

function prompt(overrides: Partial<PolicyPrompt> = {}): PolicyPrompt {
  return {
    isInteractive: () => false,
    input: async () => {
      throw new Error("Unexpected input prompt");
    },
    confirm: async () => {
      throw new Error("Unexpected confirmation");
    },
    ...overrides,
  };
}

function policyDependencies(
  f: Awaited<ReturnType<typeof policyFixture>>,
  options: {
    draft?: SecurityPolicyDraft;
    prompt?: PolicyPrompt;
    onGenerate?: (
      repository: string,
      options: SecurityPolicyOptions,
    ) => void | Promise<void>;
    onClose?: () => void;
    onConfig?: (config: unknown) => void;
    signals?: FakeSignals;
  } = {},
) {
  return {
    ...dependencies({
      currentDirectory: f.repository,
      signals: options.signals,
    }),
    policyPrompt: options.prompt ?? prompt(),
    resolvePolicyPython: async () => PYTHON,
    createPolicySecurity: (config: unknown) => {
      options.onConfig?.(config);
      return {
        generatePolicy: async (
          repository: string,
          generation: SecurityPolicyOptions,
        ) => {
          await options.onGenerate?.(repository, generation);
          generation.onOutputDirReady?.(f.outputDir);
          generation.onStage?.("architecture");
          generation.onStage?.("threat_model");
          generation.onStage?.("policy");
          return (
            options.draft ??
            (await f.generate({
              path: generation.path,
              answerQuestions: generation.answerQuestions,
            }))
          );
        },
        preflightPolicy: async () => ({
          repository: f.repository,
          scope: ".",
          targetPath: join(f.repository, "SECURITY.md"),
          outputDir: null,
          authentication: {
            method: "stored_credentials" as const,
            verified: false as const,
          },
          model: "gpt-5.6-sol",
          reasoningEffort: "xhigh",
        }),
        close: async () => {
          options.onClose?.();
        },
      };
    },
  };
}

describe("policy CLI", () => {
  test("documents the policy workflow in help", async () => {
    const stdout = capture();
    expect(
      await main(
        ["policy", "--help"],
        stdout.stream,
        capture().stream,
        dependencies(),
      ),
    ).toBe(0);
    expect(stdout.text()).toContain("SECURITY.md");
    expect(stdout.text()).toContain("--apply");
    expect(stdout.text()).toContain("--write");
    expect(stdout.text()).toContain("--headless");
    expect(stdout.text()).not.toContain("--outputDir");
    expect(stdout.text()).not.toContain("--write true");
    expect(stdout.text()).toContain(
      "--apply /path/outside/repository/policy --write",
    );
  });

  test("generates a headless draft with machine-readable paths and no source edits", async () => {
    const f = await fixture();
    const stdout = capture();
    const stderr = capture();
    let closed = false;
    let config: unknown;
    expect(
      await main(
        [
          "policy",
          ".",
          "--headless",
          "--model",
          "gpt-5.6-terra",
          "--effort",
          "high",
          "--json",
        ],
        stdout.stream,
        stderr.stream,
        policyDependencies(f, {
          onClose: () => {
            closed = true;
          },
          onConfig: (value) => {
            config = value;
          },
        }),
      ),
    ).toBe(0);
    const result = JSON.parse(stdout.text());
    expect(result.status).toBe("draft");
    expect(result.targetPath).toBe(join(f.repository, "SECURITY.md"));
    expect(result.threatModelPath).toBe(join(f.outputDir, "THREAT_MODEL.md"));
    expect(stderr.text()).toContain("[1/3]");
    expect(stderr.text()).not.toContain("+Requests must be authorized");
    expect(config).toMatchObject({
      codexOverrides: {
        model: "gpt-5.6-terra",
        model_reasoning_effort: "high",
      },
    });
    expect(await readdir(f.repository)).toEqual([]);
    expect(closed).toBe(true);
  });

  test("preserves a headless result when optional progress writes throw", async () => {
    const f = await fixture();
    const stdout = capture();
    expect(
      await main(
        ["policy", "--headless", "--json"],
        stdout.stream,
        {
          write: () => {
            throw new Error("Progress output failed");
          },
        },
        policyDependencies(f),
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text()).status).toBe("draft");
    expect(await readdir(f.repository)).toEqual([]);
  });

  test("isolates asynchronous progress stream errors", async () => {
    const f = await fixture();
    const stdout = capture();
    const stderr = new Writable({
      autoDestroy: false,
      write(_chunk, _encoding, callback) {
        queueMicrotask(() => callback(new Error("Progress output failed")));
      },
    });
    const failure = new Promise<Error>((resolve) =>
      stderr.once("error", resolve),
    );
    expect(
      await main(
        ["policy", "--headless", "--json"],
        stdout.stream,
        stderr,
        policyDependencies(f),
      ),
    ).toBe(0);
    await expect(failure).resolves.toMatchObject({
      message: "Progress output failed",
    });
    expect(JSON.parse(stdout.text()).status).toBe("draft");
  });

  test("does not offer an interactive write if the diff preview fails", async () => {
    const f = await fixture();
    await f.generate();
    let asked = false;
    expect(
      await main(
        ["policy", "--apply", f.outputDir],
        capture(true).stream,
        {
          isTTY: true,
          write: () => {
            throw new Error("Preview output failed");
          },
        },
        policyDependencies(f, {
          prompt: prompt({
            isInteractive: () => true,
            confirm: async () => {
              asked = true;
              return true;
            },
          }),
        }),
      ),
    ).toBe(2);
    expect(asked).toBe(false);
    expect(await readdir(f.repository)).toEqual([]);
  });

  test("offers source-backed questions and shows the exact diff before approval", async () => {
    const f = await fixture();
    const stderr = capture(true);
    let asked = 0;
    expect(
      await main(
        ["policy"],
        capture(true).stream,
        stderr.stream,
        policyDependencies(f, {
          prompt: prompt({
            isInteractive: () => true,
            input: async (question) => {
              asked++;
              expect(question).toContain("internet-facing");
              return "Private service";
            },
            confirm: async (_question, defaultValue) => {
              expect(defaultValue).toBe(false);
              expect(stderr.text()).toContain("--- /dev/null");
              expect(stderr.text()).toContain("+Requests must be authorized");
              expect(stderr.text()).toContain("Owner review:");
              expect(await readdir(f.repository)).toEqual([]);
              return true;
            },
          }),
        }),
      ),
    ).toBe(0);
    expect(asked).toBe(1);
    expect(await readFile(join(f.repository, "SECURITY.md"), "utf8")).toBe(
      POLICY,
    );
    expect(stderr.text()).toContain("Wrote and verified");
  });

  test("declining approval leaves the policy draft available", async () => {
    const f = await fixture();
    const draft = await f.generate();
    const stderr = capture(true);
    expect(
      await main(
        ["policy"],
        capture(true).stream,
        stderr.stream,
        policyDependencies(f, {
          draft,
          prompt: prompt({
            isInteractive: () => true,
            confirm: async () => false,
          }),
        }),
      ),
    ).toBe(0);
    expect(await readdir(f.repository)).toEqual([]);
    expect(stderr.text()).toContain("No repository files changed");
    expect(await readFile(draft.draftPath, "utf8")).toBe(POLICY);
  });

  test("applies a reviewed, edited saved draft without initializing Codex", async () => {
    const f = await fixture();
    await mkdir(join(f.repository, "component"));
    const draft = await f.generate({ path: "component" });
    const edited = `${POLICY}\nReviewed by the component owner.\n`;
    await writeFile(draft.draftPath, edited);
    const stdout = capture();
    const deps = policyDependencies(f);
    deps.createPolicySecurity = () => {
      throw new Error("Must not initialize Codex for --apply");
    };
    expect(
      await main(
        [
          "policy",
          ".",
          "--path",
          "component",
          "--apply",
          f.outputDir,
          "--write",
          "--json",
        ],
        stdout.stream,
        capture().stream,
        deps,
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text()).status).toBe("written");
    expect(await readFile(draft.targetPath, "utf8")).toBe(edited);
  });

  test("rejects writing an unseen model-generated policy", async () => {
    const f = await fixture();
    const stderr = capture();
    let generated = false;
    expect(
      await main(
        ["policy", "--write"],
        capture().stream,
        stderr.stream,
        policyDependencies(f, {
          onGenerate: () => {
            generated = true;
          },
        }),
      ),
    ).toBe(2);
    expect(stderr.text()).toContain("--write requires --apply");
    expect(generated).toBe(false);
  });

  test("does not silently ignore generation options when applying a saved draft", async () => {
    const f = await fixture();
    const deps = policyDependencies(f);
    deps.createPolicySecurity = () => {
      throw new Error("Must not initialize Codex for --apply");
    };
    for (const option of [
      ["--model", "gpt-5.6-terra"],
      ["--auth", "chatgpt"],
      ["--provider", "fireworks"],
      ["--plugin-path", "/synthetic/plugin"],
      ["--output-dir", f.outputDir],
    ]) {
      const stderr = capture();
      expect(
        await main(
          ["policy", "--apply", f.outputDir, ...option],
          capture().stream,
          stderr.stream,
          deps,
        ),
      ).toBe(2);
      expect(stderr.text()).toContain("generation options");
    }
  });

  test("preflights without generation or Python discovery", async () => {
    const f = await fixture();
    const stdout = capture();
    const deps = policyDependencies(f, {
      onGenerate: () => {
        throw new Error("Must not generate");
      },
    });
    deps.resolvePolicyPython = async () => {
      throw new Error("Must not resolve Python");
    };
    expect(
      await main(
        ["policy", "--dry-run", "--json"],
        stdout.stream,
        capture().stream,
        deps,
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text()).dryRun).toBe(true);
    expect(await readdir(f.outputDir)).toEqual([]);
  });

  test("returns only policy Markdown on stdout in Markdown mode", async () => {
    const f = await fixture();
    const markdown = `${POLICY.trimEnd()}  `;
    const draft = await f.generate({
      run: async (stage) => ({
        ...stageResult(stage),
        ...(stage === "policy" ? { markdown } : {}),
      }),
    });
    const stdout = capture();
    expect(
      await main(
        ["policy", "--format", "md"],
        stdout.stream,
        capture().stream,
        policyDependencies(f, { draft }),
      ),
    ).toBe(0);
    expect(stdout.text()).toBe(markdown);
    expect(await readdir(f.repository)).toEqual([]);
  });

  test("reports an unchanged saved policy without starting Codex or Python", async () => {
    const f = await fixture();
    await writeFile(join(f.repository, "SECURITY.md"), POLICY);
    await f.generate();
    const stdout = capture();
    const deps = policyDependencies(f);
    deps.createPolicySecurity = () => {
      throw new Error("Must not initialize Codex for --apply");
    };
    deps.resolvePolicyPython = async () => {
      throw new Error("Must not resolve Python for an unchanged draft");
    };
    expect(
      await main(
        ["policy", "--apply", f.outputDir, "--write", "--json"],
        stdout.stream,
        capture().stream,
        deps,
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text()).status).toBe("unchanged");
    expect(await readFile(join(f.repository, "SECURITY.md"), "utf8")).toBe(
      POLICY,
    );
  });

  test("does not overwrite source edited during the confirmation", async () => {
    const f = await fixture();
    const draft = await f.generate();
    const stderr = capture(true);
    expect(
      await main(
        ["policy", "--apply", f.outputDir],
        capture(true).stream,
        stderr.stream,
        policyDependencies(f, {
          prompt: prompt({
            isInteractive: () => true,
            confirm: async () => {
              await writeFile(draft.targetPath, "# Concurrent change\n");
              return true;
            },
          }),
        }),
      ),
    ).toBe(2);
    expect(stderr.text()).toContain("changed after");
    expect(await readFile(draft.targetPath, "utf8")).toBe(
      "# Concurrent change\n",
    );
  });

  test("renders terminal controls visibly without changing reviewed bytes", async () => {
    const f = await fixture();
    const draft = await f.generate();
    const controlled = `${POLICY}\nLiteral \u001b[2J text.\u202e\n`;
    await writeFile(draft.draftPath, controlled);
    const stderr = capture();
    expect(
      await main(
        ["policy", "--apply", f.outputDir, "--write"],
        capture().stream,
        stderr.stream,
        policyDependencies(f),
      ),
    ).toBe(0);
    expect(stderr.text()).not.toContain("\u001b");
    expect(stderr.text()).not.toContain("\u202e");
    expect(stderr.text()).toContain("\\u001b[2J");
    expect(stderr.text()).toContain("\\u202e");
    expect(await readFile(draft.targetPath, "utf8")).toBe(controlled);
  });

  test("returns the interrupt exit code and removes signal listeners", async () => {
    const f = await fixture();
    const signals = new FakeSignals();
    let closed = false;
    expect(
      await main(
        ["policy", "--headless"],
        capture().stream,
        capture().stream,
        policyDependencies(f, {
          signals,
          onClose: () => {
            closed = true;
          },
          onGenerate: (_repository, options) => {
            signals.emit("SIGINT");
            options.signal!.throwIfAborted();
          },
        }),
      ),
    ).toBe(130);
    expect(closed).toBe(true);
    expect(
      [...signals.listeners.values()].every(
        (listeners) => listeners.size === 0,
      ),
    ).toBe(true);
    expect(await readdir(f.repository)).toEqual([]);
  });

  test("cancels a pending review prompt on SIGTERM", async () => {
    const f = await fixture();
    await f.generate();
    const signals = new FakeSignals();
    expect(
      await main(
        ["policy", "--apply", f.outputDir],
        capture(true).stream,
        capture(true).stream,
        policyDependencies(f, {
          signals,
          prompt: prompt({
            isInteractive: () => true,
            confirm: async (_question, _defaultValue, signal) => {
              expect(signal).toBeDefined();
              signals.emit("SIGTERM");
              signal!.throwIfAborted();
              return true;
            },
          }),
        }),
      ),
    ).toBe(143);
    expect(await readdir(f.repository)).toEqual([]);
  });

  test("treats Inquirer's Ctrl-C error as cancellation without a process signal", async () => {
    const f = await fixture();
    await f.generate();
    const stderr = capture(true);
    expect(
      await main(
        ["policy", "--apply", f.outputDir],
        capture(true).stream,
        stderr.stream,
        policyDependencies(f, {
          prompt: prompt({
            isInteractive: () => true,
            confirm: async () => {
              throw Object.assign(new Error("Prompt closed"), {
                name: "ExitPromptError",
              });
            },
          }),
        }),
      ),
    ).toBe(130);
    expect(stderr.text()).toContain("canceled by Ctrl-C");
    expect(await readdir(f.repository)).toEqual([]);
  });
});

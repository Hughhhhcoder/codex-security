import { execFileSync } from "node:child_process";
import { mkdir, readFile, readdir, symlink, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import type {
  CodexOptions,
  ThreadEvent,
  ThreadOptions,
  TurnOptions,
} from "@openai/codex-sdk";
import Ajv, { type AnySchema } from "ajv";
import { afterEach, describe, expect, test } from "bun:test";
import {
  applySecurityPolicy,
  CodexSecurity,
  loadSecurityPolicyDraft,
  OutputDirectoryNotEmptyError,
  securityPolicyDiff,
  type SecurityPolicyStage,
} from "../src/index.js";
import { preparedRuntime } from "./support/api-events.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import {
  POLICY,
  PYTHON,
  addPolicySubmodule,
  policyFixture,
  policyGit,
  policyPlugin,
  stageResult,
} from "./support/security-policy.js";

const InternalSecurity = CodexSecurity as unknown as new (
  config: Record<string, unknown>,
  dependencies: Record<string, unknown>,
  runtimeOptions?: { surface: "cli" | "sdk" },
) => CodexSecurity;
const fixtures: Awaited<ReturnType<typeof policyFixture>>[] = [];
afterEach(async () => {
  await Promise.all(fixtures.splice(0).map((f) => f.cleanup()));
});

async function setup(
  options: {
    stream?: (
      stage: SecurityPolicyStage,
      signal: AbortSignal,
    ) => AsyncGenerator<ThreadEvent>;
    onPrepare?: () => void;
    onRevision?: () => Promise<void>;
    surface?: "cli" | "sdk";
    config?: Record<string, unknown>;
  } = {},
) {
  const f = await policyFixture();
  fixtures.push(f);
  const codexHome = join(f.root, "codex-home");
  await mkdir(codexHome);
  const runtime = preparedRuntime(codexHome);
  let configuration: CodexOptions | undefined;
  const threads: ThreadOptions[] = [];
  const prompts: string[] = [];
  const turns: TurnOptions[] = [];
  const stages: SecurityPolicyStage[] = [
    "architecture",
    "threat_model",
    "policy",
  ];
  const security = new InternalSecurity(
    options.config ?? {},
    {
      environment: { CODEX_SECURITY_STATE_DIR: join(f.root, "state") },
      prepareRuntime: async () => {
        options.onPrepare?.();
        return runtime;
      },
      resolvePluginPython: async () => PYTHON,
      repositoryRevision: async () => {
        await options.onRevision?.();
        return "synthetic-revision";
      },
      runWorkbench: async () => {
        throw new Error("Policy generation must not register a scan.");
      },
      createCodex: (config: CodexOptions) => {
        configuration = config;
        return {
          startThread: (threadOptions: ThreadOptions) => {
            const stage = stages[threads.length]!;
            threads.push(threadOptions);
            return {
              id: null,
              async runStreamed(prompt: string, turn: TurnOptions) {
                prompts.push(prompt);
                turns.push(turn);
                return {
                  events:
                    options.stream?.(stage, turn.signal!) ?? events(stage),
                };
              },
            };
          },
        };
      },
    },
    { surface: options.surface ?? "sdk" },
  );
  return {
    ...f,
    security,
    runtime,
    threads,
    prompts,
    turns,
    configuration: () => configuration,
  };
}

async function* events(
  stage: SecurityPolicyStage,
  result = stageResult(stage),
): AsyncGenerator<ThreadEvent> {
  yield { type: "thread.started", thread_id: `policy-${stage}` };
  yield { type: "turn.started" };
  yield {
    type: "item.completed",
    item: {
      id: "result",
      type: "agent_message",
      text: JSON.stringify(result),
    },
  };
  yield {
    type: "turn.completed",
    usage: {
      input_tokens: 100,
      cached_input_tokens: 0,
      cache_write_input_tokens: 0,
      output_tokens: 10,
      reasoning_output_tokens: 0,
    },
  };
}

describe("CodexSecurity policy API", () => {
  test("preflights without runtime initialization or output creation", async () => {
    let prepared = false;
    const f = await setup({
      onPrepare: () => {
        prepared = true;
      },
    });
    await mkdir(join(f.repository, "component"));
    const preflight = await f.security.preflightPolicy(f.repository, {
      path: "component",
      outputDir: f.outputDir,
    });
    expect(preflight.scope).toBe("component");
    expect(preflight.targetPath).toBe(
      join(f.repository, "component", "SECURITY.md"),
    );
    expect(preflight.model).toBe("gpt-5.6-sol");
    expect(prepared).toBe(false);
    expect(await readdir(f.outputDir)).toEqual([]);
    await f.security.close();
  });

  test("gives a usable remedy for a nonempty policy output directory", async () => {
    let prepared = false;
    const f = await setup({
      onPrepare: () => {
        prepared = true;
      },
    });
    const previous = join(f.outputDir, "previous.md");
    await writeFile(previous, "Keep this draft.\n");
    for (const operation of [
      () =>
        f.security.preflightPolicy(f.repository, { outputDir: f.outputDir }),
      () => f.security.generatePolicy(f.repository, { outputDir: f.outputDir }),
    ]) {
      const error = await operation().catch((value: unknown) => value);
      expect(error).toBeInstanceOf(OutputDirectoryNotEmptyError);
      expect(String(error)).toContain("Choose a new or empty directory");
      expect(String(error)).not.toContain("--archive-existing");
    }
    expect(prepared).toBe(false);
    expect(await readFile(previous, "utf8")).toBe("Keep this draft.\n");
    await f.security.close();
  });

  test("rejects redirected Git roots before inspecting policy or starting Codex", async () => {
    let prepared = false;
    const f = await setup({
      onPrepare: () => {
        prepared = true;
      },
    });
    execFileSync("git", ["init", "--quiet", f.repository]);
    execFileSync("git", [
      "-C",
      f.repository,
      "config",
      "core.worktree",
      f.root,
    ]);
    for (const operation of [
      () => f.security.preflightPolicy(f.repository),
      () => f.security.generatePolicy(f.repository),
    ])
      await expect(operation()).rejects.toThrow(
        "does not match the selected checkout",
      );
    expect(prepared).toBe(false);
    expect(f.threads).toHaveLength(0);
    expect(await readdir(f.outputDir)).toEqual([]);
    await f.security.close();
  });

  test("rejects Git metadata targets before starting Codex", async () => {
    let prepared = false;
    const f = await setup({
      onPrepare: () => {
        prepared = true;
      },
    });
    execFileSync("git", ["init", "--quiet", f.repository]);
    const options = { path: ".git/refs/heads", outputDir: f.outputDir };
    await expect(
      f.security.preflightPolicy(f.repository, options),
    ).rejects.toThrow("inside Git metadata");
    await expect(
      f.security.generatePolicy(f.repository, options),
    ).rejects.toThrow("inside Git metadata");
    expect(prepared).toBe(false);
    expect(await readdir(f.outputDir)).toEqual([]);
    expect(await readdir(join(f.repository, ".git", "refs", "heads"))).toEqual(
      [],
    );
    await f.security.close();
  });

  test("keeps submodule artifacts outside every enclosing checkout", async () => {
    let prepared = false;
    const f = await setup({
      onPrepare: () => {
        prepared = true;
      },
    });
    policyGit(f.repository, "init", "--quiet");
    const nested = await addPolicySubmodule(
      f.repository,
      join(f.root, "submodule-source"),
    );
    const inside = join(f.repository, "policy-artifacts");
    for (const [repository, path] of [
      [f.repository, "services/api"],
      [nested, "."],
    ] as const) {
      const options = { path, outputDir: inside };
      await expect(
        f.security.preflightPolicy(repository, options),
      ).rejects.toThrow("outside the protected scan root");
      await expect(
        f.security.generatePolicy(repository, options),
      ).rejects.toThrow("outside the protected scan root");
    }
    const stateInside = new InternalSecurity(
      {},
      {
        environment: { CODEX_SECURITY_STATE_DIR: join(f.repository, "state") },
      },
    );
    await expect(stateInside.preflightPolicy(nested)).rejects.toThrow(
      "outside the protected scan root",
    );
    await stateInside.close();
    expect(prepared).toBe(false);
    expect(f.threads).toHaveLength(0);
    expect(await readdir(f.outputDir)).toEqual([]);
    await expect(readdir(inside)).rejects.toMatchObject({ code: "ENOENT" });
    const preflight = await f.security.preflightPolicy(nested, {
      outputDir: f.outputDir,
    });
    expect(preflight.repository).toBe(nested);
    expect(preflight.scope).toBe(".");
    const draft = await f.security.generatePolicy(f.repository, {
      path: "services/api",
      outputDir: f.outputDir,
    });
    expect(draft.repository).toBe(nested);
    expect(draft.outputDir).toBe(f.outputDir);
    expect(
      f.threads.every((thread) => thread.workingDirectory === f.outputDir),
    ).toBe(true);
    expect(f.configuration()?.env?.["CODEX_SECURITY_REPOSITORY"]).toBe(nested);
    await f.security.close();
  });

  test("keeps literal component names intact through generation and apply", async () => {
    for (const scope of ["-component", "~component", "~", "~/child"]) {
      let prepared = false;
      const f = await setup({
        onPrepare: () => {
          prepared = true;
        },
      });
      const component = join(f.repository, scope);
      await mkdir(component, { recursive: true });
      await writeFile(
        join(f.repository, "SECURITY.md"),
        "# Root policy\nInherited guidance.\n",
      );
      const options = { path: `./${scope}`, outputDir: f.outputDir };
      const preflight = await f.security.preflightPolicy(f.repository, options);
      expect(preflight.scope).toBe(scope);
      expect(preflight.targetPath).toBe(join(component, "SECURITY.md"));
      expect(prepared).toBe(false);
      const generated = await f.security.generatePolicy(f.repository, options);
      expect(generated.scope).toBe(scope);
      expect(f.prompts[0]).toContain("Inherited guidance.");
      const saved = await loadSecurityPolicyDraft(f.repository, f.outputDir, {
        path: options.path,
      });
      expect(await securityPolicyDiff(saved, PYTHON)).toContain(
        `b/${scope}/SECURITY.md`,
      );
      await applySecurityPolicy(saved, { pythonPath: PYTHON });
      expect(await readFile(saved.targetPath, "utf8")).toBe(POLICY);
      await f.security.close();
    }
  });

  test("validates inherited policies before preflight or runtime setup", async () => {
    for (const invalid of ["utf8", "alias"] as const) {
      let prepared = false;
      const f = await setup({
        onPrepare: () => {
          prepared = true;
        },
      });
      await mkdir(join(f.repository, "component"));
      const policy = join(f.repository, "SECURITY.md");
      let message: string;
      if (invalid === "utf8") {
        await writeFile(policy, Buffer.from([0xff]));
        message = "valid UTF-8";
      } else {
        await symlink(
          join(f.repository, "component", "SECURITY.md"),
          policy,
          "file",
        );
        message = "outside the selected component";
      }
      const options = { path: "component", outputDir: f.outputDir };
      await expect(
        f.security.preflightPolicy(f.repository, options),
      ).rejects.toThrow(message);
      await expect(
        f.security.generatePolicy(f.repository, options),
      ).rejects.toThrow(message);
      expect(prepared).toBe(false);
      expect(f.threads).toHaveLength(0);
      expect(await readdir(f.outputDir)).toEqual([]);
      await f.security.close();
    }
  });

  test("rejects a closed policy client before resolving its target", async () => {
    const f = await setup();
    await f.security.close();
    await expect(
      f.security.preflightPolicy(join(f.root, "missing-repository")),
    ).rejects.toThrow("CodexSecurity is closed");
    expect(f.threads).toHaveLength(0);
  });

  test("uses the shared runtime for three fresh, scoped, structured turns", async () => {
    const f = await setup({ surface: "cli" });
    await writeFile(
      join(f.repository, "SECURITY.md"),
      "# Existing policy\nKeep the reporting channel.\n",
    );
    const observed: SecurityPolicyStage[] = [];
    const costs: number[] = [];
    const result = await f.security.generatePolicy(f.repository, {
      outputDir: f.outputDir,
      onStage: (stage) => observed.push(stage),
      onCost: (cost) => costs.push(cost.estimatedUsd),
      answerQuestions: async () => "Authenticated clients only.",
    });
    expect(observed).toEqual(["architecture", "threat_model", "policy"]);
    expect(f.threads).toHaveLength(3);
    for (const thread of f.threads) {
      expect(thread.workingDirectory).toBe(f.outputDir);
      expect(thread.approvalPolicy).toBe("never");
      expect(thread.networkAccessEnabled).toBe(false);
      expect(thread.webSearchMode).toBe("disabled");
    }
    expect(f.turns.every((turn) => turn.outputSchema !== undefined)).toBe(true);
    const outputSchema = f.turns[0]!.outputSchema as AnySchema;
    expect(JSON.stringify(outputSchema)).not.toContain('"nullable"');
    const validate = new Ajv().compile(outputSchema);
    expect(validate(stageResult("architecture"))).toBe(true);
    expect(
      validate({ ...stageResult("architecture"), blockedReason: 42 }),
    ).toBe(false);
    expect(f.prompts[0]).toContain("Keep the reporting channel.");
    expect(f.prompts[1]).toContain("Authenticated clients only.");
    expect(f.configuration()?.config?.["features"]).toMatchObject({
      plugins: false,
      apps: false,
    });
    expect(f.configuration()?.config).toMatchObject({
      default_permissions: "codex_security_policy",
      mcp_servers: {},
      web_search: "disabled",
      sandbox_workspace_write: { network_access: false },
    });
    expect(f.configuration()?.config?.["responses_api_metadata"]).toMatchObject(
      { codex_security_surface: "cli" },
    );
    expect(f.configuration()?.env?.["CODEX_SECURITY_REPOSITORY"]).toBe(
      f.repository,
    );
    expect(f.configuration()?.env?.["CODEX_SECURITY_SCAN_ID"]).toBeUndefined();
    expect(result.cost?.inputTokens).toBe(300);
    expect(result.cost?.outputTokens).toBe(30);
    expect(costs).toHaveLength(3);
    expect(costs.at(-1)).toBe(result.cost?.estimatedUsd);
    expect(await readFile(result.draftPath, "utf8")).toBe(POLICY);
    expect(await readFile(result.targetPath, "utf8")).toContain(
      "Keep the reporting channel.",
    );
    await f.security.close();
  });

  test("rejects policy changes made while resolving generation guidance", async () => {
    for (const scope of [".", "component"]) {
      const f = await setup();
      await mkdir(join(f.repository, "component"));
      await writeFile(join(f.repository, "SECURITY.md"), "# Original policy\n");
      const pluginRoot = await policyPlugin(
        f.root,
        [
          "import pathlib, sys",
          "root = pathlib.Path(sys.argv[sys.argv.index('--repo') + 1])",
          "policy = root / 'SECURITY.md'",
          "previous = policy.read_text()",
          "policy.write_bytes(b'# Concurrent policy\\n')",
          "print(previous)",
        ].join("\n"),
      );
      for (const name of [
        "references/threat-model.md",
        "references/security-guidance.md",
        "skills/define-security-policy/SKILL.md",
      ]) {
        const path = join(pluginRoot, name);
        await mkdir(dirname(path), { recursive: true });
        await writeFile(path, "Synthetic policy guidance.\n");
      }
      f.runtime["plugin"] = {
        ...(f.runtime["plugin"] as Record<string, unknown>),
        pluginRoot,
      };
      await expect(
        f.security.generatePolicy(f.repository, {
          path: scope,
          outputDir: f.outputDir,
        }),
      ).rejects.toThrow("changed after");
      expect(f.threads).toHaveLength(0);
      expect(await readFile(join(f.repository, "SECURITY.md"), "utf8")).toBe(
        "# Concurrent policy\n",
      );
      expect(await readdir(f.outputDir)).not.toContain("policy-draft.json");
      await f.security.close();
    }
  });

  test("keeps the original checkpoint when a policy changes after guidance resolution", async () => {
    let targetPath = "";
    const f = await setup({
      onRevision: async () => {
        await writeFile(targetPath, "# Concurrent policy\n");
      },
    });
    targetPath = join(f.repository, "SECURITY.md");
    const original = "# Original policy\n";
    await writeFile(targetPath, original);
    const draft = await f.security.generatePolicy(f.repository, {
      outputDir: f.outputDir,
    });
    expect(draft.previousContent).toBe(original);
    expect(f.prompts[0]).toContain(original.trim());
    expect(
      await readFile(join(f.outputDir, "previous-SECURITY.md"), "utf8"),
    ).toBe(original);
    await expect(securityPolicyDiff(draft, PYTHON)).rejects.toThrow(
      "changed after",
    );
    await f.security.close();
  });

  test("rejects an incomplete policy plugin before starting model work", async () => {
    const f = await setup();
    const pluginRoot = join(f.root, "incomplete-plugin");
    for (const path of [
      "references/threat-model.md",
      "skills/define-security-policy/SKILL.md",
      "scripts/resolve_security_md.py",
    ]) {
      const destination = join(pluginRoot, path);
      await mkdir(dirname(destination), { recursive: true });
      await writeFile(destination, "synthetic plugin fixture\n");
    }
    f.runtime["plugin"] = {
      ...(f.runtime["plugin"] as Record<string, unknown>),
      pluginRoot,
    };
    await expect(
      f.security.generatePolicy(f.repository, { outputDir: f.outputDir }),
    ).rejects.toThrow("references/security-guidance.md");
    expect(f.threads).toHaveLength(0);
    expect(await readdir(f.outputDir)).toEqual([]);
    await f.security.close();
  });

  test("removes external tools and wider sandbox settings from selected profiles", async () => {
    const f = await setup({
      config: {
        codexOverrides: {
          profile: "selected",
          features: { apps: true },
          mcp_servers: { synthetic: { command: "synthetic-tool" } },
          sandbox_workspace_write: {
            network_access: true,
            writable_roots: ["/synthetic"],
          },
          profiles: {
            selected: {
              model: "gpt-5.6-terra",
              features: { apps: true, goals: true },
              mcp_servers: { synthetic: { command: "synthetic-profile-tool" } },
              web_search: "live",
              sandbox_workspace_write: { network_access: true },
            },
          },
        },
      },
    });
    await f.security.generatePolicy(f.repository, { outputDir: f.outputDir });
    expect(f.configuration()?.config).toMatchObject({
      default_permissions: "codex_security_policy",
      features: { plugins: false, apps: false },
      mcp_servers: {},
      web_search: "disabled",
      sandbox_workspace_write: { network_access: false },
      profiles: {
        selected: { model: "gpt-5.6-terra", features: { goals: true } },
      },
    });
    const serialized = JSON.stringify(f.configuration()?.config);
    expect(serialized).not.toContain("synthetic-tool");
    expect(serialized).not.toContain("synthetic-profile-tool");
    expect(serialized).not.toContain("writable_roots");
    expect(serialized).not.toContain('"plugins":true');
    expect(serialized).not.toContain('"apps":true');
    await f.security.close();
  });

  test("retains an explicit plugin selection without persisting its location", async () => {
    const f = await setup({ config: { pluginPath: PLUGIN_ROOT } });
    const draft = await f.security.generatePolicy(f.repository, {
      outputDir: f.outputDir,
    });
    expect(draft.customPlugin).toBe(true);
    expect(draft.pluginPath).toBe(resolve(PLUGIN_ROOT));
    const manifest = JSON.parse(
      await readFile(join(f.outputDir, "policy-draft.json"), "utf8"),
    );
    expect(manifest.customPlugin).toBe(true);
    expect(manifest).not.toHaveProperty("pluginPath");
    await f.security.close();
  });

  test("keeps knowledge-base context out of source and removes its temporary extraction", async () => {
    const f = await setup();
    const context = join(f.root, "architecture.md");
    await writeFile(context, "The synthetic service is private.\n");
    await f.security.generatePolicy(f.repository, {
      outputDir: f.outputDir,
      knowledgeBasePaths: [context],
    });
    const extracted = f.configuration()?.env?.["CODEX_SECURITY_KNOWLEDGE_BASE"];
    expect(extracted).toBeDefined();
    expect(
      f.prompts.every((prompt) => prompt.includes(JSON.stringify(extracted))),
    ).toBe(true);
    await expect(readFile(extracted!)).rejects.toThrow();
    expect(await readdir(f.repository)).toEqual([]);
    await f.security.close();
  });

  test("enforces one cost budget across stages and preserves completed evidence", async () => {
    const f = await setup();
    await expect(
      f.security.generatePolicy(f.repository, {
        outputDir: f.outputDir,
        maxCostUsd: 0.001,
      }),
    ).rejects.toThrow("cost limit");
    expect(f.threads).toHaveLength(2);
    expect(
      await readFile(join(f.outputDir, "project-spec.md"), "utf8"),
    ).toContain("src/service.ts:1");
    expect(await readdir(f.repository)).toEqual([]);
    await f.security.close();
  });

  test("optional observer failures do not stop policy generation", async () => {
    const f = await setup();
    const errors: string[] = [];
    const fail = () => {
      throw new Error("optional observer");
    };
    const result = await f.security.generatePolicy(f.repository, {
      outputDir: f.outputDir,
      onStage: fail,
      onCost: fail,
      onOutputDirReady: fail,
      onObserverError: (observer) => errors.push(observer),
    });
    expect(result.content).toBe(POLICY);
    expect(errors).toContain("onStage");
    expect(errors).toContain("onCost");
    expect(errors).toContain("onOutputDirReady");
    await f.security.close();
  });

  test("optional cost-tracking failures preserve the generated policy", async () => {
    const f = await setup();
    await writeFile(join(f.root, "codex-home", "sessions"), "not a directory");
    const warnings: string[] = [];
    const result = await f.security.generatePolicy(f.repository, {
      outputDir: f.outputDir,
      onWarning: (warning) => warnings.push(warning),
    });
    expect(result.content).toBe(POLICY);
    expect(result.cost?.inputTokens).toBe(300);
    expect(warnings.some((warning) => warning.includes("track"))).toBe(true);
    await f.security.close();
  });

  test("allows unavailable usage unless an explicit cost limit needs verification", async () => {
    for (const limited of [false, true]) {
      const f = await setup({
        stream: async function* (stage) {
          for await (const event of events(stage)) {
            if (event.type === "turn.completed") {
              throw new TypeError(
                "Cannot read properties of null (reading 'cache_write_input_tokens')",
              );
            }
            yield event;
          }
        },
      });
      const result = f.security.generatePolicy(f.repository, {
        outputDir: f.outputDir,
        ...(limited ? { maxCostUsd: 1 } : {}),
      });
      if (limited) await expect(result).rejects.toThrow("cost limit");
      else expect((await result).cost).toBeNull();
      await f.security.close();
    }
  });

  test("uses scan reconnect handling and rejects definitive access failures", async () => {
    const warnings: string[] = [];
    const f = await setup({
      stream: async function* (stage) {
        yield {
          type: "error",
          message: "Reconnecting... 1/5 (connection reset)",
        };
        yield* events(stage);
      },
    });
    expect(
      (
        await f.security.generatePolicy(f.repository, {
          outputDir: f.outputDir,
          onWarning: (warning) => warnings.push(warning),
        })
      ).content,
    ).toBe(POLICY);
    expect(warnings).toHaveLength(3);
    await f.security.close();

    const denied = await setup({
      stream: async function* () {
        yield {
          type: "error",
          message: "Reconnecting... 1/5 (HTTP 403 Forbidden)",
        };
        throw new Error("Must fail before retrying");
      },
    });
    await expect(
      denied.security.generatePolicy(denied.repository, {
        outputDir: denied.outputDir,
      }),
    ).rejects.toThrow("403 Forbidden");
    await denied.security.close();
  });

  test("rejects incomplete and invalid model responses", async () => {
    for (const response of ["incomplete", "invalid"] as const) {
      const f = await setup({
        stream: async function* () {
          yield { type: "thread.started", thread_id: "policy-failed" };
          if (response === "invalid") {
            yield {
              type: "item.completed",
              item: { id: "result", type: "agent_message", text: "not JSON" },
            };
            yield {
              type: "turn.completed",
              usage: {
                input_tokens: 0,
                cached_input_tokens: 0,
                cache_write_input_tokens: 0,
                output_tokens: 0,
                reasoning_output_tokens: 0,
              },
            };
          }
        },
      });
      await expect(
        f.security.generatePolicy(f.repository, { outputDir: f.outputDir }),
      ).rejects.toThrow(
        response === "invalid"
          ? "invalid document"
          : "before the turn completed",
      );
      expect(await readdir(f.repository)).toEqual([]);
      await f.security.close();
    }
  });

  test("stops when source inspection is blocked instead of synthesizing a policy", async () => {
    const f = await setup({
      stream: (stage) =>
        events(stage, {
          ...stageResult(stage),
          blockedReason: "The source-inspection sandbox could not start.",
        }),
    });
    await expect(
      f.security.generatePolicy(f.repository, { outputDir: f.outputDir }),
    ).rejects.toThrow("source-inspection sandbox could not start");
    expect(f.threads).toHaveLength(1);
    expect(await readdir(f.outputDir)).toContain("project-spec.md");
    expect(await readdir(f.outputDir)).not.toContain("policy-draft.json");
    expect(await readdir(f.repository)).toEqual([]);
    await f.security.close();
  });

  test("cancels through AbortSignal without writing source", async () => {
    const controller = new AbortController();
    const f = await setup({
      stream: async function* (stage) {
        yield { type: "thread.started", thread_id: `policy-${stage}` };
        controller.abort(new Error("cancel"));
        yield* events(stage);
      },
    });
    await expect(
      f.security.generatePolicy(f.repository, {
        outputDir: f.outputDir,
        signal: controller.signal,
      }),
    ).rejects.toThrow("interrupted");
    expect(await readdir(f.repository)).toEqual([]);
    await f.security.close();
  });

  test("close cancels an owner-question callback even if it never settles", async () => {
    const f = await setup();
    let entered!: () => void;
    const waiting = new Promise<void>((resolve) => {
      entered = resolve;
    });
    let promptSignal: AbortSignal | undefined;
    const generation = f.security.generatePolicy(f.repository, {
      outputDir: f.outputDir,
      answerQuestions: (_questions, signal) => {
        promptSignal = signal;
        entered();
        return new Promise(() => {});
      },
    });
    const interrupted = generation.catch((error: unknown) => error);
    await waiting;
    await f.security.close();
    expect(await interrupted).toMatchObject({
      message: expect.stringContaining("interrupted"),
    });
    expect(promptSignal?.aborted).toBe(true);
    expect(f.threads).toHaveLength(1);
    expect(await readdir(f.repository)).toEqual([]);
    expect(await readdir(f.outputDir)).not.toContain("policy-draft.json");
  });
});

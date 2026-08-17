import { execFileSync } from "node:child_process";
import {
  chmod,
  lstat,
  mkdir,
  open,
  readFile,
  readdir,
  rename,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import * as fsPromises from "node:fs/promises";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, mock, test } from "bun:test";
import { strToU8, zipSync } from "fflate";
import {
  SecurityPolicyRecoveryError,
  SecurityPolicyVerificationError,
} from "../src/errors.js";
import {
  applySecurityPolicy,
  loadSecurityPolicyDraft,
  readSecurityPolicy,
  resolveSecurityPolicyGuidance,
  resolveSecurityPolicyTarget,
  securityPolicyDiff,
  type SecurityPolicyStage,
} from "../src/security-policy.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { preparePersistentPolicyRoot } from "../src/runtime.js";
import { runMockInSubprocess } from "./support/isolated-mock.js";
import {
  POLICY,
  PYTHON,
  policyFixture,
  policyPlugin,
  stageResult,
} from "./support/security-policy.js";

const fixtures: Awaited<ReturnType<typeof policyFixture>>[] = [];
async function fixture() {
  const value = await policyFixture();
  fixtures.push(value);
  return value;
}
afterEach(async () => {
  await Promise.all(fixtures.splice(0).map((value) => value.cleanup()));
});

describe("security policy generation", () => {
  test("stores policy drafts separately from scans and rejects linked state children", async () => {
    const f = await fixture();
    const state = join(f.root, "state");
    const directory = await preparePersistentPolicyRoot(
      state,
      "sample project",
    );
    expect(directory).toBe(join(state, "policies", "sample-project"));
    if (process.platform !== "win32")
      expect((await stat(directory)).mode & 0o777).toBe(0o700);
    await symlink(
      f.repository,
      join(state, "policies", "linked"),
      process.platform === "win32" ? "junction" : "dir",
    );
    await expect(preparePersistentPolicyRoot(state, "linked")).rejects.toThrow(
      "Persistent policy output must use real directories",
    );
    expect(await readdir(f.repository)).toEqual([]);
  });

  test("keeps architecture, threat model, and policy separate and leaves source unchanged", async () => {
    const f = await fixture();
    const original = "# Existing policy\n\nReport privately.\n";
    await writeFile(join(f.repository, "SECURITY.md"), original);
    const stages: SecurityPolicyStage[] = [];
    const prompts: string[] = [];
    const draft = await f.generate({
      answerQuestions: async (questions) => {
        expect(questions).toEqual(["Is this service internet-facing?"]);
        return "Only authenticated clients can reach it.";
      },
      run: async (stage, prompt) => {
        stages.push(stage);
        prompts.push(prompt);
        if (stage === "threat_model")
          expect(
            await readFile(join(f.outputDir, "project-spec.md"), "utf8"),
          ).toContain("src/service.ts:1");
        if (stage === "policy")
          expect(
            await readFile(join(f.outputDir, "THREAT_MODEL.md"), "utf8"),
          ).toContain("src/service.ts:1");
        return stageResult(stage);
      },
    });
    expect(stages).toEqual(["architecture", "threat_model", "policy"]);
    expect(prompts[0]).toContain("Synthetic inherited guidance");
    expect(prompts[1]).toContain("Only authenticated clients can reach it.");
    expect(prompts[2]).toContain("Only authenticated clients can reach it.");
    expect(await readFile(draft.targetPath, "utf8")).toBe(original);
    expect(draft.previousContent).toBe(original);
    expect(await readFile(draft.draftPath, "utf8")).toBe(POLICY);
    expect(
      (await loadSecurityPolicyDraft(f.repository, f.outputDir)).content,
    ).toBe(POLICY);
    if (process.platform !== "win32")
      expect((await stat(draft.draftPath)).mode & 0o777).toBe(0o600);
  });

  test("infers the Git root while keeping a component as the policy scope", async () => {
    const f = await fixture();
    execFileSync("git", ["init", "--quiet", f.repository]);
    const component = join(f.repository, "services", "api");
    await mkdir(component, { recursive: true });
    await writeFile(
      join(f.repository, "SECURITY.md"),
      "# Root policy\nRoot invariant.\n",
    );
    const target = await resolveSecurityPolicyTarget(component);
    expect(target).toEqual({
      repository: f.repository,
      scope: "services/api",
      targetPath: join(component, "SECURITY.md"),
    });
    expect(
      await resolveSecurityPolicyGuidance(target, PYTHON, PLUGIN_ROOT),
    ).toContain("Root invariant.");
    expect(
      await resolveSecurityPolicyTarget(f.repository, "services/api"),
    ).toEqual(target);
  });

  test("does not silently drop inherited policies when Git is unavailable", async () => {
    const name =
      "does not silently drop inherited policies when Git is unavailable";
    if (runMockInSubprocess(import.meta.path, name)) return;
    const checkout = await fixture();
    const standalone = await fixture();
    execFileSync("git", ["init", "--quiet", checkout.repository]);
    const component = join(checkout.repository, "component");
    await mkdir(component);
    await writeFile(join(checkout.repository, "SECURITY.md"), POLICY);
    const pathEntries = Object.entries(process.env).filter(
      ([key]) => key.toUpperCase() === "PATH",
    );
    try {
      for (const [key] of pathEntries) delete process.env[key];
      process.env["PATH"] = "";
      await expect(resolveSecurityPolicyTarget(component)).rejects.toThrow(
        "Could not determine the Git worktree root",
      );
      expect(
        (await resolveSecurityPolicyTarget(standalone.repository)).repository,
      ).toBe(standalone.repository);
    } finally {
      delete process.env["PATH"];
      for (const [key, value] of pathEntries) process.env[key] = value;
    }
  });

  test("asks every material owner question in groups of at most three", async () => {
    const f = await fixture();
    const questions = [
      "Which endpoints are public?",
      "Who can deploy the service?",
      "Who can read backups?",
      "Which operators are trusted?",
      "Are tenants isolated?",
      "Who controls the identity provider?",
      "Which data needs retention limits?",
    ];
    const batches: string[][] = [];
    const draft = await f.generate({
      answerQuestions: async (batch) => {
        batches.push([...batch]);
        return `Owner answer ${batches.length}`;
      },
      run: async (stage, prompt) => {
        if (stage === "architecture")
          return { ...stageResult(stage), questions };
        for (const question of questions) expect(prompt).toContain(question);
        for (let index = 1; index <= 3; index++)
          expect(prompt).toContain(`Owner answer ${index}`);
        return stageResult(stage);
      },
    });
    expect(batches).toEqual([
      questions.slice(0, 3),
      questions.slice(3, 6),
      questions.slice(6),
    ]);
    for (const question of questions)
      expect(draft.reviewNotes).toContain(question);
  });

  test("carries unanswered questions and review decisions into the final policy", async () => {
    const f = await fixture();
    const draft = await f.generate({
      run: async (stage, prompt) => {
        if (stage === "architecture") {
          return {
            ...stageResult(stage),
            questions: ["Who can deploy the service?"],
            reviewNotes: ["Confirm the operator trust boundary."],
          };
        }
        expect(prompt).toContain("Who can deploy the service?");
        expect(prompt).toContain("Confirm the operator trust boundary.");
        if (stage === "threat_model") {
          return {
            ...stageResult(stage),
            questions: ["Are backups isolated by tenant?"],
            reviewNotes: ["Review backup access."],
          };
        }
        expect(prompt).toContain("Are backups isolated by tenant?");
        expect(prompt).toContain("Review backup access.");
        return {
          ...stageResult(stage),
          questions: ["Confirm backup isolation."],
          reviewNotes: [
            "Review deployment scope.",
            "Confirm backup isolation.",
          ],
        };
      },
    });
    expect(draft.reviewNotes).toEqual([
      "Review deployment scope.",
      "Confirm backup isolation.",
      "Confirm the operator trust boundary.",
      "Who can deploy the service?",
      "Review backup access.",
      "Are backups isolated by tenant?",
    ]);
    expect(
      (await loadSecurityPolicyDraft(f.repository, f.outputDir)).reviewNotes,
    ).toEqual(draft.reviewNotes);
  });

  test("rejects files, outside paths, and outside directory links", async () => {
    const f = await fixture();
    await writeFile(join(f.repository, "source.ts"), "export {};\n");
    await symlink(
      f.outputDir,
      join(f.repository, "external"),
      process.platform === "win32" ? "junction" : "dir",
    );
    await expect(
      resolveSecurityPolicyTarget(f.repository, "source.ts"),
    ).rejects.toThrow("must be a directory");
    await expect(
      resolveSecurityPolicyTarget(f.repository, ".."),
    ).rejects.toThrow("outside the repository");
    await expect(
      resolveSecurityPolicyTarget(f.repository, "external"),
    ).rejects.toThrow("outside the repository");
  });

  test("retains completed evidence when a later stage is interrupted", async () => {
    const f = await fixture();
    const controller = new AbortController();
    await expect(
      f.generate({
        signal: controller.signal,
        run: async (stage) => {
          if (stage === "threat_model") controller.abort(new Error("stop"));
          return stageResult(stage);
        },
      }),
    ).rejects.toThrow("stop");
    expect(
      await readFile(join(f.outputDir, "project-spec.md"), "utf8"),
    ).toContain("src/service.ts:1");
    expect(await readdir(f.repository)).toEqual([]);
    await expect(
      loadSecurityPolicyDraft(f.repository, f.outputDir),
    ).rejects.toThrow();
  });

  test("rejects empty or oversized policy documents", async () => {
    for (const markdown of [
      "not a Markdown policy",
      "# Policy\n\ud800",
      `# Policy\n${"x".repeat(1024 * 1024)}`,
    ]) {
      const f = await fixture();
      await expect(
        f.generate({
          run: async (stage) => ({
            ...stageResult(stage),
            ...(stage === "policy" ? { markdown } : {}),
          }),
        }),
      ).rejects.toThrow();
      expect(await readdir(f.repository)).toEqual([]);
    }
  });

  test("enforces the resolver byte limit on existing policies and saved files", async () => {
    const header = "# Policy\n";
    const maximum =
      header + "x".repeat(1024 * 1024 - Buffer.byteLength(header));
    const existing = await fixture();
    const target = join(existing.repository, "SECURITY.md");
    await writeFile(target, maximum);
    expect(await readSecurityPolicy(target)).toBe(maximum);
    await writeFile(target, `${maximum}x`);
    await expect(existing.generate()).rejects.toThrow("1 MiB limit");
    expect(await readdir(existing.outputDir)).toEqual([]);

    const saved = await fixture();
    const draft = await saved.generate();
    await writeFile(draft.draftPath, `${maximum}x`);
    await expect(
      loadSecurityPolicyDraft(saved.repository, saved.outputDir),
    ).rejects.toThrow("1 MiB limit");
    await writeFile(draft.draftPath, POLICY);
    await writeFile(
      join(saved.outputDir, "previous-SECURITY.md"),
      `${maximum}x`,
    );
    await expect(
      loadSecurityPolicyDraft(saved.repository, saved.outputDir),
    ).rejects.toThrow("1 MiB limit");
  });
});

describe("security policy review and application", () => {
  test("previews a real diff and applies a new policy accepted by the resolver", async () => {
    const f = await fixture();
    const draft = await f.generate();
    const diff = await securityPolicyDiff(draft, PYTHON);
    expect(diff).toContain("--- /dev/null\n+++ b/SECURITY.md\n");
    expect(diff).toContain("+Requests must be authorized");
    expect(await applySecurityPolicy(draft)).toEqual({
      targetPath: draft.targetPath,
      recoveryPath: null,
    });
    expect(await readFile(draft.targetPath, "utf8")).toBe(POLICY);
    expect(
      await resolveSecurityPolicyGuidance(draft, PYTHON, PLUGIN_ROOT),
    ).toContain(POLICY.trim());
    expect(await readdir(f.repository)).toEqual(["SECURITY.md"]);
  });

  test("allows edits to a saved draft and writes the exact reviewed bytes", async () => {
    const f = await fixture();
    const original = "# Security Policy\n\nOriginal guidance.\n";
    await writeFile(join(f.repository, "SECURITY.md"), original);
    if (process.platform !== "win32")
      await chmod(join(f.repository, "SECURITY.md"), 0o640);
    await f.generate();
    const edited = `${POLICY}\nOwner-confirmed scope.\n`;
    await writeFile(join(f.outputDir, "SECURITY.md"), edited);
    const draft = await loadSecurityPolicyDraft(f.repository, f.outputDir);
    await writeFile(draft.draftPath, "# Later unreviewed edit\n");
    await applySecurityPolicy(draft);
    expect(await readFile(draft.targetPath, "utf8")).toBe(edited);
    if (process.platform !== "win32")
      expect((await stat(draft.targetPath)).mode & 0o777).toBe(0o640);
  });

  test("rejects malformed UTF-8 in existing policies and saved drafts", async () => {
    const f = await fixture();
    const malformed = Buffer.concat([
      Buffer.from("# Policy\n"),
      Buffer.from([0xe9]),
    ]);
    const draft = await f.generate();
    await writeFile(draft.draftPath, malformed);
    await expect(
      loadSecurityPolicyDraft(f.repository, f.outputDir),
    ).rejects.toThrow("valid UTF-8");
    expect(await readdir(f.repository)).toEqual([]);
    await writeFile(draft.targetPath, malformed);
    await expect(resolveSecurityPolicyTarget(f.repository)).rejects.toThrow(
      "valid UTF-8",
    );
    expect(await readFile(draft.targetPath)).toEqual(malformed);
  });

  test("preserves a valid UTF-8 byte-order mark in a reviewed draft", async () => {
    const f = await fixture();
    const draft = await f.generate();
    const bytes = Buffer.from(
      "\uFEFF# Security Policy\r\n\r\nReviewed text.\r\n",
    );
    await writeFile(draft.draftPath, bytes);
    const loaded = await loadSecurityPolicyDraft(f.repository, f.outputDir);
    await applySecurityPolicy(loaded);
    expect(await readFile(draft.targetPath)).toEqual(bytes);
  });

  test("uses the selected plugin and requires an explicit selection for saved custom drafts", async () => {
    const f = await fixture();
    const log = join(f.root, "resolver.log");
    const pluginPath = await policyPlugin(
      f.root,
      [
        "import os, pathlib",
        "with pathlib.Path(os.environ['POLICY_TEST_LOG']).open('a') as output:",
        "    output.write('custom resolver\\n')",
        "print('custom guidance')",
      ].join("\n"),
    );
    const draft = await f.generate({ pluginPath });
    const manifestPath = join(f.outputDir, "policy-draft.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    expect(manifest.customPlugin).toBe(true);
    expect(manifest).not.toHaveProperty("pluginPath");
    await writeFile(
      manifestPath,
      JSON.stringify({ ...manifest, pluginPath: "/unapproved/plugin" }),
    );
    const saved = await loadSecurityPolicyDraft(f.repository, f.outputDir);
    expect(saved.pluginPath).toBeUndefined();
    await expect(applySecurityPolicy(saved)).rejects.toThrow(
      "Select it explicitly",
    );
    expect(await readdir(f.repository)).toEqual([]);
    await applySecurityPolicy(draft, {
      pythonPath: PYTHON,
      environment: { ...process.env, POLICY_TEST_LOG: log },
    });
    expect(await readFile(log, "utf8")).toBe(
      "custom resolver\ncustom resolver\n",
    );
    expect(await readFile(draft.targetPath, "utf8")).toBe(POLICY);
  });

  test("applies a saved draft with an explicitly selected plugin ZIP", async () => {
    const f = await fixture();
    const log = join(f.root, "resolver-paths.log");
    const archive = join(f.root, "policy-plugin.zip");
    const script = [
      "import os, pathlib",
      "with pathlib.Path(os.environ['POLICY_TEST_LOG']).open('a') as output:",
      "    output.write(str(pathlib.Path(__file__).resolve()) + '\\n')",
      "print('custom guidance')",
    ].join("\n");
    await writeFile(
      archive,
      zipSync({
        ".codex-plugin/plugin.json": strToU8(
          JSON.stringify({
            name: "codex-security",
            version: "test-policy-plugin",
          }),
        ),
        "scripts/resolve_security_md.py": strToU8(script),
      }),
    );
    await f.generate({ pluginPath: archive });
    const saved = await loadSecurityPolicyDraft(f.repository, f.outputDir);
    await applySecurityPolicy(saved, {
      pluginPath: archive,
      pythonPath: PYTHON,
      environment: { ...process.env, POLICY_TEST_LOG: log },
    });
    expect(await readFile(saved.targetPath, "utf8")).toBe(POLICY);
    const resolverPaths = (await readFile(log, "utf8")).trim().split("\n");
    expect(resolverPaths).toHaveLength(2);
    for (const path of resolverPaths)
      await expect(stat(path)).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("checks the selected resolver before changing repository files", async () => {
    const f = await fixture();
    const pluginPath = await policyPlugin(
      f.root,
      "raise SystemExit('synthetic preflight failure')\n",
    );
    const draft = await f.generate({ pluginPath });
    await expect(applySecurityPolicy(draft)).rejects.toThrow(
      "synthetic preflight failure",
    );
    expect(await readdir(f.repository)).toEqual([]);
  });

  test("reports a committed policy when post-write verification fails", async () => {
    const f = await fixture();
    const pluginPath = await policyPlugin(
      f.root,
      [
        "import pathlib, sys",
        "root = pathlib.Path(sys.argv[sys.argv.index('--repo') + 1])",
        "if (root / 'SECURITY.md').exists(): raise SystemExit('synthetic verification failure')",
        "print('preflight passed')",
      ].join("\n"),
    );
    const draft = await f.generate({ pluginPath });
    const error = await applySecurityPolicy(draft).catch(
      (value: unknown) => value,
    );
    expect(error).toBeInstanceOf(SecurityPolicyVerificationError);
    expect(error).toMatchObject({ targetPath: draft.targetPath });
    expect(await readFile(draft.targetPath, "utf8")).toBe(POLICY);
  });

  test("rechecks the reviewed bytes after the resolver returns", async () => {
    for (const change of ["remove", "replace"] as const) {
      const f = await fixture();
      const original = "# Original policy\n";
      await writeFile(join(f.repository, "SECURITY.md"), original);
      const pluginPath = await policyPlugin(
        f.root,
        [
          "import pathlib, sys",
          "root = pathlib.Path(sys.argv[sys.argv.index('--repo') + 1])",
          "target = root / 'SECURITY.md'",
          `if target.read_text() == ${JSON.stringify(POLICY)}:`,
          change === "remove"
            ? "    target.unlink()"
            : "    target.write_text('# Concurrent policy\\n')",
          "print('resolver accepted the current policy chain')",
        ].join("\n"),
      );
      const draft = await f.generate({ pluginPath });
      const error = await applySecurityPolicy(draft).catch(
        (value: unknown) => value,
      );
      expect(error).toBeInstanceOf(SecurityPolicyVerificationError);
      const recovery = error as SecurityPolicyVerificationError;
      expect(await readFile(recovery.recoveryPath!, "utf8")).toBe(original);
      expect(await readSecurityPolicy(draft.targetPath)).toBe(
        change === "remove" ? null : "# Concurrent policy\n",
      );
    }
  });

  test("creates policies without hard-link support and never clobbers a racing file", async () => {
    const name =
      "creates policies without hard-link support and never clobbers a racing file";
    if (runMockInSubprocess(import.meta.path, name)) return;
    const originalLink = fsPromises.link;
    let collision = false;
    mock.module("node:fs/promises", () => ({
      ...fsPromises,
      link: async (_source: string, destination: string) => {
        if (collision) await writeFile(destination, "# Concurrent policy\n");
        throw Object.assign(new Error("hard links are unsupported"), {
          code: "ENOTSUP",
        });
      },
    }));
    try {
      const f = await fixture();
      const draft = await f.generate();
      await applySecurityPolicy(draft);
      expect(await readFile(draft.targetPath, "utf8")).toBe(POLICY);
      const existing = await fixture();
      await writeFile(
        join(existing.repository, "SECURITY.md"),
        "# Existing policy\n",
      );
      const replacement = await existing.generate();
      await applySecurityPolicy(replacement);
      expect(await readFile(replacement.targetPath, "utf8")).toBe(POLICY);
      expect(await readdir(existing.repository)).toEqual(["SECURITY.md"]);
      const other = await fixture();
      const racing = await other.generate();
      collision = true;
      await expect(applySecurityPolicy(racing)).rejects.toMatchObject({
        code: "EEXIST",
      });
      expect(await readFile(racing.targetPath, "utf8")).toBe(
        "# Concurrent policy\n",
      );
    } finally {
      mock.module("node:fs/promises", () => ({
        ...fsPromises,
        link: originalLink,
      }));
    }
  });

  test("restores a concurrent save captured immediately before replacement", async () => {
    const name =
      "restores a concurrent save captured immediately before replacement";
    if (runMockInSubprocess(import.meta.path, name)) return;
    const f = await fixture();
    await writeFile(join(f.repository, "SECURITY.md"), "# Original policy\n");
    const draft = await f.generate();
    const concurrent = "# Concurrent save\n";
    const originalRename = fsPromises.rename;
    mock.module("node:fs/promises", () => ({
      ...fsPromises,
      rename: async (source: string, destination: string) => {
        if (source === draft.targetPath) await writeFile(source, concurrent);
        await originalRename(source, destination);
      },
    }));
    try {
      const error = await applySecurityPolicy(draft).catch(
        (value: unknown) => value,
      );
      expect(error).toBeInstanceOf(SecurityPolicyRecoveryError);
      const recovery = error as SecurityPolicyRecoveryError;
      expect(dirname(recovery.recoveryPath)).toBe(f.outputDir);
      expect(await readFile(recovery.recoveryPath, "utf8")).toBe(concurrent);
      expect(await readFile(draft.targetPath, "utf8")).toBe(concurrent);
      expect(await readdir(f.repository)).toEqual(["SECURITY.md"]);
    } finally {
      mock.module("node:fs/promises", () => ({
        ...fsPromises,
        rename: originalRename,
      }));
    }
  });

  test("keeps both files when a concurrent writer claims the destination", async () => {
    const name =
      "keeps both files when a concurrent writer claims the destination";
    if (runMockInSubprocess(import.meta.path, name)) return;
    const f = await fixture();
    const original = "# Original policy\n";
    const concurrent = "# Concurrent save\n";
    await writeFile(join(f.repository, "SECURITY.md"), original);
    const draft = await f.generate();
    const originalLink = fsPromises.link;
    mock.module("node:fs/promises", () => ({
      ...fsPromises,
      link: async (source: string, destination: string) => {
        if (destination === draft.targetPath && source.endsWith(".tmp"))
          await writeFile(destination, concurrent);
        await originalLink(source, destination);
      },
    }));
    try {
      const error = await applySecurityPolicy(draft).catch(
        (value: unknown) => value,
      );
      expect(error).toBeInstanceOf(SecurityPolicyRecoveryError);
      const recovery = error as SecurityPolicyRecoveryError;
      expect(recovery.targetPath).toBe(draft.targetPath);
      expect(dirname(recovery.recoveryPath)).toBe(f.outputDir);
      expect(await readFile(recovery.recoveryPath, "utf8")).toBe(original);
      expect(await readFile(draft.targetPath, "utf8")).toBe(concurrent);
      expect(await readdir(f.repository)).toEqual(["SECURITY.md"]);
    } finally {
      mock.module("node:fs/promises", () => ({
        ...fsPromises,
        link: originalLink,
      }));
    }
  });

  test("keeps a recovery copy changed through an already-open file", async () => {
    const name = "keeps a recovery copy changed through an already-open file";
    if (runMockInSubprocess(import.meta.path, name)) return;
    const f = await fixture();
    await writeFile(join(f.repository, "SECURITY.md"), "# Original policy\n");
    const draft = await f.generate();
    const concurrent = "# Concurrent in-place save\n";
    const writer = await open(draft.targetPath, "r+");
    const originalLink = fsPromises.link;
    mock.module("node:fs/promises", () => ({
      ...fsPromises,
      link: async (source: string, destination: string) => {
        await originalLink(source, destination);
        if (destination === draft.targetPath && source.endsWith(".tmp")) {
          await writer.truncate(0);
          await writer.writeFile(concurrent);
        }
      },
    }));
    try {
      const error = await applySecurityPolicy(draft).catch(
        (value: unknown) => value,
      );
      expect(error).toBeInstanceOf(SecurityPolicyVerificationError);
      const recovery = error as SecurityPolicyVerificationError;
      expect(recovery.targetPath).toBe(draft.targetPath);
      expect(dirname(recovery.recoveryPath!)).toBe(f.outputDir);
      expect(await readFile(recovery.recoveryPath!, "utf8")).toBe(concurrent);
      expect(await readFile(draft.targetPath, "utf8")).toBe(POLICY);
    } finally {
      await writer.close();
      mock.module("node:fs/promises", () => ({
        ...fsPromises,
        link: originalLink,
      }));
    }
  });

  test("retains late writes to the displaced file after successful application", async () => {
    const f = await fixture();
    const original = "# Original policy\n";
    const late = "# Save after application completed\n";
    await writeFile(join(f.repository, "SECURITY.md"), original);
    const draft = await f.generate();
    const writer = await open(draft.targetPath, "r+");
    try {
      const applied = await applySecurityPolicy(draft);
      expect(applied.targetPath).toBe(draft.targetPath);
      expect(dirname(applied.recoveryPath!)).toBe(f.outputDir);
      await writer.truncate(0);
      await writer.writeFile(late);
      expect(await readFile(applied.recoveryPath!, "utf8")).toBe(late);
      expect(await readFile(draft.targetPath, "utf8")).toBe(POLICY);
      expect(
        await readFile(join(f.outputDir, "previous-SECURITY.md"), "utf8"),
      ).toBe(original);
      expect(await readdir(f.repository)).toEqual(["SECURITY.md"]);
    } finally {
      await writer.close();
    }
  });

  test("keeps the original inode beside the target across filesystem boundaries", async () => {
    const name =
      "keeps the original inode beside the target across filesystem boundaries";
    if (runMockInSubprocess(import.meta.path, name)) return;
    const f = await fixture();
    await writeFile(join(f.repository, "SECURITY.md"), "# Original policy\n");
    const draft = await f.generate();
    const writer = await open(draft.targetPath, "r+");
    const originalRename = fsPromises.rename;
    mock.module("node:fs/promises", () => ({
      ...fsPromises,
      rename: async (source: string, destination: string) => {
        if (
          source.endsWith(".previous") &&
          dirname(destination) === f.outputDir
        )
          throw Object.assign(new Error("different filesystem"), {
            code: "EXDEV",
          });
        await originalRename(source, destination);
      },
    }));
    try {
      const applied = await applySecurityPolicy(draft);
      expect(dirname(applied.recoveryPath!)).toBe(f.repository);
      await writer.truncate(0);
      await writer.writeFile("# Late save\n");
      expect(await readFile(applied.recoveryPath!, "utf8")).toBe(
        "# Late save\n",
      );
      expect(await readFile(draft.targetPath, "utf8")).toBe(POLICY);
      expect(
        (await readdir(f.outputDir)).filter((path) =>
          path.startsWith("recovery-SECURITY-"),
        ),
      ).toEqual([]);
    } finally {
      await writer.close();
      mock.module("node:fs/promises", () => ({
        ...fsPromises,
        rename: originalRename,
      }));
    }
  });

  test("retains open-writer data when rollback must copy instead of hard-link", async () => {
    const name =
      "retains open-writer data when rollback must copy instead of hard-link";
    if (runMockInSubprocess(import.meta.path, name)) return;
    const f = await fixture();
    const original = "# Original policy\n";
    await writeFile(join(f.repository, "SECURITY.md"), original);
    const draft = await f.generate();
    const writer = await open(draft.targetPath, "r+");
    const controller = new AbortController();
    const originalRename = fsPromises.rename;
    const originalLink = fsPromises.link;
    mock.module("node:fs/promises", () => ({
      ...fsPromises,
      rename: async (source: string, destination: string) => {
        await originalRename(source, destination);
        if (source === draft.targetPath)
          controller.abort("cancel before install");
      },
      link: async () => {
        throw Object.assign(new Error("hard links are unsupported"), {
          code: "ENOTSUP",
        });
      },
    }));
    try {
      const error = await applySecurityPolicy(draft, {
        signal: controller.signal,
      }).catch((value: unknown) => value);
      expect(error).toBeInstanceOf(SecurityPolicyRecoveryError);
      const recovery = error as SecurityPolicyRecoveryError;
      await writer.truncate(0);
      await writer.writeFile("# Late rollback save\n");
      expect(await readFile(recovery.recoveryPath, "utf8")).toBe(
        "# Late rollback save\n",
      );
      expect(await readFile(draft.targetPath, "utf8")).toBe(original);
    } finally {
      await writer.close();
      mock.module("node:fs/promises", () => ({
        ...fsPromises,
        rename: originalRename,
        link: originalLink,
      }));
    }
  });

  test("validates the recovery directory before replacing an existing policy", async () => {
    const f = await fixture();
    const original = "# Original policy\n";
    await writeFile(join(f.repository, "SECURITY.md"), original);
    const draft = await f.generate();
    const inside = join(f.repository, "artifacts");
    await mkdir(inside, { mode: 0o700 });
    await writeFile(
      join(inside, "policy-draft.json"),
      await readFile(join(f.outputDir, "policy-draft.json")),
    );
    await expect(
      applySecurityPolicy({ ...draft, outputDir: inside }),
    ).rejects.toThrow("outside the protected scan root");
    expect(await readFile(draft.targetPath, "utf8")).toBe(original);
    expect((await readdir(f.repository)).sort()).toEqual([
      "SECURITY.md",
      "artifacts",
    ]);
  });

  test("restores the original policy when canceled after moving it", async () => {
    const name = "restores the original policy when canceled after moving it";
    if (runMockInSubprocess(import.meta.path, name)) return;
    const f = await fixture();
    const original = "# Original policy\n";
    await writeFile(join(f.repository, "SECURITY.md"), original);
    const draft = await f.generate();
    const controller = new AbortController();
    const originalRename = fsPromises.rename;
    mock.module("node:fs/promises", () => ({
      ...fsPromises,
      rename: async (source: string, destination: string) => {
        await originalRename(source, destination);
        if (source === draft.targetPath)
          controller.abort(new Error("cancel before install"));
      },
    }));
    try {
      const error = await applySecurityPolicy(draft, {
        signal: controller.signal,
      }).catch((value: unknown) => value);
      expect(error).toBeInstanceOf(SecurityPolicyRecoveryError);
      expect(
        await readFile(
          (error as SecurityPolicyRecoveryError).recoveryPath,
          "utf8",
        ),
      ).toBe(original);
      expect(await readFile(draft.targetPath, "utf8")).toBe(original);
      expect(await readdir(f.repository)).toEqual(["SECURITY.md"]);
    } finally {
      mock.module("node:fs/promises", () => ({
        ...fsPromises,
        rename: originalRename,
      }));
    }
  });

  test("does not follow a symlink that races with an existing policy", async () => {
    const name = "does not follow a symlink that races with an existing policy";
    if (runMockInSubprocess(import.meta.path, name)) return;
    const f = await fixture();
    await writeFile(join(f.repository, "SECURITY.md"), "# Original policy\n");
    const draft = await f.generate();
    const outside = join(f.root, "outside-policy.md");
    await writeFile(outside, "# Outside policy\n");
    const originalRename = fsPromises.rename;
    mock.module("node:fs/promises", () => ({
      ...fsPromises,
      rename: async (source: string, destination: string) => {
        if (source === draft.targetPath) {
          await rm(source);
          await symlink(outside, source, "file");
        }
        await originalRename(source, destination);
      },
    }));
    try {
      const error = await applySecurityPolicy(draft).catch(
        (value: unknown) => value,
      );
      expect(error).toBeInstanceOf(SecurityPolicyRecoveryError);
      expect(
        (
          await lstat((error as SecurityPolicyRecoveryError).recoveryPath)
        ).isSymbolicLink(),
      ).toBe(true);
      expect(await readFile(outside, "utf8")).toBe("# Outside policy\n");
      await expect(lstat(draft.targetPath)).rejects.toMatchObject({
        code: "ENOENT",
      });
    } finally {
      mock.module("node:fs/promises", () => ({
        ...fsPromises,
        rename: originalRename,
      }));
    }
  });

  test.skipIf(process.platform === "win32")(
    "preserves an existing policy mode under a restrictive umask",
    async () => {
      const name =
        "preserves an existing policy mode under a restrictive umask";
      if (runMockInSubprocess(import.meta.path, name)) return;
      const f = await fixture();
      const target = join(f.repository, "SECURITY.md");
      await writeFile(target, "# Existing policy\n");
      await chmod(target, 0o644);
      const draft = await f.generate();
      const previous = process.umask(0o077);
      try {
        await applySecurityPolicy(draft);
        expect((await stat(target)).mode & 0o777).toBe(0o644);
      } finally {
        process.umask(previous);
      }
    },
  );

  test("finishes verification when cancellation arrives after the write commits", async () => {
    const name =
      "finishes verification when cancellation arrives after the write commits";
    if (runMockInSubprocess(import.meta.path, name)) return;
    const originalLink = fsPromises.link;
    const originalRename = fsPromises.rename;
    for (const existing of [false, true]) {
      const f = await fixture();
      if (existing)
        await writeFile(
          join(f.repository, "SECURITY.md"),
          "# Existing policy\n",
        );
      const draft = await f.generate();
      const controller = new AbortController();
      mock.module("node:fs/promises", () => ({
        ...fsPromises,
        link: async (source: string, destination: string) => {
          await originalLink(source, destination);
          if (destination === draft.targetPath)
            controller.abort(new Error("cancel after commit"));
        },
        rename: async (source: string, destination: string) => {
          await originalRename(source, destination);
          if (destination === draft.targetPath)
            controller.abort(new Error("cancel after commit"));
        },
      }));
      try {
        const applied = await applySecurityPolicy(draft, {
          pythonPath: PYTHON,
          signal: controller.signal,
        });
        expect(applied.targetPath).toBe(draft.targetPath);
        expect(applied.recoveryPath === null).toBe(!existing);
        expect(controller.signal.aborted).toBe(true);
        expect(await readFile(draft.targetPath, "utf8")).toBe(POLICY);
      } finally {
        mock.module("node:fs/promises", () => ({
          ...fsPromises,
          link: originalLink,
          rename: originalRename,
        }));
      }
    }
  });

  test("shows missing final newlines in the exact diff", async () => {
    const f = await fixture();
    await writeFile(join(f.repository, "SECURITY.md"), "# Old policy");
    const draft = await f.generate({
      run: async (stage) => ({
        ...stageResult(stage),
        ...(stage === "policy" ? { markdown: "# New policy" } : {}),
      }),
    });
    const diff = await securityPolicyDiff(draft, PYTHON);
    expect(diff).toContain("-# Old policy\n\\ No newline at end of file\n");
    expect(diff).toContain("+# New policy\n\\ No newline at end of file\n");
  });

  test("reports an early diff subprocess exit without an unhandled stdin error", async () => {
    const name =
      "reports an early diff subprocess exit without an unhandled stdin error";
    if (runMockInSubprocess(import.meta.path, name)) return;
    const f = await fixture();
    const draft = await f.generate();
    const node = execFileSync("node", ["-p", "process.execPath"], {
      encoding: "utf8",
    }).trim();
    await expect(
      securityPolicyDiff(
        { ...draft, content: `# Policy\n${"x".repeat(900_000)}` },
        node,
      ),
    ).rejects.toThrow();
    expect(await readdir(f.repository)).toEqual([]);
  });

  test("preserves UTF-8 text and CRLF content independently of Python's locale", async () => {
    const f = await fixture();
    await writeFile(
      join(f.repository, "SECURITY.md"),
      "# Policy\r\n\r\nOld naïve 🔒\r\n",
    );
    const draft = await f.generate({
      run: async (stage) => ({
        ...stageResult(stage),
        ...(stage === "policy"
          ? { markdown: "# Policy\r\n\r\nNew π 🛡️\r\n" }
          : {}),
      }),
    });
    const diff = await securityPolicyDiff(draft, PYTHON);
    expect(diff).toContain("--- a/SECURITY.md\n+++ b/SECURITY.md\n");
    expect(diff).toContain("-Old naïve 🔒\r\n");
    expect(diff).toContain("+New π 🛡️\r\n");
    expect(diff).not.toContain("\r\r\n");
  });

  test.skipIf(process.platform === "win32")(
    "quotes control characters in repository-controlled diff labels",
    async () => {
      const f = await fixture();
      const scope = "component\n+++ forged\tname";
      await mkdir(join(f.repository, scope));
      const draft = await f.generate({ path: scope });
      const diff = await securityPolicyDiff(draft, PYTHON);
      expect(diff).toContain(
        `+++ ${JSON.stringify(`b/${scope}/SECURITY.md`)}\n`,
      );
      expect(diff).not.toContain("\n+++ forged");
      expect(diff).not.toContain("\tname");
    },
  );

  test("escapes every Unicode direction control in diff labels", async () => {
    const f = await fixture();
    const controls =
      "\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069";
    const scope = `component${controls}name`;
    await mkdir(join(f.repository, scope));
    const draft = await f.generate({ path: scope });
    const diff = await securityPolicyDiff(draft, PYTHON);
    expect(diff).not.toMatch(/\p{Bidi_Control}/u);
    for (const character of controls)
      expect(diff).toContain(
        `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`,
      );
  });

  test("checks source freshness even for an unchanged draft", async () => {
    const f = await fixture();
    await writeFile(join(f.repository, "SECURITY.md"), POLICY);
    const draft = await f.generate();
    expect(await securityPolicyDiff(draft, "missing-python")).toBe("");
    expect(
      await applySecurityPolicy(draft, { pythonPath: "missing-python" }),
    ).toEqual({ targetPath: draft.targetPath, recoveryPath: null });
    await writeFile(draft.targetPath, "# Concurrent policy\n");
    await expect(securityPolicyDiff(draft, PYTHON)).rejects.toThrow(
      "changed after",
    );
    await expect(applySecurityPolicy(draft)).rejects.toThrow("changed after");
  });

  test("invalidates saved component drafts when inherited policies change", async () => {
    for (const change of ["edit", "add", "remove"] as const) {
      const f = await fixture();
      const component = join(f.repository, "services", "api");
      const rootPolicy = join(f.repository, "SECURITY.md");
      await mkdir(component, { recursive: true });
      await writeFile(rootPolicy, "# Root policy\n");
      if (change === "edit")
        await writeFile(join(component, "SECURITY.md"), POLICY);
      const generated = await f.generate({ path: "services/api" });
      const draft = await loadSecurityPolicyDraft(f.repository, f.outputDir, {
        path: "services/api",
      });
      expect(draft.inheritedPolicySha256).toBe(generated.inheritedPolicySha256);
      if (change === "edit") await writeFile(rootPolicy, "# New root policy\n");
      else if (change === "add")
        await writeFile(
          join(f.repository, "services", "SECURITY.md"),
          "# New intermediate policy\n",
        );
      else await rm(rootPolicy);
      await expect(securityPolicyDiff(draft, "missing-python")).rejects.toThrow(
        "inherited SECURITY.md changed",
      );
      await expect(
        applySecurityPolicy(draft, { pythonPath: "missing-python" }),
      ).rejects.toThrow("inherited SECURITY.md changed");
      expect(await readSecurityPolicy(draft.targetPath)).toBe(
        draft.previousContent,
      );
    }
  });

  test("tracks safe inherited policy links and rejects outside links", async () => {
    const f = await fixture();
    const linkedPolicy = join(f.repository, "owner-policy.md");
    await mkdir(join(f.repository, "component"));
    await writeFile(linkedPolicy, "# Owner policy\n");
    await symlink(linkedPolicy, join(f.repository, "SECURITY.md"), "file");
    const draft = await f.generate({ path: "component" });
    expect(await securityPolicyDiff(draft, PYTHON)).toContain(
      "b/component/SECURITY.md",
    );
    await writeFile(linkedPolicy, "# Changed owner policy\n");
    await expect(applySecurityPolicy(draft)).rejects.toThrow(
      "inherited SECURITY.md changed",
    );

    const outside = await fixture();
    await mkdir(join(outside.repository, "component"));
    const outsidePolicy = join(outside.root, "outside-policy.md");
    await writeFile(outsidePolicy, "# Outside policy\n");
    await symlink(
      outsidePolicy,
      join(outside.repository, "SECURITY.md"),
      "file",
    );
    await expect(outside.generate({ path: "component" })).rejects.toThrow(
      "outside the repository",
    );
    expect(await readdir(outside.outputDir)).toEqual([]);
  });

  test("checks inherited policies around application and verification", async () => {
    for (const timing of ["before", "after"] as const) {
      const f = await fixture();
      await mkdir(join(f.repository, "component"));
      await writeFile(join(f.repository, "SECURITY.md"), "# Root policy\n");
      const pluginPath = await policyPlugin(
        f.root,
        [
          "import pathlib, sys",
          "root = pathlib.Path(sys.argv[sys.argv.index('--repo') + 1])",
          "target = root / 'component' / 'SECURITY.md'",
          `if ${timing === "before" ? "not " : ""}target.exists():`,
          "    (root / 'SECURITY.md').write_text('# New root policy\\n')",
          "print('resolver accepted the current policy chain')",
        ].join("\n"),
      );
      const draft = await f.generate({ path: "component", pluginPath });
      const error = await applySecurityPolicy(draft).catch(
        (value: unknown) => value,
      );
      if (timing === "before")
        expect(String(error)).toContain("inherited SECURITY.md changed");
      else expect(error).toBeInstanceOf(SecurityPolicyVerificationError);
      expect(await readSecurityPolicy(draft.targetPath)).toBe(
        timing === "before" ? null : POLICY,
      );
    }
  });

  test("honors cancellation before applying a draft", async () => {
    const f = await fixture();
    const draft = await f.generate();
    const signal = AbortSignal.abort(new Error("canceled"));
    await expect(
      applySecurityPolicy(draft, { pythonPath: PYTHON, signal }),
    ).rejects.toThrow("canceled");
    expect(await readdir(f.repository)).toEqual([]);
  });

  test("does not overwrite a policy changed after generation", async () => {
    const f = await fixture();
    const draft = await f.generate();
    await writeFile(draft.targetPath, "# Someone else's new policy\n");
    await expect(applySecurityPolicy(draft)).rejects.toThrow("changed after");
    expect(await readFile(draft.targetPath, "utf8")).toBe(
      "# Someone else's new policy\n",
    );
  });

  test("binds saved drafts to the explicitly selected repository and component", async () => {
    const f = await fixture();
    await mkdir(join(f.repository, "component"));
    await f.generate({ path: "component" });
    await expect(
      loadSecurityPolicyDraft(f.repository, f.outputDir),
    ).rejects.toThrow("different repository or component");
    const draft = await loadSecurityPolicyDraft(f.repository, f.outputDir, {
      path: "component",
    });
    expect(draft.scope).toBe("component");
    const other = await fixture();
    await expect(
      loadSecurityPolicyDraft(other.repository, f.outputDir),
    ).rejects.toThrow("different repository or component");
  });

  test("rejects linked policy files and replaced component directories", async () => {
    const f = await fixture();
    const component = join(f.repository, "component");
    await mkdir(component);
    const draft = await f.generate({ path: "component" });
    const external = join(f.root, "external");
    await mkdir(external);
    const externalPolicy = join(external, "SECURITY.md");
    await writeFile(externalPolicy, "# External policy\n");
    await symlink(externalPolicy, draft.targetPath);
    await expect(applySecurityPolicy(draft)).rejects.toThrow("regular file");
    await rm(draft.targetPath);
    await rename(component, join(f.repository, "old-component"));
    await symlink(
      external,
      component,
      process.platform === "win32" ? "junction" : "dir",
    );
    await expect(applySecurityPolicy(draft)).rejects.toThrow(
      "outside the repository",
    );
    expect(await readFile(externalPolicy, "utf8")).toBe("# External policy\n");
    expect((await lstat(component)).isSymbolicLink()).toBe(true);
  });

  test("rejects a modified original-content checkpoint", async () => {
    const f = await fixture();
    await f.generate();
    await writeFile(
      join(f.outputDir, "previous-SECURITY.md"),
      "# Forged baseline\n",
    );
    await expect(
      loadSecurityPolicyDraft(f.repository, f.outputDir),
    ).rejects.toThrow("checkpoint has changed");
  });
});

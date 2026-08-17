import { execFileSync } from "node:child_process";
import {
  chmod,
  lstat,
  mkdir,
  readFile,
  readdir,
  rename,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import * as fsPromises from "node:fs/promises";
import { join } from "node:path";
import { afterEach, describe, expect, mock, test } from "bun:test";
import { strToU8, zipSync } from "fflate";
import { SecurityPolicyVerificationError } from "../src/errors.js";
import {
  applySecurityPolicy,
  loadSecurityPolicyDraft,
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
});

describe("security policy review and application", () => {
  test("previews a real diff and applies a new policy accepted by the resolver", async () => {
    const f = await fixture();
    const draft = await f.generate();
    const diff = await securityPolicyDiff(draft, PYTHON);
    expect(diff).toContain("--- /dev/null\n+++ b/SECURITY.md\n");
    expect(diff).toContain("+Requests must be authorized");
    expect(await applySecurityPolicy(draft)).toBe(draft.targetPath);
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
        expect(
          await applySecurityPolicy(draft, {
            pythonPath: PYTHON,
            signal: controller.signal,
          }),
        ).toBe(draft.targetPath);
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

  test("checks source freshness even for an unchanged draft", async () => {
    const f = await fixture();
    await writeFile(join(f.repository, "SECURITY.md"), POLICY);
    const draft = await f.generate();
    expect(await securityPolicyDiff(draft, "missing-python")).toBe("");
    expect(
      await applySecurityPolicy(draft, { pythonPath: "missing-python" }),
    ).toBe(draft.targetPath);
    await writeFile(draft.targetPath, "# Concurrent policy\n");
    await expect(securityPolicyDiff(draft, PYTHON)).rejects.toThrow(
      "changed after",
    );
    await expect(applySecurityPolicy(draft)).rejects.toThrow("changed after");
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

import * as childProcess from "node:child_process";
import { mkdir, mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { expect, mock, test } from "bun:test";
import { ConfigurationError } from "../src/errors.js";
import * as trustedExecutable from "../src/trusted-executable.js";
import { runMockInSubprocess } from "./support/isolated-mock.js";

test("preserves raw executable bindings across platform aliases", () => {
  const originalPlatform = Object.getOwnPropertyDescriptor(
    process,
    "platform",
  )!;
  const environment = {
    CODEX_SECURITY_GIT: "",
    Codex_Security_Git: "/synthetic/git",
  };
  try {
    Object.defineProperty(process, "platform", { value: "linux" });
    expect(
      trustedExecutable.executableBinding(environment, "CODEX_SECURITY_GIT"),
    ).toEqual({ keys: ["CODEX_SECURITY_GIT"], value: "" });
    expect(
      trustedExecutable.executableBinding(
        { Codex_Security_Git: "/synthetic/git" },
        "CODEX_SECURITY_GIT",
      ).value,
    ).toBeUndefined();
    Object.defineProperty(process, "platform", { value: "win32" });
    expect(
      trustedExecutable.executableBinding(environment, "CODEX_SECURITY_GIT"),
    ).toEqual({
      keys: ["CODEX_SECURITY_GIT", "Codex_Security_Git"],
      value: "",
    });
    expect(
      trustedExecutable.executableBinding(
        { Codex_Security_Git: "/synthetic/git" },
        "CODEX_SECURITY_GIT",
      ).value,
    ).toBe("/synthetic/git");
  } finally {
    Object.defineProperty(process, "platform", originalPlatform);
  }
});

test("uses one explicit Git command throughout target validation", async () => {
  const name = "uses one explicit Git command throughout target validation";
  if (runMockInSubprocess(import.meta.path, name)) return;

  const root = await realpath(await mkdtemp(join(tmpdir(), "git-binding-")));
  const repository = join(root, "repository");
  await mkdir(repository);
  const selected = join(root, "tools", "selected git");
  const discovered = join(root, "tools", "path git");
  const canonical = join(root, "tools", "canonical git");
  const missing = join(root, "tools", "missing git");
  const revision = "a".repeat(40);
  const originalChildProcess = { ...childProcess };
  const originalTrusted = { ...trustedExecutable };
  const originalBinding = process.env["CODEX_SECURITY_GIT"];
  const inspections: string[] = [];
  const calls: {
    executable: string;
    args: readonly string[];
    environment: NodeJS.ProcessEnv;
  }[] = [];
  const execute = Object.assign(
    () => {
      throw new Error("The callback form is not used by this test");
    },
    {
      [promisify.custom]: async (
        executable: string,
        args: readonly string[],
        options: { env: NodeJS.ProcessEnv },
      ) => {
        calls.push({ executable, args, environment: options.env });
        const stdout = args.includes("--show-toplevel")
          ? repository
          : args.includes("--verify")
            ? revision
            : args.includes("ls-files")
              ? "H file.txt\0"
              : "";
        return { stdout, stderr: "" };
      },
    },
  );
  mock.module("node:child_process", () => ({
    ...originalChildProcess,
    execFile: execute,
  }));
  mock.module("../src/trusted-executable.js", () => ({
    ...originalTrusted,
    inspectTrustedExecutable: async (
      candidate: string,
      environment: Record<string, string | undefined>,
      protectedRoot: string,
      options?: { preserveInvocation?: boolean },
    ) => {
      expect(protectedRoot).toBe(repository);
      inspections.push(candidate);
      return {
        executable:
          candidate === "git"
            ? discovered
            : candidate === selected
              ? options?.preserveInvocation
                ? selected
                : canonical
              : null,
        environment: { ...environment, PATH: "/synthetic/safe-path" },
      };
    },
  }));

  try {
    const targets = await import("../src/targets.js");
    const command = await targets.resolveGitCommand(
      {
        PATH: "",
        CODEX_SECURITY_GIT: selected,
        GIT_DIR: "/synthetic/ignored-directory",
        GIT_CONFIG_COUNT: "1",
        KEEP: "present",
      },
      repository,
    );
    expect(command.executable).toBe(selected);
    expect(inspections).toEqual(["git", selected]);
    const target = await targets.normalizeTarget(
      repository,
      targets.DiffTarget.refs({ base: "HEAD" }),
      undefined,
      command,
    );
    await targets.validateCommittedDiffCheckout(
      repository,
      target,
      undefined,
      command,
    );
    expect(
      await targets.enclosingGitWorktreeRoot(repository, undefined, command),
    ).toBe(repository);
    expect(
      await targets.repositoryRevision(repository, undefined, command),
    ).toBe(revision);
    expect(calls.length).toBeGreaterThan(0);
    for (const call of calls) {
      expect(call.executable).toBe(selected);
      expect(call.environment["CODEX_SECURITY_GIT"]).toBe(selected);
      expect(call.environment["PATH"]).toBe("/synthetic/safe-path");
      expect(call.environment["KEEP"]).toBe("present");
      expect(call.environment["GIT_DIR"]).toBeUndefined();
      expect(call.environment["GIT_ALLOW_PROTOCOL"]).toBe("");
      expect(call.environment["GIT_CONFIG_COUNT"]).toBe(
        call.args.includes("rev-parse") ? "1" : undefined,
      );
    }
    expect(inspections).toEqual(["git", selected]);

    const disabled = await targets.resolveGitCommand(
      { CODEX_SECURITY_GIT: "" },
      repository,
    );
    const previousCalls = calls.length;
    expect(
      await targets.repositoryRevision(repository, undefined, disabled),
    ).toBeNull();
    expect(
      await targets.enclosingGitWorktreeRoot(repository, undefined, disabled),
    ).toBeNull();
    await expect(
      targets.normalizeTarget(
        repository,
        targets.DiffTarget.refs({ base: "HEAD" }),
        undefined,
        disabled,
      ),
    ).rejects.toThrow("Diff targets require a Git repository");
    expect(calls).toHaveLength(previousCalls);

    await expect(
      targets.resolveGitCommand({ CODEX_SECURITY_GIT: "relative" }, repository),
    ).rejects.toBeInstanceOf(ConfigurationError);
    await expect(
      targets.resolveGitCommand({ CODEX_SECURITY_GIT: missing }, repository),
    ).rejects.toBeInstanceOf(ConfigurationError);
    expect(calls).toHaveLength(previousCalls);

    process.env["CODEX_SECURITY_GIT"] = selected;
    expect(await targets.repositoryRevision(repository)).toBe(revision);
    expect(calls.at(-1)?.executable).toBe(selected);
  } finally {
    if (originalBinding === undefined) delete process.env["CODEX_SECURITY_GIT"];
    else process.env["CODEX_SECURITY_GIT"] = originalBinding;
    mock.module("node:child_process", () => originalChildProcess);
    mock.module("../src/trusted-executable.js", () => originalTrusted);
    await rm(root, { recursive: true, force: true });
  }
});

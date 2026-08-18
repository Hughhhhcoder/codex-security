import { spawnSync } from "node:child_process";
import {
  link,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { resolvePluginPython } from "../src/runtime.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const python = await resolvePluginPython();
const roots: string[] = [];

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

async function fixture() {
  const root = await realpath(await mkdtemp(join(tmpdir(), "policy-inputs-")));
  roots.push(root);
  const repository = join(root, "repository");
  await mkdir(repository);
  return { root, repository };
}

function run(repository: string, ...args: string[]) {
  return spawnSync(
    python,
    [
      "-I",
      join(PLUGIN_ROOT, "scripts", "resolve_security_md.py"),
      "--repo",
      repository,
      ...args,
    ],
    { encoding: "utf8" },
  );
}

function inspect(repository: string, scope = ".", ...args: string[]) {
  const result = run(repository, "--inspect", "--scope", scope, ...args);
  expect(result.status, result.stderr).toBe(0);
  return JSON.parse(result.stdout) as {
    previousContent: string | null;
    guidance: string;
    policyPaths: string[];
  };
}

describe("shared security-policy inputs", () => {
  test("returns scoped policy evidence and keeps reporting policies separate", async () => {
    const { repository } = await fixture();
    for (const path of [
      "services/api/.hidden",
      "services/other",
      ".github",
      "docs",
    ])
      await mkdir(join(repository, path), { recursive: true });
    for (const [path, content] of [
      ["SECURITY.md", "# Root policy\n"],
      ["services/api/SECURITY.md", "# API policy\r\n"],
      ["services/api/.hidden/SECURITY.md", "# Hidden policy\n"],
      ["services/other/SECURITY.md", "# Other policy\n"],
      [".github/SECURITY.md", "# Reporting instructions\n"],
      ["docs/SECURITY.md", "# Reporting documentation\n"],
    ])
      await writeFile(join(repository, path!), content!);

    const result = inspect(repository, "services/api");
    expect(result.previousContent).toBe("# API policy\r\n");
    expect(result.guidance.indexOf("# Root policy")).toBeLessThan(
      result.guidance.indexOf("# API policy"),
    );
    expect(result.guidance).not.toContain("Reporting instructions");
    expect(result.guidance).not.toContain("Other policy");
    expect(result.policyPaths).toEqual([
      ".github/SECURITY.md",
      "SECURITY.md",
      "docs/SECURITY.md",
      "services/api/.hidden/SECURITY.md",
      "services/api/SECURITY.md",
    ]);
    expect(
      JSON.parse(run(repository, "--list", "--scope", "services/api").stdout),
    ).toEqual(["services/api/.hidden/SECURITY.md", "services/api/SECURITY.md"]);
  });

  test("reads safe inherited links but rejects a linked destination", async () => {
    const { repository } = await fixture();
    await mkdir(join(repository, "component"));
    await writeFile(join(repository, "guidance.md"), "# Shared guidance\n");
    await symlink("guidance.md", join(repository, "SECURITY.md"), "file");
    expect(inspect(repository, "component").guidance).toContain(
      "# Shared guidance",
    );
    const selected = run(repository, "--inspect", "--scope", ".");
    expect(selected.status).toBe(2);
    expect(selected.stderr).toContain(
      "selected SECURITY.md must not be a symbolic link",
    );
  });

  test("rejects outside, dangling outside, cyclic, and hard-linked evidence", async () => {
    for (const kind of ["outside", "missing", "cycle", "hard-link"]) {
      const { root, repository } = await fixture();
      await mkdir(join(repository, "component"));
      const outside = join(root, "outside.md");
      const policy = join(repository, "component", "SECURITY.md");
      await writeFile(outside, "synthetic private text\n");
      if (kind === "hard-link") await link(outside, policy);
      else
        await symlink(
          kind === "outside"
            ? outside
            : kind === "missing"
              ? join(root, "missing.md")
              : policy,
          policy,
          "file",
        );
      const result = run(repository, "--inspect", "--scope", ".");
      expect(result.status, kind).toBe(2);
      expect(result.stdout).toBe("");
      expect(result.stderr).not.toContain("synthetic private text");
    }
  });

  test("does not traverse directory links or Git metadata", async () => {
    const { root, repository } = await fixture();
    const outside = join(root, "outside");
    const metadata = join(repository, "git-data");
    await mkdir(outside);
    await mkdir(join(repository, ".git"));
    await mkdir(metadata);
    await writeFile(join(outside, "SECURITY.md"), "# Outside\n");
    await writeFile(
      join(repository, ".git", "SECURITY.md"),
      "# Git metadata\n",
    );
    await writeFile(join(metadata, "SECURITY.md"), "# Separate Git metadata\n");
    await symlink(
      outside,
      join(repository, "linked-directory"),
      process.platform === "win32" ? "junction" : "dir",
    );
    expect(inspect(repository, ".", "--git-dir", metadata).policyPaths).toEqual(
      [],
    );
    await mkdir(join(repository, "component"));
    await symlink(
      join(metadata, "SECURITY.md"),
      join(repository, "component", "SECURITY.md"),
      "file",
    );
    const result = run(
      repository,
      "--inspect",
      "--scope",
      ".",
      "--git-dir",
      metadata,
    );
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("Git metadata");
  });

  test("rejects case aliases of caller-supplied Git metadata directories", async () => {
    const { repository } = await fixture();
    const metadata = join(repository, "GitData");
    const alias = join(repository, "gitdata");
    await mkdir(metadata);
    await mkdir(join(repository, "component"));
    await writeFile(join(metadata, "private.md"), "synthetic metadata\n");
    if ((await stat(alias).catch(() => null)) === null)
      await symlink(
        metadata,
        alias,
        process.platform === "win32" ? "junction" : "dir",
      );
    await symlink(
      join(alias, "private.md"),
      join(repository, "SECURITY.md"),
      "file",
    );
    const result = run(
      repository,
      "--inspect",
      "--scope",
      "component",
      "--git-dir",
      metadata,
    );
    expect(result.status).toBe(2);
    expect(result.stdout).toBe("");
    expect(result.stderr).toContain("Git metadata");
  });

  test("enforces the existing byte and UTF-8 contract in both resolver modes", async () => {
    for (const content of [
      Buffer.alloc(1024 * 1024 + 1, "x"),
      Buffer.from([0xff]),
    ]) {
      const { repository } = await fixture();
      await writeFile(join(repository, "SECURITY.md"), content);
      for (const mode of [[], ["--inspect"]]) {
        const result = run(repository, ...mode, "--scope", ".");
        expect(result.status).toBe(2);
        expect(result.stdout).toBe("");
      }
    }
  });

  test("requires a directory scope and never writes the repository", async () => {
    const { root, repository } = await fixture();
    const source = join(repository, "source.ts");
    await writeFile(source, "export const value = 1;\n");
    expect(run(repository, "--inspect", "--scope", source).status).toBe(2);
    expect(run(repository, "--inspect", "--scope", root).status).toBe(2);
    expect(inspect(repository)).toEqual({
      previousContent: null,
      guidance: "",
      policyPaths: [],
    });
    expect(await readFile(source, "utf8")).toBe("export const value = 1;\n");
  });
});

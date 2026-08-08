import { execFileSync } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

describe("security scan file inventory", () => {
  test("includes hidden source files without exposing ignored repository files", async () => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-scan-inventory-")),
    );
    temporaryDirectories.push(root);

    const repository = join(root, "repository");
    const output = join(root, "in-scope-files.txt");
    await mkdir(join(repository, "src"), { recursive: true });
    await mkdir(join(repository, "ignored"));
    execFileSync("git", ["init", "-q"], { cwd: repository });

    await Promise.all([
      writeFile(join(repository, ".gitignore"), "ignored/\n.env\n"),
      writeFile(join(repository, ".env"), "SECRET=private\n"),
      writeFile(join(repository, ".visible-config"), "visible=true\n"),
      writeFile(join(repository, "ignored", "secret.ts"), "private data\n"),
      writeFile(join(repository, "src", "handler.ts"), "export {};\n"),
    ]);

    const python =
      Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
    expect(python).not.toBeNull();
    if (python === null) throw new Error("A Python interpreter is required.");

    execFileSync(
      python,
      [
        "-B",
        join(PLUGIN_ROOT, "scripts", "generate_in_scope_files.py"),
        "--repo",
        repository,
        "--scope",
        ".",
        "--out",
        output,
      ],
      { cwd: repository, stdio: "pipe" },
    );

    expect((await readFile(output, "utf8")).trimEnd().split("\n")).toEqual([
      "./.gitignore",
      "./.visible-config",
      "./src/handler.ts",
    ]);
  });
});

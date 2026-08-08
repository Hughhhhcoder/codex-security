import { execFileSync } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  symlink,
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
    if (Bun.which("rg") === null) {
      const generator = await readFile(
        join(PLUGIN_ROOT, "scripts", "generate_in_scope_files.py"),
        "utf8",
      );
      expect(generator).not.toContain('"--no-ignore"');
      expect(generator).toContain('"--cached"');
      expect(generator).toContain('"--no-config"');
      expect(generator).toContain('"--no-ignore-parent"');
      expect(generator).toContain('"--no-require-git"');
      expect(generator).toContain('"--literal-pathspecs"');
      expect(generator).toContain('"core.fsmonitor=false"');
      return;
    }

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
      writeFile(
        join(repository, ".gitignore"),
        "ignored/\n.env\ntracked.env\ntracked-link\n",
      ),
      writeFile(join(repository, ".env"), "SECRET=private\n"),
      writeFile(join(repository, ".visible-config"), "visible=true\n"),
      writeFile(join(repository, "ignored", "secret.ts"), "private data\n"),
      writeFile(join(repository, "src", "handler.ts"), "export {};\n"),
      writeFile(join(repository, "tracked.env"), "checked in intentionally\n"),
      writeFile(join(repository, ".ignore"), "hidden-by-rg.ts\n"),
      writeFile(join(repository, "hidden-by-rg.ts"), "tracked source\n"),
    ]);
    execFileSync(
      "git",
      ["add", "--force", "--", "tracked.env", "hidden-by-rg.ts"],
      {
        cwd: repository,
      },
    );
    if (process.platform !== "win32") {
      const external = join(root, "external.txt");
      await writeFile(external, "private external file\n");
      await symlink(external, join(repository, "tracked-link"));
      execFileSync("git", ["add", "--force", "--", "tracked-link"], {
        cwd: repository,
      });
    }

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

    expect(
      (await readFile(output, "utf8"))
        .trimEnd()
        .split("\n")
        .map((path) => path.replaceAll("\\", "/")),
    ).toEqual([
      "./.gitignore",
      "./.ignore",
      "./.visible-config",
      "./hidden-by-rg.ts",
      "./src/handler.ts",
      "./tracked.env",
    ]);
  });

  test("respects ignore files in non-Git directory snapshots", async () => {
    if (Bun.which("rg") === null) return;

    const root = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-directory-inventory-")),
    );
    temporaryDirectories.push(root);
    const repository = join(root, "snapshot");
    const output = join(root, "in-scope-files.txt");
    await mkdir(repository);
    await writeFile(join(root, ".gitignore"), "snapshot/source.ts\n");
    await Promise.all([
      writeFile(join(repository, ".gitignore"), ".env\n"),
      writeFile(join(repository, ".env"), "SECRET=private\n"),
      writeFile(join(repository, "source.ts"), "export {};\n"),
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

    const rows = (await readFile(output, "utf8"))
      .trimEnd()
      .split("\n")
      .map((path) => path.replaceAll("\\", "/"));
    expect(rows).toEqual(["./.gitignore", "./source.ts"]);
  });
});

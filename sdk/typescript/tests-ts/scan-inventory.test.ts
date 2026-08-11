import { execFileSync } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rename,
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
    const globalIgnore = join(root, "global-ignore");
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
      writeFile(join(repository, "src", "info-secret.ts"), "local secret\n"),
      writeFile(join(repository, "tracked.env"), "checked in intentionally\n"),
      writeFile(join(repository, ".ignore"), "hidden-by-rg.ts\n"),
      writeFile(join(repository, "hidden-by-rg.ts"), "tracked source\n"),
      writeFile(
        join(repository, "info-secret.ts"),
        "local Git-excluded data\n",
      ),
      writeFile(globalIgnore, "*.ts\n"),
    ]);
    await writeFile(
      join(repository, ".git", "info", "exclude"),
      "info-secret.ts\nsrc/info-secret.ts\n",
    );
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
      const externalRepository = join(root, "external-repository");
      await mkdir(externalRepository);
      execFileSync("git", ["init", "-q"], { cwd: externalRepository });
      await symlink(
        externalRepository,
        join(repository, "tracked-repository-link"),
      );
      execFileSync("git", ["add", "--", "tracked-repository-link"], {
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
      {
        cwd: repository,
        stdio: "pipe",
        env: {
          ...process.env,
          GIT_CONFIG_COUNT: "1",
          GIT_CONFIG_KEY_0: "core.excludesFile",
          GIT_CONFIG_VALUE_0: globalIgnore,
          GIT_GLOB_PATHSPECS: "1",
          GIT_ICASE_PATHSPECS: "1",
        },
      },
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

    execFileSync(
      python,
      [
        "-B",
        join(PLUGIN_ROOT, "scripts", "generate_in_scope_files.py"),
        "--repo",
        repository,
        "--scope",
        "src",
        "--out",
        output,
      ],
      { cwd: repository, stdio: "pipe" },
    );
    expect((await readFile(output, "utf8")).trim()).toBe("src/handler.ts");
  });

  test.each(["repository ", "repository\t"])(
    "preserves trailing whitespace in the Git worktree root %j",
    async (directory) => {
      if (process.platform === "win32" || Bun.which("rg") === null) return;

      const root = await realpath(
        await mkdtemp(join(tmpdir(), "codex-security-whitespace-inventory-")),
      );
      temporaryDirectories.push(root);
      const repository = join(root, directory);
      const output = join(root, "in-scope-files.txt");
      await mkdir(repository);
      execFileSync("git", ["init", "-q"], { cwd: repository });
      await writeFile(join(repository, ".ignore"), "tracked.py\n");
      await writeFile(join(repository, "tracked.py"), "print('tracked')\n");
      execFileSync("git", ["add", "--", "tracked.py"], { cwd: repository });

      const python =
        Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
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
      expect((await readFile(output, "utf8")).split("\n")).toContain(
        "./tracked.py",
      );
    },
  );

  test("respects ignore files in non-Git directory snapshots", async () => {
    if (Bun.which("rg") === null) return;

    const root = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-directory-inventory-")),
    );
    temporaryDirectories.push(root);
    const repository = join(root, "snapshot");
    const nested = join(repository, "nested");
    const output = join(root, "in-scope-files.txt");
    await mkdir(nested, { recursive: true });
    execFileSync("git", ["init", "-q"], { cwd: root });
    execFileSync("git", ["init", "-q"], { cwd: nested });
    await writeFile(join(root, ".gitignore"), "snapshot/source.ts\n");
    await Promise.all([
      writeFile(
        join(repository, process.platform === "win32" ? ".GIT" : ".git"),
        `gitdir: ${join(root, "missing-snapshot-metadata")}\n`,
      ),
      writeFile(join(repository, ".gitignore"), ".env\n"),
      writeFile(join(repository, ".env"), "SECRET=private\n"),
      writeFile(join(repository, "source.ts"), "export {};\n"),
      writeFile(join(nested, ".ignore"), "tracked.py\n"),
      writeFile(join(nested, "tracked.py"), "print('tracked')\n"),
    ]);
    execFileSync("git", ["add", "--", "tracked.py"], { cwd: nested });

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
    expect(rows).toEqual([
      "./.gitignore",
      "./nested/.ignore",
      "./nested/tracked.py",
      "./source.ts",
    ]);

    await writeFile(
      join(repository, process.platform === "win32" ? ".GIT" : ".git"),
      "malformed snapshot marker\n",
    );
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
    expect((await readFile(output, "utf8")).split("\n")).toContain(
      "./source.ts",
    );
    expect(() =>
      execFileSync(
        python,
        [
          "-B",
          join(PLUGIN_ROOT, "scripts", "generate_in_scope_files.py"),
          "--repo",
          repository,
          "--scope",
          process.platform === "win32" ? ".GIT" : ".git",
          "--out",
          output,
        ],
        { cwd: repository, stdio: "pipe" },
      ),
    ).toThrow("Git metadata paths are not supported");
  });

  test("preserves case-distinct Git-like source directories", async () => {
    if (process.platform === "win32" || Bun.which("rg") === null) return;

    const root = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-case-sensitive-inventory-")),
    );
    temporaryDirectories.push(root);
    const repository = join(root, "snapshot");
    await mkdir(join(repository, ".GIT"), { recursive: true });
    try {
      await realpath(join(repository, ".git"));
      return;
    } catch {
      // A case-distinct source directory exists only on case-sensitive volumes.
    }
    await Promise.all([
      writeFile(join(repository, ".GIT", "source.py"), "print('source')\n"),
      writeFile(join(repository, "visible.py"), "print('visible')\n"),
    ]);

    const python =
      Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
    if (python === null) throw new Error("A Python interpreter is required.");
    const output = join(root, "in-scope-files.txt");
    for (const scope of [".", ".GIT/source.py"]) {
      execFileSync(
        python,
        [
          "-B",
          join(PLUGIN_ROOT, "scripts", "generate_in_scope_files.py"),
          "--repo",
          repository,
          "--scope",
          scope,
          "--out",
          output,
        ],
        { cwd: repository, stdio: "pipe" },
      );
      expect((await readFile(output, "utf8")).split("\n")).toContain(
        scope === "." ? "./.GIT/source.py" : ".GIT/source.py",
      );
    }
  });

  test("keeps tracked files after a case-only working-tree rename", async () => {
    if (Bun.which("rg") === null) return;

    const root = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-case-renamed-inventory-")),
    );
    temporaryDirectories.push(root);
    const repository = join(root, "repository");
    const output = join(root, "in-scope-files.txt");
    await mkdir(repository);
    execFileSync("git", ["init", "-q"], { cwd: repository });
    execFileSync("git", ["config", "core.ignoreCase", "true"], {
      cwd: repository,
    });
    await writeFile(join(repository, "tracked.py"), "print('tracked')\n");
    execFileSync("git", ["add", "--", "tracked.py"], { cwd: repository });
    await rename(
      join(repository, "tracked.py"),
      join(repository, "TRACKED.py"),
    );

    const python =
      Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
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

    expect((await readFile(output, "utf8")).trim()).toBe("./TRACKED.py");
  });

  test.each([false, true])(
    "applies intermediate scope ignore files (Git repository: %s)",
    async (useGit) => {
      if (Bun.which("rg") === null) return;

      const root = await realpath(
        await mkdtemp(join(tmpdir(), "codex-security-ancestor-inventory-")),
      );
      temporaryDirectories.push(root);
      const repository = join(root, "repository");
      const scoped = join(repository, "parent", "nested");
      const output = join(root, "in-scope-files.txt");
      await mkdir(scoped, { recursive: true });
      if (useGit) execFileSync("git", ["init", "-q"], { cwd: repository });
      await Promise.all([
        writeFile(join(repository, "parent", ".ignore"), "nested/secret.py\n"),
        writeFile(
          join(repository, "parent", ".gitignore"),
          "nested/private.py\n",
        ),
        writeFile(join(scoped, "secret.py"), "secret\n"),
        writeFile(join(scoped, "private.py"), "private\n"),
        writeFile(join(scoped, "safe.py"), "safe\n"),
      ]);

      const python =
        Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
      if (python === null) throw new Error("A Python interpreter is required.");
      for (const scope of [
        "parent/nested",
        "parent/./nested",
        "./parent/nested",
      ]) {
        execFileSync(
          python,
          [
            "-B",
            join(PLUGIN_ROOT, "scripts", "generate_in_scope_files.py"),
            "--repo",
            repository,
            "--scope",
            scope,
            "--out",
            output,
          ],
          { cwd: repository, stdio: "pipe" },
        );

        expect((await readFile(output, "utf8")).trim()).toBe(
          `${scope.startsWith("./") ? "./" : ""}parent/nested/safe.py`,
        );
      }
    },
  );

  test("retains visible files inside nested Git worktrees", async () => {
    if (Bun.which("rg") === null) return;

    const root = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-nested-inventory-")),
    );
    temporaryDirectories.push(root);
    const repository = join(root, "repository");
    const nested = join(repository, "nested");
    const output = join(root, "in-scope-files.txt");
    await mkdir(nested, { recursive: true });
    execFileSync("git", ["init", "-q"], { cwd: repository });
    execFileSync("git", ["init", "-q"], { cwd: nested });
    execFileSync("git", ["config", "core.ignoreCase", "true"], {
      cwd: nested,
    });
    await Promise.all([
      writeFile(join(nested, ".gitignore"), ".env\nsecret.py\n"),
      writeFile(join(nested, ".env"), "SECRET=private\n"),
      writeFile(join(nested, "SECRET.PY"), "private data\n"),
      writeFile(join(nested, "tracked.py"), "print('tracked')\n"),
      writeFile(join(nested, "local.py"), "print('local')\n"),
      writeFile(join(nested, "chosen.skip"), "explicit nested source\n"),
      writeFile(join(nested, ".git", "info", "exclude"), "chosen.skip\n"),
    ]);
    execFileSync("git", ["add", "--", "tracked.py"], { cwd: nested });

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
    expect(rows).toContain("./nested/tracked.py");
    expect(rows).toContain("./nested/local.py");
    expect(rows).not.toContain("./nested/.env");
    expect(rows).not.toContain("./nested/SECRET.PY");

    execFileSync(
      python,
      [
        "-B",
        join(PLUGIN_ROOT, "scripts", "generate_in_scope_files.py"),
        "--repo",
        repository,
        "--scope",
        "nested/tracked.py",
        "--out",
        output,
      ],
      { cwd: repository, stdio: "pipe" },
    );
    expect((await readFile(output, "utf8")).trim()).toBe("nested/tracked.py");

    execFileSync(
      python,
      [
        "-B",
        join(PLUGIN_ROOT, "scripts", "generate_in_scope_files.py"),
        "--repo",
        repository,
        "--scope",
        "nested/chosen.skip",
        "--out",
        output,
      ],
      { cwd: repository, stdio: "pipe" },
    );
    expect((await readFile(output, "utf8")).trim()).toBe("nested/chosen.skip");

    execFileSync(
      "git",
      [
        "-c",
        "user.name=Inventory Test",
        "-c",
        "user.email=inventory@example.test",
        "commit",
        "-qm",
        "Track nested source",
      ],
      { cwd: nested },
    );
    const inner = join(nested, "inner");
    await mkdir(inner);
    execFileSync("git", ["init", "-q"], { cwd: inner });
    await writeFile(join(inner, "security.py"), "print('nested security')\n");
    execFileSync("git", ["add", "--", "security.py"], { cwd: inner });
    execFileSync(
      "git",
      [
        "-c",
        "user.name=Inventory Test",
        "-c",
        "user.email=inventory@example.test",
        "commit",
        "-qm",
        "Track inner security source",
      ],
      { cwd: inner },
    );
    execFileSync("git", ["add", "--", "inner"], {
      cwd: nested,
      stdio: "ignore",
    });
    execFileSync(
      "git",
      [
        "-c",
        "user.name=Inventory Test",
        "-c",
        "user.email=inventory@example.test",
        "commit",
        "-qm",
        "Track inner worktree",
      ],
      { cwd: nested },
    );
    await writeFile(join(repository, ".gitignore"), "nested/\n");
    execFileSync("git", ["add", "--force", "--", "nested"], {
      cwd: repository,
      stdio: "ignore",
    });
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
    expect((await readFile(output, "utf8")).split("\n")).toContain(
      "./nested/tracked.py",
    );
    expect((await readFile(output, "utf8")).split("\n")).toContain(
      "./nested/inner/security.py",
    );
  });

  test("discovers embedded repositories beneath outer tracked directories", async () => {
    if (Bun.which("rg") === null) return;

    const root = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-embedded-inventory-")),
    );
    temporaryDirectories.push(root);
    const repository = join(root, "repository");
    const embedded = join(repository, "shared");
    const output = join(root, "in-scope-files.txt");
    await mkdir(embedded, { recursive: true });
    execFileSync("git", ["init", "-q"], { cwd: repository });
    await writeFile(join(embedded, "outer.py"), "print('outer')\n");
    execFileSync("git", ["add", "--", "shared/outer.py"], {
      cwd: repository,
    });

    execFileSync("git", ["init", "-q"], { cwd: embedded });
    await writeFile(join(embedded, ".ignore"), "hidden.py\n");
    await writeFile(join(embedded, "hidden.py"), "print('tracked')\n");
    execFileSync("git", ["add", "--", "hidden.py"], { cwd: embedded });

    const caseDistinct = join(repository, "SHARED");
    let distinctRoot = false;
    try {
      await mkdir(caseDistinct);
      distinctRoot = true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }
    if (distinctRoot) {
      execFileSync("git", ["init", "-q"], { cwd: caseDistinct });
      await writeFile(join(caseDistinct, ".ignore"), "hidden.py\n");
      await writeFile(join(caseDistinct, "hidden.py"), "print('distinct')\n");
      execFileSync("git", ["add", "--", "hidden.py"], {
        cwd: caseDistinct,
      });
    }

    const stale = join(repository, "vendor");
    await mkdir(stale);
    await writeFile(join(stale, ".git"), "malformed nested Git marker\n");
    await writeFile(join(stale, "source.py"), "print('copied source')\n");

    const python =
      Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
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
      .split("\n")
      .map((path) => path.replaceAll("\\", "/"));
    expect(rows).toContain("./shared/outer.py");
    expect(rows).toContain("./shared/hidden.py");
    if (distinctRoot) expect(rows).toContain("./SHARED/hidden.py");
    expect(rows).toContain("./vendor/source.py");
  });

  test("retains ignored explicit files without exposing ignored directory descendants", async () => {
    if (Bun.which("rg") === null) return;

    const root = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-explicit-inventory-")),
    );
    temporaryDirectories.push(root);
    const repository = join(root, "repository");
    const output = join(root, "in-scope-files.txt");
    await mkdir(repository);
    execFileSync("git", ["init", "-q"], { cwd: repository });
    await Promise.all([
      writeFile(join(repository, ".gitignore"), "*.skip\n"),
      writeFile(join(repository, "selected.skip"), "explicit source\n"),
    ]);

    const python =
      Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
    expect(python).not.toBeNull();
    if (python === null) throw new Error("A Python interpreter is required.");
    const enumerate = (scope: string, target = repository) =>
      execFileSync(
        python,
        [
          "-B",
          join(PLUGIN_ROOT, "scripts", "generate_in_scope_files.py"),
          "--repo",
          target,
          "--scope",
          scope,
          "--out",
          output,
        ],
        { cwd: target, stdio: "pipe" },
      );

    enumerate("selected.skip");
    expect((await readFile(output, "utf8")).trim()).toBe("selected.skip");

    const ignored = join(repository, "ignored");
    await mkdir(ignored);
    await Promise.all([
      writeFile(join(repository, ".gitignore"), "*.skip\nignored/\n"),
      writeFile(join(ignored, "public.py"), "tracked source\n"),
      writeFile(join(ignored, "private.py"), "ignored source\n"),
    ]);
    execFileSync("git", ["add", "--force", "ignored/public.py"], {
      cwd: repository,
    });

    enumerate("ignored");
    expect((await readFile(output, "utf8")).trim()).toBe("ignored/public.py");

    const tracked = join(repository, "tracked");
    await mkdir(tracked);
    await writeFile(join(tracked, "private.py"), "previous tracked source\n");
    execFileSync("git", ["add", "--", "tracked/private.py"], {
      cwd: repository,
    });
    await rm(tracked, { recursive: true });
    await symlink(
      ignored,
      tracked,
      process.platform === "win32" ? "junction" : "dir",
    );

    enumerate(".");
    const rows = (await readFile(output, "utf8"))
      .split("\n")
      .map((path) => path.replaceAll("\\", "/"));
    expect(rows).toContain("./ignored/public.py");
    expect(rows).not.toContain("./tracked/private.py");
    expect(rows).not.toContain("./ignored/private.py");

    const snapshot = join(root, "snapshot");
    const nested = join(snapshot, "ignored");
    await mkdir(nested, { recursive: true });
    await Promise.all([
      writeFile(join(snapshot, ".gitignore"), "ignored/\n"),
      writeFile(join(nested, "private.py"), "ignored source\n"),
    ]);
    const alias = join(snapshot, "alias");
    await symlink(
      nested,
      alias,
      process.platform === "win32" ? "junction" : "dir",
    );
    expect(() => enumerate("alias/private.py", snapshot)).toThrow(
      "symbolic links",
    );

    enumerate("ignored", snapshot);
    expect((await readFile(output, "utf8")).trim()).toBe("");

    execFileSync("git", ["init", "-q"], { cwd: nested });
    await writeFile(join(nested, "public.py"), "tracked nested source\n");
    execFileSync("git", ["add", "public.py"], { cwd: nested });

    enumerate("ignored", snapshot);
    expect((await readFile(output, "utf8")).trim()).toBe("ignored/public.py");
  });

  test("rejects symbolic scope and ignore-file paths", async () => {
    if (process.platform === "win32" || Bun.which("rg") === null) return;

    const root = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-symbolic-inventory-")),
    );
    temporaryDirectories.push(root);
    const repository = join(root, "repository");
    const output = join(root, "in-scope-files.txt");
    await mkdir(join(repository, "source"), { recursive: true });
    await writeFile(join(repository, "source", "file.ts"), "export {};\n");
    await writeFile(join(repository, ".gitignore"), "ignored.ts\n");
    await symlink("source", join(repository, "alias"));
    const unrelated = join(repository, "unrelated");
    await mkdir(unrelated);
    await symlink(join(repository, ".gitignore"), join(unrelated, ".ignore"));
    const python =
      Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
    if (python === null) throw new Error("A Python interpreter is required.");
    const command = [
      "-B",
      join(PLUGIN_ROOT, "scripts", "generate_in_scope_files.py"),
      "--repo",
      repository,
      "--out",
      output,
    ];

    execFileSync(python, [...command, "--scope", "source"], {
      cwd: repository,
      stdio: "pipe",
    });
    expect((await readFile(output, "utf8")).trim()).toBe("source/file.ts");

    expect(() =>
      execFileSync(python, [...command, "--scope", "alias"], {
        cwd: repository,
        stdio: "pipe",
      }),
    ).toThrow("symbolic links are not supported");

    await symlink(".gitignore", join(repository, ".ignore"));
    expect(() =>
      execFileSync(python, [...command, "--scope", "."], {
        cwd: repository,
        stdio: "pipe",
      }),
    ).toThrow("symbolic ignore files are not supported");
  });
});

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmod,
  link as hardlink,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  realpath,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { normalizeTarget } from "../src/targets.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const directories: string[] = [];
const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");

afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

async function repository(initializeGit = true): Promise<string> {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-scan-inventory-")),
  );
  directories.push(root);
  const checkout = join(root, "repository");
  await mkdir(checkout);
  if (initializeGit) execFileSync("git", ["init", "-q"], { cwd: checkout });
  return checkout;
}

function commit(checkout: string): void {
  execFileSync(
    "git",
    [
      "-c",
      "user.name=Inventory Test",
      "-c",
      "user.email=inventory@example.test",
      "commit",
      "-qm",
      "Track source",
    ],
    { cwd: checkout },
  );
}

function windowsShortPath(path: string): string | null {
  if (process.platform !== "win32" || python === null) return null;
  const alias = execFileSync(
    python,
    [
      "-B",
      "-c",
      [
        "import ctypes, sys",
        "function = ctypes.windll.kernel32.GetShortPathNameW",
        "size = function(sys.argv[1], None, 0)",
        "buffer = ctypes.create_unicode_buffer(size) if size else None",
        "print(buffer.value if buffer is not None and function(sys.argv[1], buffer, size) else '')",
      ].join("\n"),
      path,
    ],
    { encoding: "utf8" },
  ).trim();
  return alias && alias.toLowerCase() !== path.toLowerCase() ? alias : null;
}

async function inventory(
  checkout: string,
  scope = ".",
  env: NodeJS.ProcessEnv = process.env,
): Promise<string[]> {
  if (python === null) throw new Error("A Python interpreter is required.");
  const output = join(dirname(checkout), "inventory.txt");
  execFileSync(
    python,
    [
      "-B",
      join(PLUGIN_ROOT, "scripts", "generate_in_scope_files.py"),
      "--repo",
      checkout,
      "--scope",
      scope,
      "--out",
      output,
    ],
    { cwd: checkout, env, stdio: "pipe" },
  );
  return (await readFile(output, "utf8"))
    .trimEnd()
    .split("\n")
    .filter(Boolean)
    .map((path) => path.replaceAll("\\", "/"));
}

describe("security scan file inventory", () => {
  test("keeps tracked source while excluding ignored untracked files", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    await mkdir(join(checkout, "ignored"));
    await mkdir(join(checkout, "src"));
    await Promise.all([
      writeFile(join(checkout, ".gitignore"), ".env\nignored/\ntracked.env\n"),
      writeFile(join(checkout, ".ignore"), "hidden.ts\n"),
      writeFile(join(checkout, ".env"), "private\n"),
      writeFile(join(checkout, "ignored", "private.ts"), "private\n"),
      writeFile(join(checkout, "tracked.env"), "tracked\n"),
      writeFile(join(checkout, "hidden.ts"), "tracked\n"),
      writeFile(join(checkout, "src", "visible.ts"), "export {};\n"),
    ]);
    execFileSync("git", ["add", "--force", "tracked.env", "hidden.ts"], {
      cwd: checkout,
    });

    expect(await inventory(checkout)).toEqual([
      "./.gitignore",
      "./.ignore",
      "./hidden.ts",
      "./src/visible.ts",
      "./tracked.env",
    ]);
  });

  test.each([".gitignore", ".ignore", ".rgignore"])(
    "inventories ordinary directories named %s",
    async (name) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const directory = join(checkout, name);
      await mkdir(directory);
      await writeFile(join(directory, "visible.ts"), "visible\n");

      expect(await inventory(checkout)).toContain(`./${name}/visible.ts`);
    },
  );

  test.each([".ignore", ".rgignore"])(
    "keeps ordinary files re-included by higher-precedence %s rules",
    async (override) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      await Promise.all([
        writeFile(join(checkout, ".gitignore"), "source.ts\n"),
        writeFile(join(checkout, override), "!source.ts\n"),
        writeFile(join(checkout, "source.ts"), "visible\n"),
      ]);

      expect(await inventory(checkout)).toContain("./source.ts");
    },
  );

  test("shares ignore probes across directories with the same rules", async () => {
    if (Bun.which("rg") === null) return;

    async function countLookups(branches: number): Promise<number> {
      const checkout = await repository();
      const trace = join(dirname(checkout), "git-trace.log");
      await writeFile(join(checkout, ".ignore"), "ignored/\n");
      for (let index = 0; index < branches; index++) {
        const nested = join(checkout, `branch-${index}`, "nested");
        await mkdir(nested, { recursive: true });
        await writeFile(join(nested, "source.ts"), "visible\n");
      }
      await inventory(checkout, ".", { ...process.env, GIT_TRACE: trace });
      return (
        (await readFile(trace, "utf8")).match(/--git-path info\/exclude/g) ?? []
      ).length;
    }

    expect(await countLookups(18)).toBeLessThanOrEqual(await countLookups(2));
  });

  test("validates Git object files once across many scan directories", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const instrumentation = join(dirname(checkout), "instrumentation");
    const trace = join(dirname(checkout), "object-stats.log");
    await mkdir(instrumentation);
    await writeFile(
      join(instrumentation, "sitecustomize.py"),
      "import os\nfrom pathlib import Path\noriginal = Path.stat\ndef observed(self, *args, **kwargs):\n    if self.parent.parent.name == 'objects' and len(self.parent.name) == 2 and len(self.name) == 38:\n        with open(os.environ['INVENTORY_OBJECT_STAT_TRACE'], 'a') as trace:\n            trace.write(str(self) + '\\n')\n    return original(self, *args, **kwargs)\nPath.stat = observed\n",
    );
    for (let index = 0; index < 5; index++) {
      execFileSync("git", ["hash-object", "-w", "--stdin"], {
        cwd: checkout,
        input: `object-${index}\n`,
      });
    }
    for (let index = 0; index < 10; index++) {
      const branch = join(checkout, `branch-${index}`, "nested");
      await mkdir(branch, { recursive: true });
      await writeFile(join(branch, "visible.ts"), "visible\n");
    }

    await inventory(checkout, ".", {
      ...process.env,
      PYTHONPATH: instrumentation,
      INVENTORY_OBJECT_STAT_TRACE: trace,
    });
    expect((await readFile(trace, "utf8")).trim().split("\n")).toHaveLength(5);
  });

  test.each([".ignore", ".rgignore"])(
    "preserves ancestor %s precedence for explicit directory scopes",
    async (override) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const nested = join(checkout, "nested");
      await mkdir(nested);
      await Promise.all([
        writeFile(join(checkout, override), "!nested/visible.ts\n"),
        writeFile(join(nested, ".gitignore"), "*.ts\n"),
        writeFile(join(nested, "visible.ts"), "visible\n"),
        writeFile(join(nested, "private.ts"), "private\n"),
      ]);

      const rows = await inventory(checkout, "nested");
      expect(rows).toContain("nested/visible.ts");
      expect(rows).not.toContain("nested/private.ts");
    },
  );

  test.each(["case-alias", "short-alias"])(
    "accepts absolute directory scopes through a %s",
    async (kind) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const nested = join(checkout, "nested");
      await mkdir(nested);
      await writeFile(join(nested, "visible.ts"), "visible\n");
      const alias =
        kind === "case-alias"
          ? join(dirname(checkout), basename(checkout).toUpperCase())
          : windowsShortPath(checkout);
      if (alias === null) return;
      const equivalent = await realpath(alias).then(
        async (resolved) => resolved === (await realpath(checkout)),
        () => false,
      );
      if (!equivalent) return;

      expect(await inventory(checkout, join(alias, "nested"))).toContain(
        "nested/visible.ts",
      );
    },
  );

  test.skipIf(process.platform === "win32")(
    "rejects symbolic absolute directory scopes",
    async () => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const nested = join(checkout, "nested");
      const alias = join(checkout, "alias");
      await mkdir(nested);
      await writeFile(join(nested, "visible.ts"), "visible\n");
      await symlink(nested, alias);

      await expect(inventory(checkout, alias)).rejects.toThrow(
        "symbolic links are not supported",
      );
    },
  );

  test.each([".ignore", ".rgignore"])(
    "keeps nested checkout files re-included by higher-precedence %s rules",
    async (override) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const nested = join(checkout, "nested");
      await mkdir(nested);
      execFileSync("git", ["init", "-q"], { cwd: nested });
      await Promise.all([
        writeFile(join(nested, ".gitignore"), "source.ts\n"),
        writeFile(join(nested, override), "!source.ts\n"),
        writeFile(join(nested, "source.ts"), "visible\n"),
      ]);

      expect(await inventory(checkout)).toContain("./nested/source.ts");
      expect(await inventory(checkout, "nested")).toContain("nested/source.ts");
    },
  );

  test("applies snapshot ignores without inheriting unrelated parent rules", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository(false);
    await Promise.all([
      writeFile(
        join(dirname(checkout), ".gitignore"),
        "repository/visible.ts\n",
      ),
      writeFile(join(checkout, ".gitignore"), "private.ts\n"),
      writeFile(join(checkout, ".ignore"), "hidden.ts\n"),
      writeFile(join(checkout, "private.ts"), "private\n"),
      writeFile(join(checkout, "hidden.ts"), "private\n"),
      writeFile(join(checkout, "visible.ts"), "export {};\n"),
    ]);

    expect(await inventory(checkout)).toEqual([
      "./.gitignore",
      "./.ignore",
      "./visible.ts",
    ]);
  });

  test.each([
    ["SS", "ss"],
    ["Ä", "ä"],
    ["Σ", "ς"],
    ["ss", "\u00df"],
    ["I", "\u0131"],
    ["caf\u00e9", "cafe\u0301"],
  ])(
    "matches indexed %s against replacement %s using filesystem identity",
    async (indexed, replacement) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      await mkdir(join(checkout, indexed));
      await writeFile(join(checkout, indexed, "private.ts"), "tracked\n");
      execFileSync("git", ["add", `${indexed}/private.ts`], { cwd: checkout });
      execFileSync("git", ["config", "core.ignoreCase", "true"], {
        cwd: checkout,
      });
      await rm(join(checkout, indexed), { recursive: true });
      await mkdir(join(checkout, replacement));
      await writeFile(
        join(checkout, replacement, "private.ts"),
        "replacement\n",
      );
      await writeFile(join(checkout, ".gitignore"), `${replacement}/\n`);
      const expected = await realpath(
        join(checkout, indexed, "private.ts"),
      ).then(
        async (path) =>
          path === (await realpath(join(checkout, replacement, "private.ts"))),
        () => false,
      );

      expect(
        (await inventory(checkout)).includes(`./${replacement}/private.ts`),
      ).toBe(expected);

      execFileSync("git", ["config", "core.ignoreCase", "false"], {
        cwd: checkout,
      });
      expect(
        (await inventory(checkout)).includes(`./${replacement}/private.ts`),
      ).toBe(expected);
      expect(
        (await inventory(checkout, replacement)).includes(
          `${replacement}/private.ts`,
        ),
      ).toBe(expected);
    },
  );

  test("keeps an explicitly selected ignored file without widening its directory", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    await mkdir(join(checkout, "ignored"));
    await Promise.all([
      writeFile(join(checkout, ".gitignore"), "selected.skip\nignored/\n"),
      writeFile(join(checkout, "selected.skip"), "selected\n"),
      writeFile(join(checkout, "ignored", "tracked.ts"), "tracked\n"),
      writeFile(join(checkout, "ignored", "private.ts"), "private\n"),
    ]);
    execFileSync("git", ["add", "--force", "ignored/tracked.ts"], {
      cwd: checkout,
    });

    expect(await inventory(checkout, "selected.skip")).toEqual([
      "selected.skip",
    ]);
    expect(await inventory(checkout, "ignored")).toEqual([
      "ignored/tracked.ts",
    ]);
  });

  test("respects tracked files and ignore rules inside nested Git checkouts", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const nested = join(checkout, "nested");
    await mkdir(nested);
    execFileSync("git", ["init", "-q"], { cwd: nested });
    await Promise.all([
      writeFile(join(nested, ".gitignore"), ".env\n"),
      writeFile(join(nested, ".ignore"), "tracked.ts\n"),
      writeFile(join(nested, ".env"), "private\n"),
      writeFile(join(nested, "tracked.ts"), "tracked\n"),
      writeFile(join(nested, "visible.ts"), "visible\n"),
    ]);
    execFileSync("git", ["add", "tracked.ts"], { cwd: nested });

    const rows = await inventory(checkout);
    expect(rows).toContain("./nested/tracked.ts");
    expect(rows).toContain("./nested/visible.ts");
    expect(rows).not.toContain("./nested/.env");
  });

  test.each([
    ["embedded", "."],
    ["embedded", "nested"],
    ["conflicted Gitlink", "."],
    ["conflicted Gitlink", "nested"],
  ])(
    "retains outer tracked source inside %s checkout for %s",
    async (staging, scope) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const nested = join(checkout, "nested");
      await mkdir(nested);
      await Promise.all([
        writeFile(join(nested, "outer.ts"), "outer tracked\n"),
        writeFile(join(nested, "inner.ts"), "inner tracked\n"),
        writeFile(join(nested, "private.ts"), "private\n"),
      ]);
      execFileSync("git", ["add", "nested/outer.ts"], { cwd: checkout });
      execFileSync("git", ["init", "-q"], { cwd: nested });
      await writeFile(
        join(nested, ".ignore"),
        "outer.ts\ninner.ts\nprivate.ts\n",
      );
      execFileSync("git", ["add", "inner.ts"], { cwd: nested });
      if (staging === "conflicted Gitlink") {
        commit(nested);
        const gitlink = execFileSync("git", ["rev-parse", "HEAD"], {
          cwd: nested,
          encoding: "utf8",
        }).trim();
        const outer = execFileSync("git", ["rev-parse", ":nested/outer.ts"], {
          cwd: checkout,
          encoding: "utf8",
        }).trim();
        execFileSync("git", ["update-index", "--index-info"], {
          cwd: checkout,
          input: [
            `0 ${"0".repeat(40)}\tnested/outer.ts`,
            `160000 ${gitlink} 1\tnested`,
            `100644 ${outer} 2\tnested/outer.ts`,
            "",
          ].join("\n"),
        });
      }

      const prefix = scope === "." ? "./nested" : "nested";
      const rows = await inventory(checkout, scope);
      expect(rows).toContain(`${prefix}/outer.ts`);
      expect(rows).toContain(`${prefix}/inner.ts`);
      expect(rows).not.toContain(`${prefix}/private.ts`);
    },
  );

  test("recovers an embedded checkout hidden only by its own ignore file", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const nested = join(checkout, "nested");
    await mkdir(nested);
    execFileSync("git", ["init", "-q"], { cwd: nested });
    await writeFile(join(nested, ".ignore"), "*\n");
    await writeFile(join(nested, "tracked.ts"), "export {};\n");
    execFileSync("git", ["add", "tracked.ts"], { cwd: nested });

    expect(await inventory(checkout)).toContain("./nested/tracked.ts");
    await writeFile(join(checkout, ".ignore"), ".*\n");
    expect(await inventory(checkout)).toContain("./nested/tracked.ts");
    await writeFile(join(checkout, ".ignore"), "nested/\n");
    expect(await inventory(checkout)).not.toContain("./nested/tracked.ts");
  });

  test.each([".ignore", ".rgignore", ".git/info/exclude"])(
    "does not recover nested tracked files excluded by outer %s rules",
    async (ignore) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const nested = join(checkout, "nested");
      await mkdir(nested);
      execFileSync("git", ["init", "-q"], { cwd: nested });
      await writeFile(join(checkout, ignore), "nested/private.ts\n");
      await writeFile(join(nested, "private.ts"), "private\n");
      await writeFile(join(nested, "visible.ts"), "visible\n");
      execFileSync("git", ["add", "private.ts", "visible.ts"], {
        cwd: nested,
      });

      const rows = await inventory(checkout);
      expect(rows).toContain("./nested/visible.ts");
      expect(rows).not.toContain("./nested/private.ts");
    },
  );

  test.each([".ignore", ".gitignore", ".git/info/exclude"])(
    "applies %s file exclusions beneath tracked Git checkouts",
    async (outerIgnore) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const nested = join(checkout, "nested");
      await mkdir(nested);
      execFileSync("git", ["init", "-q"], { cwd: nested });
      await Promise.all([
        writeFile(
          join(checkout, ".gitignore"),
          outerIgnore === ".gitignore"
            ? "nested/\nnested/private.ts\n"
            : "nested/\n",
        ),
        ...(outerIgnore === ".gitignore"
          ? []
          : [writeFile(join(checkout, outerIgnore), "nested/private.ts\n")]),
        writeFile(join(nested, "private.ts"), "private\n"),
        writeFile(join(nested, "visible.ts"), "visible\n"),
      ]);
      execFileSync("git", ["add", "private.ts", "visible.ts"], { cwd: nested });
      commit(nested);
      execFileSync("git", ["add", "--force", "nested"], {
        cwd: checkout,
        stdio: "ignore",
      });

      const rows = await inventory(checkout);
      expect(rows).toContain("./nested/visible.ts");
      expect(rows).not.toContain("./nested/private.ts");

      const scoped = await inventory(checkout, "nested");
      expect(scoped).toContain("nested/visible.ts");
      expect(scoped).not.toContain("nested/private.ts");

      if (outerIgnore === ".git/info/exclude") {
        await writeFile(
          join(checkout, ".gitignore"),
          "nested/\n!nested/private.ts\n",
        );
        expect(await inventory(checkout)).toContain("./nested/private.ts");
        expect(await inventory(checkout, "nested")).toContain(
          "nested/private.ts",
        );
      }
    },
  );

  test.each(["nested", " #nested"])(
    "applies configured excludes from every enclosing checkout to %s",
    async (directory) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const middle = join(checkout, "middle");
      const nested = join(middle, directory);
      await mkdir(nested, { recursive: true });
      execFileSync("git", ["init", "-q"], { cwd: middle });
      execFileSync("git", ["init", "-q"], { cwd: nested });
      await Promise.all([
        writeFile(
          join(middle, ".git", "info", "exclude"),
          `${directory}/private.ts\n`,
        ),
        writeFile(join(nested, "private.ts"), "private\n"),
        writeFile(join(nested, "visible.ts"), "visible\n"),
      ]);
      execFileSync("git", ["add", "private.ts", "visible.ts"], { cwd: nested });

      const rows = await inventory(checkout);
      expect(rows).toContain(`./middle/${directory}/visible.ts`);
      expect(rows).not.toContain(`./middle/${directory}/private.ts`);
    },
  );

  test("preserves intermediate ignores beneath an ancestor Git link", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const middle = join(checkout, "middle");
    const nested = join(middle, "nested");
    await mkdir(nested, { recursive: true });
    execFileSync("git", ["init", "-q"], { cwd: middle });
    await writeFile(join(middle, "visible.ts"), "visible\n");
    execFileSync("git", ["add", "visible.ts"], { cwd: middle });
    commit(middle);
    execFileSync("git", ["add", "middle"], {
      cwd: checkout,
      stdio: "ignore",
    });
    execFileSync("git", ["init", "-q"], { cwd: nested });
    await Promise.all([
      writeFile(join(middle, ".gitignore"), "nested/private.ts\n"),
      writeFile(join(nested, "private.ts"), "private\n"),
      writeFile(join(nested, "visible.ts"), "visible\n"),
    ]);
    execFileSync("git", ["add", "private.ts", "visible.ts"], { cwd: nested });

    const rows = await inventory(checkout);
    expect(rows).toContain("./middle/nested/visible.ts");
    expect(rows).not.toContain("./middle/nested/private.ts");
  });

  test.each(["stage-0", "conflicted"])(
    "admits %s tracked Gitlinks through configured directory excludes",
    async (staging) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const nested = join(checkout, "nested");
      await mkdir(nested);
      execFileSync("git", ["init", "-q"], { cwd: nested });
      await Promise.all([
        writeFile(join(nested, "visible.ts"), "visible\n"),
        writeFile(join(nested, "private.ts"), "private\n"),
      ]);
      execFileSync("git", ["add", "visible.ts", "private.ts"], {
        cwd: nested,
      });
      commit(nested);
      execFileSync("git", ["add", "nested"], {
        cwd: checkout,
        stdio: "ignore",
      });
      if (staging === "conflicted") {
        const object = execFileSync("git", ["rev-parse", "HEAD"], {
          cwd: nested,
          encoding: "utf8",
        }).trim();
        execFileSync("git", ["update-index", "--index-info"], {
          cwd: checkout,
          input: [
            `0 ${"0".repeat(40)}\tnested`,
            ...[1, 2, 3].map((stage) => `160000 ${object} ${stage}\tnested`),
            "",
          ].join("\n"),
        });
      }
      await writeFile(
        join(checkout, ".git", "info", "exclude"),
        "nested/\nnested/private.ts\n",
      );

      const rows = await inventory(checkout);
      expect(rows).toContain("./nested/visible.ts");
      expect(rows).not.toContain("./nested/private.ts");
    },
  );

  test.skipIf(process.platform === "win32").each([".ignore", ".rgignore"])(
    "rejects a hidden Gitlink ancestor's symbolic %s",
    async (name) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const hidden = join(checkout, "hidden");
      const nested = join(hidden, "nested");
      const external = join(dirname(checkout), "external.ignore");
      await mkdir(nested, { recursive: true });
      execFileSync("git", ["init", "-q"], { cwd: nested });
      await writeFile(join(nested, "private.ts"), "tracked\n");
      execFileSync("git", ["add", "private.ts"], { cwd: nested });
      commit(nested);
      await writeFile(join(checkout, ".gitignore"), "hidden/\n");
      execFileSync("git", ["add", "--force", "hidden/nested"], {
        cwd: checkout,
        stdio: "ignore",
      });
      await writeFile(external, "nested/private.ts\n");
      await symlink(external, join(hidden, name));

      await expect(inventory(checkout)).rejects.toThrow(
        "symbolic ignore files are not supported",
      );
    },
  );

  test.each([
    ["visible", "nested/private.ts\n"],
    ["ignored", "nested/\nnested/private.ts\n"],
  ])(
    "preserves outer Git file exclusions for %s explicit nested scopes",
    async (_visibility, outerIgnores) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const nested = join(checkout, "nested");
      await mkdir(nested);
      execFileSync("git", ["init", "-q"], { cwd: nested });
      await Promise.all([
        writeFile(join(checkout, ".gitignore"), outerIgnores),
        writeFile(join(nested, "private.ts"), "private\n"),
        writeFile(join(nested, "visible.ts"), "visible\n"),
      ]);
      execFileSync("git", ["add", "private.ts", "visible.ts"], { cwd: nested });

      expect(await inventory(checkout, "nested")).toEqual([
        "nested/visible.ts",
      ]);

      await writeFile(join(checkout, ".git", "info", "exclude"), "nested/\n");
      expect(await inventory(checkout, "nested")).toEqual([]);
    },
  );

  test("does not grant Git link exemptions to replaced tracked files", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const nested = join(checkout, "nested");
    await writeFile(nested, "previously tracked file\n");
    execFileSync("git", ["add", "nested"], { cwd: checkout });
    await rm(nested);
    await mkdir(nested);
    execFileSync("git", ["init", "-q"], { cwd: nested });
    await Promise.all([
      writeFile(join(checkout, ".gitignore"), "nested/private.ts\n"),
      writeFile(join(nested, "private.ts"), "private\n"),
      writeFile(join(nested, "visible.ts"), "visible\n"),
    ]);
    execFileSync("git", ["add", "private.ts", "visible.ts"], { cwd: nested });

    const rows = await inventory(checkout);
    expect(rows).toContain("./nested/visible.ts");
    expect(rows).not.toContain("./nested/private.ts");
  });

  test.each([".ignore", ".rgignore", ".gitignore"])(
    "does not inspect checkout metadata excluded by outer %s rules",
    async (ignore) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const nested = join(checkout, "nested");
      const external = join(dirname(checkout), "external.config");
      await mkdir(nested);
      execFileSync("git", ["init", "-q"], { cwd: nested });
      await writeFile(external, "[core]\n\tignoreCase = true\n");
      execFileSync("git", ["config", "--local", "include.path", external], {
        cwd: nested,
      });
      await writeFile(join(checkout, ignore), "nested/\n");
      await writeFile(join(checkout, "visible.ts"), "visible\n");

      expect(await inventory(checkout)).toContain("./visible.ts");
    },
  );

  test("discovers self-hidden checkouts through visible snapshot directories", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository(false);
    const nested = join(checkout, "container", "nested");
    await mkdir(nested, { recursive: true });
    await writeFile(join(checkout, ".ignore"), "scan-source\n");
    execFileSync("git", ["init", "-q"], { cwd: nested });
    await writeFile(join(nested, ".ignore"), "*\n");
    await writeFile(join(nested, "tracked.ts"), "export {};\n");
    execFileSync("git", ["add", "tracked.ts"], { cwd: nested });

    expect(await inventory(checkout)).toContain(
      "./container/nested/tracked.ts",
    );

    await writeFile(
      join(checkout, "container", ".git"),
      "malformed nested Git marker\n",
    );
    expect(await inventory(checkout)).toContain(
      "./container/nested/tracked.ts",
    );

    await writeFile(join(checkout, ".ignore"), "scan-source\ncontainer/\n");
    expect(await inventory(checkout)).not.toContain(
      "./container/nested/tracked.ts",
    );
    await writeFile(join(checkout, ".ignore"), "scan-source\n");
    await writeFile(join(checkout, ".git"), "malformed snapshot marker\n");
    expect(await inventory(checkout)).toContain(
      "./container/nested/tracked.ts",
    );
  });

  test.skipIf(process.platform === "win32")(
    "rejects line-separated snapshot directory names before parsing ignore diagnostics",
    async () => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository(false);
      const nested = join(checkout, "victim", "nested");
      await mkdir(nested, { recursive: true });
      await mkdir(join(checkout, "evil\nrg: DEBUG|x: ignoring victim"));
      await writeFile(join(checkout, ".ignore"), "evil*\n");
      execFileSync("git", ["init", "-q"], { cwd: nested });
      await writeFile(join(nested, ".ignore"), "*\n");
      await writeFile(join(nested, "private.ts"), "tracked\n");
      execFileSync("git", ["add", "private.ts"], { cwd: nested });

      await expect(inventory(checkout)).rejects.toThrow(
        "line separators are not supported in inventory paths",
      );
    },
  );

  test("discovers Git-hidden checkouts reopened by ripgrep ignore rules", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const nested = join(checkout, "container", "nested");
    await mkdir(nested, { recursive: true });
    execFileSync("git", ["init", "-q"], { cwd: nested });
    await Promise.all([
      writeFile(join(checkout, ".gitignore"), "container/\n"),
      writeFile(join(checkout, ".ignore"), "!container/\n!container/nested/\n"),
      writeFile(join(nested, ".ignore"), "*\n"),
      writeFile(join(nested, "tracked.ts"), "export {};\n"),
    ]);
    execFileSync("git", ["add", "tracked.ts"], { cwd: nested });

    expect(await inventory(checkout)).toContain(
      "./container/nested/tracked.ts",
    );
  });

  test("discovers checkout overrides that hide their own ignore files", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const container = join(checkout, "container");
    const nested = join(container, "mid", "nested");
    await mkdir(nested, { recursive: true });
    execFileSync("git", ["init", "-q"], { cwd: nested });
    await Promise.all([
      writeFile(join(checkout, ".gitignore"), "container/mid/\n"),
      writeFile(
        join(container, ".ignore"),
        "*\n!mid/\n!mid/nested/\n!mid/nested/**\n",
      ),
      writeFile(join(nested, ".ignore"), "*\n"),
      writeFile(join(nested, "tracked.ts"), "export {};\n"),
    ]);
    execFileSync("git", ["add", "tracked.ts"], { cwd: nested });

    expect(await inventory(checkout)).toContain(
      "./container/mid/nested/tracked.ts",
    );
  });

  test("keeps ignore scaffolding separate from case-distinct checkouts", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    await Promise.all([
      writeFile(join(checkout, ".gitignore"), ".IGNORE/tracked.ts\n"),
      writeFile(
        join(checkout, ".ignore"),
        "!.IGNORE/tracked.ts\n.IGNORE/private.ts\n",
      ),
    ]);
    const nested = join(checkout, ".IGNORE");
    try {
      await mkdir(nested);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") return;
      throw error;
    }
    execFileSync("git", ["init", "-q"], { cwd: nested });
    await Promise.all([
      writeFile(join(nested, "tracked.ts"), "visible\n"),
      writeFile(join(nested, "private.ts"), "private\n"),
    ]);
    execFileSync("git", ["add", "tracked.ts", "private.ts"], { cwd: nested });

    const rows = await inventory(checkout);
    expect(rows).toContain("./.IGNORE/tracked.ts");
    expect(rows).not.toContain("./.IGNORE/private.ts");
  });

  test("preserves rgignore precedence for case-distinct checkout paths", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    await Promise.all([
      writeFile(join(checkout, ".ignore"), "!.RGIGNORE/private.ts\n"),
      writeFile(join(checkout, ".rgignore"), ".RGIGNORE/private.ts\n"),
    ]);
    const nested = join(checkout, ".RGIGNORE");
    try {
      await mkdir(nested);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") return;
      throw error;
    }
    execFileSync("git", ["init", "-q"], { cwd: nested });
    await Promise.all([
      writeFile(join(nested, "tracked.ts"), "visible\n"),
      writeFile(join(nested, "private.ts"), "private\n"),
    ]);
    execFileSync("git", ["add", "tracked.ts", "private.ts"], { cwd: nested });

    const rows = await inventory(checkout);
    expect(rows).toContain("./.RGIGNORE/tracked.ts");
    expect(rows).not.toContain("./.RGIGNORE/private.ts");
  });

  test.each([
    ["slash-only", "/\n"],
    ["whitespace-only", "   \n"],
    ["embedded-carriage-return", ".IGNORE/tracked.ts\rignored\n"],
    ["unterminated-carriage-return", ".IGNORE/tracked.ts\r"],
  ])(
    "keeps %s ignores inert when isolating nested checkout names",
    async (_description, contents) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const container = join(checkout, "container");
      const nested = join(container, ".IGNORE");
      await mkdir(container);
      await writeFile(join(container, ".ignore"), contents);
      try {
        await mkdir(nested);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "EEXIST") return;
        throw error;
      }
      execFileSync("git", ["init", "-q"], { cwd: nested });
      await writeFile(join(nested, ".ignore"), "*\n");
      await writeFile(join(nested, "tracked.ts"), "tracked\n");
      execFileSync("git", ["add", "tracked.ts"], { cwd: nested });

      expect(await inventory(checkout)).toContain(
        "./container/.IGNORE/tracked.ts",
      );
    },
  );

  test("preserves BOM-prefixed ignores when isolating nested checkout names", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const container = join(checkout, "container");
    const nested = join(container, ".IGNORE");
    await mkdir(container);
    await writeFile(join(container, ".ignore"), "\ufeff.IGNORE/private.ts\n");
    try {
      await mkdir(nested);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") return;
      throw error;
    }
    execFileSync("git", ["init", "-q"], { cwd: nested });
    await writeFile(join(nested, ".ignore"), "*\n");
    await writeFile(join(nested, "tracked.ts"), "tracked\n");
    await writeFile(join(nested, "private.ts"), "private\n");
    execFileSync("git", ["add", "tracked.ts", "private.ts"], {
      cwd: nested,
    });

    const rows = await inventory(checkout);
    expect(rows).toContain("./container/.IGNORE/tracked.ts");
    expect(rows).not.toContain("./container/.IGNORE/private.ts");
  });

  test("preserves canonically equivalent tracked directory spellings", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const nested = join(checkout, "nested");
    const composed = join(nested, "caf\u00e9");
    const decomposed = join(nested, "cafe\u0301");
    await mkdir(composed, { recursive: true });
    try {
      await mkdir(decomposed);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") return;
      throw error;
    }
    execFileSync("git", ["init", "-q"], { cwd: nested });
    await Promise.all([
      writeFile(join(checkout, ".gitignore"), "nested/private.ts\n"),
      writeFile(join(nested, ".ignore"), "*\n"),
      writeFile(join(composed, "first.ts"), "first\n"),
      writeFile(join(decomposed, "second.ts"), "second\n"),
    ]);
    execFileSync(
      "git",
      ["add", "--force", "caf\u00e9/first.ts", "cafe\u0301/second.ts"],
      {
        cwd: nested,
      },
    );

    const rows = await inventory(checkout);
    expect(rows).toContain("./nested/caf\u00e9/first.ts");
    expect(rows).toContain("./nested/cafe\u0301/second.ts");
  });

  test("keeps tracked files when an ignored snapshot checkout is explicitly selected", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository(false);
    const nested = join(checkout, "ignored");
    await mkdir(nested);
    await writeFile(join(checkout, ".gitignore"), "ignored/\n");
    execFileSync("git", ["init", "-q"], { cwd: nested });
    await Promise.all([
      writeFile(join(nested, "public.ts"), "tracked\n"),
      writeFile(join(nested, "private.ts"), "ignored\n"),
    ]);
    execFileSync("git", ["add", "public.ts"], { cwd: nested });

    expect(await inventory(checkout, "ignored")).toEqual(["ignored/public.ts"]);
  });

  test.each(["marker", "gitfile"])(
    "rejects symbolic Git metadata through a %s",
    async (kind) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository(false);
      const external = await repository();
      const metadata =
        kind === "marker"
          ? join(checkout, ".git")
          : join(dirname(checkout), "linked-metadata");
      await symlink(
        join(external, ".git"),
        metadata,
        process.platform === "win32" ? "junction" : "dir",
      );
      if (kind === "gitfile") {
        await writeFile(join(checkout, ".git"), `gitdir: ${metadata}\n`);
      }
      await writeFile(join(checkout, "visible.ts"), "visible\n");

      await expect(inventory(checkout)).rejects.toThrow(
        "symbolic Git metadata paths are not supported",
      );
    },
  );

  test.each(["gitdir", "backpointer", "commondir", "worktree"])(
    "rejects symbolic %s metadata hops before parent traversal",
    async (kind) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      await writeFile(join(checkout, "visible.ts"), "tracked\n");
      execFileSync("git", ["add", "visible.ts"], { cwd: checkout });
      commit(checkout);
      const linked = join(dirname(checkout), "linked-worktree");
      execFileSync("git", ["worktree", "add", "--detach", linked, "HEAD"], {
        cwd: checkout,
        stdio: "ignore",
      });
      const gitdir = (await readFile(join(linked, ".git"), "utf8"))
        .replace(/^gitdir: /, "")
        .trim();
      const outside = join(dirname(checkout), "outside", "hop-target");
      await mkdir(outside, { recursive: true });
      const hop =
        kind === "gitdir"
          ? join(dirname(gitdir), "hop")
          : kind === "commondir"
            ? join(checkout, "hop")
            : join(linked, "hop");
      await symlink(
        outside,
        hop,
        process.platform === "win32" ? "junction" : "dir",
      );

      if (kind === "gitdir") {
        await writeFile(
          join(linked, ".git"),
          `gitdir: ${hop}/../${basename(gitdir)}\n`,
        );
      } else if (kind === "backpointer") {
        await writeFile(join(gitdir, "gitdir"), `${hop}/../.git\n`);
      } else if (kind === "commondir") {
        await writeFile(join(gitdir, "commondir"), `${hop}/../.git\n`);
      } else {
        execFileSync("git", ["config", "extensions.worktreeConfig", "true"], {
          cwd: linked,
        });
        execFileSync(
          "git",
          ["config", "--worktree", "core.worktree", `${hop}/..`],
          {
            cwd: linked,
          },
        );
      }

      await expect(inventory(linked)).rejects.toThrow(
        "symbolic Git metadata paths are not supported",
      );
    },
  );

  test.skipIf(process.platform !== "win32").each([
    ["gitdir", "network"],
    ["gitdir", "device"],
    ["backpointer", "network"],
    ["commondir", "network"],
    ["worktree", "network"],
    ["alternates", "network"],
  ])(
    "rejects %s %s metadata before accessing its Windows anchor",
    async (kind, prefix) => {
      const checkout = await repository(kind !== "gitdir");
      const remote = `${
        prefix === "device" ? "\\\\?\\UNC" : "\\"
      }\\codex-security.invalid\\share\\one\\two\\three\\four\\five\\six\\seven\\eight`;
      let selected = checkout;
      if (kind === "gitdir") {
        await writeFile(join(checkout, ".git"), `gitdir: ${remote}\n`);
      } else if (kind === "alternates") {
        await writeFile(
          join(checkout, ".git", "objects", "info", "alternates"),
          `${remote}\n`,
        );
      } else {
        await writeFile(join(checkout, "tracked.ts"), "tracked\n");
        execFileSync("git", ["add", "tracked.ts"], { cwd: checkout });
        commit(checkout);
        selected = join(dirname(checkout), "linked-worktree");
        execFileSync("git", ["worktree", "add", "--detach", selected, "HEAD"], {
          cwd: checkout,
          stdio: "ignore",
        });
        const gitdir = (await readFile(join(selected, ".git"), "utf8"))
          .replace(/^gitdir: /, "")
          .trim();
        if (kind === "backpointer") {
          await writeFile(join(gitdir, "gitdir"), `${remote}\n`);
        } else if (kind === "commondir") {
          await writeFile(join(gitdir, "commondir"), `${remote}\n`);
        } else {
          execFileSync("git", ["config", "extensions.worktreeConfig", "true"], {
            cwd: selected,
          });
          await writeFile(
            join(gitdir, "config.worktree"),
            `[core]\n\tworktree = ${JSON.stringify(remote)}\n`,
          );
        }
      }
      const instrumentation = join(dirname(checkout), "instrumentation");
      await mkdir(instrumentation);
      await writeFile(
        join(instrumentation, "sitecustomize.py"),
        [
          "from pathlib import Path",
          "original = Path.stat",
          "def guarded(self, *args, **kwargs):",
          "    if self.anchor.startswith(chr(92) * 2) and 'codex-security.invalid' in str(self).casefold():",
          "        raise RuntimeError('attempted network metadata access')",
          "    return original(self, *args, **kwargs)",
          "Path.stat = guarded",
        ].join("\n"),
      );

      await expect(
        inventory(selected, ".", {
          ...process.env,
          PYTHONPATH: instrumentation,
        }),
      ).rejects.toThrow("network Git metadata paths are not supported");
    },
  );

  test.each(["worktrees", "owner"])(
    "rejects symbolic common %s metadata before following worktree ownership",
    async (kind) => {
      const checkout = await repository();
      await writeFile(join(checkout, "tracked.ts"), "tracked\n");
      execFileSync("git", ["add", "tracked.ts"], { cwd: checkout });
      commit(checkout);
      const linked = join(dirname(checkout), "linked-worktree");
      execFileSync("git", ["worktree", "add", "--detach", linked, "HEAD"], {
        cwd: checkout,
        stdio: "ignore",
      });
      const gitdir = (await readFile(join(linked, ".git"), "utf8"))
        .replace(/^gitdir: /, "")
        .trim();
      const common = join(dirname(checkout), "common-metadata");
      const external = join(dirname(checkout), "external-worktrees");
      await mkdir(common);
      await mkdir(external);
      if (kind === "owner") await mkdir(join(common, "worktrees"));
      const symbolic =
        kind === "worktrees"
          ? join(common, "worktrees")
          : join(common, "worktrees", basename(gitdir));
      await symlink(
        external,
        symbolic,
        process.platform === "win32" ? "junction" : "dir",
      );
      await writeFile(join(gitdir, "commondir"), `${common}\n`);

      const instrumentation = join(dirname(checkout), "instrumentation");
      await mkdir(instrumentation);
      await writeFile(
        join(instrumentation, "sitecustomize.py"),
        [
          "from pathlib import Path",
          `owner = Path(${JSON.stringify(join(common, "worktrees", basename(gitdir)))})`,
          "original = Path.stat",
          "def guarded(self, *args, **kwargs):",
          "    if self == owner and kwargs.get('follow_symlinks', True):",
          "        raise RuntimeError('followed unvalidated Git worktree owner')",
          "    return original(self, *args, **kwargs)",
          "Path.stat = guarded",
        ].join("\n"),
      );

      await expect(
        inventory(linked, ".", {
          ...process.env,
          PYTHONPATH: instrumentation,
        }),
      ).rejects.toThrow("symbolic Git metadata paths are not supported");
    },
  );

  test.each([".GIT", ".GIT.", ".g\u0131t", ".g\u0131t."])(
    "rejects symbolic %s metadata before resolving its filesystem alias",
    async (alias) => {
      if (process.platform === "win32" && alias.endsWith(".")) return;

      const checkout = await repository();
      const nested = join(checkout, "visible");
      const external = join(dirname(checkout), "external-metadata");
      await mkdir(nested);
      await mkdir(external);
      await symlink(
        external,
        join(nested, alias),
        process.platform === "win32" ? "junction" : "dir",
      );

      const instrumentation = join(dirname(checkout), "instrumentation");
      await mkdir(instrumentation);
      await writeFile(
        join(instrumentation, "sitecustomize.py"),
        [
          "from pathlib import Path",
          "original = Path.samefile",
          "def guarded(self, other):",
          "    if self.parent.name == 'visible' and self.name.upper().casefold().rstrip('. ') == '.git':",
          "        raise RuntimeError('followed symbolic Git metadata alias')",
          "    return original(self, other)",
          "Path.samefile = guarded",
        ].join("\n"),
      );

      await expect(
        inventory(checkout, ".", {
          ...process.env,
          PYTHONPATH: instrumentation,
        }),
      ).rejects.toThrow("symbolic Git metadata paths are not supported");
    },
  );

  test.each(["missing", "mismatched"])(
    "rejects an external gitdir with a %s worktree backpointer",
    async (ownership) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository(false);
      const external = await repository();
      await writeFile(join(external, "secret.ts"), "tracked\n");
      execFileSync("git", ["add", "secret.ts"], { cwd: external });
      await writeFile(join(checkout, ".gitignore"), "secret.ts\n");
      await writeFile(join(checkout, "secret.ts"), "private\n");
      await writeFile(
        join(checkout, ".git"),
        `gitdir: ${join(external, ".git")}\n`,
      );
      if (ownership === "mismatched") {
        await writeFile(
          join(external, ".git", "gitdir"),
          `${join(external, ".git")}\n`,
        );
      }

      await expect(inventory(checkout)).rejects.toThrow(
        "Git metadata directory does not own selected worktree",
      );
    },
  );

  test.each(["missing", "conflicting"])(
    "rejects an internal gitfile with %s checkout ownership",
    async (ownership) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const nested = join(checkout, "nested");
      await mkdir(nested);
      await writeFile(join(checkout, "secret.ts"), "tracked\n");
      execFileSync("git", ["add", "secret.ts"], { cwd: checkout });
      await writeFile(join(nested, ".ignore"), "secret.ts\n");
      await writeFile(join(nested, "secret.ts"), "private\n");
      await writeFile(join(nested, ".git"), "gitdir: ../.git\n");
      if (ownership === "conflicting") {
        execFileSync(
          "git",
          ["config", "--local", "core.worktree", "../nested"],
          {
            cwd: checkout,
          },
        );
      }

      await expect(inventory(checkout)).rejects.toThrow(
        "Git metadata directory does not own selected worktree",
      );
    },
  );

  test.each([
    "disabled",
    "disabled-comment",
    "disabled-empty",
    "disabled-quoted",
    "disabled-carriage",
    "disabled-symlink",
    "hash-comment-override",
    "semicolon-comment-override",
    "indented-override",
    "inline-section-override",
    "inline-carriage-override",
    "chained-section-override",
    "inline-extension-disabled",
    "carriage-return-override",
    "carriage-return-section",
    "carriage-return-section-comment",
    "default-inheritance",
    "unquoted-escape",
    "literal-tab",
    "literal-tab-missing",
    "quoted-tab-owned",
    "vertical-tab-owned",
    "form-feed-owned",
    "case-alias",
    "short-alias",
    "short-worktree",
    "owned",
    "external",
    "mixed-case-external",
  ])(
    "honors %s worktree-specific Git ownership configuration",
    async (ownership) => {
      if (Bun.which("rg") === null) return;
      if (ownership === "disabled-symlink" && process.platform === "win32")
        return;
      if (ownership === "unquoted-escape" && process.platform === "win32")
        return;
      const tabOwnership =
        ownership.startsWith("literal-tab") || ownership === "quoted-tab-owned";
      const controlOwnership =
        ownership === "vertical-tab-owned" || ownership === "form-feed-owned";
      if ((tabOwnership || controlOwnership) && process.platform === "win32")
        return;
      if (
        ownership.startsWith("short-") &&
        (process.platform !== "win32" || python === null)
      )
        return;

      const checkout = await repository();
      const nested = join(
        checkout,
        ownership === "unquoted-escape"
          ? "nested\\towner"
          : tabOwnership
            ? "nested\towner"
            : ownership === "vertical-tab-owned"
              ? "nested\vowner"
              : ownership === "form-feed-owned"
                ? "nested\fowner"
                : "nested",
      );
      const metadata = join(checkout, ".git", "modules", "nested");
      const external =
        ownership === "unquoted-escape"
          ? join(checkout, "nested\towner")
          : ownership === "literal-tab"
            ? join(checkout, "nested owner")
            : join(dirname(checkout), "external-worktree");
      await mkdir(dirname(metadata), { recursive: true });
      await mkdir(external);
      execFileSync(
        "git",
        ["init", "-q", "--separate-git-dir", metadata, nested],
        {
          cwd: checkout,
        },
      );
      execFileSync("git", ["-C", nested, "config", "core.worktree", nested]);
      execFileSync("git", [
        "-C",
        nested,
        "config",
        "extensions.worktreeConfig",
        ownership.startsWith("disabled") ||
        ownership.endsWith("comment-override") ||
        ownership === "indented-override" ||
        ownership === "inline-section-override" ||
        ownership === "inline-carriage-override" ||
        ownership === "chained-section-override" ||
        ownership.startsWith("carriage-return") ||
        ownership === "default-inheritance" ||
        ownership === "unquoted-escape" ||
        tabOwnership ||
        controlOwnership
          ? "false"
          : "true",
      ]);
      await writeFile(join(nested, "visible.ts"), "tracked\n");
      execFileSync("git", ["-C", nested, "add", "visible.ts"]);
      const effective =
        ownership === "owned" ||
        ownership === "case-alias" ||
        ownership === "short-alias" ||
        ownership === "short-worktree"
          ? nested
          : external;
      const config = join(metadata, "config");
      if (ownership === "mixed-case-external") {
        await writeFile(
          config,
          (await readFile(config, "utf8")).replace(
            /^\[extensions\]$/im,
            "[Extensions]",
          ),
        );
      } else if (
        ownership === "disabled-comment" ||
        ownership === "disabled-empty" ||
        ownership === "disabled-quoted" ||
        ownership === "disabled-carriage"
      ) {
        await writeFile(
          config,
          (await readFile(config, "utf8")).replace(
            /^([ \t]*worktreeConfig[ \t]*=[ \t]*)false$/im,
            ownership === "disabled-comment"
              ? "$1false # disabled"
              : ownership === "disabled-quoted"
                ? '$1f"al"se'
                : ownership === "disabled-carriage"
                  ? "$1\rfalse"
                  : "$1",
          ),
        );
      } else if (ownership.endsWith("comment-override")) {
        const comment = ownership.startsWith("hash") ? "#" : ";";
        await writeFile(
          config,
          (await readFile(config, "utf8")).replace(
            /^([ \t]*worktree[ \t]*=.*)$/im,
            `$1\n\t${comment} owner comment \\\n\tworktree = ${external}`,
          ),
        );
      } else if (ownership === "indented-override") {
        await writeFile(
          config,
          (await readFile(config, "utf8")).replace(
            /^([ \t]*worktree[ \t]*=.*)$/im,
            `$1 # selected owner\n\t\tworktree = ${external}`,
          ),
        );
      } else if (
        ownership === "inline-section-override" ||
        ownership === "inline-carriage-override" ||
        ownership === "chained-section-override"
      ) {
        const header =
          ownership === "chained-section-override"
            ? '[0][-][.legacy][ "quoted"][feature][unused.value][core]'
            : "[core]";
        const whitespace = ownership === "inline-carriage-override" ? "\r" : "";
        await writeFile(
          config,
          `${await readFile(config, "utf8")}\n${header}${whitespace}worktree = ${external}\n`,
        );
      } else if (ownership === "inline-extension-disabled") {
        await writeFile(
          config,
          `${await readFile(config, "utf8")}\n[extensions]worktreeConfig = false\n`,
        );
      } else if (ownership === "carriage-return-override") {
        await writeFile(
          config,
          (await readFile(config, "utf8")).replace(
            /^([ \t]*worktree[ \t]*=.*)$/im,
            `$1\n\rworktree = ${external}`,
          ),
        );
      } else if (
        ownership === "carriage-return-section" ||
        ownership === "carriage-return-section-comment"
      ) {
        await writeFile(
          config,
          `${await readFile(config, "utf8")}\n${
            ownership === "carriage-return-section"
              ? "\r[core]"
              : "[core]\r# selected owner"
          }\n\tworktree = ${external}\n`,
        );
      } else if (ownership === "default-inheritance") {
        const withoutOwner = (await readFile(config, "utf8")).replace(
          /^[ \t]*worktree[ \t]*=.*\n/im,
          "",
        );
        await writeFile(
          config,
          `${withoutOwner}\n[DEFAULT]\n\tworktree = ${nested}\n`,
        );
      } else if (
        ownership === "unquoted-escape" ||
        tabOwnership ||
        controlOwnership
      ) {
        await writeFile(
          config,
          (await readFile(config, "utf8")).replace(
            /^([ \t]*worktree[ \t]*=).*$/im,
            ownership === "quoted-tab-owned"
              ? `$1 "${nested.replaceAll("\t", "\\t")}"`
              : `$1 ${nested}`,
          ),
        );
      }
      const configuredOwner =
        ownership === "short-worktree" ? windowsShortPath(nested) : effective;
      if (configuredOwner === null) return;
      const override = `[${ownership === "mixed-case-external" ? "Core" : "core"}]\n\tworktree = ${configuredOwner}\n`;
      if (ownership === "disabled-symlink") {
        const unused = join(dirname(checkout), "unused.config");
        await writeFile(unused, override);
        await symlink(unused, join(metadata, "config.worktree"));
      } else if (
        ownership === "disabled-quoted" ||
        ownership === "disabled-carriage"
      ) {
        await mkdir(join(metadata, "config.worktree"));
      } else {
        await writeFile(join(metadata, "config.worktree"), override);
      }
      if (ownership === "case-alias" || ownership === "short-alias") {
        const alias =
          ownership === "case-alias"
            ? metadata.toUpperCase()
            : windowsShortPath(metadata);
        if (alias === null) return;
        const equivalent = await realpath(alias).then(
          async (resolved) => resolved === (await realpath(metadata)),
          () => false,
        );
        if (!equivalent) return;
        await writeFile(join(nested, ".git"), `gitdir: ${alias}\n`);
      }

      if (
        ownership === "external" ||
        ownership === "mixed-case-external" ||
        ownership.endsWith("comment-override") ||
        ownership === "indented-override" ||
        ownership === "inline-section-override" ||
        ownership === "inline-carriage-override" ||
        ownership === "chained-section-override" ||
        ownership.startsWith("carriage-return") ||
        ownership === "default-inheritance" ||
        ownership === "unquoted-escape" ||
        ownership.startsWith("literal-tab")
      ) {
        await expect(inventory(checkout)).rejects.toThrow(
          "Git metadata directory does not own selected worktree",
        );
      } else {
        expect(await inventory(checkout)).toContain(
          `./${basename(nested)}/visible.ts`,
        );
      }
    },
  );

  test
    .skipIf(process.platform === "win32")
    .each(["symbolic", "missing", "quoted"])(
    "validates %s carriage-return Git worktree normalization",
    async (ownership) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const nested = join(checkout, "nested");
      const metadata = join(checkout, ".git", "modules", "nested");
      const original = join(checkout, ".git", "owned\rmetadata");
      const normalized = join(checkout, ".git", "owned metadata");
      const external = join(dirname(checkout), "external-worktree");
      await mkdir(dirname(metadata), { recursive: true });
      await mkdir(original);
      await mkdir(external);
      if (ownership !== "missing") await symlink(external, normalized);
      execFileSync(
        "git",
        ["init", "-q", "--separate-git-dir", metadata, nested],
        { cwd: checkout },
      );
      execFileSync("git", ["-C", nested, "config", "core.worktree", nested]);
      await writeFile(join(nested, "visible.ts"), "tracked\n");
      execFileSync("git", ["-C", nested, "add", "visible.ts"]);
      const config = join(metadata, "config");
      const configured = `${original}/../../nested`;
      await writeFile(
        config,
        (await readFile(config, "utf8")).replace(
          /^([ \t]*worktree[ \t]*=).*$/im,
          `$1 ${ownership === "quoted" ? `"${configured}"` : configured}`,
        ),
      );

      if (ownership === "quoted") {
        expect(await inventory(checkout)).toContain("./nested/visible.ts");
      } else {
        await expect(inventory(checkout)).rejects.toThrow(
          ownership === "symbolic"
            ? "symbolic Git metadata paths are not supported"
            : "Git metadata directory does not own selected worktree",
        );
      }
    },
  );

  test("rejects unrelated external Git common directories", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const external = await repository();
    await writeFile(join(checkout, "visible.ts"), "visible\n");
    await writeFile(
      join(checkout, ".git", "commondir"),
      `${join(external, ".git")}\n`,
    );

    await expect(inventory(checkout)).rejects.toThrow(
      "Git common directory does not own selected worktree",
    );
  });

  test("binds Git discovery to the selected checkout despite external core.worktree", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const external = join(dirname(checkout), "external-worktree");
    const trace = join(dirname(checkout), "git-trace.log");
    await mkdir(external);
    await writeFile(join(checkout, "visible.ts"), "visible\n");
    execFileSync("git", ["config", "--local", "core.worktree", external], {
      cwd: checkout,
    });

    expect(
      await inventory(checkout, ".", {
        ...process.env,
        GIT_TRACE: trace,
        GIT_TRACE_SETUP: "1",
      }),
    ).toEqual(["./visible.ts"]);
    expect(await readFile(trace, "utf8")).not.toContain(external);
  });

  test
    .skipIf(process.platform === "win32")
    .each(["objects", "objects/info/alternates"])(
    "rejects symbolic Git object metadata at %s",
    async (relative) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const external = await repository();
      const metadata = join(checkout, ".git", relative);
      const target =
        relative === "objects"
          ? join(external, ".git", "objects")
          : join(dirname(checkout), "external-alternates");
      if (relative !== "objects") await writeFile(target, "external\n");
      await rm(metadata, { recursive: relative === "objects", force: true });
      await symlink(target, metadata);

      await expect(inventory(checkout)).rejects.toThrow(
        "symbolic Git metadata paths are not supported",
      );
    },
  );

  test("rejects external Git object alternates before invoking Git", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const external = await repository();
    const trace = join(dirname(checkout), "git-trace.log");
    await writeFile(
      join(checkout, ".git", "objects", "info", "alternates"),
      `${join(external, ".git", "objects")}\n`,
    );

    await expect(
      inventory(checkout, ".", { ...process.env, GIT_TRACE: trace }),
    ).rejects.toThrow("external Git object alternates are not supported");
    await expect(readFile(trace, "utf8")).rejects.toThrow();
  });

  test.each(["pack", "ab"])(
    "rejects symbolic Git object-store %s directories",
    async (name) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const external = await repository();
      const internal = join(checkout, ".git", "extra-objects");
      const target = join(external, ".git", "objects", name);
      await mkdir(join(internal, "info"), { recursive: true });
      if (name !== "pack") await mkdir(target);
      await symlink(
        target,
        join(internal, name),
        process.platform === "win32" ? "junction" : "dir",
      );
      await writeFile(
        join(checkout, ".git", "objects", "info", "alternates"),
        `${internal}\n`,
      );

      await expect(inventory(checkout)).rejects.toThrow(
        "symbolic Git metadata paths are not supported",
      );
    },
  );

  test.each(["primary", "alternate"])(
    "rejects symbolic incremental %s Git multi-pack-index directories",
    async (owner) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const external = await repository();
      const objects =
        owner === "primary"
          ? join(checkout, ".git", "objects")
          : join(checkout, ".git", "extra-objects");
      if (owner === "alternate") {
        await mkdir(join(objects, "info"), { recursive: true });
        await mkdir(join(objects, "pack"));
        await writeFile(
          join(checkout, ".git", "objects", "info", "alternates"),
          `${objects}\n`,
        );
      }
      const target = join(
        external,
        ".git",
        "objects",
        "pack",
        "multi-pack-index.d",
      );
      await mkdir(target);
      await symlink(
        target,
        join(objects, "pack", "multi-pack-index.d"),
        process.platform === "win32" ? "junction" : "dir",
      );

      await expect(inventory(checkout)).rejects.toThrow(
        "symbolic Git metadata paths are not supported",
      );
    },
  );

  test
    .skipIf(process.platform === "win32")
    .each(["chain", "midx", "bitmap", "rev"])(
    "rejects symbolic incremental Git multi-pack-index %s files",
    async (kind) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const directory = join(
        checkout,
        ".git",
        "objects",
        "pack",
        "multi-pack-index.d",
      );
      const target = join(dirname(checkout), "external-index");
      await mkdir(directory);
      await writeFile(target, "external\n");
      const name =
        kind === "chain"
          ? "multi-pack-index-chain"
          : `multi-pack-index-${"a".repeat(40)}.${kind}`;
      await symlink(target, join(directory, name));

      await expect(inventory(checkout)).rejects.toThrow(
        "symbolic Git metadata paths are not supported",
      );
    },
  );

  test("inventories genuine incremental Git multi-pack indexes", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    await writeFile(join(checkout, "visible.ts"), "tracked\n");
    execFileSync("git", ["add", "visible.ts"], { cwd: checkout });
    commit(checkout);
    execFileSync("git", ["repack", "-ad"], { cwd: checkout, stdio: "ignore" });
    try {
      execFileSync("git", ["multi-pack-index", "write", "--incremental"], {
        cwd: checkout,
        stdio: "pipe",
      });
    } catch (error) {
      const stderr = String(
        (error as Error & { stderr?: Buffer }).stderr ?? "",
      );
      if (/unknown|unrecognized/i.test(stderr)) return;
      throw error;
    }
    await mkdir(
      join(
        checkout,
        ".git",
        "objects",
        "pack",
        "multi-pack-index.d",
        "unrelated-dir",
      ),
    );

    expect(await inventory(checkout)).toContain("./visible.ts");
  });

  test.skipIf(process.platform === "win32").each([
    ["primary", "pack"],
    ["primary-uppercase", "pack"],
    ["primary-arbitrary-pack", "pack"],
    ["primary-arbitrary-index", "pack"],
    ["primary-midx", "pack"],
    ["primary-uppercase-midx", "pack"],
    ["primary-uppercase-extension", "pack"],
    ["primary", "ab"],
    ["primary-uppercase", "ab"],
    ["alternate", "pack"],
    ["alternate-uppercase", "pack"],
    ["alternate-arbitrary-pack", "pack"],
    ["alternate-arbitrary-index", "pack"],
    ["alternate-midx", "pack"],
    ["alternate-uppercase-midx", "pack"],
    ["alternate-uppercase-extension", "pack"],
    ["alternate", "ab"],
    ["alternate-uppercase", "ab"],
  ])("rejects symbolic %s Git object files in %s", async (owner, kind) => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const external = join(dirname(checkout), "external-object");
    await writeFile(external, "external\n");
    const objects = owner.startsWith("primary")
      ? join(checkout, ".git", "objects")
      : join(checkout, ".git", "extra-objects");
    if (owner.startsWith("alternate")) {
      await mkdir(join(objects, "info"), { recursive: true });
      await mkdir(join(objects, "pack"));
      await writeFile(
        join(checkout, ".git", "objects", "info", "alternates"),
        `${objects}\n`,
      );
    }
    const directory = join(objects, kind);
    if (kind !== "pack") await mkdir(directory);
    const hex = owner.endsWith("uppercase") ? "A" : "0";
    const basename = owner.includes("arbitrary")
      ? "arbitrary"
      : `pack-${hex.repeat(40)}`;
    const suffix = owner.endsWith("index")
      ? "idx"
      : owner.endsWith("extension")
        ? "PACK"
        : "pack";
    const member =
      kind !== "pack"
        ? hex.repeat(38)
        : owner.endsWith("midx")
          ? owner.includes("uppercase")
            ? "MULTI-PACK-INDEX"
            : "multi-pack-index"
          : `${basename}.${suffix}`;
    await symlink(external, join(directory, member));
    if (
      (kind !== "pack" && hex === "A") ||
      member === "MULTI-PACK-INDEX" ||
      member.endsWith(".PACK")
    ) {
      const aliases = await realpath(
        join(directory, member.toLowerCase()),
      ).then(
        () => true,
        () => false,
      );
      if (!aliases) {
        await writeFile(join(checkout, "visible.ts"), "visible\n");
        expect(await inventory(checkout)).toContain("./visible.ts");
        return;
      }
    }

    await expect(inventory(checkout)).rejects.toThrow(
      "symbolic Git metadata paths are not supported",
    );
  });

  test.each(["pack", "ab"])(
    "allows unrelated tooling directories inside Git object %s",
    async (kind) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const directory = join(checkout, ".git", "objects", kind);
      if (kind !== "pack") await mkdir(directory);
      await mkdir(join(directory, "unrelated-dir"));
      await writeFile(join(checkout, "visible.ts"), "visible\n");

      expect(await inventory(checkout)).toContain("./visible.ts");
    },
  );

  test.skipIf(process.platform === "win32").each(["PACK", "AB"])(
    "ignores unrelated uppercase Git object-store name %s",
    async (name) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const external = await repository();
      const objects = join(checkout, ".git", "objects");
      if (name === "AB") await mkdir(join(objects, "ab"));
      try {
        await symlink(join(external, ".git", "objects"), join(objects, name));
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "EEXIST") return;
        throw error;
      }
      await writeFile(join(checkout, "visible.ts"), "visible\n");

      expect(await inventory(checkout)).toContain("./visible.ts");
    },
  );

  test.skipIf(process.platform === "win32")(
    "preserves carriage returns in Git object-alternate paths",
    async () => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const external = await repository();
      const internal = join(checkout, ".git", "safe-objects");
      await mkdir(join(internal, "info"), { recursive: true });
      await mkdir(join(internal, "pack"));
      await symlink(join(external, ".git", "objects"), `${internal}\r`);
      await writeFile(
        join(checkout, ".git", "objects", "info", "alternates"),
        `${internal}\r\n`,
      );

      await expect(inventory(checkout)).rejects.toThrow(
        "symbolic Git metadata paths are not supported",
      );
    },
  );

  test("rejects external transitive Git object alternates before invoking Git", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const external = await repository();
    const internal = join(checkout, ".git", "extra-objects");
    const trace = join(dirname(checkout), "git-trace.log");
    await mkdir(join(internal, "info"), { recursive: true });
    await mkdir(join(internal, "pack"));
    await writeFile(
      join(checkout, ".git", "objects", "info", "alternates"),
      `${internal}\n`,
    );
    await writeFile(
      join(internal, "info", "alternates"),
      `${join(external, ".git", "objects")}\n`,
    );

    await expect(
      inventory(checkout, ".", { ...process.env, GIT_TRACE: trace }),
    ).rejects.toThrow("external Git object alternates are not supported");
    await expect(readFile(trace, "utf8")).rejects.toThrow();
  });

  test.skipIf(process.platform === "win32").each(["primary", "transitive"])(
    "rejects symbolic %s Git object-alternate hops before parent traversal",
    async (kind) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const outside = join(dirname(checkout), "outside");
      const external = join(outside, "store");
      const decoy = join(checkout, ".git", "store");
      const hop = join(checkout, ".git", "hop");
      await mkdir(join(outside, "hop-target"), { recursive: true });
      for (const objects of [external, decoy]) {
        await mkdir(join(objects, "info"), { recursive: true });
        await mkdir(join(objects, "pack"));
      }
      await symlink(join(outside, "hop-target"), hop);
      const alternate = `${hop}/../store`;
      if (kind === "primary") {
        await writeFile(
          join(checkout, ".git", "objects", "info", "alternates"),
          `${alternate}\n`,
        );
      } else {
        const first = join(checkout, ".git", "first-objects");
        await mkdir(join(first, "info"), { recursive: true });
        await mkdir(join(first, "pack"));
        await writeFile(
          join(checkout, ".git", "objects", "info", "alternates"),
          `${first}\n`,
        );
        await writeFile(join(first, "info", "alternates"), `${alternate}\n`);
      }

      await expect(inventory(checkout)).rejects.toThrow(
        "symbolic Git metadata paths are not supported",
      );
    },
  );

  test.each(["\\x61", "\\400"])(
    "rejects quoted Git object alternates with unsupported escape %s",
    async (escape) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const objects = join(checkout, ".git", "extra-objects");
      await writeFile(
        join(checkout, ".git", "objects", "info", "alternates"),
        `"${objects}${escape}"\n`,
      );

      await expect(inventory(checkout)).rejects.toThrow(
        "invalid Git object alternate paths",
      );
    },
  );

  test("rejects differently cased sibling Git object alternates", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const sibling = join(dirname(checkout), "REPOSITORY");
    try {
      await mkdir(sibling);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") return;
      throw error;
    }
    execFileSync("git", ["init", "-q"], { cwd: sibling });
    await writeFile(
      join(checkout, ".git", "objects", "info", "alternates"),
      `${join(sibling, ".git", "objects")}\n`,
    );

    await expect(inventory(checkout)).rejects.toThrow(
      "external Git object alternates are not supported",
    );
  });

  test("allows repository-owned Git object alternates", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const objects = join(checkout, ".git", "extra objects");
    await mkdir(join(objects, "info"), { recursive: true });
    await mkdir(join(objects, "pack"));
    await writeFile(
      join(checkout, ".git", "objects", "info", "alternates"),
      `${JSON.stringify(objects).replace("extra objects", "extra\\040objects")}\n`,
    );
    await writeFile(join(checkout, "visible.ts"), "visible\n");

    expect(await inventory(checkout)).toContain("./visible.ts");
  });

  test.each(["quoted", "unquoted"])(
    "allows %s CRLF-terminated repository-owned Git object alternates",
    async (format) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const objects = join(checkout, ".git", "extra objects");
      await mkdir(join(objects, "info"), { recursive: true });
      await mkdir(join(objects, "pack"));
      await writeFile(
        join(checkout, ".git", "objects", "info", "alternates"),
        `${format === "quoted" ? JSON.stringify(objects) : objects}\r\n`,
      );
      await writeFile(join(checkout, "visible.ts"), "visible\n");

      expect(await inventory(checkout)).toContain("./visible.ts");
    },
  );

  test("allows safe parent traversal to repository-owned Git object alternates", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const objects = join(checkout, ".git", "extra-objects");
    await mkdir(join(objects, "info"), { recursive: true });
    await mkdir(join(objects, "pack"));
    await writeFile(
      join(checkout, ".git", "objects", "info", "alternates"),
      "../extra-objects\n",
    );
    await writeFile(join(checkout, "visible.ts"), "visible\n");

    expect(await inventory(checkout)).toContain("./visible.ts");
  });

  test.each(["case-alias", "short-alias"])(
    "allows %s repository-owned Git object alternate paths",
    async (kind) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const objects = join(checkout, ".git", "extra-objects");
      await mkdir(join(objects, "info"), { recursive: true });
      await mkdir(join(objects, "pack"));
      const alias =
        kind === "case-alias"
          ? objects.toUpperCase()
          : windowsShortPath(objects);
      if (alias === null) return;
      const equivalent = await realpath(alias).then(
        async (resolved) => resolved === (await realpath(objects)),
        () => false,
      );
      if (!equivalent) return;
      await writeFile(
        join(checkout, ".git", "objects", "info", "alternates"),
        `${alias}\n`,
      );
      await writeFile(join(checkout, "visible.ts"), "visible\n");

      expect(await inventory(checkout)).toContain("./visible.ts");
    },
  );

  test("allows repository-owned transitive Git object alternates", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const first = join(checkout, ".git", "first-objects");
    const second = join(checkout, ".git", "second-objects");
    for (const objects of [first, second]) {
      await mkdir(join(objects, "info"), { recursive: true });
      await mkdir(join(objects, "pack"));
    }
    await writeFile(
      join(checkout, ".git", "objects", "info", "alternates"),
      `${first}\n`,
    );
    await writeFile(
      join(first, "info", "alternates"),
      `${JSON.stringify(second)}\n`,
    );
    await writeFile(join(second, "info", "alternates"), `${first}\n`);
    await writeFile(join(checkout, "visible.ts"), "visible\n");

    expect(await inventory(checkout)).toContain("./visible.ts");
  });

  test.skipIf(process.platform === "win32")(
    "rejects escaped Git index entries before probing sibling metadata",
    async () => {
      const git = Bun.which("git");
      if (Bun.which("rg") === null || git === null) return;

      const checkout = await repository();
      const outside = join(dirname(checkout), "outside");
      const wrappers = join(dirname(checkout), "bin");
      await mkdir(outside);
      await mkdir(wrappers);
      execFileSync("git", ["init", "-q"], { cwd: outside });
      await writeFile(join(checkout, "source.ts"), "visible\n");
      const wrapper = join(wrappers, "git");
      await writeFile(
        wrapper,
        `#!/bin/sh\ncase " $* " in\n  *" ls-files --sparse --cached "*) printf '../outside\\000' ;;\n  *) exec ${JSON.stringify(git)} "$@" ;;\nesac\n`,
      );
      await chmod(wrapper, 0o755);

      await expect(
        inventory(checkout, ".", {
          ...process.env,
          PATH: `${wrappers}:${process.env["PATH"] ?? ""}`,
        }),
      ).rejects.toThrow("out-of-scope Git inventory paths are not supported");
    },
  );

  test.skipIf(process.platform === "win32")(
    "disables lazy Git object fetching and replacement during inventory",
    async () => {
      const git = Bun.which("git");
      if (Bun.which("rg") === null || git === null) return;

      const checkout = await repository();
      const wrappers = join(dirname(checkout), "bin");
      const trace = join(dirname(checkout), "lazy-fetch.log");
      await mkdir(wrappers);
      await writeFile(join(checkout, "visible.ts"), "visible\n");
      const wrapper = join(wrappers, "git");
      await writeFile(
        wrapper,
        `#!/bin/sh\nprintf '%s:%s\\n' "$GIT_NO_LAZY_FETCH" "$GIT_NO_REPLACE_OBJECTS" >> ${JSON.stringify(trace)}\nexec ${JSON.stringify(git)} "$@"\n`,
      );
      await chmod(wrapper, 0o755);

      expect(
        await inventory(checkout, ".", {
          ...process.env,
          GIT_NO_LAZY_FETCH: "0",
          GIT_NO_REPLACE_OBJECTS: "0",
          PATH: `${wrappers}:${process.env["PATH"] ?? ""}`,
        }),
      ).toContain("./visible.ts");
      expect((await readFile(trace, "utf8")).trim().split("\n")).toSatisfy(
        (values: string[]) =>
          values.length > 0 && values.every((value) => value === "1:1"),
      );
    },
  );

  test.each(["selected", "nested"])(
    "rejects symbolic ancestors in %s Git-listed paths before reading external metadata",
    async (kind) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const owner = kind === "selected" ? checkout : join(checkout, "nested");
      if (kind === "nested") {
        await mkdir(owner);
        execFileSync("git", ["init", "-q"], { cwd: owner });
      }
      const link = join(owner, "link");
      await mkdir(link);
      await writeFile(join(link, "nested"), "tracked\n");
      execFileSync("git", ["add", "link/nested"], { cwd: owner });

      const external = await repository();
      const nested = join(external, "nested");
      await mkdir(nested);
      execFileSync("git", ["init", "-q"], { cwd: nested });
      await writeFile(
        join(nested, ".git", "config"),
        "[include]\n\tpath = outside\n",
      );
      await rm(link, { recursive: true });
      await symlink(
        external,
        link,
        process.platform === "win32" ? "junction" : "dir",
      );

      await expect(inventory(checkout)).rejects.toThrow(
        "symbolic Git inventory paths are not supported",
      );
    },
  );

  test.skipIf(process.platform !== "win32")(
    "rejects drive-relative Git index entries before probing another drive",
    async () => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const original = "D-checkout";
      await writeFile(join(checkout, original), "tracked\n");
      execFileSync("git", ["add", original], { cwd: checkout });
      const indexPath = join(checkout, ".git", "index");
      const index = await readFile(indexPath);
      const offset = index.indexOf(Buffer.from(`${original}\0`));
      if (offset === -1)
        throw new Error("Expected the staged Git index entry.");
      index.write("D:checkout", offset, "utf8");
      createHash("sha1")
        .update(index.subarray(0, index.length - 20))
        .digest()
        .copy(index, index.length - 20);
      await writeFile(indexPath, index);

      await expect(inventory(checkout)).rejects.toThrow(
        "out-of-scope Git inventory paths are not supported",
      );
    },
  );

  test.each([
    "shared-index",
    "multi-pack-index",
    "pack-index-suffix",
    "incremental-index-directory",
    "incremental-index-chain",
    "incremental-index-bitmap",
  ])("rejects Windows-compatible %s metadata aliases", async (kind) => {
    const checkout = await repository();
    const gitdir = join(checkout, ".git");
    let directory = join(gitdir, "objects", "pack");
    let canonical = "multi-pack-index";

    if (kind === "shared-index") {
      await writeFile(join(checkout, "tracked.ts"), "tracked\n");
      execFileSync("git", ["add", "tracked.ts"], { cwd: checkout });
      execFileSync("git", ["update-index", "--split-index"], {
        cwd: checkout,
      });
      const shared = (await readdir(gitdir)).find((name) =>
        name.startsWith("sharedindex."),
      );
      if (shared === undefined) throw new Error("Expected a split Git index.");
      directory = gitdir;
      canonical = shared;
      await rm(join(directory, canonical));
    } else if (kind === "pack-index-suffix") {
      canonical = `pack-${"a".repeat(40)}.idx`;
    } else if (kind === "incremental-index-directory") {
      canonical = "multi-pack-index.d";
    } else if (kind.startsWith("incremental-index-")) {
      directory = join(directory, "multi-pack-index.d");
      await mkdir(directory);
      canonical =
        kind === "incremental-index-chain"
          ? "multi-pack-index-chain"
          : `multi-pack-index-${"a".repeat(40)}.bitmap`;
    }

    const alias = canonical.replace("i", "\u0131");
    const external = join(dirname(checkout), "external-metadata");
    await mkdir(external);
    await symlink(
      external,
      join(directory, alias),
      process.platform === "win32" ? "junction" : "dir",
    );

    const instrumentation = join(dirname(checkout), "instrumentation");
    await mkdir(instrumentation);
    await writeFile(
      join(instrumentation, "sitecustomize.py"),
      [
        "from pathlib import Path",
        `canonical = Path(${JSON.stringify(join(directory, canonical))})`,
        `alias = Path(${JSON.stringify(join(directory, alias))})`,
        "original = Path.stat",
        "def guarded(self, *args, **kwargs):",
        "    if self == canonical and kwargs.get('follow_symlinks') is False:",
        "        return original(alias, *args, **kwargs)",
        "    return original(self, *args, **kwargs)",
        "Path.stat = guarded",
      ].join("\n"),
    );

    await expect(
      inventory(checkout, ".", {
        ...process.env,
        PYTHONPATH: instrumentation,
      }),
    ).rejects.toThrow("symbolic Git metadata paths are not supported");
  });

  test.skipIf(process.platform === "win32").each(["lowercase", "uppercase"])(
    "rejects %s split-index backing files that leave the checkout",
    async (casing) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      await writeFile(join(checkout, "tracked.ts"), "tracked\n");
      execFileSync("git", ["add", "tracked.ts"], { cwd: checkout });
      execFileSync("git", ["update-index", "--split-index"], {
        cwd: checkout,
      });
      const gitdir = join(checkout, ".git");
      const shared = (await readdir(gitdir)).find((name) =>
        name.startsWith("sharedindex."),
      );
      if (shared === undefined) throw new Error("Expected a split Git index.");
      await mkdir(join(gitdir, "sharedindex.notes"));

      expect(await inventory(checkout)).toContain("./tracked.ts");
      const original = join(gitdir, shared);
      const external = join(dirname(checkout), shared);
      await writeFile(external, await readFile(original));
      await rm(original);
      const replacement =
        casing === "uppercase" ? join(gitdir, shared.toUpperCase()) : original;
      await symlink(external, replacement);
      if (
        casing === "uppercase" &&
        !(await realpath(original).then(
          () => true,
          () => false,
        ))
      ) {
        return;
      }

      await expect(inventory(checkout)).rejects.toThrow(
        "symbolic Git metadata paths are not supported",
      );
    },
  );

  test.each([
    ["include", "without BOM"],
    ['includeIf "gitdir:**"', "without BOM"],
    ["include", "with BOM"],
    ["include", "with leading carriage return"],
    ["include", "with carriage return after header"],
    ["include", "with same-line path"],
    ["include", "with same-line carriage path"],
    ["include", "with chained section headers"],
    ['includeIf "gitdir:**"', "with same-line path"],
    ['includeIf "gitdir:**"', "with chained section headers"],
    ['includeIf "gitdir:**"', "with carriage return before condition"],
    [
      'includeIf "gitdir:**"',
      "with carriage return after condition whitespace",
    ],
    [
      'includeIf "gitdir:**"',
      "with carriage return replacing condition whitespace",
    ],
  ])(
    "rejects repository-directed %s config %s before invoking Git",
    async (section, bom) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const external = join(dirname(checkout), "external.config");
      await writeFile(external, "[core]\n\tignoreCase = true\n");
      const config = join(checkout, ".git", "config");
      const whitespace =
        bom === "with carriage return before condition"
          ? "\r "
          : bom === "with carriage return after condition whitespace"
            ? " \r"
            : bom === "with carriage return replacing condition whitespace"
              ? "\r"
              : " ";
      const configuredSection = section.replace(" ", whitespace);
      const headers =
        bom === "with chained section headers"
          ? `[0][-][.legacy][ "quoted"][feature][unused.value][${configuredSection}]`
          : `[${configuredSection}]`;
      const assignment =
        bom === "with same-line carriage path"
          ? "\rpath"
          : bom === "with same-line path" ||
              bom === "with chained section headers"
            ? "path"
            : "\n\tpath";
      await writeFile(
        config,
        `${bom === "with BOM" ? "\ufeff" : ""}${bom === "with leading carriage return" ? "\r" : ""}${headers}${bom === "with carriage return after header" ? "\r# included" : ""}${assignment} = ${external}\n${await readFile(config, "utf8")}`,
      );

      await expect(inventory(checkout)).rejects.toThrow(
        "Git config includes are not supported",
      );
    },
  );

  test.each([
    ["include", "foo = bar"],
    ["include", "# path = ignored"],
    ['includeIf "gitdir:**"', "foo = bar"],
    ['include "inactive"', "path = ignored"],
  ])("allows inert [%s] Git config sections", async (section, assignment) => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const config = join(checkout, ".git", "config");
    await writeFile(
      config,
      `[${section}]\n\t${assignment}\n${await readFile(config, "utf8")}`,
    );
    await writeFile(join(checkout, "visible.ts"), "visible\n");

    expect(await inventory(checkout)).toContain("./visible.ts");
  });

  test.each([
    ["unset", "directory", false],
    ["false", "symbolic", false],
    ["false", "fifo", false],
    ["00", "directory", false],
    ["+0", "symbolic", false],
    ["0k", "fifo", false],
    ["0x0", "directory", false],
    ["+0x00g", "directory", false],
    ["1k", "directory", true],
    ["true", "directory", true],
    ["worktree-false", "directory", false],
    ["worktree-true", "directory", true],
  ])(
    "inspects %s sparse-checkout %s metadata only when active",
    async (setting, kind, active) => {
      if (
        Bun.which("rg") === null ||
        (kind !== "directory" && process.platform === "win32") ||
        (kind === "fifo" && Bun.which("mkfifo") === null)
      ) {
        return;
      }

      const checkout = await repository();
      if (setting.startsWith("worktree-")) {
        execFileSync(
          "git",
          ["config", "core.sparseCheckout", active ? "false" : "true"],
          { cwd: checkout },
        );
        execFileSync("git", ["config", "extensions.worktreeConfig", "true"], {
          cwd: checkout,
        });
        execFileSync(
          "git",
          ["config", "--worktree", "core.sparseCheckout", String(active)],
          { cwd: checkout },
        );
      } else if (setting !== "unset") {
        execFileSync("git", ["config", "core.sparseCheckout", setting], {
          cwd: checkout,
        });
      }

      const metadata = join(checkout, ".git", "info", "sparse-checkout");
      if (kind === "symbolic") {
        const external = join(dirname(checkout), "unused-sparse-checkout");
        await writeFile(external, "external\n");
        await symlink(external, metadata);
      } else if (kind === "fifo") {
        execFileSync("mkfifo", [metadata]);
      } else {
        await mkdir(metadata);
      }
      await writeFile(join(checkout, "visible.ts"), "visible\n");

      if (active) {
        await expect(inventory(checkout)).rejects.toThrow(
          "non-regular Git metadata files are not supported",
        );
      } else {
        expect(await inventory(checkout)).toContain("./visible.ts");
      }
    },
  );

  test
    .skipIf(process.platform === "win32")
    .each(["config", "info/sparse-checkout"])(
    "rejects non-regular Git %s metadata before invoking Git",
    async (relative) => {
      if (Bun.which("rg") === null || Bun.which("mkfifo") === null) return;

      const checkout = await repository();
      if (relative === "info/sparse-checkout") {
        execFileSync("git", ["config", "core.sparseCheckout", "true"], {
          cwd: checkout,
        });
      }
      const metadata = join(checkout, ".git", relative);
      await rm(metadata, { force: true });
      execFileSync("mkfifo", [metadata]);

      await expect(inventory(checkout)).rejects.toThrow(
        "non-regular Git metadata files are not supported",
      );
    },
  );

  test("requires the Git info metadata path to be a directory", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const info = join(checkout, ".git", "info");
    await rm(info, { recursive: true });
    await writeFile(info, "not a directory\n");

    await expect(inventory(checkout)).rejects.toThrow(
      "non-directory Git metadata paths are not supported",
    );
  });

  test
    .skipIf(process.platform === "win32")
    .each([
      "index",
      "config",
      "info/exclude",
      "info/sparse-checkout",
      "packed-refs",
      "refs",
      "refs/heads",
      "refs/replace",
    ])("rejects a symbolic Git metadata %s", async (relative) => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    if (relative === "info/sparse-checkout") {
      execFileSync("git", ["config", "core.sparseCheckout", "true"], {
        cwd: checkout,
      });
    }
    const external = await repository();
    await writeFile(join(external, "source.ts"), "tracked\n");
    execFileSync("git", ["add", "source.ts"], { cwd: external });
    const metadata = join(checkout, ".git", relative);
    const directory = relative === "refs" || relative.startsWith("refs/");
    const target = join(external, ".git", relative);
    if (relative === "info/sparse-checkout" || relative === "packed-refs") {
      await writeFile(target, "external\n");
    }
    await rm(metadata, { recursive: directory, force: true });
    await symlink(target, metadata);
    await writeFile(join(checkout, "visible.ts"), "visible\n");

    await expect(inventory(checkout)).rejects.toThrow(
      "symbolic Git metadata paths are not supported",
    );
  });

  test.skipIf(process.platform === "win32")(
    "rejects symbolic Git object replacement refs",
    async () => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const replacement = join(checkout, ".git", "refs", "replace");
      const external = join(dirname(checkout), "external-replacement");
      await mkdir(replacement);
      await writeFile(external, `${"0".repeat(40)}\n`);
      await symlink(external, join(replacement, "a".repeat(40)));
      await writeFile(join(checkout, "visible.ts"), "visible\n");

      await expect(inventory(checkout)).rejects.toThrow(
        "symbolic Git metadata paths are not supported",
      );
    },
  );

  test("inventories linked worktrees with regular Git metadata", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    await writeFile(join(checkout, "visible.ts"), "visible\n");
    execFileSync("git", ["add", "visible.ts"], { cwd: checkout });
    commit(checkout);
    const linked = join(dirname(checkout), "linked-worktree");
    execFileSync("git", ["worktree", "add", "--detach", linked, "HEAD"], {
      cwd: checkout,
      stdio: "ignore",
    });

    expect(await inventory(linked)).toContain("./visible.ts");

    const gitdir = (await readFile(join(linked, ".git"), "utf8"))
      .replace(/^gitdir: /, "")
      .trim();
    await writeFile(join(gitdir, "objects"), "inactive worktree metadata\n");
    await mkdir(join(gitdir, "packed-refs"));
    await writeFile(
      join(gitdir, "refs", "heads"),
      "inactive worktree references\n",
    );
    await writeFile(join(gitdir, "config"), "[include]\npath = inactive\n");
    await mkdir(join(gitdir, "info", "exclude"), { recursive: true });
    expect(await inventory(linked)).toContain("./visible.ts");

    const shortBackpointer = windowsShortPath(join(linked, ".git"));
    if (shortBackpointer !== null) {
      await writeFile(join(gitdir, "gitdir"), `${shortBackpointer}\n`);
      expect(await inventory(linked)).toContain("./visible.ts");
    }

    const alternateBackpointer = join(
      dirname(linked),
      "LINKED-WORKTREE",
      ".git",
    );
    const equivalentBackpointer = await realpath(alternateBackpointer).then(
      async (resolved) => resolved === (await realpath(join(linked, ".git"))),
      () => false,
    );
    if (equivalentBackpointer) {
      await writeFile(join(gitdir, "gitdir"), `${alternateBackpointer}\n`);
      expect(await inventory(linked)).toContain("./visible.ts");
    }

    const aliased = join(dirname(checkout), "REPOSITORY", ".git");
    const equivalent = await realpath(aliased).then(
      async (resolved) => resolved === (await realpath(join(checkout, ".git"))),
      () => false,
    );
    if (!equivalent) return;
    await writeFile(join(gitdir, "commondir"), `${aliased}\n`);

    expect(await inventory(linked)).toContain("./visible.ts");
  });

  test.each(["owned", "external"])(
    "honors %s worktree-specific ownership for linked Git worktrees",
    async (ownership) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      await writeFile(join(checkout, "visible.ts"), "tracked\n");
      execFileSync("git", ["add", "visible.ts"], { cwd: checkout });
      commit(checkout);
      const linked = join(dirname(checkout), "linked-worktree");
      const external = join(dirname(checkout), "external-worktree");
      await mkdir(external);
      execFileSync("git", ["worktree", "add", "--detach", linked, "HEAD"], {
        cwd: checkout,
        stdio: "ignore",
      });
      execFileSync("git", ["config", "extensions.worktreeConfig", "true"], {
        cwd: checkout,
      });
      const metadata = execFileSync(
        "git",
        ["rev-parse", "--absolute-git-dir"],
        {
          cwd: linked,
          encoding: "utf8",
        },
      ).trim();
      const effective = ownership === "owned" ? linked : external;
      await writeFile(
        join(metadata, "config.worktree"),
        `[Core]\n\tworktree = ${effective}\n`,
      );

      if (ownership === "external") {
        await expect(inventory(linked)).rejects.toThrow(
          "Git metadata directory does not own selected worktree",
        );
      } else {
        expect(await inventory(linked)).toContain("./visible.ts");
      }
    },
  );

  test("rejects worktree backpointers hard-linked through equivalent sibling names", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const source = await repository();
    const hidden = join(checkout, "ß");
    const visible = join(checkout, "ss");
    await writeFile(join(source, "secret.ts"), "tracked\n");
    execFileSync("git", ["add", "secret.ts"], { cwd: source });
    commit(source);
    execFileSync("git", ["worktree", "add", "--detach", hidden, "HEAD"], {
      cwd: source,
      stdio: "ignore",
    });
    try {
      await mkdir(visible);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") return;
      throw error;
    }
    await writeFile(join(checkout, ".ignore"), "ß/\n");
    await writeFile(join(visible, ".ignore"), "secret.ts\n");
    await writeFile(join(visible, "secret.ts"), "private\n");
    await hardlink(join(hidden, ".git"), join(visible, ".git"));

    await expect(inventory(checkout)).rejects.toThrow(
      "Git metadata directory does not own selected worktree",
    );
  });

  test("inventories genuine Git submodules with internal metadata", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const source = await repository();
    await writeFile(join(source, "visible.ts"), "tracked\n");
    execFileSync("git", ["add", "visible.ts"], { cwd: source });
    commit(source);
    execFileSync(
      "git",
      [
        "-c",
        "protocol.file.allow=always",
        "submodule",
        "add",
        "-q",
        source,
        "nested",
      ],
      { cwd: checkout },
    );
    const gitdir = execFileSync("git", ["rev-parse", "--absolute-git-dir"], {
      cwd: join(checkout, "nested"),
      encoding: "utf8",
    }).trim();
    const config = join(gitdir, "config");
    const configured = (await readFile(config, "utf8")).replace(
      /^([ \t]*worktree[ \t]*=[ \t]*)(.+)$/m,
      (_match, prefix: string, value: string) =>
        `${prefix}"${value.slice(0, -3)}\\\n${value.slice(-3)}" # valid Git comment`,
    );
    const suffix =
      process.platform === "win32"
        ? Buffer.alloc(0)
        : Buffer.from([0x23, 0x20, 0xff, 0x0a]);
    await writeFile(
      config,
      Buffer.concat([
        Buffer.from(`${configured}\n[feature]\n\tenabled\n`),
        suffix,
      ]),
    );

    expect(await inventory(checkout)).toContain("./nested/visible.ts");
  });

  test.skipIf(process.platform !== "linux")(
    "preserves non-UTF-8 paths in genuine Git worktree configurations",
    async () => {
      if (Bun.which("rg") === null || python === null) return;

      const checkout = await repository();
      const configure = [
        "import os, subprocess, sys",
        "root = os.fsencode(sys.argv[1])",
        "worktree = root + b'/nested-\\xff'",
        "gitdir = root + b'/.git/modules/nested-bytes'",
        "os.makedirs(os.path.dirname(gitdir), exist_ok=True)",
        "subprocess.run([b'git', b'init', b'-q', b'--separate-git-dir', gitdir, worktree], check=True)",
        "subprocess.run([b'git', b'--git-dir=' + gitdir, b'config', b'core.worktree', worktree], check=True)",
        "with open(worktree + b'/visible.ts', 'wb') as source: source.write(b'tracked\\n')",
        "subprocess.run([b'git', b'-C', worktree, b'add', b'visible.ts'], check=True)",
      ].join("\n");
      execFileSync(python, ["-B", "-c", configure, checkout], {
        stdio: "pipe",
      });

      expect(
        (await inventory(checkout)).some((path) =>
          path.endsWith("/visible.ts"),
        ),
      ).toBe(true);
    },
  );

  test("does not inspect a differently cased checkout outside an explicit scope", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const selected = join(checkout, "NESTED");
    const unselected = join(checkout, "nested");
    await mkdir(selected);
    try {
      await mkdir(unselected);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") return;
      throw error;
    }
    for (const nested of [selected, unselected]) {
      execFileSync("git", ["init", "-q"], { cwd: nested });
      await writeFile(join(nested, "tracked.ts"), "tracked\n");
      execFileSync("git", ["add", "tracked.ts"], { cwd: nested });
    }
    const trace = join(dirname(checkout), "git-trace.log");

    expect(
      await inventory(checkout, "NESTED", {
        ...process.env,
        GIT_TRACE: trace,
        GIT_TRACE_SETUP: "1",
      }),
    ).toEqual(["NESTED/tracked.ts"]);
    expect(await readFile(trace, "utf8")).not.toContain(unselected);
  });

  test.skipIf(process.platform !== "win32")(
    "does not traverse external Windows directory junctions",
    async () => {
      if (Bun.which("rg") === null) return;

      for (const initializeGit of [false, true]) {
        const checkout = await repository(initializeGit);
        const external = join(dirname(checkout), "outside");
        await mkdir(join(external, ".ignore"), { recursive: true });
        execFileSync("git", ["init", "-q"], { cwd: external });
        if (initializeGit) {
          await writeFile(join(checkout, "junction"), "tracked\n");
          execFileSync("git", ["add", "junction"], { cwd: checkout });
          await rm(join(checkout, "junction"));
        }
        await symlink(external, join(checkout, "junction"), "junction");
        await writeFile(join(checkout, "visible.ts"), "visible\n");

        expect(await inventory(checkout)).toEqual(["./visible.ts"]);
      }
    },
  );

  test.skipIf(process.platform === "win32")(
    "inventories an explicit file without listing its parent directory",
    async () => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const directory = join(checkout, "restricted");
      await mkdir(directory);
      await writeFile(join(directory, "source.ts"), "export {};\n");
      await chmod(directory, 0o111);
      try {
        expect(await inventory(checkout, "restricted/source.ts")).toEqual([
          "restricted/source.ts",
        ]);
      } finally {
        await chmod(directory, 0o755);
      }
    },
  );

  test("preserves supported in-repository symbolic path targets", async () => {
    const checkout = await repository();
    const source = join(checkout, "source");
    await mkdir(source);
    await writeFile(join(source, "app.ts"), "export {};\n");
    await symlink(
      source,
      join(checkout, "linked"),
      process.platform === "win32" ? "junction" : "dir",
    );

    await expect(normalizeTarget(checkout, ["linked/app.ts"])).resolves.toEqual(
      { kind: "paths", paths: ["source/app.ts"] },
    );
  });

  test("rejects ignore files that point outside the requested repository", async () => {
    if (process.platform === "win32" || Bun.which("rg") === null) return;

    const checkout = await repository(false);
    const external = join(dirname(checkout), "external.ignore");
    await writeFile(external, "hidden.ts\n");
    await writeFile(join(checkout, "hidden.ts"), "export {};\n");
    await symlink(external, join(checkout, ".ignore"));

    await expect(inventory(checkout)).rejects.toThrow(
      "symbolic ignore files are not supported",
    );
  });

  test.skipIf(process.platform === "win32")(
    "rejects descendant ignore links before invoking repository-wide ripgrep",
    async () => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const visible = join(checkout, "visible");
      const external = join(dirname(checkout), "external.ignore");
      await mkdir(visible);
      await writeFile(join(visible, "source.ts"), "visible\n");
      await writeFile(external, "source.ts\n");
      await symlink(external, join(visible, ".ignore"));

      await expect(inventory(checkout)).rejects.toThrow(
        "symbolic ignore files are not supported",
      );
    },
  );

  test.skipIf(process.platform === "win32")(
    "excludes case-equivalent Git metadata before running ripgrep",
    async () => {
      const ripgrep = Bun.which("rg");
      if (ripgrep === null) return;

      const checkout = await repository();
      const metadata = join(checkout, ".GIT");
      await rename(join(checkout, ".git"), metadata);
      const equivalent = await realpath(join(checkout, ".git")).then(
        async (resolved) => resolved === (await realpath(metadata)),
        () => false,
      );
      if (!equivalent) return;

      const external = join(dirname(checkout), "external.ignore");
      const trace = join(dirname(checkout), "ripgrep-output");
      const wrappers = join(dirname(checkout), "bin");
      await mkdir(wrappers);
      await writeFile(external, "# external ignore rules\n");
      await symlink(external, join(metadata, ".ignore"));
      await writeFile(join(checkout, ".rgignore"), "!.GIT/\n!.GIT/**\n");
      await writeFile(join(checkout, "visible.ts"), "visible\n");
      const wrapper = join(wrappers, "rg");
      await writeFile(
        wrapper,
        `#!/bin/sh\nif [ "$PWD" = ${JSON.stringify(checkout)} ]; then\n ${JSON.stringify(ripgrep)} "$@" > ${JSON.stringify(trace)}\n status=$?\n cat ${JSON.stringify(trace)}\n exit "$status"\nfi\nexec ${JSON.stringify(ripgrep)} "$@"\n`,
      );
      await chmod(wrapper, 0o755);

      expect(
        await inventory(checkout, ".", {
          ...process.env,
          PATH: `${wrappers}:${process.env["PATH"] ?? ""}`,
        }),
      ).toEqual(["./.rgignore", "./visible.ts"]);
      expect((await readFile(trace)).toString()).not.toContain(".GIT/");
    },
  );

  test.skipIf(process.platform === "win32")(
    "rejects snapshot ignore links without discovering a parent checkout",
    async () => {
      if (Bun.which("rg") === null) return;

      const parent = await repository();
      const snapshot = join(parent, "snapshot");
      const visible = join(snapshot, "visible");
      const external = join(dirname(parent), "external.ignore");
      const trace = join(dirname(parent), "git-trace.log");
      await mkdir(visible, { recursive: true });
      await writeFile(external, "# ignore rules\n");
      await writeFile(join(visible, "source.ts"), "visible\n");
      await symlink(external, join(visible, ".ignore"));

      await expect(
        inventory(snapshot, ".", {
          ...process.env,
          GIT_DIR: join(parent, ".git"),
          GIT_TRACE: trace,
        }),
      ).rejects.toThrow("symbolic ignore files are not supported");
      await expect(readFile(trace, "utf8")).rejects.toThrow();
    },
  );
});

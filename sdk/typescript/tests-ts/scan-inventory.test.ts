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
import { dirname, join } from "node:path";
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
    ["SS", "ss", true],
    ["Ä", "ä", true],
    ["ss", "\u00df", false],
    ["caf\u00e9", "cafe\u0301", true],
  ])(
    "matches indexed %s against replacement %s using filesystem identity",
    async (indexed, replacement, allowAlias) => {
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
      const expected =
        allowAlias &&
        (await realpath(join(checkout, indexed, "private.ts")).then(
          async (path) =>
            path ===
            (await realpath(join(checkout, replacement, "private.ts"))),
          () => false,
        ));

      expect(
        (await inventory(checkout)).includes(`./${replacement}/private.ts`),
      ).toBe(expected);

      if (indexed === "caf\u00e9") {
        execFileSync("git", ["config", "core.ignoreCase", "false"], {
          cwd: checkout,
        });
        expect(
          (await inventory(checkout, replacement)).includes(
            `${replacement}/private.ts`,
          ),
        ).toBe(expected);
      }
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

  test("admits tracked Gitlinks through configured directory excludes", async () => {
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
    await writeFile(
      join(checkout, ".git", "info", "exclude"),
      "nested/\nnested/private.ts\n",
    );

    const rows = await inventory(checkout);
    expect(rows).toContain("./nested/visible.ts");
    expect(rows).not.toContain("./nested/private.ts");
  });

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

  test.skipIf(process.platform === "win32").each([
    ["primary", "pack"],
    ["primary", "ab"],
    ["alternate", "pack"],
    ["alternate", "ab"],
  ])("rejects symbolic %s Git object files in %s", async (owner, kind) => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const external = join(dirname(checkout), "external-object");
    await writeFile(external, "external\n");
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
    const directory = join(objects, kind);
    if (kind !== "pack") await mkdir(directory);
    const member = kind === "pack" ? "pack-external.pack" : "0".repeat(38);
    await symlink(external, join(directory, member));

    await expect(inventory(checkout)).rejects.toThrow(
      "symbolic Git metadata paths are not supported",
    );
  });

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
    const objects = join(checkout, ".git", "extra-objects");
    await mkdir(join(objects, "info"), { recursive: true });
    await mkdir(join(objects, "pack"));
    await writeFile(
      join(checkout, ".git", "objects", "info", "alternates"),
      `${JSON.stringify(objects)}\n`,
    );
    await writeFile(join(checkout, "visible.ts"), "visible\n");

    expect(await inventory(checkout)).toContain("./visible.ts");
  });

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
    "disables lazy Git object fetching during inventory",
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
        `#!/bin/sh\nprintf '%s\\n' "$GIT_NO_LAZY_FETCH" >> ${JSON.stringify(trace)}\nexec ${JSON.stringify(git)} "$@"\n`,
      );
      await chmod(wrapper, 0o755);

      expect(
        await inventory(checkout, ".", {
          ...process.env,
          GIT_NO_LAZY_FETCH: "0",
          PATH: `${wrappers}:${process.env["PATH"] ?? ""}`,
        }),
      ).toContain("./visible.ts");
      expect((await readFile(trace, "utf8")).trim().split("\n")).toSatisfy(
        (values: string[]) =>
          values.length > 0 && values.every((value) => value === "1"),
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

  test.skipIf(process.platform === "win32")(
    "rejects split-index backing files that leave the checkout",
    async () => {
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

      expect(await inventory(checkout)).toContain("./tracked.ts");
      const original = join(gitdir, shared);
      const external = join(dirname(checkout), shared);
      await writeFile(external, await readFile(original));
      await rm(original);
      await symlink(external, original);

      await expect(inventory(checkout)).rejects.toThrow(
        "symbolic Git metadata paths are not supported",
      );
    },
  );

  test.each([
    ["include", "without BOM"],
    ['includeIf "gitdir:**"', "without BOM"],
    ["include", "with BOM"],
  ])(
    "rejects repository-directed %s config %s before invoking Git",
    async (section, bom) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const external = join(dirname(checkout), "external.config");
      await writeFile(external, "[core]\n\tignoreCase = true\n");
      const config = join(checkout, ".git", "config");
      await writeFile(
        config,
        `${bom === "with BOM" ? "\ufeff" : ""}[${section}]\n\tpath = ${external}\n${await readFile(config, "utf8")}`,
      );

      await expect(inventory(checkout)).rejects.toThrow(
        "Git config includes are not supported",
      );
    },
  );

  test
    .skipIf(process.platform === "win32")
    .each(["config", "info/sparse-checkout"])(
    "rejects non-regular Git %s metadata before invoking Git",
    async (relative) => {
      if (Bun.which("rg") === null || Bun.which("mkfifo") === null) return;

      const checkout = await repository();
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
    ])("rejects a symbolic Git metadata %s", async (relative) => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const external = await repository();
    await writeFile(join(external, "source.ts"), "tracked\n");
    execFileSync("git", ["add", "source.ts"], { cwd: external });
    const metadata = join(checkout, ".git", relative);
    const directory = relative === "refs" || relative === "refs/heads";
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
      '$1"$2"',
    );
    await writeFile(config, `${configured}\n[feature]\n\tenabled\n`);

    expect(await inventory(checkout)).toContain("./nested/visible.ts");
  });

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

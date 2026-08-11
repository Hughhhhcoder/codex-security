import { execFileSync } from "node:child_process";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
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

async function inventory(checkout: string, scope = "."): Promise<string[]> {
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
    { cwd: checkout, stdio: "pipe" },
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
    },
  );

  test("applies configured excludes from every enclosing Git checkout", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const middle = join(checkout, "middle");
    const nested = join(middle, "nested");
    await mkdir(nested, { recursive: true });
    execFileSync("git", ["init", "-q"], { cwd: middle });
    execFileSync("git", ["init", "-q"], { cwd: nested });
    await Promise.all([
      writeFile(join(middle, ".git", "info", "exclude"), "nested/private.ts\n"),
      writeFile(join(nested, "private.ts"), "private\n"),
      writeFile(join(nested, "visible.ts"), "visible\n"),
    ]);
    execFileSync("git", ["add", "private.ts", "visible.ts"], { cwd: nested });

    const rows = await inventory(checkout);
    expect(rows).toContain("./middle/nested/visible.ts");
    expect(rows).not.toContain("./middle/nested/private.ts");
  });

  test("preserves intermediate ignores beneath an ancestor Git link", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const middle = join(checkout, "middle");
    const nested = join(middle, "nested");
    await mkdir(nested, { recursive: true });
    execFileSync("git", ["init", "-q"], { cwd: middle });
    await writeFile(join(middle, "visible.ts"), "visible\n");
    execFileSync("git", ["add", "visible.ts"], { cwd: middle });
    execFileSync(
      "git",
      [
        "-c",
        "user.name=Inventory Test",
        "-c",
        "user.email=inventory@example.test",
        "commit",
        "-qm",
        "Track intermediate source",
      ],
      { cwd: middle },
    );
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

  test("rejects symbolic Git metadata before reading another checkout", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository(false);
    const external = await repository();
    await symlink(
      join(external, ".git"),
      join(checkout, ".git"),
      process.platform === "win32" ? "junction" : "dir",
    );
    await writeFile(join(checkout, "visible.ts"), "visible\n");

    await expect(inventory(checkout)).rejects.toThrow(
      "symbolic Git metadata paths are not supported",
    );
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
});

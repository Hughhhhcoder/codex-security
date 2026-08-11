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
import { dirname, join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

type DiffMode = "revisions" | "local-patch";
type RankInputRow = { path: string; area: string; preview: string };
type TestRepository = { root: string; repository: string; base: string };

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function git(repository: string, ...args: string[]): string {
  return execFileSync("git", args, {
    cwd: repository,
    encoding: "utf8",
    stdio: "pipe",
  }).trim();
}

async function writeRepositoryFile(
  repository: string,
  path: string,
  contents: string | Uint8Array,
): Promise<void> {
  const destination = join(repository, path);
  await mkdir(dirname(destination), { recursive: true });
  await writeFile(destination, contents);
}

async function createRepository(): Promise<TestRepository> {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-diff-rank-input-")),
  );
  temporaryDirectories.push(root);

  const repository = join(root, "repository");
  await mkdir(repository);
  git(repository, "init", "-q", "-b", "main");
  git(repository, "config", "user.name", "Codex Security Test");
  git(repository, "config", "user.email", "codex-security@example.invalid");
  git(repository, "config", "commit.gpgsign", "false");

  await Promise.all([
    writeRepositoryFile(repository, ".gitignore", "node_modules/\nvendor/\n"),
    writeRepositoryFile(repository, "AGENTS.md", "Follow existing policy.\n"),
    writeRepositoryFile(repository, "docker-compose.yml", "services: {}\n"),
    writeRepositoryFile(repository, "src/app.ts", "export const value = 1;\n"),
    writeRepositoryFile(repository, "src/remove.py", "print('remove')\n"),
    writeRepositoryFile(repository, "src/old.py", "print('rename')\n"),
  ]);
  git(repository, "add", ".");
  git(repository, "commit", "-qm", "initial");

  return { root, repository, base: git(repository, "rev-parse", "HEAD") };
}

async function runDiffRankInput(
  fixture: TestRepository,
  mode: DiffMode,
  head = "HEAD",
): Promise<RankInputRow[]> {
  const interpreter =
    Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  if (interpreter === null) {
    throw new Error("A Python interpreter is required.");
  }

  const output = join(fixture.root, `rank-input-${mode}.jsonl`);
  execFileSync(
    interpreter,
    [
      "-B",
      join(PLUGIN_ROOT, "scripts", "generate_rank_input.py"),
      "make-diff-rank-input",
      "--repo",
      fixture.repository,
      "--base",
      fixture.base,
      "--mode",
      mode,
      "--head",
      head,
      "--out",
      output,
    ],
    { stdio: "pipe" },
  );
  const contents = (await readFile(output, "utf8")).trim();
  return contents
    ? contents.split("\n").map((line) => JSON.parse(line) as RankInputRow)
    : [];
}

describe("diff rank input", () => {
  test("includes changed security-sensitive files without dependency noise", async () => {
    const fixture = await createRepository();
    const included: Record<string, string> = {
      ".circleci/config.yml": "version: 2.1\n",
      ".devcontainer/devcontainer.json": '{"image":"example"}\n',
      ".github/actions/local/index.js": "runTrustedAction();\n",
      ".github/CODEOWNERS": "* @security\n",
      ".github/workflows/security.yml": "name: Security\n",
      "AGENTS.md": "Review authorization boundaries.\n",
      Dockerfile: "FROM scratch\n",
      "docs/CODEOWNERS": "* @documentation\n",
      "docs/SECURITY.md": "Report vulnerabilities privately.\n",
      "infra/main.tf": 'resource "example" "service" {}\n',
      "src/app.ts": "export const value = 2;\n",
    };
    await Promise.all(
      Object.entries(included).map(([path, contents]) =>
        writeRepositoryFile(fixture.repository, path, contents),
      ),
    );
    await writeRepositoryFile(
      fixture.repository,
      "vendor/dependency.py",
      "print('external dependency')\n",
    );
    git(fixture.repository, "add", "-A");
    git(fixture.repository, "add", "-f", "vendor/dependency.py");
    git(fixture.repository, "commit", "-qm", "change security-sensitive files");

    const rows = await runDiffRankInput(fixture, "revisions");
    expect(rows.map(({ path }) => path)).toEqual(Object.keys(included).sort());
    expect(rows.every(({ area, preview }) => area === "diff" && preview)).toBe(
      true,
    );
  });

  test.skipIf(process.platform === "win32")(
    "treats repository-controlled Git pathspecs literally",
    async () => {
      const fixture = await createRepository();
      const path = ":!literal.py";
      await writeRepositoryFile(fixture.repository, path, "print('literal')\n");
      git(fixture.repository, "--literal-pathspecs", "add", "--", path);
      git(fixture.repository, "commit", "-qm", "add literal path");

      expect(
        (await runDiffRankInput(fixture, "revisions")).map((row) => row.path),
      ).toContain(path);
    },
  );

  test("includes staged and unstaged files but not untracked paths", async () => {
    const fixture = await createRepository();
    await writeRepositoryFile(
      fixture.repository,
      ".github/workflows/staged.yml",
      "name: Staged\n",
    );
    git(fixture.repository, "add", ".github/workflows/staged.yml");
    await writeRepositoryFile(
      fixture.repository,
      "src/app.ts",
      "export const value = 2;\n",
    );
    await writeRepositoryFile(
      fixture.repository,
      ".github/workflows/untracked.yml",
      "name: Untracked\n",
    );

    expect(
      (await runDiffRankInput(fixture, "local-patch")).map(({ path }) => path),
    ).toEqual([".github/workflows/staged.yml", "src/app.ts"]);
  });

  test("reads the selected committed head instead of the current checkout", async () => {
    const fixture = await createRepository();
    await writeRepositoryFile(
      fixture.repository,
      "AGENTS.md",
      "Require head-only authorization.\n",
    );
    git(fixture.repository, "add", "AGENTS.md");
    git(fixture.repository, "commit", "-qm", "change authorization policy");
    const head = git(fixture.repository, "rev-parse", "HEAD");
    git(fixture.repository, "checkout", "--quiet", fixture.base);

    expect(await runDiffRankInput(fixture, "revisions", head)).toEqual([
      {
        path: "AGENTS.md",
        area: "diff",
        preview: "Require head-only authorization.",
      },
    ]);
  });

  test("includes both staged and working-tree content when they differ", async () => {
    const fixture = await createRepository();
    const workflow = ".github/workflows/deploy.yml";
    await writeRepositoryFile(fixture.repository, workflow, "run: staged\n");
    git(fixture.repository, "add", workflow);
    await writeRepositoryFile(fixture.repository, workflow, "run: worktree\n");

    const [row] = await runDiffRankInput(fixture, "local-patch");
    expect(row?.preview).toContain("Staged Git index:\nrun: staged");
    expect(row?.preview).toContain("Worktree:\nrun: worktree");
  });

  test("preserves deleted and renamed files using their committed content", async () => {
    const fixture = await createRepository();
    await rm(join(fixture.repository, "src/remove.py"));
    await rename(
      join(fixture.repository, "src/old.py"),
      join(fixture.repository, "src/renamed.py"),
    );
    git(fixture.repository, "add", "-A");
    git(fixture.repository, "commit", "-qm", "delete and rename source");

    expect(await runDiffRankInput(fixture, "revisions")).toEqual([
      { path: "src/remove.py", area: "diff", preview: "print('remove')" },
      { path: "src/renamed.py", area: "diff", preview: "print('rename')" },
    ]);
  });

  test("records the pinned commit for local-action submodules", async () => {
    const fixture = await createRepository();
    git(
      fixture.repository,
      "update-index",
      "--add",
      "--cacheinfo",
      `160000,${fixture.base},.github/actions/local`,
    );
    git(fixture.repository, "commit", "-qm", "pin local action submodule");

    expect(await runDiffRankInput(fixture, "revisions")).toEqual([
      {
        path: ".github/actions/local",
        area: "diff",
        preview: `Git submodule commit ${fixture.base}`,
      },
    ]);
  });

  test("keeps UTF-16 action scripts while excluding large binary objects", async () => {
    const fixture = await createRepository();
    const action = ".github/actions/local/run.ps1";
    await writeRepositoryFile(
      fixture.repository,
      action,
      Buffer.concat([
        Buffer.from([0xff, 0xfe]),
        Buffer.from("Invoke-Expression $command\n", "utf16le"),
      ]),
    );
    await writeRepositoryFile(
      fixture.repository,
      "src/binary.py",
      Buffer.alloc(1024 * 1024),
    );
    git(fixture.repository, "add", "-A");
    git(fixture.repository, "commit", "-qm", "add action and binary");

    expect(await runDiffRankInput(fixture, "revisions")).toEqual([
      {
        path: action,
        area: "diff",
        preview: "Invoke-Expression $command",
      },
    ]);
  });

  test.skipIf(process.platform === "win32")(
    "rejects staged symlinks pointing outside the repository",
    async () => {
      const fixture = await createRepository();
      const external = join(fixture.root, "external.py");
      await writeFile(external, "private = True\n");
      await symlink(external, join(fixture.repository, "src/linked.py"));
      git(fixture.repository, "add", "src/linked.py");

      await expect(runDiffRankInput(fixture, "local-patch")).rejects.toThrow(
        /symbolic links/,
      );
    },
  );

  test("rejects working-tree replacements after staged deletions", async () => {
    const fixture = await createRepository();
    git(fixture.repository, "rm", "--quiet", "--", "src/remove.py");
    await writeRepositoryFile(
      fixture.repository,
      "src/remove.py",
      "print('replacement')\n",
    );

    await expect(runDiffRankInput(fixture, "local-patch")).rejects.toThrow(
      /working-tree replacements/,
    );
  });
});

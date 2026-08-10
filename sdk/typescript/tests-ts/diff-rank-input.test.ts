import { execFileSync } from "node:child_process";
import {
  chmod,
  mkdir,
  mkdtemp,
  link,
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

type RankInputRow = {
  path: string;
  area: string;
  preview: string;
};

type TestRepository = {
  root: string;
  repository: string;
  base: string;
};

type PathSwap = {
  path: string;
  replacement: string;
};

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
    writeRepositoryFile(
      repository,
      "AGENTS.md",
      "Follow the existing policy.\n",
    ),
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
  swap?: PathSwap,
  head = "HEAD",
): Promise<RankInputRow[]> {
  const interpreter =
    Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  if (interpreter === null) {
    throw new Error(
      "A Python interpreter is required for diff rank input tests.",
    );
  }

  const output = join(
    fixture.root,
    `rank-input-${mode}${swap ? "-swapped" : ""}.jsonl`,
  );
  const command = [
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
  ];
  const script = join(PLUGIN_ROOT, "scripts", "generate_rank_input.py");
  const swapHook = [
    "from pathlib import Path",
    "import sys",
    "scripts, candidate, replacement = sys.argv[1:4]",
    "sys.path.insert(0, scripts)",
    "import generate_rank_input",
    "original_resolve = Path.resolve",
    "def swap_after_resolve(path, *args, **kwargs):",
    "    resolved = original_resolve(path, *args, **kwargs)",
    "    if path == Path(candidate) and kwargs.get('strict', False):",
    "        path.unlink()",
    "        path.symlink_to(replacement)",
    "    return resolved",
    "Path.resolve = swap_after_resolve",
    "sys.argv = [generate_rank_input.__file__, *sys.argv[4:]]",
    "generate_rank_input.main()",
  ].join("\n");
  const args = swap
    ? [
        "-B",
        "-c",
        swapHook,
        dirname(script),
        join(fixture.repository, swap.path),
        swap.replacement,
        ...command,
      ]
    : ["-B", script, ...command];
  execFileSync(interpreter, args, { stdio: "pipe" });

  const contents = (await readFile(output, "utf8")).trim();
  return contents
    ? contents.split("\n").map((line) => JSON.parse(line) as RankInputRow)
    : [];
}

describe("diff rank input", () => {
  test("inventories committed security-sensitive workflows, containers, and agent instructions", async () => {
    const fixture = await createRepository();
    const files: Record<string, string> = {
      ".circleci/config.yml": "version: 2.1\njobs: {}\n",
      ".devcontainer/devcontainer.json":
        '{"postCreateCommand":"npm run setup"}\n',
      ".dockerignore": "node_modules\nvendor\n",
      ".github/actions/security/action.yml": "runs:\n  using: composite\n",
      ".github/actions/security/index.js": "export const secure = true;\n",
      ".github/actions/security/script.py": "print('review action')\n",
      ".github/CODEOWNERS": "* @security-reviewers\n",
      ".github/copilot-instructions.md":
        "Review changes before running code.\n",
      ".github/dependabot.yml": "version: 2\nupdates: []\n",
      ".github/ISSUE_TEMPLATE/bug.yml": "name: Bug report\n",
      ".github/scripts/security.py": "print('review first-party changes')\n",
      ".github/workflows/security.yml": "name: Security\non: pull_request\n",
      ".github/workflows/scripts/check.py": "print('check workflow')\n",
      ".env.example": "AUTH_PROVIDER=example\n",
      "AGENTS.md": "Require authorization before exposing credentials.\n",
      "CLAUDE.md": "Keep repository credentials private.\n",
      CODEOWNERS: "* @repository-owners\n",
      "SECURITY.md": "Do not suppress authentication or credential findings.\n",
      Containerfile: "FROM scratch\n",
      Dockerfile: "FROM node:24-alpine\n",
      Jenkinsfile: "pipeline { agent any }\n",
      "compose.yaml": "services:\n  app:\n    image: app\n",
      "config/nginx.conf": "server { listen 443 ssl; }\n",
      "docker-compose.yml": "services:\n  app:\n    image: app\n",
      "docs/example.py": "print('documentation example')\n",
      "docs/AGENTS.md":
        "Example instructions, not executable repository scope.\n",
      "docs/CODEOWNERS": "* @documentation-owners\n",
      "docs/SECURITY.md": "Report repository vulnerabilities privately.\n",
      "infra/main.tf": 'resource "example" "service" {}\n',
      "infra/variables.hcl": 'environment = "production"\n',
      "node_modules/AGENTS.md": "External dependency instructions.\n",
      "node_modules/dependency.py": "print('external dependency')\n",
      "policy/security.rego": "package security\ndefault allow = false\n",
      "services/api/AGENTS.md": "Do not read files outside this service.\n",
      "services/api/CLAUDE.md": "Review authentication changes.\n",
      "services/api/Dockerfile.production": "FROM node:24-alpine\n",
      "services/api/app.Dockerfile": "FROM node:24-alpine\n",
      "src/app.ts": "export const value = 2;\n",
      "src/auth.cjs": "module.exports = { authenticated: true };\n",
      "vendor/Dockerfile": "FROM external-vendor\n",
      "vendor/dependency.py": "print('vendored dependency')\n",
    };

    await Promise.all(
      Object.entries(files).map(([path, contents]) =>
        writeRepositoryFile(fixture.repository, path, contents),
      ),
    );
    git(fixture.repository, "add", "-A");
    git(
      fixture.repository,
      "add",
      "-f",
      "node_modules/AGENTS.md",
      "node_modules/dependency.py",
      "vendor/Dockerfile",
      "vendor/dependency.py",
    );
    git(fixture.repository, "commit", "-qm", "change security-sensitive files");

    const rows = await runDiffRankInput(fixture, "revisions");

    expect(rows.map((row) => row.path)).toEqual(
      [
        ".circleci/config.yml",
        ".devcontainer/devcontainer.json",
        ".dockerignore",
        ".github/actions/security/action.yml",
        ".github/actions/security/index.js",
        ".github/actions/security/script.py",
        ".github/CODEOWNERS",
        ".github/copilot-instructions.md",
        ".github/dependabot.yml",
        ".github/scripts/security.py",
        ".github/workflows/security.yml",
        ".github/workflows/scripts/check.py",
        ".env.example",
        "AGENTS.md",
        "CLAUDE.md",
        "CODEOWNERS",
        "SECURITY.md",
        "Containerfile",
        "Dockerfile",
        "Jenkinsfile",
        "compose.yaml",
        "config/nginx.conf",
        "docker-compose.yml",
        "docs/CODEOWNERS",
        "docs/SECURITY.md",
        "infra/main.tf",
        "infra/variables.hcl",
        "policy/security.rego",
        "services/api/AGENTS.md",
        "services/api/CLAUDE.md",
        "services/api/Dockerfile.production",
        "services/api/app.Dockerfile",
        "src/app.ts",
        "src/auth.cjs",
      ].sort(),
    );
    expect(rows.every((row) => row.area === "diff")).toBe(true);
    expect(rows.every((row) => row.preview.length > 0)).toBe(true);
  });

  test("inventories both staged and unstaged security-sensitive changes", async () => {
    const fixture = await createRepository();

    await Promise.all([
      writeRepositoryFile(
        fixture.repository,
        ".github/workflows/staged.yml",
        "name: Staged security workflow\n",
      ),
      writeRepositoryFile(fixture.repository, "Dockerfile", "FROM scratch\n"),
    ]);
    git(
      fixture.repository,
      "add",
      ".github/workflows/staged.yml",
      "Dockerfile",
    );

    await Promise.all([
      writeRepositoryFile(
        fixture.repository,
        "AGENTS.md",
        "Review the staged changes.\n",
      ),
      writeRepositoryFile(
        fixture.repository,
        "docker-compose.yml",
        "services:\n  app:\n    image: changed\n",
      ),
      writeRepositoryFile(
        fixture.repository,
        "src/app.ts",
        "export const value = 2;\n",
      ),
    ]);

    const rows = await runDiffRankInput(fixture, "local-patch");

    expect(rows.map((row) => row.path)).toEqual(
      [
        ".github/workflows/staged.yml",
        "AGENTS.md",
        "Dockerfile",
        "docker-compose.yml",
        "src/app.ts",
      ].sort(),
    );
    expect(rows.every((row) => row.preview.length > 0)).toBe(true);
  });

  test("keeps untracked files outside the declared local-patch scope", async () => {
    const fixture = await createRepository();

    await Promise.all([
      writeRepositoryFile(
        fixture.repository,
        ".github/workflows/untracked.yml",
        "name: Untracked security workflow\n",
      ),
      writeRepositoryFile(
        fixture.repository,
        "node_modules/ignored.ts",
        "export const ignored = true;\n",
      ),
    ]);

    expect(await runDiffRankInput(fixture, "local-patch")).toEqual([]);
  });

  test("includes every unresolved Git index stage in a local patch", async () => {
    const fixture = await createRepository();
    const workflow = ".github/workflows/conflicted.yml";
    await writeRepositoryFile(fixture.repository, workflow, "run: base\n");
    git(fixture.repository, "add", workflow);
    git(fixture.repository, "commit", "-qm", "add workflow");
    fixture.base = git(fixture.repository, "rev-parse", "HEAD");

    const stages = ["base", "ours", "theirs"].map((label, index) => {
      const object = execFileSync("git", ["hash-object", "-w", "--stdin"], {
        cwd: fixture.repository,
        encoding: "utf8",
        input: `run: ${label}\n`,
      }).trim();
      const mode = index === 1 ? "100755" : "100644";
      return `${mode} ${object} ${index + 1}\t${workflow}\n`;
    });
    execFileSync("git", ["update-index", "--index-info"], {
      cwd: fixture.repository,
      input: `0 ${"0".repeat(40)}\t${workflow}\n${stages.join("")}`,
    });
    await writeRepositoryFile(fixture.repository, workflow, "run: worktree\n");

    const [finding] = await runDiffRankInput(fixture, "local-patch");
    expect(finding?.path).toBe(workflow);
    for (const label of ["base", "ours", "theirs", "worktree"]) {
      expect(finding?.preview).toContain(`run: ${label}`);
    }
    expect(finding?.preview).toContain("Git merge stage 2 (mode 100755):");
  });

  test("includes executable mode changes in committed diff previews", async () => {
    const fixture = await createRepository();
    git(fixture.repository, "update-index", "--chmod=+x", "src/app.ts");
    git(fixture.repository, "commit", "-qm", "make source executable");

    const [finding] = await runDiffRankInput(fixture, "revisions");
    expect(finding?.path).toBe("src/app.ts");
    expect(finding?.preview).toContain("Git file mode: 100644 → 100755");
  });

  test("preserves executable modes for binary merge-conflict stages", async () => {
    const fixture = await createRepository();
    const action = ".github/actions/local/run.sh";
    await writeRepositoryFile(fixture.repository, action, "run safe\n");
    git(fixture.repository, "add", action);
    git(fixture.repository, "commit", "-qm", "add local action");
    fixture.base = git(fixture.repository, "rev-parse", "HEAD");

    const stages = ["100644", "100755", "100644"].map((mode, index) => {
      const object = execFileSync("git", ["hash-object", "-w", "--stdin"], {
        cwd: fixture.repository,
        encoding: "utf8",
        input: Buffer.from([0, index + 1]),
      }).trim();
      return `${mode} ${object} ${index + 1}\t${action}\n`;
    });
    execFileSync("git", ["update-index", "--index-info"], {
      cwd: fixture.repository,
      input: `0 ${"0".repeat(40)}\t${action}\n${stages.join("")}`,
    });

    const [finding] = await runDiffRankInput(fixture, "local-patch");
    expect(finding?.preview).toContain("Git merge stage 2 (mode 100755):");
    expect(finding?.preview).toContain("(binary content)");
  });

  test.skipIf(process.platform === "win32")(
    "includes unstaged executable mode changes in local patch previews",
    async () => {
      const fixture = await createRepository();
      await chmod(join(fixture.repository, "src", "app.ts"), 0o755);

      const [finding] = await runDiffRankInput(fixture, "local-patch");
      expect(finding?.path).toBe("src/app.ts");
      expect(finding?.preview).toContain("Git file mode: 100644 → 100755");
    },
  );

  test.skipIf(process.platform === "win32")(
    "does not invent executable mode changes when Git ignores file modes",
    async () => {
      const fixture = await createRepository();
      git(fixture.repository, "config", "core.filemode", "false");
      await writeRepositoryFile(
        fixture.repository,
        "src/app.ts",
        "export const value = 2;\n",
      );
      await chmod(join(fixture.repository, "src", "app.ts"), 0o755);

      const [finding] = await runDiffRankInput(fixture, "local-patch");
      expect(finding?.path).toBe("src/app.ts");
      expect(finding?.preview).not.toContain("Git file mode:");
    },
  );

  test.skipIf(process.platform === "win32")(
    "rejects changed worktree files with another hard link",
    async () => {
      const fixture = await createRepository();
      const external = join(fixture.root, "external-source.yml");
      const workflow = ".github/workflows/linked.yml";
      await writeFile(external, "synthetic private source\n");
      await mkdir(join(fixture.repository, ".github", "workflows"), {
        recursive: true,
      });
      await link(external, join(fixture.repository, workflow));
      git(fixture.repository, "add", workflow);

      await expect(runDiffRankInput(fixture, "local-patch")).rejects.toThrow(
        /hard links/,
      );
    },
  );

  test.skipIf(process.platform === "win32")(
    "reads revision objects even when the current checkout has another hard link",
    async () => {
      const fixture = await createRepository();
      await writeRepositoryFile(
        fixture.repository,
        "src/app.ts",
        "export const value = 2;\n",
      );
      git(fixture.repository, "add", "src/app.ts");
      git(fixture.repository, "commit", "-qm", "update linked source");
      await link(
        join(fixture.repository, "src", "app.ts"),
        join(fixture.root, "linked-source.ts"),
      );

      const [finding] = await runDiffRankInput(fixture, "revisions");
      expect(finding?.path).toBe("src/app.ts");
      expect(finding?.preview).toContain("value = 2");
    },
  );

  test("previews revision changes from their selected head instead of the current checkout", async () => {
    const fixture = await createRepository();
    await Promise.all([
      writeRepositoryFile(
        fixture.repository,
        "AGENTS.md",
        "Require the head-only authorization policy.\n",
      ),
      writeRepositoryFile(
        fixture.repository,
        "SECURITY.md",
        "Review the head-only credential boundary.\n",
      ),
    ]);
    git(fixture.repository, "add", "AGENTS.md", "SECURITY.md");
    git(fixture.repository, "commit", "-qm", "change security policy");
    const head = git(fixture.repository, "rev-parse", "HEAD");
    git(fixture.repository, "checkout", "--quiet", fixture.base);

    const rows = await runDiffRankInput(fixture, "revisions", undefined, head);

    expect(rows).toEqual([
      {
        path: "AGENTS.md",
        area: "diff",
        preview: "Require the head-only authorization policy.",
      },
      {
        path: "SECURITY.md",
        area: "diff",
        preview: "Review the head-only credential boundary.",
      },
    ]);
  });

  test("reviews selected head text when the checked-out source is binary", async () => {
    const fixture = await createRepository();
    await writeRepositoryFile(
      fixture.repository,
      "src/app.ts",
      Buffer.from([0x00, 0x01, 0x02]),
    );
    git(fixture.repository, "add", "src/app.ts");
    git(fixture.repository, "commit", "-qm", "store binary base");
    fixture.base = git(fixture.repository, "rev-parse", "HEAD");
    await writeRepositoryFile(
      fixture.repository,
      "src/app.ts",
      "export const authenticated = false;\n",
    );
    git(fixture.repository, "add", "src/app.ts");
    git(fixture.repository, "commit", "-qm", "replace binary with source");
    const head = git(fixture.repository, "rev-parse", "HEAD");
    git(fixture.repository, "checkout", "--quiet", fixture.base);

    expect(
      await runDiffRankInput(fixture, "revisions", undefined, head),
    ).toEqual([
      {
        path: "src/app.ts",
        area: "diff",
        preview: "export const authenticated = false;",
      },
    ]);
  });

  test("does not apply repository replacement refs to selected revision content", async () => {
    const fixture = await createRepository();
    await writeRepositoryFile(
      fixture.repository,
      "src/app.ts",
      "dangerous();\n",
    );
    git(fixture.repository, "add", "src/app.ts");
    git(fixture.repository, "commit", "-qm", "record actual head");
    const head = git(fixture.repository, "rev-parse", "HEAD");
    await writeRepositoryFile(fixture.repository, "src/app.ts", "safe();\n");
    git(fixture.repository, "add", "src/app.ts");
    const replacementTree = git(fixture.repository, "write-tree");
    const replacement = git(
      fixture.repository,
      "commit-tree",
      replacementTree,
      "-p",
      fixture.base,
      "-m",
      "substitute safe source",
    );
    git(fixture.repository, "replace", head, replacement);

    expect(
      await runDiffRankInput(fixture, "revisions", undefined, head),
    ).toEqual([{ path: "src/app.ts", area: "diff", preview: "dangerous();" }]);
  });

  test("keeps security-relevant rename sources when destinations are excluded", async () => {
    const fixture = await createRepository();
    await mkdir(join(fixture.repository, "docs"));
    await rename(
      join(fixture.repository, "AGENTS.md"),
      join(fixture.repository, "docs", "archived-policy.md"),
    );
    git(fixture.repository, "add", "-A");
    git(fixture.repository, "commit", "-qm", "archive active security policy");

    expect(await runDiffRankInput(fixture, "revisions")).toEqual([
      {
        path: "AGENTS.md",
        area: "diff",
        preview: "Follow the existing policy.",
      },
    ]);
  });

  test("keeps reviewable source renames into excluded directories", async () => {
    const fixture = await createRepository();
    await mkdir(join(fixture.repository, "docs"));
    await rename(
      join(fixture.repository, "src", "old.py"),
      join(fixture.repository, "docs", "old.py"),
    );
    git(fixture.repository, "add", "-A");
    git(fixture.repository, "commit", "-qm", "archive reviewable source");

    expect(await runDiffRankInput(fixture, "revisions")).toEqual([
      { path: "src/old.py", area: "diff", preview: "print('rename')" },
    ]);
  });

  test("includes checked-in executable payloads from local GitHub actions", async () => {
    const fixture = await createRepository();
    const payloads = [
      ".github/actions/local/dist/index.js",
      ".github/actions/local/node_modules/pkg/index.js",
    ];
    await Promise.all(
      payloads.map((path) =>
        writeRepositoryFile(fixture.repository, path, "runTrustedAction();\n"),
      ),
    );
    git(fixture.repository, "add", "--force", ...payloads);
    git(fixture.repository, "commit", "-qm", "check in local action payloads");

    expect(
      (await runDiffRankInput(fixture, "revisions")).map(({ path }) => path),
    ).toEqual(payloads);
  });

  test("keeps executable UTF-16 local-action scripts reviewable", async () => {
    const fixture = await createRepository();
    const script = ".github/actions/local/run.ps1";
    await writeRepositoryFile(
      fixture.repository,
      script,
      Buffer.concat([
        Buffer.from([0xff, 0xfe]),
        Buffer.from("Invoke-Expression $command\n", "utf16le"),
      ]),
    );
    git(fixture.repository, "add", script);
    git(fixture.repository, "commit", "-qm", "add PowerShell action");

    expect(await runDiffRankInput(fixture, "revisions")).toEqual([
      {
        path: script,
        area: "diff",
        preview: "Invoke-Expression $command",
      },
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

  test("records every unresolved local-action submodule pin", async () => {
    const fixture = await createRepository();
    const action = ".github/actions/[local]";
    git(
      fixture.repository,
      "update-index",
      "--add",
      "--cacheinfo",
      `160000,${fixture.base},.github/actions/l`,
    );
    git(fixture.repository, "commit", "-qm", "pin sibling local action");
    fixture.base = git(fixture.repository, "rev-parse", "HEAD");
    const revisions = [fixture.base];
    for (const label of ["ours", "theirs"]) {
      git(fixture.repository, "commit", "--allow-empty", "-qm", label);
      revisions.push(git(fixture.repository, "rev-parse", "HEAD"));
    }
    fixture.base = git(fixture.repository, "rev-parse", "HEAD");
    const stages = revisions.map(
      (revision, index) => `160000 ${revision} ${index + 1}\t${action}\n`,
    );
    execFileSync("git", ["update-index", "--index-info"], {
      cwd: fixture.repository,
      input: `0 ${"0".repeat(40)}\t${action}\n${stages.join("")}`,
    });

    const [finding] = await runDiffRankInput(fixture, "local-patch");
    expect(finding?.path).toBe(action);
    for (const revision of revisions) {
      expect(finding?.preview).toContain(`Git submodule commit ${revision}`);
    }

    const submodule = join(fixture.repository, action);
    await mkdir(submodule, { recursive: true });
    git(submodule, "init", "-q", "-b", "main");
    git(submodule, "config", "user.name", "Codex Security Test");
    git(submodule, "config", "user.email", "codex-security@example.invalid");
    git(submodule, "config", "commit.gpgsign", "false");
    await writeRepositoryFile(submodule, "action.yml", "runs: worktree\n");
    git(submodule, "add", "action.yml");
    git(submodule, "commit", "-qm", "initialize conflicted action");
    const worktree = git(submodule, "rev-parse", "HEAD");

    const [initialized] = await runDiffRankInput(fixture, "local-patch");
    expect(initialized?.path).toBe(action);
    for (const revision of [...revisions, worktree]) {
      expect(initialized?.preview).toContain(
        `Git submodule commit ${revision}`,
      );
    }

    const conflictingFile = execFileSync(
      "git",
      ["hash-object", "-w", "--stdin"],
      {
        cwd: fixture.repository,
        encoding: "utf8",
        input: "runs: conflicting file\n",
      },
    ).trim();
    const mixedStages = [
      `160000 ${revisions[0]} 1\t${action}\n`,
      `160000 ${revisions[1]} 2\t${action}\n`,
      `100755 ${conflictingFile} 3\t${action}\n`,
    ];
    execFileSync("git", ["update-index", "--index-info"], {
      cwd: fixture.repository,
      input: `0 ${"0".repeat(40)}\t${action}\n${mixedStages.join("")}`,
    });

    const [mixed] = await runDiffRankInput(fixture, "local-patch");
    expect(mixed?.preview).toContain("Git merge stage 3 (mode 100755):");
    expect(mixed?.preview).toContain("runs: conflicting file");
    expect(mixed?.preview).toContain(`Git submodule commit ${worktree}`);
  });

  test("records unstaged local-action submodule revisions from their worktree", async () => {
    const fixture = await createRepository();
    const submodule = join(fixture.repository, ".github", "actions", "local");
    await mkdir(submodule, { recursive: true });
    git(submodule, "init", "-q", "-b", "main");
    git(submodule, "config", "user.name", "Codex Security Test");
    git(submodule, "config", "user.email", "codex-security@example.invalid");
    git(submodule, "config", "commit.gpgsign", "false");
    await writeRepositoryFile(submodule, "action.yml", "runs: old\n");
    git(submodule, "add", "action.yml");
    git(submodule, "commit", "-qm", "initial action");
    const staged = git(submodule, "rev-parse", "HEAD");
    git(
      fixture.repository,
      "update-index",
      "--add",
      "--cacheinfo",
      `160000,${staged},.github/actions/local`,
    );
    git(fixture.repository, "commit", "-qm", "pin local action");
    fixture.base = git(fixture.repository, "rev-parse", "HEAD");
    await writeRepositoryFile(submodule, "action.yml", "runs: updated\n");
    git(submodule, "add", "action.yml");
    git(submodule, "commit", "-qm", "update action");
    const unstaged = git(submodule, "rev-parse", "HEAD");

    expect(await runDiffRankInput(fixture, "local-patch")).toEqual([
      {
        path: ".github/actions/local",
        area: "diff",
        preview: `Git submodule commit ${staged} (staged); ${unstaged} (worktree)`,
      },
    ]);

    git(fixture.repository, "add", "--", ".github/actions/local");
    git(submodule, "checkout", "--quiet", staged);
    expect(await runDiffRankInput(fixture, "local-patch")).toEqual([
      {
        path: ".github/actions/local",
        area: "diff",
        preview: `Git submodule commit ${unstaged} (staged); ${staged} (worktree)`,
      },
    ]);
  });

  test("keeps staged gitlink pins when the local action is uninitialized", async () => {
    const fixture = await createRepository();
    const pin = fixture.base;
    git(fixture.repository, "commit", "--allow-empty", "-qm", "advance parent");
    fixture.base = git(fixture.repository, "rev-parse", "HEAD");
    const submodule = join(fixture.repository, ".github", "actions", "local");
    await mkdir(submodule, { recursive: true });
    git(
      fixture.repository,
      "update-index",
      "--add",
      "--cacheinfo",
      `160000,${pin},.github/actions/local`,
    );

    expect(await runDiffRankInput(fixture, "local-patch")).toEqual([
      {
        path: ".github/actions/local",
        area: "diff",
        preview: `Git submodule commit ${pin}`,
      },
    ]);
  });

  test.skipIf(process.platform === "win32")(
    "refuses to assign changed workflow symlinks to deep reviewers",
    async () => {
      const fixture = await createRepository();
      const externalFile = join(fixture.root, "external-workflow.yml");
      await writeFile(externalFile, "name: external secret\n");
      await mkdir(join(fixture.repository, ".github", "workflows"), {
        recursive: true,
      });
      await symlink(
        externalFile,
        join(fixture.repository, ".github", "workflows", "deploy.yml"),
      );
      git(fixture.repository, "add", ".github/workflows/deploy.yml");

      await expect(runDiffRankInput(fixture, "local-patch")).rejects.toThrow(
        /symbolic links/,
      );
    },
  );

  test("exposes both staged and working-tree source when they differ", async () => {
    const fixture = await createRepository();
    const workflow = ".github/workflows/deploy.yml";
    await writeRepositoryFile(
      fixture.repository,
      workflow,
      "run: stagedDangerousCommand\n",
    );
    git(fixture.repository, "add", workflow);
    await writeRepositoryFile(
      fixture.repository,
      workflow,
      "run: worktreeSafeCommand\n",
    );

    const rows = await runDiffRankInput(fixture, "local-patch");
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ path: workflow, area: "diff" });
    expect(rows[0]?.preview).toContain("Staged Git index:");
    expect(rows[0]?.preview).toContain("stagedDangerousCommand");
    expect(rows[0]?.preview).toContain("Worktree:");
    expect(rows[0]?.preview).toContain("worktreeSafeCommand");
  });

  test.skipIf(process.platform === "win32")(
    "refuses repository paths escaping through a symlinked parent",
    async () => {
      const fixture = await createRepository();
      const canary = "CODEX_SECURITY_SYNTHETIC_EXTERNAL_SECRET_7e98526d";
      const externalDirectory = join(fixture.root, "external-directory");
      const externalFile = join(externalDirectory, "escaped.py");
      await mkdir(externalDirectory);
      await Promise.all([
        writeFile(externalFile, `secret = '${canary}'\n`),
        writeRepositoryFile(
          fixture.repository,
          "src/parent/escaped.py",
          "print('safe committed source')\n",
        ),
      ]);
      git(fixture.repository, "add", "-A");
      git(fixture.repository, "commit", "-qm", "add changed source");

      await rm(join(fixture.repository, "src", "parent"), {
        recursive: true,
        force: true,
      });
      await symlink(
        externalDirectory,
        join(fixture.repository, "src", "parent"),
        "dir",
      );

      await expect(runDiffRankInput(fixture, "revisions")).rejects.toThrow(
        /symbolic links/,
      );
      expect(await readFile(externalFile, "utf8")).toContain(canary);
    },
  );

  test.skipIf(process.platform === "win32")(
    "refuses staged symlinks in a local patch",
    async () => {
      const fixture = await createRepository();
      const canary = "CODEX_SECURITY_SYNTHETIC_LOCAL_PATCH_SECRET_ef9b01d2";
      const externalFile = join(fixture.root, "external-canary.py");
      await writeFile(externalFile, `secret = '${canary}'\n`);
      await symlink(externalFile, join(fixture.repository, "src", "linked.py"));
      git(fixture.repository, "add", "src/linked.py");
      await writeRepositoryFile(
        fixture.repository,
        "src/app.ts",
        "export const value = 2;\n",
      );

      await expect(runDiffRankInput(fixture, "local-patch")).rejects.toThrow(
        /symbolic links/,
      );
      expect(await readFile(externalFile, "utf8")).toContain(canary);
    },
  );

  test.skipIf(process.platform === "win32")(
    "refuses tracked files replaced with symlinks in committed and local diffs",
    async () => {
      for (const mode of ["revisions", "local-patch"] as const) {
        const fixture = await createRepository();
        const canary = `CODEX_SECURITY_SYNTHETIC_TYPE_CHANGE_${mode}`;
        const externalFile = join(fixture.root, "external-canary.py");
        await writeFile(externalFile, `secret = '${canary}'\n`);

        const trackedFile = join(fixture.repository, "src", "app.ts");
        await rm(trackedFile);
        await symlink(externalFile, trackedFile);
        git(fixture.repository, "add", "src/app.ts");
        if (mode === "revisions") {
          git(
            fixture.repository,
            "commit",
            "-qm",
            "replace source with symlink",
          );
        }

        await expect(runDiffRankInput(fixture, mode)).rejects.toThrow(
          /symbolic links/,
        );
        expect(await readFile(externalFile, "utf8")).toContain(canary);
      }
    },
  );

  test.skipIf(process.platform === "win32")(
    "rejects a deterministic symlink swap after canonical containment is checked",
    async () => {
      const fixture = await createRepository();
      const canary = "CODEX_SECURITY_SYNTHETIC_POST_CHECK_SECRET_c326a1f4";
      const externalFile = join(fixture.root, "external-canary.py");
      await writeFile(externalFile, `secret = '${canary}'\n`);
      await writeRepositoryFile(
        fixture.repository,
        "src/app.ts",
        "export const value = 2;\n",
      );
      git(fixture.repository, "add", "src/app.ts");
      git(fixture.repository, "commit", "-qm", "update reviewed source");

      await expect(
        runDiffRankInput(fixture, "revisions", {
          path: "src/app.ts",
          replacement: externalFile,
        }),
      ).rejects.toThrow(/symbolic links/);
      expect(await readFile(externalFile, "utf8")).toContain(canary);
    },
  );

  test.skipIf(process.platform === "win32")(
    "refuses a changed FIFO without blocking or reading it",
    async () => {
      const fixture = await createRepository();
      await writeRepositoryFile(
        fixture.repository,
        "src/app.ts",
        "export const value = 2;\n",
      );
      git(fixture.repository, "add", "src/app.ts");
      git(fixture.repository, "commit", "-qm", "update reviewed source");

      const trackedFile = join(fixture.repository, "src", "app.ts");
      await rm(trackedFile);
      execFileSync("mkfifo", [trackedFile], { stdio: "pipe" });

      await expect(runDiffRankInput(fixture, "revisions")).rejects.toThrow(
        /non-regular files/,
      );
    },
  );

  test("preserves deleted and renamed source files without following deleted paths", async () => {
    const fixture = await createRepository();
    await rm(join(fixture.repository, "src", "remove.py"));
    await rename(
      join(fixture.repository, "src", "old.py"),
      join(fixture.repository, "src", "renamed.py"),
    );
    git(fixture.repository, "add", "-A");
    git(fixture.repository, "commit", "-qm", "delete and rename source");

    const rows = await runDiffRankInput(fixture, "revisions");

    expect(rows).toEqual([
      {
        path: "src/remove.py",
        area: "diff",
        preview: "print('remove')",
      },
      {
        path: "src/renamed.py",
        area: "diff",
        preview: "print('rename')",
      },
    ]);
  });

  test("continues to exclude binary files and ignored dependency directories", async () => {
    const fixture = await createRepository();
    await Promise.all([
      writeRepositoryFile(
        fixture.repository,
        "src/app.ts",
        "export const value = 2;\n",
      ),
      writeRepositoryFile(
        fixture.repository,
        "src/binary.py",
        Buffer.from([0x00, 0x01, 0x02, 0x03]),
      ),
      writeRepositoryFile(
        fixture.repository,
        "node_modules/dependency.py",
        "print('external dependency')\n",
      ),
      writeRepositoryFile(
        fixture.repository,
        "vendor/dependency.py",
        "print('vendored dependency')\n",
      ),
    ]);
    git(fixture.repository, "add", "-A");
    git(
      fixture.repository,
      "add",
      "-f",
      "node_modules/dependency.py",
      "vendor/dependency.py",
    );
    git(fixture.repository, "commit", "-qm", "change source and dependencies");

    const rows = await runDiffRankInput(fixture, "revisions");

    expect(rows.map((row) => row.path)).toEqual(["src/app.ts"]);
    expect(rows[0]?.preview).toContain("value = 2");
  });
});

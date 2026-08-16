import { execFileSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";

type GitHubRequest = (
  method: string,
  path: string,
  body?: Record<string, unknown>,
) => Promise<unknown>;

type ReconcileResult = {
  status: "skipped" | "existing" | "would-create" | "created";
  reason?: string;
  version?: string;
  pullRequest?: unknown;
  baseSha?: string;
  headSha?: string;
};

type PatchReleaseAutomation = {
  nextPatchVersion: (version: string) => string;
  isPackageReleasePath: (path: string) => boolean;
  replacePackageVersion: (source: string, nextVersion: string) => string;
  renderReleasePullRequest: (
    template: string,
    values: {
      repository: string;
      currentVersion: string;
      nextVersion: string;
      baseSha: string;
      ciRunId: string | number;
    },
  ) => { title: string; body: string };
  reconcilePatchRelease: (options: {
    repository: string;
    github: GitHubRequest;
    git: (args: string[]) => string;
    template: string;
    dryRun?: boolean;
    log?: (message: string) => void;
  }) => Promise<ReconcileResult>;
};

const automationScript = new URL(
  "../scripts/patch-release-pr.mjs",
  import.meta.url,
);
const {
  nextPatchVersion,
  isPackageReleasePath,
  replacePackageVersion,
  renderReleasePullRequest,
  reconcilePatchRelease,
} = (await import(automationScript.href)) as PatchReleaseAutomation;

const repository = "example/project";
const packagePath = "sdk/typescript/package.json";
const currentVersion = "1.2.3";
const nextVersion = "1.2.4";
const releaseSha = "1".repeat(40);
const baseSha = "2".repeat(40);
const branchSha = "3".repeat(40);
const movedMainSha = "4".repeat(40);
const baseTree = "a".repeat(40);
const releaseTree = "b".repeat(40);
const nextTree = "c".repeat(40);
const managedBranch = `release/patch-${nextVersion}`;
const managedMarker = `<!-- codex-security-patch-release:${nextVersion} -->`;
const ciRunId = 12345;
const template = readFileSync(
  new URL("../../../.github/PULL_REQUEST_TEMPLATE.md", import.meta.url),
  "utf8",
);

function packageSource(version = currentVersion): string {
  return `{
  "name": "@openai/codex-security",
  "version": "${version}",
  "description": "Synthetic package fixture",
  "dependencies": { "example-library": "1.2.3" }
}\n`;
}

type WorkflowRun = {
  id: number;
  name: string;
  path: string;
  event: string;
  status: string;
  conclusion: string | null;
  head_branch: string;
  head_sha: string;
  head_repository: { full_name: string };
};

type Release = {
  id: number;
  tag_name: string;
  draft: boolean;
  prerelease: boolean;
  published_at: string | null;
};

type PullRequest = {
  number: number;
  title: string;
  body: string;
  state: "open" | "closed";
  draft: boolean;
  merged_at: string | null;
  user: { id: number };
  labels: { name: string }[];
  html_url: string;
  head: { ref: string; sha: string; repo: { full_name: string } };
  base: { ref: string; sha: string; repo: { full_name: string } };
};

type Commit = {
  sha: string;
  tree: string;
  parents: string[];
  manifest: string;
  changedPaths: string[];
  message: string;
};

type ApiRequest = {
  method: string;
  path: string;
  body?: Record<string, unknown>;
};

type Comment = {
  id: number;
  body: string;
  user: { id: number; login: string; type: string };
};

function apiError(status: number, message = "Synthetic API failure"): Error {
  return Object.assign(new Error(message), { status });
}

function workflowRun(overrides: Partial<WorkflowRun> = {}): WorkflowRun {
  return {
    id: ciRunId,
    name: "node-ci",
    path: ".github/workflows/node-ci.yml",
    event: "push",
    status: "completed",
    conclusion: "success",
    head_branch: "main",
    head_sha: baseSha,
    head_repository: { full_name: repository },
    ...overrides,
  };
}

function publishedRelease(version = currentVersion): Release {
  return {
    id: 100,
    tag_name: `npm-v${version}`,
    draft: false,
    prerelease: false,
    published_at: "2026-01-01T00:00:00Z",
  };
}

function pullRequest(overrides: Partial<PullRequest> = {}): PullRequest {
  return {
    number: 17,
    title: `release: bump package to ${nextVersion}`,
    body: managedMarker,
    state: "open",
    draft: true,
    merged_at: null,
    user: { id: 418 },
    labels: [{ name: "skip-release-notes" }],
    html_url: `https://github.com/${repository}/pull/17`,
    head: {
      ref: managedBranch,
      sha: branchSha,
      repo: { full_name: repository },
    },
    base: { ref: "main", sha: baseSha, repo: { full_name: repository } },
    ...overrides,
  };
}

function reviewComment(sha: string): Comment {
  return {
    id: 51,
    body: `@codex review\n\n<!-- codex-security-release-review:${sha} -->`,
    user: { id: 418, login: "github-actions[bot]", type: "Bot" },
  };
}

function releaseFixture() {
  const commits = new Map<string, Commit>([
    [
      releaseSha,
      {
        sha: releaseSha,
        tree: releaseTree,
        parents: [],
        manifest: packageSource(),
        changedPaths: [],
        message: `release: bump package to ${currentVersion}`,
      },
    ],
    [
      baseSha,
      {
        sha: baseSha,
        tree: baseTree,
        parents: [releaseSha],
        manifest: packageSource(),
        changedPaths: ["sdk/typescript/src/index.ts"],
        message: "fix: synthetic package behavior",
      },
    ],
  ]);
  const refs = new Map<string, string>([
    ["heads/main", baseSha],
    [`tags/npm-v${currentVersion}`, releaseSha],
  ]);
  const state = {
    checkoutSha: baseSha,
    commits,
    refs,
    releases: [publishedRelease()],
    runs: [workflowRun()],
    pulls: [] as PullRequest[],
    comments: new Map<number, Comment[]>(),
    requests: [] as ApiRequest[],
    gitRequests: [] as string[][],
    trees: new Map<string, { manifest: string; changedPaths: string[] }>(),
    tagObjects: new Map<string, { type: string; sha: string }>(),
    onRequest: undefined as ((request: ApiRequest) => void) | undefined,
    loseCreateRefResponse: false,
    loseCreatePullResponse: false,
  };

  function commit(sha: string): Commit {
    const value = commits.get(sha);
    if (value === undefined) throw new Error(`Unknown fixture commit ${sha}`);
    return value;
  }

  function resolve(reference: string): string {
    const ref = reference.replace(/\^\{commit\}$/u, "");
    if (ref === "HEAD") return state.checkoutSha;
    if (["FETCH_HEAD", "origin/main"].includes(ref)) {
      return refs.get("heads/main")!;
    }
    if (commits.has(ref)) return ref;
    const normalized = ref
      .replace(/^refs\/remotes\/origin\//u, "heads/")
      .replace(/^refs\//u, "");
    const resolved = refs.get(normalized) ?? refs.get(`tags/${normalized}`);
    if (resolved === undefined) throw new Error(`Unknown fixture ref ${ref}`);
    return resolved;
  }

  function ancestor(older: string, newer: string): boolean {
    if (older === newer) return true;
    return commit(newer).parents.some((parent) => ancestor(older, parent));
  }

  function mergeBase(left: string, right: string): string {
    if (ancestor(left, right)) return left;
    if (ancestor(right, left)) return right;
    for (const parent of commit(left).parents) {
      const base = mergeBase(parent, right);
      if (base !== "0".repeat(40)) return base;
    }
    return "0".repeat(40);
  }

  function changedPaths(older: string, newer: string): string[] {
    if (older === newer) return [];
    const newerCommit = commit(newer);
    if (newerCommit.parents.includes(older)) return newerCommit.changedPaths;
    if (ancestor(older, newer)) {
      return [
        ...new Set(
          newerCommit.parents.flatMap((parent) => [
            ...changedPaths(older, parent),
            ...newerCommit.changedPaths,
          ]),
        ),
      ];
    }
    return newerCommit.changedPaths;
  }

  function git(args: string[]): string {
    state.gitRequests.push([...args]);
    const [command, ...rest] = args;
    if (command === "fetch") return "";
    if (command === "rev-parse") {
      const reference = rest.filter((arg) => !arg.startsWith("-"))[0]!;
      if (reference.endsWith("^{tree}")) {
        return `${commit(resolve(reference.slice(0, -"^{tree}".length))).tree}\n`;
      }
      return `${resolve(reference)}\n`;
    }
    if (command === "show") {
      const object = rest.find((arg) => !arg.startsWith("-"))!;
      const separator = object.indexOf(":");
      const sha = resolve(object.slice(0, separator));
      const path = object.slice(separator + 1);
      if (path === packagePath) return commit(sha).manifest;
      throw new Error(`Unknown fixture path ${path}`);
    }
    if (command === "merge-base") {
      const objects = rest.filter((arg) => !arg.startsWith("-"));
      const older = resolve(objects[0]!);
      const newer = resolve(objects[1]!);
      if (!ancestor(older, newer)) {
        if (rest.includes("--is-ancestor")) throw new Error("Not an ancestor");
        return `${mergeBase(older, newer)}\n`;
      }
      return rest.includes("--is-ancestor") ? "" : `${older}\n`;
    }
    if (command === "diff") {
      const objects = rest.filter((arg) => !arg.startsWith("-"));
      const paths = changedPaths(resolve(objects[0]!), resolve(objects[1]!));
      const separator = rest.includes("-z") ? "\0" : "\n";
      return paths.length === 0 ? "" : paths.join(separator) + separator;
    }
    throw new Error(`Unexpected fixture git command: ${args.join(" ")}`);
  }

  function pullByNumber(number: number): PullRequest {
    const pull = state.pulls.find((candidate) => candidate.number === number);
    if (pull === undefined) throw apiError(404);
    return pull;
  }

  function gitCommit(sha: string) {
    const value = commit(sha);
    return {
      sha,
      message: value.message,
      tree: { sha: value.tree },
      parents: value.parents.map((parent) => ({ sha: parent })),
    };
  }

  const github: GitHubRequest = async (method, path, body) => {
    const request = { method, path, ...(body === undefined ? {} : { body }) };
    state.requests.push(structuredClone(request));
    state.onRequest?.(request);
    const url = new URL(path, "https://api.github.com/");
    const prefix = `/repos/${repository}/`;
    if (!url.pathname.startsWith(prefix)) {
      throw new Error(`Unexpected fixture repository: ${path}`);
    }
    const endpoint = decodeURIComponent(url.pathname.slice(prefix.length));
    const page = Number(url.searchParams.get("page") ?? "1");
    const perPage = Number(url.searchParams.get("per_page") ?? "100");
    const paginate = <T>(values: T[]): T[] =>
      values.slice((page - 1) * perPage, page * perPage);

    if (method === "GET" && endpoint.startsWith("git/ref/")) {
      const name = endpoint.slice("git/ref/".length);
      const sha = refs.get(name);
      if (sha === undefined) throw apiError(404);
      return {
        ref: `refs/${name}`,
        object: { type: state.tagObjects.has(sha) ? "tag" : "commit", sha },
      };
    }
    if (method === "GET" && endpoint.startsWith("git/tags/")) {
      const object = state.tagObjects.get(endpoint.slice("git/tags/".length));
      if (object === undefined) throw apiError(404);
      return { object };
    }
    if (
      method === "GET" &&
      /^actions\/workflows\/[^/]+\/runs$/u.test(endpoint)
    ) {
      return { total_count: state.runs.length, workflow_runs: state.runs };
    }
    if (method === "GET" && endpoint === "releases") {
      return paginate(state.releases);
    }
    if (method === "GET" && endpoint.startsWith("releases/tags/")) {
      const tag = endpoint.slice("releases/tags/".length);
      const release = state.releases.find((value) => value.tag_name === tag);
      if (release === undefined) throw apiError(404);
      return release;
    }
    if (method === "GET" && endpoint === "pulls") {
      const requestedState = url.searchParams.get("state") ?? "open";
      const head = url.searchParams.get("head")?.split(":").slice(1).join(":");
      const base = url.searchParams.get("base");
      return paginate(
        state.pulls.filter(
          (pull) =>
            (requestedState === "all" || pull.state === requestedState) &&
            (head === undefined || pull.head.ref === head) &&
            (base === null || pull.base.ref === base),
        ),
      );
    }
    if (method === "GET" && /^pulls\/\d+$/u.test(endpoint)) {
      return structuredClone(pullByNumber(Number(endpoint.split("/")[1])));
    }
    if (method === "GET" && endpoint.startsWith("contents/")) {
      const path = endpoint.slice("contents/".length);
      const sha = resolve(url.searchParams.get("ref") ?? "HEAD");
      if (path !== packagePath) throw apiError(404);
      return {
        type: "file",
        encoding: "base64",
        content: Buffer.from(commit(sha).manifest).toString("base64"),
        sha: `manifest-${sha}`,
        path,
      };
    }
    if (method === "GET" && endpoint.startsWith("compare/")) {
      const [from, to] = endpoint.slice("compare/".length).split("...");
      const older = resolve(from!);
      const newer = resolve(to!);
      return {
        status: ancestor(older, newer) ? "ahead" : "diverged",
        ahead_by: older === newer ? 0 : 1,
        behind_by: ancestor(older, newer) ? 0 : 1,
        total_commits: older === newer ? 0 : 1,
        merge_base_commit: { sha: mergeBase(older, newer) },
        commits: older === newer ? [] : [gitCommit(newer)],
        files: changedPaths(older, newer).map((filename) => ({
          filename,
          status: "modified",
        })),
      };
    }
    if (method === "GET" && /^issues\/\d+\/comments$/u.test(endpoint)) {
      const number = Number(endpoint.split("/")[1]);
      return paginate(state.comments.get(number) ?? []);
    }
    if (method === "POST" && endpoint === "git/trees") {
      const entries = body?.["tree"] as {
        path: string;
        content: string;
      }[];
      const manifest = entries.find((entry) => entry.path === packagePath);
      if (manifest === undefined)
        throw new Error("Missing manifest tree entry");
      state.trees.set(nextTree, {
        manifest: manifest.content,
        changedPaths: entries.map((entry) => entry.path),
      });
      return { sha: nextTree };
    }
    if (method === "POST" && endpoint === "git/commits") {
      const tree = String(body?.["tree"]);
      const files = state.trees.get(tree);
      if (files === undefined) throw new Error(`Unknown fixture tree ${tree}`);
      commits.set(branchSha, {
        sha: branchSha,
        tree,
        parents: body?.["parents"] as string[],
        message: String(body?.["message"]),
        ...files,
      });
      return gitCommit(branchSha);
    }
    if (method === "POST" && endpoint === "git/refs") {
      const name = String(body?.["ref"]).replace(/^refs\//u, "");
      if (refs.has(name)) throw apiError(422, "Reference already exists");
      const sha = String(body?.["sha"]);
      refs.set(name, sha);
      if (state.loseCreateRefResponse) {
        state.loseCreateRefResponse = false;
        throw apiError(502, "Synthetic lost ref-create response");
      }
      return { ref: `refs/${name}`, object: { type: "commit", sha } };
    }
    if (method === "POST" && endpoint === "pulls") {
      const head = String(body?.["head"]).split(":").at(-1)!;
      if (
        state.pulls.some(
          (pull) => pull.state === "open" && pull.head.ref === head,
        )
      ) {
        throw apiError(422, "Pull request already exists");
      }
      const value = pullRequest({
        title: String(body?.["title"]),
        body: String(body?.["body"]),
        draft: body?.["draft"] === true,
        labels: [],
        head: {
          ref: head,
          sha: refs.get(`heads/${head}`)!,
          repo: { full_name: repository },
        },
        base: {
          ref: "main",
          sha: refs.get("heads/main")!,
          repo: { full_name: repository },
        },
      });
      state.pulls.push(value);
      if (state.loseCreatePullResponse) {
        state.loseCreatePullResponse = false;
        throw apiError(502, "Synthetic lost create response");
      }
      return structuredClone(value);
    }
    if (method === "POST" && /^issues\/\d+\/labels$/u.test(endpoint)) {
      const pull = pullByNumber(Number(endpoint.split("/")[1]));
      const labels = body?.["labels"] as string[];
      pull.labels.push(
        ...labels
          .filter((name) => !pull.labels.some((label) => label.name === name))
          .map((name) => ({ name })),
      );
      return structuredClone(pull.labels);
    }
    if (method === "POST" && /^issues\/\d+\/comments$/u.test(endpoint)) {
      const number = Number(endpoint.split("/")[1]);
      const value = {
        ...reviewComment(branchSha),
        body: String(body?.["body"]),
      };
      state.comments.set(number, [
        ...(state.comments.get(number) ?? []),
        value,
      ]);
      return value;
    }
    throw new Error(`Unexpected fixture GitHub request: ${method} ${path}`);
  };

  function addManagedBranch(
    options: Omit<Partial<Commit>, "changedPaths"> & {
      changedPaths?: readonly string[];
    } = {},
  ): Commit {
    const value: Commit = {
      sha: branchSha,
      tree: nextTree,
      parents: [baseSha],
      manifest: packageSource(nextVersion),
      message: `release: bump Codex Security to ${nextVersion}`,
      ...options,
      changedPaths: [...(options.changedPaths ?? [packagePath])],
    };
    commits.set(value.sha, value);
    refs.set(`heads/${managedBranch}`, value.sha);
    return value;
  }

  async function run(dryRun = false): Promise<ReconcileResult> {
    return reconcilePatchRelease({
      repository,
      github,
      git,
      template,
      dryRun,
      log: () => {},
    });
  }

  function writes(): ApiRequest[] {
    return state.requests.filter((request) => request.method !== "GET");
  }

  return { state, git, github, run, writes, addManagedBranch };
}

describe("patch release inputs", () => {
  test.each([
    ["0.0.0", "0.0.1"],
    ["0.1.99", "0.1.100"],
    ["12.34.56", "12.34.57"],
    ["1.2.9007199254740993", "1.2.9007199254740994"],
    [
      "9007199254740993.9007199254740994.99999999999999999999",
      "9007199254740993.9007199254740994.100000000000000000000",
    ],
  ])("increments only the patch of %s", (version, expected) => {
    expect(nextPatchVersion(version)).toBe(expected);
  });

  test.each([
    "",
    "1.2",
    "v1.2.3",
    "01.2.3",
    "1.02.3",
    "1.2.03",
    "1.2.3-rc.1",
    "1.2.3+build.1",
    "1.2.3\n",
    " 1.2.3",
    "1.2.-1",
  ])("rejects nonstable version %j", (version) => {
    expect(() => nextPatchVersion(version)).toThrow();
  });

  test.each([
    "sdk/typescript/src/index.ts",
    "sdk/typescript/bin/codex-security.mjs",
    "sdk/typescript/_bundled_plugin/skills/example/SKILL.md",
    "sdk/typescript/package.json",
    "sdk/typescript/pnpm-lock.yaml",
    "sdk/typescript/README.md",
    "sdk/typescript/LICENSE",
    "sdk/typescript/tsconfig.json",
    "sdk/typescript/tsconfig.build.json",
    "sdk/typescript/.gitignore",
    "sdk/typescript/.npmignore",
  ])("includes package input %s", (path) => {
    expect(isPackageReleasePath(path)).toBe(true);
  });

  test.each([
    "README.md",
    "AGENTS.md",
    ".github/workflows/node-ci.yml",
    "docs/release-process.md",
    "sdk/typescript/tests-ts/example.test.ts",
    "sdk/typescript/scripts/check-package.mjs",
    "sdk/typescript/plugin-files.json",
    "mcp/server.mjs",
    "scripts/workbench_db.py",
    "skills/security-scan/SKILL.md",
    "sdk/typescript/src-old/index.ts",
    "other/sdk/typescript/src/index.ts",
  ])("excludes nonpackage input %s", (path) => {
    expect(isPackageReleasePath(path)).toBe(false);
  });

  test("updates only the top-level version and preserves formatting", () => {
    const source =
      '{\r\n\t"name" : "@openai/codex-security",\r\n' +
      '\t"metadata": {"version": "1.2.3"},\r\n' +
      '\t"version"  :  "1.2.3",\r\n' +
      '\t"description": "version: 1.2.3",\r\n' +
      '\t"dependencies": {"example-library": "1.2.3"}\r\n}\r\n';
    const expected = source.replace(
      '\t"version"  :  "1.2.3"',
      '\t"version"  :  "1.2.4"',
    );

    expect(replacePackageVersion(source, nextVersion)).toBe(expected);
    expect(JSON.parse(expected)).toEqual({
      ...JSON.parse(source),
      version: nextVersion,
    });
  });

  test("rejects malformed or mismatched release manifests", () => {
    for (const source of [
      "not json",
      JSON.stringify({ name: "example-package", version: currentVersion }),
      JSON.stringify({ name: "@openai/codex-security" }),
      packageSource("1.2.3-rc.1"),
    ]) {
      expect(() => replacePackageVersion(source, nextVersion)).toThrow();
    }
    expect(() =>
      replacePackageVersion(packageSource(), "1.2.4-rc.1"),
    ).toThrow();
  });

  test("uses every PR-template section without attesting for a reviewer", () => {
    const rendered = renderReleasePullRequest(template, {
      repository,
      currentVersion,
      nextVersion,
      baseSha,
      ciRunId,
    });

    expect(rendered.title).toMatch(/^release:/u);
    expect(rendered.title).toContain(nextVersion);
    const headings = template.match(/^## .+$/gmu) ?? [];
    for (const heading of headings) {
      expect(rendered.body).toContain(heading);
      const section = rendered.body
        .split(heading)[1]
        ?.split(/^## /mu)[0]
        ?.replace(/<!--[\s\S]*?-->/gu, "")
        .trim();
      expect(section).toBeTruthy();
    }
    const disclosures = template.match(/^- \[ \] .+$/gmu) ?? [];
    expect(disclosures).toHaveLength(3);
    for (const disclosure of disclosures) {
      expect(rendered.body).toContain(disclosure);
    }
    expect(rendered.body).not.toMatch(/^- \[[xX]\]/mu);
    expect(rendered.body).toContain(packagePath);
    expect(rendered.body).toContain(currentVersion);
    expect(rendered.body).toContain(nextVersion);
    expect(rendered.body).toContain(baseSha);
    expect(rendered.body).toContain(
      `https://github.com/${repository}/actions/runs/${ciRunId}`,
    );
  });
});

describe("patch release reconciliation", () => {
  test("creates one manifest-only PR from exact-head successful CI", async () => {
    const fixture = releaseFixture();

    expect(await fixture.run()).toEqual({
      status: "created",
      version: nextVersion,
      pullRequest: 17,
      headSha: branchSha,
    });
    expect(fixture.state.commits.get(branchSha)).toMatchObject({
      parents: [baseSha],
      changedPaths: [packagePath],
      manifest: packageSource(nextVersion),
    });
    expect(fixture.state.refs.get(`heads/${managedBranch}`)).toBe(branchSha);
    expect(fixture.state.pulls).toHaveLength(1);
    expect(fixture.state.pulls[0]).toMatchObject({
      state: "open",
      draft: false,
      head: { ref: managedBranch, sha: branchSha },
      base: { ref: "main", sha: baseSha },
      labels: [{ name: "skip-release-notes" }],
    });
    expect(fixture.state.pulls[0]?.body).toContain(managedMarker);
    expect(fixture.state.pulls[0]?.body).not.toMatch(/^- \[[xX]\]/mu);
    expect(fixture.state.comments.get(17)).toHaveLength(1);
    expect(fixture.state.comments.get(17)?.[0]?.body).toContain(
      "@codex review",
    );
    expect(fixture.state.comments.get(17)?.[0]?.body).toContain(
      `<!-- codex-security-release-review:${branchSha} -->`,
    );
    const ciRequest = fixture.state.requests.find((request) =>
      request.path.includes("/actions/workflows/node-ci.yml/runs?"),
    );
    expect(
      new URL(ciRequest!.path, "https://api.github.com/").searchParams.get(
        "head_sha",
      ),
    ).toBe(baseSha);
    const treeRequest = fixture
      .writes()
      .find((request) => request.path.endsWith("/git/trees"));
    expect(treeRequest?.body).toMatchObject({
      base_tree: baseTree,
      tree: [{ path: packagePath, content: packageSource(nextVersion) }],
    });
    expect(fixture.writes().every((request) => request.method === "POST")).toBe(
      true,
    );
  });

  test("is idempotent after creating the release PR and exact-head review", async () => {
    const fixture = releaseFixture();
    await fixture.run();
    const previousWrites = fixture.writes();
    const previousPull = structuredClone(fixture.state.pulls[0]);

    expect(await fixture.run()).toMatchObject({
      status: "existing",
      version: nextVersion,
      pullRequest: 17,
    });
    expect(fixture.writes()).toEqual(previousWrites);
    expect(fixture.state.pulls[0]).toEqual(previousPull);
    expect(fixture.state.comments.get(17)).toHaveLength(1);
  });

  test("accepts an annotated release tag after resolving its commit", async () => {
    const fixture = releaseFixture();
    const tagObject = "e".repeat(40);
    fixture.state.refs.set(`tags/npm-v${currentVersion}`, tagObject);
    fixture.state.tagObjects.set(tagObject, {
      type: "commit",
      sha: releaseSha,
    });

    expect(await fixture.run(true)).toMatchObject({ status: "would-create" });
    expect(fixture.writes()).toEqual([]);
  });

  test("skips a stale checkout before making any writes", async () => {
    const fixture = releaseFixture();
    fixture.state.refs.set("heads/main", movedMainSha);

    expect(await fixture.run()).toMatchObject({ status: "skipped" });
    expect(fixture.writes()).toEqual([]);
  });

  test.each([
    ["no successful run", []],
    ["an older successful head", [workflowRun({ head_sha: releaseSha })]],
    ["a failed exact head", [workflowRun({ conclusion: "failure" })]],
    [
      "an unfinished exact head",
      [workflowRun({ status: "in_progress", conclusion: null })],
    ],
    ["a PR-only run", [workflowRun({ event: "pull_request" })]],
  ] as const)("skips %s", async (_description, runs) => {
    const fixture = releaseFixture();
    fixture.state.runs = [...runs];

    expect(await fixture.run()).toMatchObject({ status: "skipped" });
    expect(fixture.writes()).toEqual([]);
  });

  test.each([
    "missing tag",
    "missing GitHub release",
    "draft GitHub release",
    "prerelease GitHub release",
    "unpublished GitHub release",
  ])("waits when release history has a %s", async (condition) => {
    const fixture = releaseFixture();
    if (condition === "missing tag") {
      fixture.state.refs.delete(`tags/npm-v${currentVersion}`);
    } else if (condition === "missing GitHub release") {
      fixture.state.releases = [];
    } else if (condition === "draft GitHub release") {
      fixture.state.releases[0]!.draft = true;
    } else if (condition === "prerelease GitHub release") {
      fixture.state.releases[0]!.prerelease = true;
    } else {
      fixture.state.releases[0]!.published_at = null;
    }

    expect(await fixture.run()).toMatchObject({ status: "skipped" });
    expect(fixture.writes()).toEqual([]);
  });

  test("does not confuse a failed history lookup with an absent release", async () => {
    const fixture = releaseFixture();
    fixture.state.onRequest = ({ path }) => {
      if (path.endsWith(`/releases/tags/npm-v${currentVersion}`)) {
        throw apiError(403, "Synthetic denied release lookup");
      }
    };

    await expect(fixture.run()).rejects.toThrow(
      "Synthetic denied release lookup",
    );
    expect(fixture.writes()).toEqual([]);
  });

  test.each(["ancestry", "manifest version"])(
    "rejects a current tag with inconsistent %s",
    async (condition) => {
      const fixture = releaseFixture();
      if (condition === "ancestry") {
        fixture.state.commits.get(baseSha)!.parents = [];
      } else {
        fixture.state.commits.get(releaseSha)!.manifest =
          packageSource("1.2.2");
      }

      await expect(fixture.run()).rejects.toThrow(/version history/u);
      expect(fixture.writes()).toEqual([]);
    },
  );

  test("rejects a newer published stable release, including later API pages", async () => {
    const fixture = releaseFixture();
    fixture.state.releases = [
      publishedRelease(),
      ...Array.from({ length: 99 }, (_, index) =>
        publishedRelease(`0.0.${index}`),
      ),
      publishedRelease("1.3.0"),
    ];

    await expect(fixture.run()).rejects.toThrow(/published/u);
    expect(fixture.writes()).toEqual([]);
  });

  test("ignores unpublished and prerelease versions in newer history", async () => {
    const fixture = releaseFixture();
    fixture.state.releases.push(
      { ...publishedRelease("1.3.0"), draft: true },
      { ...publishedRelease("2.0.0"), prerelease: true },
      { ...publishedRelease(), tag_name: "npm-v1.2.4-rc.1" },
    );

    expect(await fixture.run(true)).toMatchObject({ status: "would-create" });
    expect(fixture.writes()).toEqual([]);
  });

  test("rejects an occupied next release tag", async () => {
    const fixture = releaseFixture();
    fixture.state.refs.set(`tags/npm-v${nextVersion}`, branchSha);

    await expect(fixture.run()).rejects.toThrow(/already exists/u);
    expect(fixture.writes()).toEqual([]);
  });

  test.each([
    { name: "a fully reverted package change", paths: [] },
    {
      name: "repository documentation and CI changes",
      paths: ["README.md", ".github/workflows/node-ci.yml"],
    },
    {
      name: "SDK maintenance-only changes",
      paths: [
        "sdk/typescript/tests-ts/example.test.ts",
        "sdk/typescript/scripts/check-package.mjs",
        "sdk/typescript/plugin-files.json",
      ],
    },
  ])("skips $name", async ({ paths }) => {
    const fixture = releaseFixture();
    fixture.state.commits.get(baseSha)!.changedPaths = [...paths];

    expect(await fixture.run()).toMatchObject({ status: "skipped" });
    expect(fixture.writes()).toEqual([]);
  });

  test.each([
    "sdk/typescript/_bundled_plugin/skills/example/SKILL.md",
    "sdk/typescript/pnpm-lock.yaml",
  ])("proposes a release for a net change to %s", async (path) => {
    const fixture = releaseFixture();
    fixture.state.commits.get(baseSha)!.changedPaths = [path];

    expect(await fixture.run(true)).toMatchObject({ status: "would-create" });
    expect(fixture.writes()).toEqual([]);
  });

  test("counts the removal when Git recognizes a rename out of the package", async () => {
    const root = mkdtempSync(join(tmpdir(), "codex-security-release-rename-"));
    const hooks = join(root, "empty-hooks");
    mkdirSync(hooks);
    const realGit = (args: string[]): string =>
      execFileSync(
        "git",
        [
          "-c",
          "user.name=Example Release Fixture",
          "-c",
          "user.email=release-fixture@example.invalid",
          "-c",
          "commit.gpgsign=false",
          "-c",
          `core.hooksPath=${hooks}`,
          ...args,
        ],
        { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
      );

    try {
      realGit(["init", "-q", "--initial-branch=main"]);
      const sourceDirectory = join(root, "sdk", "typescript", "src");
      mkdirSync(sourceDirectory, { recursive: true });
      writeFileSync(
        join(sourceDirectory, "example.ts"),
        "export const example = true;\n",
      );
      realGit(["add", "sdk"]);
      realGit(["commit", "-q", "-m", "Add synthetic package input"]);
      const before = realGit(["rev-parse", "HEAD"]).trim();
      mkdirSync(join(root, "docs"));
      renameSync(
        join(sourceDirectory, "example.ts"),
        join(root, "docs", "example.ts"),
      );
      realGit(["add", "-A"]);
      realGit(["commit", "-q", "-m", "Move synthetic input into docs"]);
      const after = realGit(["rev-parse", "HEAD"]).trim();
      expect(
        realGit(["diff", "--name-status", "--find-renames", before, after]),
      ).toContain("R100");

      const fixture = releaseFixture();
      const refs = new Map([
        [releaseSha, before],
        [baseSha, after],
      ]);
      const result = await reconcilePatchRelease({
        repository,
        github: fixture.github,
        git: (args) =>
          args[0] === "diff"
            ? realGit(args.map((argument) => refs.get(argument) ?? argument))
            : fixture.git(args),
        template,
        dryRun: true,
        log: () => {},
      });

      expect(result).toMatchObject({ status: "would-create" });
      expect(fixture.writes()).toEqual([]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }, 30_000);

  test("preserves a competing same-repository manual version bump", async () => {
    const fixture = releaseFixture();
    const manualSha = "5".repeat(40);
    fixture.state.commits.set(manualSha, {
      ...fixture.state.commits.get(baseSha)!,
      sha: manualSha,
      parents: [baseSha],
      manifest: packageSource("1.3.0"),
      changedPaths: [packagePath],
    });
    fixture.state.pulls.push(
      pullRequest({
        number: 23,
        title: "chore: prepare the next version",
        body: "Human-authored release notes and attestations.",
        head: {
          ref: "manual-version-bump",
          sha: manualSha,
          repo: { full_name: repository },
        },
      }),
    );
    const previousPulls = structuredClone(fixture.state.pulls);

    expect(await fixture.run()).toMatchObject({
      status: "existing",
      pullRequest: 23,
    });
    expect(fixture.state.pulls).toEqual(previousPulls);
    expect(fixture.writes()).toEqual([]);
  });

  test("does not mistake an external fork PR for a same-repository release", async () => {
    const fixture = releaseFixture();
    fixture.state.pulls.push(
      pullRequest({
        number: 23,
        head: {
          ref: "external-version-bump",
          sha: "5".repeat(40),
          repo: { full_name: "example-fork/project" },
        },
      }),
    );

    expect(await fixture.run()).toMatchObject({ status: "created" });
    expect(fixture.state.pulls).toHaveLength(2);
  });

  test("preserves an existing managed PR body, attestations, and head", async () => {
    const fixture = releaseFixture();
    fixture.addManagedBranch();
    fixture.state.pulls.push(
      pullRequest({
        body: `${managedMarker}\n\nHuman release notes.\n\n- [x] Reviewed public artifacts.`,
      }),
    );
    fixture.state.comments.set(17, [reviewComment(branchSha)]);
    const previousPull = structuredClone(fixture.state.pulls[0]);
    const previousRefs = [...fixture.state.refs];

    expect(await fixture.run()).toMatchObject({ status: "existing" });
    expect(fixture.state.pulls[0]).toEqual(previousPull);
    expect([...fixture.state.refs]).toEqual(previousRefs);
    expect(fixture.writes()).toEqual([]);
  });

  test("leaves a human-modified managed PR entirely untouched", async () => {
    const fixture = releaseFixture();
    fixture.addManagedBranch({
      changedPaths: [packagePath, "sdk/typescript/src/index.ts"],
    });
    fixture.state.pulls.push(pullRequest());
    const previousPulls = structuredClone(fixture.state.pulls);

    expect(await fixture.run()).toMatchObject({ status: "existing" });
    expect(fixture.state.pulls).toEqual(previousPulls);
    expect(fixture.writes()).toEqual([]);
  });

  test("does not recreate an intentionally closed managed PR", async () => {
    const fixture = releaseFixture();
    fixture.addManagedBranch();
    fixture.state.pulls.push(pullRequest({ state: "closed" }));

    expect(await fixture.run()).toMatchObject({ status: "skipped" });
    expect(fixture.state.pulls).toHaveLength(1);
    expect(fixture.state.pulls[0]?.state).toBe("closed");
    expect(fixture.writes()).toEqual([]);
  });

  test("recovers an orphaned expected branch without rewriting it", async () => {
    const fixture = releaseFixture();
    fixture.addManagedBranch();
    const previousCommit = structuredClone(
      fixture.state.commits.get(branchSha),
    );

    expect(await fixture.run()).toMatchObject({
      status: "created",
      headSha: branchSha,
    });
    expect(fixture.state.commits.get(branchSha)).toEqual(previousCommit);
    expect(fixture.state.refs.get(`heads/${managedBranch}`)).toBe(branchSha);
    expect(
      fixture.writes().some((request) => request.path.includes("/git/")),
    ).toBe(false);
  });

  test.each([
    {
      name: "an additional source change",
      changes: { changedPaths: [packagePath, "sdk/typescript/src/index.ts"] },
    },
    {
      name: "the wrong package version",
      changes: { manifest: packageSource("1.2.5") },
    },
    {
      name: "an additional manifest edit",
      changes: {
        manifest: packageSource(nextVersion).replace("fixture", "human edit"),
      },
    },
  ])("rejects an orphan with $name", async ({ changes }) => {
    const fixture = releaseFixture();
    fixture.addManagedBranch(changes);
    const previousCommit = structuredClone(
      fixture.state.commits.get(branchSha),
    );

    await expect(fixture.run()).rejects.toThrow(/expected version bump/u);
    expect(fixture.state.commits.get(branchSha)).toEqual(previousCommit);
    expect(fixture.writes()).toEqual([]);
  });

  test("stops when main moves while the proposal is being planned", async () => {
    const fixture = releaseFixture();
    fixture.state.onRequest = ({ method, path }) => {
      const url = new URL(path, "https://api.github.com/");
      if (
        method === "GET" &&
        url.pathname.endsWith("/pulls") &&
        url.searchParams.get("state") === "all"
      ) {
        fixture.state.refs.set("heads/main", movedMainSha);
      }
    };

    expect(await fixture.run()).toMatchObject({ status: "skipped" });
    expect(fixture.writes()).toEqual([]);
  });

  test("leaves a recoverable branch if main moves after branch creation", async () => {
    const fixture = releaseFixture();
    fixture.state.onRequest = ({ method, path }) => {
      if (method === "POST" && path.endsWith("/git/refs")) {
        fixture.state.refs.set("heads/main", movedMainSha);
      }
    };

    expect(await fixture.run()).toMatchObject({ status: "skipped" });
    expect(fixture.state.refs.get(`heads/${managedBranch}`)).toBe(branchSha);
    expect(fixture.state.pulls).toEqual([]);
    expect(fixture.state.comments.size).toBe(0);

    fixture.state.onRequest = undefined;
    fixture.state.commits.set(movedMainSha, {
      ...fixture.state.commits.get(baseSha)!,
      sha: movedMainSha,
      parents: [baseSha],
      changedPaths: ["README.md"],
    });
    fixture.state.checkoutSha = movedMainSha;
    fixture.state.runs = [workflowRun({ head_sha: movedMainSha })];
    const previousGitWrites = fixture
      .writes()
      .filter((request) => request.path.includes("/git/"));

    expect(await fixture.run()).toMatchObject({
      status: "created",
      headSha: branchSha,
    });
    expect(
      fixture.writes().filter((request) => request.path.includes("/git/")),
    ).toEqual(previousGitWrites);
  });

  test("preserves a manual release PR opened while the managed branch is created", async () => {
    const fixture = releaseFixture();
    const manualSha = "5".repeat(40);
    fixture.state.onRequest = ({ method, path }) => {
      if (method !== "POST" || !path.endsWith("/git/refs")) return;
      fixture.state.commits.set(manualSha, {
        ...fixture.state.commits.get(baseSha)!,
        sha: manualSha,
        parents: [baseSha],
        manifest: packageSource(nextVersion),
        changedPaths: [packagePath],
      });
      fixture.state.pulls.push(
        pullRequest({
          number: 23,
          body: "Human-authored release proposal.",
          head: {
            ref: "manual-version-bump",
            sha: manualSha,
            repo: { full_name: repository },
          },
        }),
      );
    };

    expect(await fixture.run()).toMatchObject({ status: "skipped" });
    expect(fixture.state.refs.get(`heads/${managedBranch}`)).toBe(branchSha);
    expect(fixture.state.pulls.map((pull) => pull.number)).toEqual([23]);
    expect(
      fixture.writes().filter((request) => request.path.endsWith("/pulls")),
    ).toEqual([]);
  });

  test("recovers a concurrent creation of the same expected branch", async () => {
    const fixture = releaseFixture();
    fixture.state.onRequest = ({ method, path }) => {
      if (method === "POST" && path.endsWith("/git/refs")) {
        fixture.state.refs.set(`heads/${managedBranch}`, branchSha);
      }
    };

    expect(await fixture.run()).toMatchObject({
      status: "created",
      headSha: branchSha,
    });
    expect(fixture.state.pulls).toHaveLength(1);
    expect(fixture.writes().every((request) => request.method === "POST")).toBe(
      true,
    );
  });

  test("recovers a successful ref creation whose response was lost", async () => {
    const fixture = releaseFixture();
    fixture.state.loseCreateRefResponse = true;

    expect(await fixture.run()).toMatchObject({
      status: "created",
      headSha: branchSha,
    });
    expect(fixture.state.refs.get(`heads/${managedBranch}`)).toBe(branchSha);
    expect(fixture.state.pulls).toHaveLength(1);
    expect(
      fixture.writes().filter((request) => request.path.endsWith("/git/refs")),
    ).toHaveLength(1);
    expect(fixture.writes().every((request) => request.method === "POST")).toBe(
      true,
    );
  });

  test("recovers a successful PR creation whose response was lost", async () => {
    const fixture = releaseFixture();
    fixture.state.loseCreatePullResponse = true;

    expect(await fixture.run()).toMatchObject({
      status: "existing",
      pullRequest: 17,
      headSha: branchSha,
    });
    expect(fixture.state.pulls).toHaveLength(1);
    expect(
      fixture.writes().filter((request) => request.path.endsWith("/pulls")),
    ).toHaveLength(1);
    expect(fixture.state.comments.get(17)).toHaveLength(1);
  });

  test("requests Codex review once for each exact managed head", async () => {
    const fixture = releaseFixture();
    fixture.addManagedBranch();
    fixture.state.pulls.push(pullRequest());
    fixture.state.comments.set(17, [reviewComment(releaseSha)]);

    expect(await fixture.run()).toMatchObject({ status: "existing" });
    expect(fixture.state.comments.get(17)).toHaveLength(2);
    expect(fixture.state.comments.get(17)?.[1]?.body).toContain(branchSha);
    const previousWrites = fixture.writes();

    expect(await fixture.run()).toMatchObject({ status: "existing" });
    expect(fixture.writes()).toEqual(previousWrites);
  });

  test("does not trust an unrelated user's copied review marker", async () => {
    const fixture = releaseFixture();
    fixture.addManagedBranch();
    fixture.state.pulls.push(pullRequest());
    fixture.state.comments.set(17, [
      {
        ...reviewComment(branchSha),
        user: { id: 999, login: "example-contributor", type: "User" },
      },
    ]);

    expect(await fixture.run()).toMatchObject({ status: "existing" });
    expect(fixture.state.comments.get(17)).toHaveLength(2);
  });

  test("does not request review for a head that changed during reconciliation", async () => {
    const fixture = releaseFixture();
    fixture.state.onRequest = ({ method, path }) => {
      if (method === "POST" && path.endsWith("/issues/17/labels")) {
        fixture.state.pulls[0]!.head.sha = movedMainSha;
      }
    };

    expect(await fixture.run()).toMatchObject({ status: "created" });
    expect(fixture.state.comments.get(17) ?? []).toEqual([]);
  });

  test("dry-run reports eligibility without creating Git objects or PR metadata", async () => {
    const fixture = releaseFixture();
    const previousRefs = [...fixture.state.refs];

    expect(await fixture.run(true)).toEqual({
      status: "would-create",
      version: nextVersion,
      baseSha,
    });
    expect([...fixture.state.refs]).toEqual(previousRefs);
    expect(fixture.state.pulls).toEqual([]);
    expect(fixture.state.comments.size).toBe(0);
    expect(fixture.writes()).toEqual([]);
  });

  test("dry-run reports the head of a reusable orphan branch", async () => {
    const fixture = releaseFixture();
    fixture.addManagedBranch();

    expect(await fixture.run(true)).toEqual({
      status: "would-create",
      version: nextVersion,
      baseSha,
      headSha: branchSha,
    });
    expect(fixture.state.pulls).toEqual([]);
    expect(fixture.writes()).toEqual([]);
  });

  test("dry-run preserves an existing PR without requesting review", async () => {
    const fixture = releaseFixture();
    fixture.addManagedBranch();
    fixture.state.pulls.push(pullRequest({ labels: [] }));

    expect(await fixture.run(true)).toMatchObject({ status: "existing" });
    expect(fixture.state.comments.size).toBe(0);
    expect(fixture.writes()).toEqual([]);
  });

  test("dry-run rejects a human-modified orphan without writing", async () => {
    const fixture = releaseFixture();
    fixture.addManagedBranch({
      changedPaths: [packagePath, "sdk/typescript/src/index.ts"],
    });

    await expect(fixture.run(true)).rejects.toThrow(/expected version bump/u);
    expect(fixture.writes()).toEqual([]);
  });
});

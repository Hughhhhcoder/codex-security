import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  compareReleaseVersions,
  publishedReleaseMode,
  releaseVersion,
} from "./release-automation.mjs";

const packageName = "@openai/codex-security";
const packageJsonPath = "sdk/typescript/package.json";
const managedBranchPrefix = "release/patch-";
const releasePaths = new Set([
  packageJsonPath,
  "sdk/typescript/pnpm-lock.yaml",
  "sdk/typescript/tsconfig.json",
  "sdk/typescript/tsconfig.build.json",
  "sdk/typescript/README.md",
  "sdk/typescript/LICENSE",
  "sdk/typescript/.gitignore",
  "sdk/typescript/.npmignore",
]);
const releaseDirectories = [
  "sdk/typescript/src/",
  "sdk/typescript/bin/",
  "sdk/typescript/_bundled_plugin/",
];

export function nextPatchVersion(version) {
  releaseVersion({ name: packageName, version });
  const [major, minor, patch] = version.split(".");
  return `${major}.${minor}.${BigInt(patch) + 1n}`;
}

export function isPackageReleasePath(path) {
  return (
    releasePaths.has(path) ||
    releaseDirectories.some((directory) => path.startsWith(directory))
  );
}

export function replacePackageVersion(source, nextVersion) {
  const manifest = JSON.parse(source);
  const currentVersion = releaseVersion(manifest);
  if (nextPatchVersion(currentVersion) !== nextVersion) {
    throw new Error("The release PR must increment exactly one patch version.");
  }

  const expected = JSON.stringify({ ...manifest, version: nextVersion });
  for (const match of source.matchAll(
    /("version"\s*:\s*)("(?:\\.|[^"\\])*")/gu,
  )) {
    if (JSON.parse(match[2]) !== currentVersion) continue;
    const start = match.index + match[1].length;
    const updated =
      source.slice(0, start) +
      JSON.stringify(nextVersion) +
      source.slice(start + match[2].length);
    if (JSON.stringify(JSON.parse(updated)) === expected) return updated;
  }
  throw new Error("Could not update only the top-level package version.");
}

function releaseMarker(version) {
  return `<!-- codex-security-patch-release:${version} -->`;
}

function reviewMarker(sha) {
  return `<!-- codex-security-release-review:${sha} -->`;
}

export function renderReleasePullRequest(
  template,
  { repository, currentVersion, nextVersion, baseSha, ciRunId },
) {
  const title = `release: bump Codex Security to ${nextVersion}`;
  const url = `https://github.com/${repository}`;
  const contents = new Map([
    [
      "Summary",
      `Prepare the \`${packageName}\` patch release \`${nextVersion}\`.\n\n${releaseMarker(nextVersion)}`,
    ],
    [
      "Changes",
      `- Update \`${packageJsonPath}\` from \`${currentVersion}\` to \`${nextVersion}\`.\n- Review the [changes since the current release](${url}/compare/npm-v${currentVersion}...${baseSha}).`,
    ],
    [
      "Testing",
      `- Stable-version and patch-increase checks passed.\n- [\`node-ci\` passed for the base commit](${url}/actions/runs/${ciRunId}).\n- The release PR's CI and Codex review must finish before merge.`,
    ],
    [
      "Risk and rollout",
      "- This PR changes only the package version.\n- After merge, the existing release workflows create the npm tag, require protected npm approval, and publish the verified package and GitHub release.",
    ],
  ]);
  const seen = new Set();
  const body = template
    .split(/(?=^## )/mu)
    .map((section) => {
      const heading = /^## ([^\r\n]+)/u.exec(section)?.[1];
      if (contents.has(heading)) {
        if (seen.has(heading))
          throw new Error(`Duplicate PR section: ${heading}`);
        seen.add(heading);
        return `## ${heading}\n\n${contents.get(heading)}\n\n`;
      }
      if (heading === "Public disclosure review") {
        seen.add(heading);
        return section
          .replace(/<!--[\s\S]*?-->\s*/gu, "")
          .replace(/- \[[xX]\]/gu, "- [ ]");
      }
      return section;
    })
    .join("")
    .trim();
  for (const heading of [...contents.keys(), "Public disclosure review"]) {
    if (!seen.has(heading)) throw new Error(`Missing PR section: ${heading}`);
  }
  return { title, body: `${body}\n` };
}

function query(path, parameters) {
  return `${path}?${new URLSearchParams(parameters)}`;
}

async function optional(github, path) {
  try {
    return await github("GET", path);
  } catch (error) {
    if (error.status === 404) return null;
    throw error;
  }
}

async function list(github, path, parameters = {}) {
  const values = [];
  for (let page = 1; ; page += 1) {
    const batch = await github(
      "GET",
      query(path, { ...parameters, per_page: "100", page: String(page) }),
    );
    values.push(...batch);
    if (batch.length < 100) return values;
  }
}

async function manifestAt(github, root, ref) {
  const file = await optional(
    github,
    query(`${root}/contents/${packageJsonPath}`, { ref }),
  );
  if (file === null) return null;
  if (file.encoding !== "base64") {
    throw new Error("GitHub did not return the package manifest as base64.");
  }
  return Buffer.from(file.content, "base64").toString("utf8");
}

function stableManifestVersion(source) {
  if (source === null) return null;
  try {
    return releaseVersion(JSON.parse(source));
  } catch {
    return null;
  }
}

async function tagCommit(github, root, tag) {
  const ref = await optional(github, `${root}/git/ref/tags/${tag}`);
  if (ref === null) return null;
  let object = ref.object;
  while (object.type === "tag") {
    object = (await github("GET", `${root}/git/tags/${object.sha}`)).object;
  }
  if (object.type !== "commit") {
    throw new Error(`Release tag ${tag} does not identify a commit.`);
  }
  return object.sha;
}

async function openVersionPullRequests(
  github,
  root,
  repository,
  currentVersion,
  readManifest,
) {
  const pulls = await list(github, `${root}/pulls`, {
    state: "open",
    base: "main",
  });
  const releases = [];
  for (const pull of pulls) {
    if (pull.head.repo?.full_name !== repository) continue;
    const version = stableManifestVersion(await readManifest(pull.head.sha));
    if (
      version !== null &&
      compareReleaseVersions(version, currentVersion) > 0
    ) {
      releases.push(pull);
    }
  }
  return releases;
}

async function ensureReviewRequest(github, root, pull, expectedSha) {
  const current = await github("GET", `${root}/pulls/${pull.number}`);
  if (current.state !== "open" || current.head.sha !== expectedSha) return;
  if (!current.labels.some((label) => label.name === "skip-release-notes")) {
    await github("POST", `${root}/issues/${pull.number}/labels`, {
      labels: ["skip-release-notes"],
    });
  }

  const marker = reviewMarker(expectedSha);
  const comments = await list(github, `${root}/issues/${pull.number}/comments`);
  if (
    comments.some(
      (comment) =>
        comment.body.includes(marker) &&
        (comment.user.type === "Bot" || comment.user.id === current.user.id),
    )
  ) {
    return;
  }
  const latest = await github("GET", `${root}/pulls/${pull.number}`);
  if (latest.state !== "open" || latest.head.sha !== expectedSha) return;
  await github("POST", `${root}/issues/${pull.number}/comments`, {
    body: `@codex review\n\nPlease review commit \`${expectedSha}\`.\n\n${marker}`,
  });
}

export async function reconcilePatchRelease({
  repository,
  github,
  git,
  template,
  dryRun = false,
  log = console.log,
}) {
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(repository)) {
    throw new Error("GITHUB_REPOSITORY must identify one GitHub repository.");
  }
  const root = `repos/${repository}`;
  const manifests = new Map();
  const readManifest = (sha) => {
    if (!manifests.has(sha)) {
      manifests.set(sha, manifestAt(github, root, sha));
    }
    return manifests.get(sha);
  };
  const skip = (reason) => {
    log(reason);
    return { status: "skipped", reason };
  };
  const mainHead = async () =>
    (await github("GET", `${root}/git/ref/heads/main`)).object.sha;
  const mainSha = git(["rev-parse", "HEAD"]).trim();
  if ((await mainHead()) !== mainSha) {
    return skip("The checkout is not the current main commit.");
  }

  const runs = await github(
    "GET",
    query(`${root}/actions/workflows/node-ci.yml/runs`, {
      branch: "main",
      event: "push",
      status: "success",
      head_sha: mainSha,
      per_page: "1",
    }),
  );
  const ciRun = runs.workflow_runs.find(
    (run) =>
      run.head_sha === mainSha &&
      run.event === "push" &&
      run.conclusion === "success",
  );
  if (!ciRun) return skip("The current main commit has not passed node-ci.");

  const source = git(["show", `${mainSha}:${packageJsonPath}`]);
  const currentVersion = releaseVersion(JSON.parse(source));
  const currentTag = `npm-v${currentVersion}`;
  const releasedSha = await tagCommit(github, root, currentTag);
  const published = await optional(
    github,
    `${root}/releases/tags/${currentTag}`,
  );
  if (
    releasedSha === null ||
    published === null ||
    published.draft ||
    published.prerelease ||
    !published.published_at
  ) {
    return skip(`Waiting for ${currentTag} to finish publishing.`);
  }
  if (
    git(["merge-base", releasedSha, mainSha]).trim() !== releasedSha ||
    releaseVersion(
      JSON.parse(git(["show", `${releasedSha}:${packageJsonPath}`])),
    ) !== currentVersion
  ) {
    throw new Error(
      `Release tag ${currentTag} does not match main's version history.`,
    );
  }
  const releases = await list(github, `${root}/releases`);
  publishedReleaseMode(
    currentVersion,
    releases
      .filter(
        (release) =>
          !release.draft &&
          !release.prerelease &&
          release.tag_name.startsWith("npm-v"),
      )
      .map((release) => release.tag_name.slice("npm-v".length)),
  );

  const nextVersion = nextPatchVersion(currentVersion);
  const branch = `${managedBranchPrefix}${nextVersion}`;
  const isExpectedBranch = async (headSha) => {
    const comparison = await github(
      "GET",
      `${root}/compare/${mainSha}...${headSha}`,
    );
    if (
      comparison.files?.length !== 1 ||
      comparison.files[0].filename !== packageJsonPath ||
      comparison.files[0].status !== "modified"
    ) {
      return false;
    }
    const base = await readManifest(comparison.merge_base_commit.sha);
    return (
      stableManifestVersion(base) === currentVersion &&
      replacePackageVersion(base, nextVersion) === (await readManifest(headSha))
    );
  };
  const existing = await openVersionPullRequests(
    github,
    root,
    repository,
    currentVersion,
    readManifest,
  );
  if (existing.length > 0) {
    const pull =
      existing.find((item) => item.head.ref !== branch) ?? existing[0];
    if (
      existing.length === 1 &&
      pull.head.ref === branch &&
      pull.body?.includes(releaseMarker(nextVersion)) &&
      !dryRun &&
      (await isExpectedBranch(pull.head.sha))
    ) {
      await ensureReviewRequest(github, root, pull, pull.head.sha);
    }
    log(`Preserving existing release PR #${pull.number}.`);
    return {
      status: "existing",
      version: nextVersion,
      pullRequest: pull.number,
    };
  }

  const changedPaths = git([
    "diff",
    "--name-only",
    "-z",
    "--no-renames",
    releasedSha,
    mainSha,
    "--",
  ]).split("\0");
  if (!changedPaths.some(isPackageReleasePath)) {
    return skip("No package-affecting changes have landed since the release.");
  }
  if ((await tagCommit(github, root, `npm-v${nextVersion}`)) !== null) {
    throw new Error(`The next release tag npm-v${nextVersion} already exists.`);
  }

  const managedPulls = await list(github, `${root}/pulls`, {
    state: "all",
    base: "main",
    head: `${repository.split("/")[0]}:${branch}`,
  });
  const closed = managedPulls.find(
    (pull) => pull.state === "closed" && !pull.merged_at,
  );
  if (closed) {
    return skip(
      `Release PR #${closed.number} was closed; it will not be recreated.`,
    );
  }

  const rendered = renderReleasePullRequest(template, {
    repository,
    currentVersion,
    nextVersion,
    baseSha: mainSha,
    ciRunId: ciRun.id,
  });
  const updatedManifest = replacePackageVersion(source, nextVersion);
  let ref = await optional(github, `${root}/git/ref/heads/${branch}`);
  if (dryRun) {
    if (ref !== null && !(await isExpectedBranch(ref.object.sha))) {
      throw new Error(
        `Managed branch ${branch} contains changes other than the expected version bump.`,
      );
    }
    log(`Would open ${rendered.title} from ${ref?.object.sha ?? mainSha}.`);
    return {
      status: "would-create",
      version: nextVersion,
      baseSha: mainSha,
      ...(ref === null ? {} : { headSha: ref.object.sha }),
    };
  }

  if ((await mainHead()) !== mainSha)
    return skip("Main advanced; retry on its next successful CI run.");
  if (ref === null) {
    const tree = await github("POST", `${root}/git/trees`, {
      base_tree: git(["rev-parse", `${mainSha}^{tree}`]).trim(),
      tree: [
        {
          path: packageJsonPath,
          mode: "100644",
          type: "blob",
          content: updatedManifest,
        },
      ],
    });
    const commit = await github("POST", `${root}/git/commits`, {
      message: rendered.title,
      tree: tree.sha,
      parents: [mainSha],
    });
    try {
      ref = await github("POST", `${root}/git/refs`, {
        ref: `refs/heads/${branch}`,
        sha: commit.sha,
      });
    } catch (error) {
      ref = await optional(github, `${root}/git/ref/heads/${branch}`);
      if (ref === null) throw error;
    }
  }
  const branchSha = (await github("GET", `${root}/git/ref/heads/${branch}`))
    .object.sha;
  if (!(await isExpectedBranch(branchSha))) {
    throw new Error(
      `Managed branch ${branch} contains changes other than the expected version bump.`,
    );
  }
  if ((await mainHead()) !== mainSha) {
    return skip(
      "Main advanced after branch creation; the next run can reuse the branch.",
    );
  }
  const finalPulls = await openVersionPullRequests(
    github,
    root,
    repository,
    currentVersion,
    readManifest,
  );
  const competing = finalPulls.find((item) => item.head.ref !== branch);
  if (competing) {
    return skip(
      `Release PR #${competing.number} was opened while creating the branch.`,
    );
  }

  let pull = finalPulls.find((item) => item.head.ref === branch);
  let created = false;
  try {
    if (pull === undefined) {
      pull = await github("POST", `${root}/pulls`, {
        title: rendered.title,
        body: rendered.body,
        head: branch,
        base: "main",
        draft: false,
      });
      created = true;
    }
  } catch (error) {
    const recovered = await list(github, `${root}/pulls`, {
      state: "open",
      base: "main",
      head: `${repository.split("/")[0]}:${branch}`,
    });
    if (recovered.length !== 1) throw error;
    pull = recovered[0];
  }
  if (pull.body?.includes(releaseMarker(nextVersion))) {
    await ensureReviewRequest(github, root, pull, branchSha);
  }
  log(
    `${created ? "Opened" : "Preserving"} release PR #${pull.number} for ${nextVersion}.`,
  );
  return {
    status: created ? "created" : "existing",
    version: nextVersion,
    pullRequest: pull.number,
    headSha: branchSha,
  };
}

function githubClient(token) {
  return async (method, path, body) => {
    const response = await fetch(`https://api.github.com/${path}`, {
      method,
      redirect: "error",
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${token}`,
        "X-GitHub-Api-Version": "2022-11-28",
        ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const text = await response.text();
    const data = text === "" ? null : JSON.parse(text);
    if (!response.ok) {
      const error = new Error(
        `GitHub ${method} ${path} failed (${response.status}): ${data?.message ?? response.statusText}`,
      );
      error.status = response.status;
      throw error;
    }
    return data;
  };
}

async function main() {
  if (process.argv.slice(2).some((argument) => argument !== "--dry-run")) {
    throw new Error("Usage: node scripts/patch-release-pr.mjs [--dry-run]");
  }
  const root = fileURLToPath(new URL("../../../", import.meta.url));
  const token =
    process.env.GH_TOKEN ||
    process.env.GITHUB_TOKEN ||
    execFileSync("gh", ["auth", "token", "--hostname", "github.com"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  await reconcilePatchRelease({
    repository: process.env.GITHUB_REPOSITORY,
    github: githubClient(token),
    git: (args) => execFileSync("git", args, { cwd: root, encoding: "utf8" }),
    template: readFileSync(
      new URL("../../../.github/PULL_REQUEST_TEMPLATE.md", import.meta.url),
      "utf8",
    ),
    dryRun: process.argv.includes("--dry-run"),
  });
}

if (
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}

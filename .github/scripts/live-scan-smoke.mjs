import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  cp,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve, sep } from "node:path";

const PACKAGE = "@openai/codex-security";
const ARTIFACTS =
  "scan-manifest.json findings.json coverage.json report.md".split(" ");
const TOKEN_URL = "https://auth.openai.com/oauth/token";
const SENSITIVE =
  /^(?:ACTIONS_|GITHUB_|GH_|OPENAI_|AZURE_|AWS_|ARM_|GOOGLE_|GCLOUD_|.*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY).*)/iu;

function options(args, env = process.env) {
  if (args.length === 1 && args[0] === "--self-test") return { selfTest: true };
  const values = {
    archive: env.CODEX_SECURITY_SMOKE_PACKAGE,
    model: env.CODEX_SECURITY_SMOKE_MODEL || "gpt-5.6-luna",
    effort: env.CODEX_SECURITY_SMOKE_EFFORT || "low",
    maxCostUsd: Number(env.CODEX_SECURITY_SMOKE_MAX_COST || "0.25"),
    timeoutSeconds: Number(env.CODEX_SECURITY_SMOKE_TIMEOUT_SECONDS || "240"),
    artifactsDir: env.CODEX_SECURITY_SMOKE_ARTIFACT_DIR,
    expectedGitHead: env.CODEX_SECURITY_EXPECTED_GIT_HEAD,
  };
  const names = {
    "--package": "archive",
    "--model": "model",
    "--effort": "effort",
    "--max-cost": "maxCostUsd",
    "--timeout-seconds": "timeoutSeconds",
    "--artifacts-dir": "artifactsDir",
  };
  for (let index = 0; index < args.length; index += 2) {
    const key = names[args[index]];
    if (!key || !args[index + 1])
      throw new Error(`Invalid smoke argument: ${args[index]}.`);
    values[key] =
      key === "maxCostUsd" || key === "timeoutSeconds"
        ? Number(args[index + 1])
        : args[index + 1];
  }
  if (!values.archive)
    throw new Error(
      "Provide the exact candidate with --package <npm-tarball>.",
    );
  if (!/^[a-z0-9][a-z0-9._/-]*$/iu.test(values.model))
    throw new Error("Invalid model identifier.");
  if (!["minimal", "low", "medium", "high", "xhigh"].includes(values.effort))
    throw new Error("Invalid reasoning effort.");
  for (const key of ["maxCostUsd", "timeoutSeconds"]) {
    if (!Number.isFinite(values[key]) || values[key] <= 0)
      throw new Error(`${key} must be positive.`);
  }
  if (
    values.expectedGitHead &&
    !/^[0-9a-f]{40}$/u.test(values.expectedGitHead)
  ) {
    throw new Error(
      "CODEX_SECURITY_EXPECTED_GIT_HEAD must be a full commit SHA.",
    );
  }
  return values;
}

function cleanEnvironment(env, additions = {}) {
  return {
    ...Object.fromEntries(
      Object.entries(env).filter(
        ([key, value]) => value !== undefined && !SENSITIVE.test(key),
      ),
    ),
    ...additions,
  };
}

function command(executable, args, { cwd, env, timeout = 120_000 }) {
  const result = spawnSync(executable, args, {
    cwd,
    env,
    timeout,
    encoding: "utf8",
    stdio: "pipe",
    maxBuffer: 8 * 1024 * 1024,
    windowsHide: true,
  });
  if (result.error)
    throw new Error(`${basename(executable)} failed: ${result.error.message}`);
  if (result.status !== 0) {
    const detail = (result.stderr || result.stdout || "").trim().slice(-4000);
    throw new Error(
      `${basename(executable)} exited ${result.status}: ${detail}`,
    );
  }
  return result.stdout;
}

async function npm(env) {
  const node = dirname(process.execPath);
  for (const [index, item] of [
    env.npm_execpath,
    "../lib",
    ".",
    "..",
  ].entries()) {
    if (typeof item !== "string") continue;
    const candidate = index
      ? resolve(node, item, "node_modules/npm/bin/npm-cli.js")
      : item;
    if (basename(candidate) !== "npm-cli.js") continue;
    if ((await stat(candidate).catch(() => null))?.isFile())
      return { executable: process.execPath, args: [candidate] };
  }
  if (process.platform === "win32")
    throw new Error("Node.js does not include npm-cli.js.");
  return { executable: "npm", args: [] };
}

async function install(archive, consumer, settings) {
  await writeFile(
    join(consumer, "package.json"),
    JSON.stringify({ name: "live-smoke", private: true }),
  );
  const runner = await npm(process.env);
  const safe = cleanEnvironment(process.env, {
    npm_config_audit: "false",
    npm_config_fund: "false",
  });
  const installArgs =
    "install --prefer-offline --include=optional --ignore-scripts --no-audit --no-fund".split(
      " ",
    );
  command(runner.executable, [...runner.args, ...installArgs, archive], {
    cwd: consumer,
    env: safe,
    timeout: 180_000,
  });

  const root = join(consumer, "node_modules", "@openai", "codex-security");
  const manifest = JSON.parse(
    await readFile(join(root, "package.json"), "utf8"),
  );
  assert.equal(manifest.name, PACKAGE, "Unexpected candidate package.");
  if (settings.expectedGitHead)
    assert.equal(
      manifest.gitHead,
      settings.expectedGitHead,
      "Wrong candidate commit.",
    );
  const plugin = JSON.parse(
    await readFile(
      join(root, "_bundled_plugin", ".codex-plugin", "plugin.json"),
      "utf8",
    ),
  );
  assert.equal(plugin.name, "codex-security", "Unexpected candidate plugin.");
  assert.equal(typeof plugin.version, "string", "Missing plugin version.");
  const relative = manifest.bin?.["codex-security"];
  assert.equal(typeof relative, "string", "Candidate CLI launcher is missing.");
  const launcher = resolve(root, relative);
  assert.ok(
    launcher.startsWith(`${root}${sep}`),
    "Candidate launcher escapes.",
  );
  assert.ok((await stat(launcher)).isFile(), "Missing candidate launcher.");
  assert.equal(
    command(process.execPath, [launcher, "--version"], {
      cwd: consumer,
      env: safe,
    }).trim(),
    manifest.version,
  );
  return { launcher, manifest, plugin };
}

async function fixture(directory) {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await writeFile(
    join(directory, "server.js"),
    [
      'import { exec } from "node:child_process";',
      'import { createServer } from "node:http";',
      "createServer((request, response) => {",
      '  const command = new URL(request.url, "http://localhost").searchParams.get("command");',
      "  exec(`printf ${command}`, (_error, output) => response.end(output));",
      "}).listen(3000);\n",
    ].join("\n"),
  );
  const git = cleanEnvironment(process.env, {
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: process.platform === "win32" ? "NUL" : "/dev/null",
    GIT_TERMINAL_PROMPT: "0",
    GIT_AUTHOR_NAME: "Codex Security CI",
    GIT_AUTHOR_EMAIL: "codex-security-ci@users.noreply.github.com",
    GIT_COMMITTER_NAME: "Codex Security CI",
    GIT_COMMITTER_EMAIL: "codex-security-ci@users.noreply.github.com",
  });
  command("git", ["init", "--quiet"], { cwd: directory, env: git });
  command("git", ["add", "--", "server.js"], { cwd: directory, env: git });
  command("git", ["-c", "commit.gpgsign=false", "commit", "-qm", "fixture"], {
    cwd: directory,
    env: git,
  });
}

async function credential(env, request = fetch, endpoint = TOKEN_URL) {
  const provider = env.OPENAI_IDENTITY_PROVIDER_ID?.trim();
  const account = env.OPENAI_SERVICE_ACCOUNT_ID?.trim();
  if (!provider && !account) {
    const value = env.OPENAI_API_KEY?.trim();
    if (!value)
      throw new Error(
        "Configure workload identity federation or protected OPENAI_API_KEY.",
      );
    return { value, method: "protected_environment", expires: null };
  }
  const requestUrl = env.ACTIONS_ID_TOKEN_REQUEST_URL?.trim();
  const requestToken = env.ACTIONS_ID_TOKEN_REQUEST_TOKEN?.trim();
  if (!provider || !account || !requestUrl || !requestToken) {
    throw new Error(
      "Workload identity federation requires provider, service account, and id-token: write.",
    );
  }
  const url = new URL(requestUrl);
  url.searchParams.set(
    "audience",
    env.OPENAI_WIF_AUDIENCE || "https://api.openai.com/v1",
  );
  const github = await request(url, {
    headers: { Authorization: `bearer ${requestToken}` },
  });
  if (!github.ok)
    throw new Error(`GitHub identity request failed: ${github.status}.`);
  const identity = (await github.json()).value;
  if (!identity) throw new Error("GitHub identity response omitted its token.");
  const response = await request(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      subject_token_type: "urn:ietf:params:oauth:token-type:jwt",
      subject_token: identity,
      identity_provider_id: provider,
      service_account_id: account,
    }),
  });
  if (!response.ok)
    throw new Error(`OpenAI token exchange failed: ${response.status}.`);
  const exchanged = await response.json();
  if (typeof exchanged.access_token !== "string" || !exchanged.access_token) {
    throw new Error("OpenAI token exchange omitted its bearer.");
  }
  if (env.GITHUB_ACTIONS === "true")
    process.stdout.write(`::add-mask::${exchanged.access_token}\n`);
  return {
    value: exchanged.access_token,
    method: "workload_identity_federation",
    expires: exchanged.expires_in ?? null,
  };
}

function scan(installed, repository, output, state, settings, authentication) {
  const allowed =
    authentication.expires === null
      ? settings.timeoutSeconds
      : Math.min(
          settings.timeoutSeconds,
          Math.floor(authentication.expires) - 15,
        );
  if (!Number.isFinite(allowed) || allowed < 30)
    throw new Error("OpenAI bearer expires too soon to complete a scan.");
  const env = cleanEnvironment(process.env, {
    OPENAI_API_KEY: authentication.value,
    CODEX_SECURITY_STATE_DIR: state,
    CI: "true",
    NO_COLOR: "1",
  });
  const arguments_ = [
    installed.launcher,
    "scan",
    repository,
    "--output-dir",
    output,
  ];
  arguments_.push("--json", "--headless", "--auth", "api-key");
  arguments_.push("--model", settings.model, "--effort", settings.effort);
  arguments_.push("--max-cost", String(settings.maxCostUsd));
  arguments_.push(
    "--codex",
    "features.multi_agent_v2.max_concurrent_threads_per_session=1",
  );
  return JSON.parse(
    command(process.execPath, arguments_, {
      cwd: repository,
      env,
      timeout: allowed * 1000,
    }),
  );
}

async function verify(result, output, installed, model) {
  const scanResult = result.manifest?.scan;
  assert.equal(result.manifest?.documentType, "codex-security.scan-manifest");
  assert.equal(scanResult?.status, "completed", "Scan did not complete.");
  assert.equal(scanResult?.producer?.name, "codex-security-plugin");
  assert.equal(scanResult?.producer?.version, installed.plugin.version);
  assert.equal(
    result.coverage?.completeness,
    "complete",
    "Incomplete scan coverage.",
  );
  assert.equal(result.coverage?.scanId, scanResult.id);
  assert.equal(result.findings?.scanId, scanResult.id);
  assert.ok(Array.isArray(result.findings?.findings));
  assert.equal(result.turn?.status, "completed");
  assert.equal(result.turn?.model, model);
  assert.equal(await realpath(result.scanDir), await realpath(output));
  for (const name of ARTIFACTS) {
    const metadata = await stat(join(output, name));
    assert.ok(metadata.isFile() && metadata.size > 0, `Invalid ${name}.`);
  }
  for (const name of ARTIFACTS.slice(0, 3)) {
    const disk = JSON.parse(await readFile(join(output, name), "utf8"));
    assert.equal(disk.scan?.id ?? disk.scanId, scanResult.id);
    if (name === "coverage.json") assert.equal(disk.completeness, "complete");
  }
}

async function save(output, destination, summary) {
  if (!destination) return;
  await mkdir(destination, { recursive: true, mode: 0o700 });
  for (const name of ARTIFACTS) {
    await cp(join(output, name), join(destination, name)).catch((error) => {
      if (error.code !== "ENOENT") throw error;
    });
  }
  await writeFile(
    join(destination, "smoke-summary.json"),
    `${JSON.stringify(summary, null, 2)}\n`,
  );
}

async function selfTest() {
  const secrets = {
    PATH: "/safe/bin",
    GITHUB_TOKEN: "github-secret",
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: "oidc-secret",
    OPENAI_API_KEY: "parent-secret",
    RANDOM_SERVICE_TOKEN: "other-secret",
  };
  const safe = cleanEnvironment(secrets, { OPENAI_API_KEY: "child-only" });
  assert.deepEqual(safe, { PATH: "/safe/bin", OPENAI_API_KEY: "child-only" });
  assert.throws(() => options([]), /--package/u);
  assert.throws(
    () => options(["--package", "x", "--max-cost", "0"]),
    /positive/u,
  );
  assert.equal(
    (await credential({ OPENAI_API_KEY: "fallback" })).method,
    "protected_environment",
  );
  await assert.rejects(
    credential({ OPENAI_IDENTITY_PROVIDER_ID: "partial" }),
    /id-token/u,
  );

  const requests = [];
  const fakeFetch = async (url, init) => {
    requests.push({ url: String(url), init });
    const result =
      requests.length === 1
        ? { value: "github-jwt" }
        : { access_token: "openai-bearer", expires_in: 240 };
    return { ok: true, json: async () => result };
  };
  const result = await credential(
    {
      OPENAI_IDENTITY_PROVIDER_ID: "provider",
      OPENAI_SERVICE_ACCOUNT_ID: "account",
      OPENAI_WIF_AUDIENCE: "https://api.openai.com/v1",
      ACTIONS_ID_TOKEN_REQUEST_URL:
        "https://oidc.example.test/token?existing=yes",
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: "oidc-capability",
    },
    fakeFetch,
  );
  assert.equal(result.value, "openai-bearer");
  assert.equal(result.method, "workload_identity_federation");
  assert.equal(
    new URL(requests[0].url).searchParams.get("audience"),
    "https://api.openai.com/v1",
  );
  assert.equal(
    requests[0].init.headers.Authorization,
    "bearer oidc-capability",
  );
  assert.equal(JSON.parse(requests[1].init.body).subject_token, "github-jwt");
  process.stdout.write("Live scan smoke helper self-tests passed.\n");
}

async function main() {
  const settings = options(process.argv.slice(2));
  if (settings.selfTest) return await selfTest();
  const archive = await realpath(resolve(settings.archive));
  assert.ok(
    archive.endsWith(".tgz") && (await stat(archive)).isFile(),
    "Candidate must be an npm tarball.",
  );

  const root = await mkdtemp(join(tmpdir(), "codex-security-live-smoke-"));
  const consumer = join(root, "consumer");
  const repository = join(root, "fixture");
  const output = join(root, "results");
  const state = join(root, "state");
  let authentication;
  try {
    await mkdir(consumer, { recursive: true, mode: 0o700 });
    await mkdir(state, { recursive: true, mode: 0o700 });
    const installed = await install(archive, consumer, settings);
    await fixture(repository);
    // GitHub's identity token is short-lived; finish package installation before minting.
    authentication = await credential(process.env);
    const startedAt = Date.now();
    const result = scan(
      installed,
      repository,
      output,
      state,
      settings,
      authentication,
    );
    await verify(result, output, installed, settings.model);
    const summary = {
      status: "completed",
      packageName: installed.manifest.name,
      packageVersion: installed.manifest.version,
      packageGitHead: installed.manifest.gitHead ?? null,
      pluginVersion: installed.plugin.version,
      scanId: result.manifest.scan.id,
      model: settings.model,
      effort: settings.effort,
      maxCostUsd: settings.maxCostUsd,
      actualCostUsd: result.cost?.estimatedUsd ?? null,
      inputTokens: result.cost?.inputTokens ?? null,
      outputTokens: result.cost?.outputTokens ?? null,
      authentication: authentication.method,
      coverage: result.coverage.completeness,
      findings: result.findings.findings.length,
      durationMs: Date.now() - startedAt,
      platform: process.platform,
      artifacts: ARTIFACTS,
    };
    await save(output, settings.artifactsDir, summary);
    process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
  } catch (error) {
    let message = error.message ?? String(error);
    for (const value of [
      authentication?.value,
      process.env.OPENAI_API_KEY,
      process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN,
    ]) {
      if (value?.length >= 8) message = message.split(value).join("[REDACTED]");
    }
    message = message.replace(/Bearer\s+\S+/giu, "Bearer [REDACTED]");
    const failure = { status: "failed", error: message, model: settings.model };
    await save(output, settings.artifactsDir, failure).catch(() => {});
    throw new Error(message);
  } finally {
    await rm(root, { recursive: true, force: true, maxRetries: 10 });
  }
}

try {
  await main();
} catch (error) {
  process.stderr.write(`codex-security live smoke: ${error.message}\n`);
  process.exitCode = 1;
}

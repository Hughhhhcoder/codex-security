import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath, pathToFileURL } from "node:url";
import { packageSmokeTimeouts } from "./package-smoke-timeouts.mjs";

const PACKAGE_SMOKE_TIMEOUT_MS = packageSmokeTimeouts().commandTimeoutMs;
const packageRoot = fileURLToPath(new URL("../", import.meta.url));
const packageManifest = JSON.parse(
  await readFile(new URL("../package.json", import.meta.url), "utf8"),
);
const pluginContract = JSON.parse(
  await readFile(new URL("../plugin-files.json", import.meta.url), "utf8"),
);

async function resolveArchive() {
  const args = process.argv.slice(2);
  if (args[0] === "--") args.shift();

  if (args.length > 1) {
    throw new Error("Usage: node scripts/smoke-package.mjs [npm-tarball]");
  }

  if (args.length === 1) return resolve(args[0]);

  const archiveDirectory = resolve(packageRoot, "../../dist");
  let entries;
  try {
    entries = await readdir(archiveDirectory, { withFileTypes: true });
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    throw new Error(
      "No packed npm tarball found. Run pnpm pack --pack-destination ../../dist first.",
      { cause: error },
    );
  }

  const archives = entries.filter(
    (entry) => entry.isFile() && entry.name.endsWith(".tgz"),
  );
  if (archives.length !== 1) {
    throw new Error(
      `Expected exactly one packed npm tarball in ${archiveDirectory}; found ${archives.length}.`,
    );
  }

  return join(archiveDirectory, archives[0].name);
}

function run(
  command,
  args,
  { cwd, env, capture = false, windowsVerbatimArguments = false } = {},
) {
  const result = spawnSync(command, args, {
    cwd,
    env,
    encoding: "utf8",
    stdio: capture ? "pipe" : "inherit",
    timeout: PACKAGE_SMOKE_TIMEOUT_MS,
    killSignal: "SIGKILL",
    windowsVerbatimArguments,
    windowsHide: true,
  });

  if (result.error?.code === "ETIMEDOUT") {
    throw new Error(
      `Package smoke command timed out after ${PACKAGE_SMOKE_TIMEOUT_MS} ms: ${command}.`,
      { cause: result.error },
    );
  }
  if (result.error !== undefined) {
    throw new Error(`Failed to run ${command}.`, { cause: result.error });
  }
  if (result.status !== 0) {
    const details = capture ? `\n${result.stderr.trim()}` : "";
    throw new Error(
      `${command} exited with status ${result.status}.${details}`,
    );
  }

  return result.stdout ?? "";
}

async function resolveNpm() {
  const nodeDirectory = dirname(process.execPath);
  const candidates = [
    process.env.npm_execpath,
    resolve(nodeDirectory, "../lib/node_modules/npm/bin/npm-cli.js"),
    resolve(nodeDirectory, "node_modules/npm/bin/npm-cli.js"),
    resolve(nodeDirectory, "../node_modules/npm/bin/npm-cli.js"),
  ];

  for (const candidate of new Set(candidates)) {
    if (
      typeof candidate !== "string" ||
      basename(candidate).toLowerCase() !== "npm-cli.js"
    ) {
      continue;
    }

    try {
      if ((await stat(candidate)).isFile()) {
        return { command: process.execPath, args: [candidate] };
      }
    } catch (error) {
      if (error.code !== "ENOENT" && error.code !== "ENOTDIR") throw error;
    }
  }

  if (process.platform === "win32") {
    throw new Error("The Node.js installation does not include the npm CLI.");
  }

  return { command: "npm", args: [] };
}

async function pluginFiles(directory) {
  const files = [];
  const directories = [directory];

  while (directories.length > 0) {
    const current = directories.pop();
    for (const entry of await readdir(current, { withFileTypes: true })) {
      const path = join(current, entry.name);
      if (entry.isDirectory()) {
        directories.push(path);
      } else if (entry.isFile()) {
        files.push(relative(directory, path).split(sep).join("/"));
      } else {
        throw new Error(
          `Installed plugin contains a non-regular entry: ${path}.`,
        );
      }
    }
  }

  return files.sort();
}

async function smokeInstalledMcp(installedRoot, consumer) {
  const privateRoot = await realpath(consumer);
  const fixture = join(privateRoot, "mcp-fixture");
  const state = join(privateRoot, "mcp-state");
  const scans = join(privateRoot, "mcp-scans");
  const home = join(privateRoot, "mcp-home");
  await Promise.all(
    [fixture, state, scans, home].map((directory) =>
      mkdir(directory, { mode: 0o700 }),
    ),
  );
  await writeFile(join(fixture, "fixture.js"), "export const smoke = true;\n");

  const environment = {
    ...Object.fromEntries(
      Object.entries(process.env).filter(
        ([name]) =>
          !/^(?:OPENAI|ANTHROPIC|AWS|AZURE|GOOGLE|GCLOUD|FIREWORKS|OPENROUTER|GITHUB|GH|ACTIONS)_/iu.test(
            name,
          ) &&
          !/(?:^|_)(?:API_?KEY|ACCESS_?KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIALS?)(?:_|$)/iu.test(
            name,
          ),
      ),
    ),
    HOME: home,
    USERPROFILE: home,
    CODEX_HOME: home,
    CODEX_SQLITE_HOME: home,
    CODEX_SECURITY_SCAN_ROOT: scans,
    CODEX_SECURITY_STATE_DIR: state,
    PYTHONDONTWRITEBYTECODE: "1",
  };
  const child = spawn(
    process.execPath,
    [join(installedRoot, "_bundled_plugin", "mcp", "server.mjs"), "--stdio"],
    {
      cwd: consumer,
      env: environment,
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    },
  );
  const messages = createInterface({ input: child.stdout })[
    Symbol.asyncIterator
  ]();
  const closed = new Promise((resolve) => child.once("close", resolve));
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });
  child.on("error", (error) => {
    stderr += error.message;
  });
  let nextId = 0;
  let timedOut = false;
  const timeout = setTimeout(() => {
    timedOut = true;
    child.kill();
  }, 30_000);

  async function request(method, params) {
    const id = ++nextId;
    child.stdin.write(
      `${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`,
    );
    while (true) {
      const message = await messages.next();
      if (message.done) {
        const reason = timedOut ? "timed out" : "exited";
        throw new Error(`Installed MCP ${reason} before ${method}: ${stderr}`);
      }
      const response = JSON.parse(message.value);
      if (response.id !== id) continue;
      if (response.error !== undefined || response.result?.isError === true) {
        throw new Error(
          `Installed MCP ${method} failed: ${JSON.stringify(response.error ?? response.result)}`,
        );
      }
      return response.result;
    }
  }

  try {
    await request("initialize", {
      protocolVersion: "2025-11-25",
      capabilities: {},
      clientInfo: { name: "codex-security-package-smoke", version: "1.0.0" },
    });
    child.stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        method: "notifications/initialized",
        params: {},
      })}\n`,
    );
    const toolNames = new Set(
      (await request("tools/list", {})).tools.map((tool) => tool.name),
    );
    const requiredTools = [
      "start_codex_security_standard_scan",
      "record_codex_security_scan_draft",
      "complete_codex_security_scan",
      "get_codex_security_completed_scan",
    ];
    for (const name of requiredTools) {
      assert.equal(
        toolNames.has(name),
        true,
        `Installed MCP is missing ${name}.`,
      );
    }

    async function call(name, arguments_) {
      return (
        await request("tools/call", {
          name,
          arguments: arguments_,
          _meta: { "openai/threadId": "codex-security-package-smoke" },
        })
      ).structuredContent;
    }

    const started = await call("start_codex_security_standard_scan", {
      targetPath: fixture,
    });
    const { scanId, handoffClaimToken, scanDir } = started;
    assert.equal(typeof scanId, "string");
    assert.equal(typeof handoffClaimToken, "string");
    await call("record_codex_security_scan_draft", {
      scanId,
      handoffClaimToken,
      findings: [],
      coverage: {
        completeness: "complete",
        surfaces: [{ label: "Fixture", disposition: "rejected" }],
        explicitExclusions: [],
        deferred: [],
      },
    });
    await call("complete_codex_security_scan", { scanId, handoffClaimToken });
    const completed = await call("get_codex_security_completed_scan", {
      scanId,
      handoffClaimToken,
    });
    const pluginManifest = JSON.parse(
      await readFile(
        join(installedRoot, "_bundled_plugin", ".codex-plugin", "plugin.json"),
        "utf8",
      ),
    );
    assert.equal(completed.manifest.scan.id, scanId);
    assert.equal(completed.manifest.scan.status, "completed");
    assert.equal(
      completed.manifest.scan.sealedAt,
      completed.manifest.scan.completedAt,
    );
    assert.deepEqual(completed.manifest.scan.producer, {
      name: "codex-security-plugin",
      version: pluginManifest.version,
    });
    assert.equal(completed.coverage.scanId, scanId);
    assert.equal(completed.coverage.completeness, "complete");
    assert.deepEqual(completed.findings.findings, []);
    for (const name of [
      "scan-manifest.json",
      "findings.json",
      "coverage.json",
      "report.md",
    ]) {
      assert.ok(
        (await stat(join(scanDir, name))).size > 0,
        `Completed installed MCP scan is missing ${name}.`,
      );
    }
  } finally {
    child.stdin.end();
    await closed;
    clearTimeout(timeout);
  }

  return { fixture, environment };
}

async function smokeNestedDeepScanWorker(installedRoot, consumer) {
  const sdk = await import(
    pathToFileURL(join(installedRoot, "dist", "index.js")).href
  );
  const codexCommand = sdk.resolveCodexCommand();
  assert.equal(
    isAbsolute(codexCommand.command),
    true,
    "The bundled Codex executable must resolve to an absolute path.",
  );

  const workerHome = join(consumer, "nested-worker-home");
  await mkdir(workerHome, { recursive: true, mode: 0o700 });
  const parentEnvironment = sdk.pluginExecutionEnvironment(process.execPath, {
    PATH: "",
    HOME: workerHome,
    USERPROFILE: workerHome,
    CODEX_HOME: workerHome,
    ...(process.env.SystemRoot === undefined
      ? {}
      : { SystemRoot: process.env.SystemRoot }),
    ...(process.env.WINDIR === undefined ? {} : { WINDIR: process.env.WINDIR }),
  });
  const mcpConfiguration = JSON.parse(
    await readFile(join(installedRoot, "_bundled_plugin", ".mcp.json"), "utf8"),
  );
  const inherited = new Set([
    "PATH",
    "HOME",
    "USERPROFILE",
    "SystemRoot",
    "WINDIR",
    ...mcpConfiguration.mcpServers["codex-security"].env_vars,
  ]);
  const workerEnvironment = Object.fromEntries(
    Object.entries(parentEnvironment).filter(
      ([name, value]) => value !== undefined && inherited.has(name),
    ),
  );
  assert.equal(
    workerEnvironment.CODEX_CLI_PATH,
    codexCommand.command,
    "The installed plugin must propagate the bundled Codex path into nested workers.",
  );

  const globalCodex = spawnSync("codex", ["--version"], {
    cwd: consumer,
    encoding: "utf8",
    env: workerEnvironment,
    windowsHide: true,
  });
  assert.equal(
    globalCodex.error?.code,
    "ENOENT",
    "Nested-worker smoke must not depend on a globally installed codex executable.",
  );
  const codexVersion = run(codexCommand.command, ["--version"], {
    cwd: consumer,
    env: workerEnvironment,
    capture: true,
  });
  assert.match(codexVersion, /^codex-cli\s+\d/u);

  const workerSdkBridge = join(consumer, "nested-worker-sdk.mjs");
  await writeFile(
    workerSdkBridge,
    'export { Codex } from "@openai/codex-sdk";\n',
  );
  const { Codex } = await import(pathToFileURL(workerSdkBridge).href);
  const controller = new AbortController();
  const timeout = setTimeout(
    () => controller.abort(new Error("The nested Codex worker did not start.")),
    15_000,
  );
  let started = false;
  try {
    const codex = new Codex({
      codexPathOverride: workerEnvironment.CODEX_CLI_PATH,
      env: workerEnvironment,
      baseUrl: "http://127.0.0.1:1/v1",
      apiKey: "synthetic-codex-security-package-smoke",
    });
    const { events } = await codex
      .startThread({
        workingDirectory: workerHome,
        skipGitRepoCheck: true,
        sandboxMode: "read-only",
      })
      .runStreamed("Validate packaged nested worker startup.", {
        signal: controller.signal,
      });
    for await (const event of events) {
      if (event.type === "thread.started") {
        started = true;
        controller.abort();
        break;
      }
    }
  } finally {
    clearTimeout(timeout);
    controller.abort();
  }
  assert.equal(
    started,
    true,
    "The installed package must launch an actual nested Codex worker without codex on PATH.",
  );
}

const archive = await resolveArchive();
assert.equal(
  (await stat(archive)).isFile(),
  true,
  `Packed npm tarball is not a regular file: ${archive}.`,
);

const publicPluginManifest = ".codex-plugin/plugin.json";
assert.ok(
  Array.isArray(pluginContract.externalOwnedExact) &&
    pluginContract.externalOwnedExact.includes(publicPluginManifest),
  "Plugin contract must include its public manifest.",
);
assert.ok(
  Array.isArray(pluginContract.shippedExact) &&
    pluginContract.shippedExact.every((path) => typeof path === "string"),
  "Plugin contract must declare its shipped files.",
);

const expectedPluginFiles = [
  publicPluginManifest,
  ...pluginContract.shippedExact.filter((path) => !path.startsWith("sdk/")),
].sort();
assert.equal(
  new Set(expectedPluginFiles).size,
  expectedPluginFiles.length,
  "Plugin contract must not contain duplicate installed paths.",
);

const consumer = await mkdtemp(join(tmpdir(), "codex-security-package-"));
try {
  await writeFile(
    join(consumer, "package.json"),
    `${JSON.stringify({
      name: "codex-security-package-smoke",
      private: true,
      type: "module",
    })}\n`,
  );

  const npm = await resolveNpm();
  run(
    npm.command,
    [
      ...npm.args,
      "install",
      "--prefer-offline",
      "--include=optional",
      "--ignore-scripts",
      "--package-lock=false",
      "--no-audit",
      "--no-fund",
      archive,
    ],
    { cwd: consumer },
  );

  const installedRoot = join(
    consumer,
    "node_modules",
    ...packageManifest.name.split("/"),
  );
  const installedManifest = JSON.parse(
    await readFile(join(installedRoot, "package.json"), "utf8"),
  );
  assert.equal(installedManifest.name, packageManifest.name);
  assert.equal(installedManifest.version, packageManifest.version);

  assert.deepEqual(
    await pluginFiles(join(installedRoot, "_bundled_plugin")),
    expectedPluginFiles,
    "Installed npm package does not match the complete bundled-plugin contract.",
  );

  run(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      `const sdk = await import(${JSON.stringify(packageManifest.name)}); if (typeof sdk.CodexSecurity !== "function") throw new Error("The installed package does not export CodexSecurity.");`,
    ],
    { cwd: consumer },
  );

  assert.equal(
    typeof installedManifest.bin?.["codex-security"],
    "string",
    "Installed package must declare the codex-security launcher.",
  );
  const launcher = resolve(
    installedRoot,
    installedManifest.bin["codex-security"],
  );
  assert.ok(
    launcher.startsWith(`${installedRoot}${sep}`),
    "Installed CLI launcher must remain inside its package.",
  );
  assert.equal(
    (await stat(launcher)).isFile(),
    true,
    "Installed package must contain its declared CLI launcher.",
  );

  const shim = join(
    consumer,
    "node_modules",
    ".bin",
    process.platform === "win32" ? "codex-security.cmd" : "codex-security",
  );
  assert.equal(
    (await stat(shim)).isFile(),
    true,
    "npm must create the published codex-security executable shim.",
  );

  function runInstalledCli(argument) {
    const options = { cwd: consumer, capture: true };
    if (process.platform === "win32") {
      return run(
        process.env.ComSpec ?? "cmd.exe",
        ["/d", "/s", "/c", `""${shim}" ${argument}"`],
        { ...options, windowsVerbatimArguments: true },
      );
    }

    return run(shim, [argument], options);
  }

  const version = runInstalledCli("--version");
  assert.equal(version.trim(), packageManifest.version);

  const help = runInstalledCli("--help");
  assert.match(help, /Usage: codex-security\b/u);

  const { fixture, environment } = await smokeInstalledMcp(
    installedRoot,
    consumer,
  );
  const dryRun = JSON.parse(
    run(
      process.execPath,
      [launcher, "scan", fixture, "--dry-run", "--json", "--auth", "api-key"],
      {
        cwd: consumer,
        env: {
          ...environment,
          OPENAI_API_KEY: "synthetic-codex-security-package-smoke",
        },
        capture: true,
      },
    ),
  );
  assert.equal(dryRun.dryRun, true);
  assert.equal(dryRun.repository, fixture);
  assert.deepEqual(dryRun.authentication, {
    method: "api_key",
    source: "OPENAI_API_KEY",
    verified: false,
  });

  await smokeNestedDeepScanWorker(installedRoot, consumer);

  console.log(
    `Validated installed ${packageManifest.name}@${packageManifest.version}: public import, CLI dry run, ${expectedPluginFiles.length} bundled plugin files, completed MCP scan, bundled Codex version, and a nested worker without global codex.`,
  );
} finally {
  await rm(consumer, {
    recursive: true,
    force: true,
    maxRetries: 10,
    retryDelay: 100,
  });
}

import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { Codex } from "@openai/codex-sdk";
import { afterEach, describe, expect, test } from "bun:test";
import {
  enrichPublicationIssues,
  publicationEnrichmentEnvironment,
  type PublicationEnrichmentCodex,
} from "../src/publication-enrichment.js";
import type { LinearPublicationCatalogLabel } from "../src/linear.js";
import type { Finding } from "../src/models.js";
import type { PreparedPublicationIssue } from "../src/publication.js";

const temporaryDirectories: string[] = [];
const LABELS = [
  { id: "label-exploit", name: "Exploitable" },
  { id: "label-internet", name: "Internet exposed" },
] as const;
const GROUPED_LABELS: readonly LinearPublicationCatalogLabel[] = [
  { id: "label-customer", name: "Customer data", groupId: "impact" },
  { id: "label-internal", name: "Internal data", groupId: "impact" },
];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

async function policyFile(): Promise<string> {
  const directory = await mkdtemp(
    join(tmpdir(), "codex-security-publication-policy-test-"),
  );
  temporaryDirectories.push(directory);
  const path = join(directory, "publication-policy.md");
  await writeFile(
    path,
    [
      "# Publication policy",
      "P0 findings are urgent.",
      "Internet-facing findings receive the Internet exposed label.",
    ].join("\n"),
  );
  return path;
}

function issues(): PreparedPublicationIssue[] {
  return [
    {
      findingId: "finding-one",
      occurrenceId: "occurrence-one",
      title: "P0 remote execution",
      description: "An internet-facing synthetic finding.",
    },
    {
      findingId: "finding-two",
      occurrenceId: "occurrence-two",
      title: "Informational observation",
      description: "No publication rule applies.",
    },
  ];
}

function response(
  findings: Array<{
    findingId: string;
    priority: "none" | "urgent" | "high" | "medium" | "low";
    labelIds: string[];
    error?: string;
  }>,
): string {
  return JSON.stringify({
    findings: findings.map((finding) => ({
      ...finding,
      error: finding.error ?? null,
    })),
  });
}

function fakeCodex(
  finalResponse: string,
  capture: {
    thread?: unknown;
    prompt?: string;
    turn?: unknown;
  } = {},
): PublicationEnrichmentCodex {
  return {
    startThread(options) {
      capture.thread = options;
      return {
        async run(input, options) {
          capture.prompt = input;
          capture.turn = options;
          return { finalResponse };
        },
      };
    },
  };
}

describe("publication knowledge-base enrichment", () => {
  test("applies native priorities and multiple existing labels in a hardened turn", async () => {
    const policy = await policyFile();
    const capture: { thread?: unknown; prompt?: string; turn?: unknown } = {};
    const key = "lin_api_SYNTHETIC_SECRET";
    const enriched = await enrichPublicationIssues(issues(), LABELS, [policy], {
      codex: fakeCodex(
        response([
          {
            findingId: "finding-one",
            priority: "urgent",
            labelIds: ["label-exploit", "label-internet"],
          },
          {
            findingId: "finding-two",
            priority: "none",
            labelIds: [],
          },
        ]),
        capture,
      ),
      environment: {
        CODEX_SECURITY_SCAN_ID: "synthetic-parent-scan",
        CODEX_SECURITY_LINEAR_API_KEY: key,
      },
    });

    expect(enriched[0]).toMatchObject({
      priority: 1,
      labels: [LABELS[0], LABELS[1]],
    });
    expect(enriched[1]).not.toHaveProperty("priority");
    expect(enriched[1]).not.toHaveProperty("labels");
    expect(capture.thread).toMatchObject({
      sandboxMode: "read-only",
      approvalPolicy: "never",
      networkAccessEnabled: false,
      webSearchMode: "disabled",
      skipGitRepoCheck: true,
    });
    expect(capture.turn).toHaveProperty("outputSchema");
    expect(capture.turn).toMatchObject({
      outputSchema: {
        properties: {
          findings: {
            items: {
              properties: {
                error: {
                  anyOf: [{ type: "string" }, { type: "null" }],
                },
              },
              required: ["findingId", "priority", "labelIds", "error"],
            },
          },
        },
      },
    });
    expect(capture.prompt).toContain("P0 findings are urgent");
    expect(capture.prompt).toContain("label-internet");
    expect(capture.prompt).toContain("untrusted inert data");
    expect(capture.prompt).not.toContain(key);
  });

  test("leaves priority and labels unset when no explicit rule applies", async () => {
    const source = issues().map((issue) => ({
      ...issue,
      priority: 2 as const,
      labels: [{ ...LABELS[0] }],
    }));
    const enriched = await enrichPublicationIssues(
      source,
      LABELS,
      [await policyFile()],
      {
        codex: fakeCodex(
          response(
            source.map(({ findingId }) => ({
              findingId,
              priority: "none",
              labelIds: [],
            })),
          ),
        ),
        environment: { CODEX_SECURITY_SCAN_ID: "synthetic-parent-scan" },
      },
    );

    expect(enriched.every((issue) => issue.priority === undefined)).toBe(true);
    expect(enriched.every((issue) => issue.labels === undefined)).toBe(true);
  });

  test("disables ambient MCP servers without changing the authenticated home", async () => {
    let config: unknown;
    let receivedCodexHome: string | undefined;
    let receivedLowercaseCodexHome: string | undefined;
    const ambientCodexHome = await mkdtemp(
      join(tmpdir(), "codex-security-publication-ambient-home-test-"),
    );
    temporaryDirectories.push(ambientCodexHome);
    await writeFile(
      join(ambientCodexHome, "config.toml"),
      [
        "[mcp_servers.synthetic]",
        'command = "synthetic-write-tool"',
        "",
        "[mcp_servers.remote_server]",
        'url = "https://user:synthetic-secret@mcp.invalid"',
      ].join("\n"),
    );
    await enrichPublicationIssues(issues(), LABELS, [await policyFile()], {
      createCodex(options) {
        config = options.config;
        receivedCodexHome = options.env?.["CODEX_HOME"];
        receivedLowercaseCodexHome = options.env?.["codex_home"];
        return fakeCodex(
          response(
            issues().map(({ findingId }) => ({
              findingId,
              priority: "none",
              labelIds: [],
            })),
          ),
        );
      },
      environment: {
        codex_home: relative(process.cwd(), ambientCodexHome),
        CODEX_SECURITY_SCAN_ID: "synthetic-parent-scan",
      },
    });

    expect(config).toMatchObject({
      "mcp_servers.synthetic.enabled": false,
      "mcp_servers.remote_server.enabled": false,
      "features.image_generation": false,
      "features.view_image": false,
      tools: {
        experimental_request_user_input: { enabled: false },
        update_plan: { enabled: false },
      },
    });
    expect(receivedCodexHome).toBe(ambientCodexHome);
    expect(receivedLowercaseCodexHome).toBeUndefined();
    expect(JSON.stringify(config)).not.toContain("synthetic-secret");
    expect(JSON.stringify(config)).not.toContain("synthetic-write-tool");
    expect((await stat(ambientCodexHome)).isDirectory()).toBe(true);
  });

  test("fails closed for ambient MCP names the SDK cannot safely override", async () => {
    const codexHome = await mkdtemp(
      join(tmpdir(), "codex-security-publication-dotted-mcp-test-"),
    );
    temporaryDirectories.push(codexHome);
    await writeFile(
      join(codexHome, "config.toml"),
      '[mcp_servers."company.tools"]\ncommand = "company-tool"\n',
    );

    await expect(
      enrichPublicationIssues(issues(), LABELS, [await policyFile()], {
        createCodex() {
          throw new Error("Codex must not start.");
        },
        environment: {
          CODEX_HOME: codexHome,
          CODEX_SECURITY_SCAN_ID: "synthetic-parent-scan",
        },
      }),
    ).rejects.toThrow(
      /cannot safely disable an ambient Codex MCP server.*Disable that server/u,
    );
  });

  test("uses Codex trust decisions for project MCP configuration", async () => {
    let config: unknown;
    const project = await mkdtemp(
      join(tmpdir(), "codex-security-publication-project-config-test-"),
    );
    temporaryDirectories.push(project);
    const codexHome = await mkdtemp(
      join(tmpdir(), "codex-security-publication-project-home-test-"),
    );
    temporaryDirectories.push(codexHome);
    const workingDirectory = join(project, "tmp", "knowledge-base");
    await mkdir(join(project, ".codex"), { recursive: true });
    await mkdir(workingDirectory, { recursive: true });
    await writeFile(
      join(codexHome, "config.toml"),
      '[mcp_servers.ambient_tool]\ncommand = "ambient-tool"\n',
    );
    await writeFile(
      join(project, ".codex", "config.toml"),
      "[mcp_servers.ambient_tool]\nenabled = false\n",
    );
    await writeFile(join(workingDirectory, "policy.md"), "No metadata.");

    await enrichPublicationIssues(issues(), LABELS, ["unused"], {
      createCodex(options) {
        config = options.config;
        return fakeCodex(
          response(
            issues().map(({ findingId }) => ({
              findingId,
              priority: "none",
              labelIds: [],
            })),
          ),
        );
      },
      environment: {
        CODEX_HOME: codexHome,
        CODEX_SECURITY_SCAN_ID: "synthetic-parent-scan",
      },
      prepareKnowledgeBase: async () => ({
        path: workingDirectory,
        sources: [],
        cleanup: async () => undefined,
      }),
    });

    expect(config).toMatchObject({
      "mcp_servers.ambient_tool.enabled": false,
    });
  });

  test("fails before prompting when effective settings prevent isolation", async () => {
    let started = false;
    await expect(
      enrichPublicationIssues(issues(), LABELS, [await policyFile()], {
        createCodex() {
          started = true;
          return fakeCodex("{}");
        },
        environment: { CODEX_SECURITY_SCAN_ID: "synthetic-parent-scan" },
        loadConfiguredMcpServers: async () => [],
        verifyCodexIsolation: async () => {
          throw new Error(
            "Codex configuration does not allow publication enrichment to disable every external tool.",
          );
        },
      }),
    ).rejects.toThrow(/does not allow.*disable every external tool/u);
    expect(started).toBe(false);
  });

  test("removes configurable data access from the native enrichment turn", async () => {
    const codexHome = await mkdtemp(
      join(tmpdir(), "codex-security-publication-native-home-test-"),
    );
    temporaryDirectories.push(codexHome);
    const marker = join(codexHome, "mcp-started");
    const mcpServer = join(codexHome, "mcp-server.cjs");
    await writeFile(
      mcpServer,
      [
        'const fs = require("node:fs");',
        'const readline = require("node:readline");',
        "fs.writeFileSync(process.argv[2], 'started');",
        "const lines = readline.createInterface({ input: process.stdin });",
        "lines.on('line', (line) => {",
        "  const message = JSON.parse(line);",
        "  if (message.id === undefined) return;",
        "  let result = {};",
        "  if (message.method === 'initialize') result = { protocolVersion: message.params.protocolVersion, capabilities: { resources: {} }, serverInfo: { name: 'publication-test', version: '1' } };",
        "  if (message.method === 'resources/list') result = { resources: [{ uri: 'synthetic://secret', name: 'Synthetic' }] };",
        "  if (message.method === 'resources/read') result = { contents: [{ uri: 'synthetic://secret', text: 'unrelated data' }] };",
        "  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: message.id, result }) + '\\n');",
        "});",
      ].join("\n"),
    );
    const jwt = (payload: Record<string, unknown>) =>
      `${Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url")}.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.synthetic`;
    const token = jwt({
      "https://api.openai.com/auth": {
        chatgpt_plan_type: "pro",
        chatgpt_account_id: "synthetic-account",
        chatgpt_user_id: "synthetic-user",
      },
    });
    await writeFile(
      join(codexHome, "auth.json"),
      JSON.stringify({
        auth_mode: "chatgpt",
        tokens: {
          id_token: token,
          access_token: token,
          refresh_token: "synthetic-refresh",
          account_id: "synthetic-account",
        },
        last_refresh: new Date().toISOString(),
      }),
    );
    await writeFile(
      join(codexHome, "config.toml"),
      [
        "[mcp_servers.native_test]",
        `command = ${JSON.stringify(process.execPath)}`,
        `args = ${JSON.stringify([mcpServer, marker])}`,
        "",
        "[mcp_servers.native_http_test]",
        'url = "http://127.0.0.1:9/mcp"',
      ].join("\n"),
    );
    const requests: Array<{ tools?: Array<{ name?: string }> }> = [];
    const finalResponse = response(
      issues().map(({ findingId }) => ({
        findingId,
        priority: "none",
        labelIds: [],
      })),
    );
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      async fetch(request) {
        const path = new URL(request.url).pathname;
        if (request.method !== "POST" || !path.endsWith("/responses")) {
          return Response.json({}, { status: 404 });
        }
        requests.push(
          (await request.json()) as {
            tools?: Array<{ name?: string }>;
          },
        );
        const item = {
          type: "message",
          role: "assistant",
          id: "msg_synthetic",
          status: "completed",
          content: [
            { type: "output_text", text: finalResponse, annotations: [] },
          ],
        };
        const completed = {
          id: "resp_synthetic",
          status: "completed",
          output: [item],
          usage: {
            input_tokens: 1,
            output_tokens: 1,
            total_tokens: 2,
            input_tokens_details: { cached_tokens: 0 },
          },
        };
        const events = [
          {
            type: "response.output_item.added",
            output_index: 0,
            item: { ...item, status: "in_progress", content: [] },
          },
          {
            type: "response.output_text.delta",
            item_id: item.id,
            output_index: 0,
            content_index: 0,
            delta: finalResponse,
          },
          { type: "response.output_item.done", output_index: 0, item },
          { type: "response.completed", response: completed },
        ];
        return new Response(
          events
            .map(
              (event) =>
                `event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`,
            )
            .join(""),
          { headers: { "Content-Type": "text/event-stream" } },
        );
      },
    });
    try {
      await enrichPublicationIssues(issues(), LABELS, [await policyFile()], {
        createCodex(options) {
          return new Codex({
            ...options,
            config: {
              ...options.config,
              chatgpt_base_url: `http://127.0.0.1:${server.port}`,
              cli_auth_credentials_store: "file",
              model: "gpt-5.5",
              model_provider: "publication_test",
              "model_providers.publication_test": {
                name: "Publication test",
                base_url: `http://127.0.0.1:${server.port}/v1`,
                env_key: "PUBLICATION_TEST_KEY",
                wire_api: "responses",
                supports_websockets: false,
                requires_openai_auth: true,
                request_max_retries: 0,
                stream_max_retries: 0,
              },
            },
          });
        },
        environment: {
          ...process.env,
          CODEX_HOME: codexHome,
          HOME: codexHome,
          CODEX_SECURITY_SCAN_ID: "synthetic-parent-scan",
          PUBLICATION_TEST_KEY: "synthetic",
        },
        signal: AbortSignal.timeout(15_000),
      });
    } finally {
      server.stop(true);
    }

    const toolNames = requests[0]?.tools?.flatMap(({ name }) =>
      name === undefined ? [] : [name],
    );
    expect(toolNames).not.toContain("view_image");
    expect(toolNames).not.toContain("update_plan");
    expect(toolNames).not.toContain("request_user_input");
    expect(toolNames).not.toContain("image_gen");
    expect(JSON.stringify(requests[0])).not.toContain("native_test");
    expect(
      await readFile(marker, "utf8").catch(() => undefined),
    ).toBeUndefined();
  });

  test("supplies the canonical sealed finding to publication policy", async () => {
    const capture: { prompt?: string } = {};
    const canonicalFinding = {
      findingId: "finding-one",
      severity: {
        level: "critical",
        score: 9.8,
        vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      },
      validation: { status: "validated" },
      attackPath: { source: "internet", sink: "command execution" },
    } as unknown as Finding;

    await enrichPublicationIssues(
      issues().slice(0, 1),
      LABELS,
      [await policyFile()],
      {
        codex: fakeCodex(
          response([
            {
              findingId: "finding-one",
              priority: "urgent",
              labelIds: [],
            },
          ]),
          capture,
        ),
        environment: { CODEX_SECURITY_SCAN_ID: "synthetic-parent-scan" },
        findings: [canonicalFinding],
      },
    );

    const input = JSON.parse(capture.prompt!.split("\n").at(-1)!) as {
      findings: Array<{ canonicalFinding: Finding }>;
    };
    expect(input.findings[0]!.canonicalFinding).toEqual(canonicalFinding);
  });

  test.each([
    ["urgent", 1],
    ["high", 2],
    ["medium", 3],
    ["low", 4],
  ] as const)(
    "maps the policy-selected %s priority to %s",
    async (name, value) => {
      const source = issues().slice(0, 1);
      const enriched = await enrichPublicationIssues(
        source,
        LABELS,
        [await policyFile()],
        {
          codex: fakeCodex(
            response([
              {
                findingId: source[0]!.findingId,
                priority: name,
                labelIds: [],
              },
            ]),
          ),
          environment: { CODEX_SECURITY_SCAN_ID: "synthetic-parent-scan" },
        },
      );

      expect(enriched[0]!.priority).toBe(value);
    },
  );

  test.each([
    ["malformed output", "not-json", /invalid JSON/u],
    [
      "invalid priority",
      JSON.stringify({
        findings: issues().map(({ findingId }) => ({
          findingId,
          priority: "critical",
          labelIds: [],
        })),
      }),
      /invalid result/u,
    ],
    [
      "missing finding",
      response([
        {
          findingId: "finding-one",
          priority: "high",
          labelIds: [],
        },
      ]),
      /did not classify every finding/u,
    ],
    [
      "duplicate finding",
      response([
        {
          findingId: "finding-one",
          priority: "high",
          labelIds: [],
        },
        {
          findingId: "finding-one",
          priority: "low",
          labelIds: [],
        },
      ]),
      /repeated a finding/u,
    ],
    [
      "invented finding",
      response([
        {
          findingId: "finding-one",
          priority: "high",
          labelIds: [],
        },
        {
          findingId: "invented-finding",
          priority: "low",
          labelIds: [],
        },
      ]),
      /unknown finding/u,
    ],
    [
      "invented label",
      response([
        {
          findingId: "finding-one",
          priority: "high",
          labelIds: ["invented-label"],
        },
        {
          findingId: "finding-two",
          priority: "none",
          labelIds: [],
        },
      ]),
      /unavailable Linear label/u,
    ],
    [
      "duplicate label",
      response([
        {
          findingId: "finding-one",
          priority: "high",
          labelIds: ["label-exploit", "label-exploit"],
        },
        {
          findingId: "finding-two",
          priority: "none",
          labelIds: [],
        },
      ]),
      /repeated a Linear label/u,
    ],
    [
      "mutually exclusive labels",
      response([
        {
          findingId: "finding-one",
          priority: "high",
          labelIds: ["label-customer", "label-internal"],
        },
        {
          findingId: "finding-two",
          priority: "none",
          labelIds: [],
        },
      ]),
      /mutually exclusive Linear labels/u,
    ],
    [
      "contradictory policy",
      response([
        {
          findingId: "finding-one",
          priority: "none",
          labelIds: [],
          error: "Two explicit priority rules conflict.",
        },
        {
          findingId: "finding-two",
          priority: "none",
          labelIds: [],
        },
      ]),
      /could not classify finding finding-one/u,
    ],
  ])("rejects %s", async (name, finalResponse, expected) => {
    await expect(
      enrichPublicationIssues(
        issues(),
        name === "mutually exclusive labels" ? GROUPED_LABELS : LABELS,
        [await policyFile()],
        {
          codex: fakeCodex(finalResponse),
          environment: { CODEX_SECURITY_SCAN_ID: "synthetic-parent-scan" },
        },
      ),
    ).rejects.toThrow(expected);
  });

  test("removes terminal controls from model-authored policy errors", async () => {
    const policyError = "Conflicting rule.\u001B]52;c;copied-secret\u0007";
    let error: unknown;
    try {
      await enrichPublicationIssues(issues(), LABELS, [await policyFile()], {
        codex: fakeCodex(
          response([
            {
              findingId: "finding-one",
              priority: "none",
              labelIds: [],
              error: policyError,
            },
            {
              findingId: "finding-two",
              priority: "none",
              labelIds: [],
            },
          ]),
        ),
        environment: { CODEX_SECURITY_SCAN_ID: "synthetic-parent-scan" },
      });
    } catch (caught) {
      error = caught;
    }

    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toContain("Conflicting rule.");
    expect((error as Error).message).not.toContain("\u001B");
    expect((error as Error).message).not.toContain("copied-secret");
  });

  test("cleans prepared knowledge bases when enrichment is canceled", async () => {
    const directory = await mkdtemp(
      join(tmpdir(), "codex-security-publication-prepared-test-"),
    );
    temporaryDirectories.push(directory);
    await writeFile(join(directory, "0-policy.md.txt"), "Synthetic policy");
    let cleaned = false;
    const controller = new AbortController();
    const codex: PublicationEnrichmentCodex = {
      startThread() {
        return {
          async run() {
            controller.abort("synthetic cancellation");
            throw controller.signal.reason;
          },
        };
      },
    };

    await expect(
      enrichPublicationIssues(issues(), LABELS, ["C:\\policy.md"], {
        codex,
        environment: { CODEX_SECURITY_SCAN_ID: "synthetic-parent-scan" },
        signal: controller.signal,
        prepareKnowledgeBase: async () => ({
          path: directory,
          sources: ["C:\\policy.md"],
          async cleanup() {
            cleaned = true;
          },
        }),
      }),
    ).rejects.toBe("synthetic cancellation");
    expect(cleaned).toBe(true);
  });

  test("removes Linear credentials from the Codex environment", async () => {
    const environment = await publicationEnrichmentEnvironment({
      CODEX_SECURITY_SCAN_ID: "synthetic-parent-scan",
      CODEX_SECURITY_LINEAR_API_KEY: "publication-key",
      linear_api_key: "generic-key",
      LINEAR_ACCESS_TOKEN: "access-token",
      OPENAI_API_KEY: "codex-key",
    });

    expect(environment).toEqual({
      CODEX_SECURITY_SCAN_ID: "synthetic-parent-scan",
      OPENAI_API_KEY: "codex-key",
    });
  });

  test("cleans the extracted knowledge base after success", async () => {
    const policy = await policyFile();
    let workingDirectory: string | undefined;
    const codex: PublicationEnrichmentCodex = {
      startThread(options) {
        workingDirectory = options.workingDirectory;
        return {
          async run() {
            return {
              finalResponse: response(
                issues().map(({ findingId }) => ({
                  findingId,
                  priority: "none",
                  labelIds: [],
                })),
              ),
            };
          },
        };
      },
    };

    await enrichPublicationIssues(issues(), LABELS, [policy], {
      codex,
      environment: { CODEX_SECURITY_SCAN_ID: "synthetic-parent-scan" },
    });
    expect(workingDirectory).toBeDefined();
    await expect(stat(workingDirectory!)).rejects.toThrow();
  });
});

import { mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import {
  enrichPublicationIssues,
  publicationEnrichmentEnvironment,
  type PublicationEnrichmentCodex,
} from "../src/publication-enrichment.js";
import type { LinearPublicationCatalogLabel } from "../src/linear.js";
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
        'url = "https://mcp.invalid"',
      ].join("\n"),
    );
    await enrichPublicationIssues(issues(), LABELS, [await policyFile()], {
      createCodex(options) {
        config = options.config;
        receivedCodexHome = options.env?.["CODEX_HOME"];
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
        CODEX_HOME: ambientCodexHome,
        CODEX_SECURITY_SCAN_ID: "synthetic-parent-scan",
      },
    });

    expect(config).toMatchObject({
      mcp_servers: {},
      "mcp_servers.synthetic.command": "synthetic-write-tool",
      "mcp_servers.synthetic.enabled": false,
      "mcp_servers.remote_server.url": "https://mcp.invalid",
      "mcp_servers.remote_server.enabled": false,
      "tools.view_image": false,
    });
    expect(receivedCodexHome).toBe(ambientCodexHome);
    expect((await stat(ambientCodexHome)).isDirectory()).toBe(true);
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

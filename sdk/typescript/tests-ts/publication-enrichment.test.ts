import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { join, relative } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import {
  disabledMcpServerConfiguration,
  enrichPublicationIssues,
  parsePublicationEnrichment,
  publicationEnrichmentEnvironment,
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
  {
    id: "label-customer",
    name: "Customer data",
    groupId: "impact",
    groupName: "Impact",
  },
  {
    id: "label-internal",
    name: "Internal data",
    groupId: "impact",
    groupName: "Impact",
  },
];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

function issues(): PreparedPublicationIssue[] {
  return [
    {
      findingId: "finding-one",
      occurrenceId: "occurrence-one",
      title: "Rendered title must not be policy input",
      description: "Rendered description must not be policy input",
    },
    {
      findingId: "finding-two",
      occurrenceId: "occurrence-two",
      title: "Second rendered title",
      description: "Second rendered description",
    },
  ];
}

function findings(marker = "canonical-marker"): Finding[] {
  return issues().map(
    ({ findingId, occurrenceId }, index) =>
      ({
        findingId,
        occurrenceId,
        title: `Canonical finding ${index + 1}`,
        summary: index === 0 ? marker : "No explicit policy applies.",
        severity: { level: index === 0 ? "critical" : "informational" },
      }) as unknown as Finding,
  );
}

function response(
  values: Array<{
    findingId: string;
    priority: "none" | "urgent" | "high" | "medium" | "low";
    labelIds: string[];
    error?: string;
  }>,
): string {
  return JSON.stringify({
    findings: values.map((value) => ({
      ...value,
      error: value.error ?? null,
    })),
  });
}

async function policyFile(
  text = "Critical findings are urgent.",
): Promise<string> {
  const directory = await mkdtemp(
    join(tmpdir(), "codex-security-publication-policy-test-"),
  );
  temporaryDirectories.push(directory);
  const path = join(directory, "policy.md");
  await writeFile(path, text);
  return path;
}

async function filesUnder(root: string): Promise<string[]> {
  const files: string[] = [];
  const visit = async (directory: string): Promise<void> => {
    const entries = await readdir(directory, { withFileTypes: true }).catch(
      () => [],
    );
    for (const entry of entries) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) await visit(path);
      else if (entry.isFile()) files.push(path);
    }
  };
  await visit(root);
  return files.sort();
}

describe("publication knowledge-base enrichment", () => {
  test("quotes punctuation in external integration overrides", () => {
    expect(
      disabledMcpServerConfiguration(["company.tools", 'quoted"server']),
    ).toBe(
      '{"company.tools"={enabled=false,command="codex-security-disabled"},"quoted\\"server"={enabled=false,command="codex-security-disabled"}}',
    );
  });

  test("uses canonical findings and applies policy-selected Linear metadata", async () => {
    const capture: { prompt?: string } = {};
    const key = "lin_api_SYNTHETIC_SECRET";
    const enriched = await enrichPublicationIssues(
      issues(),
      LABELS,
      [await policyFile("P0 findings are urgent and internet exposed.")],
      {
        findings: findings("canonical-policy-input"),
        environment: {
          CODEX_SECURITY_SCAN_ID: "synthetic-parent-scan",
          CODEX_SECURITY_LINEAR_API_KEY: key,
        },
        async runCodex(_command, _environment, _workingDirectory, prompt) {
          capture.prompt = prompt;
          return {
            finalResponse: response([
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
          };
        },
      },
    );

    expect(enriched[0]).toMatchObject({
      priority: 1,
      labels: [LABELS[0], LABELS[1]],
    });
    expect(enriched[1]).not.toHaveProperty("priority");
    expect(enriched[1]).not.toHaveProperty("labels");
    expect(capture.prompt).toContain("canonical-policy-input");
    expect(capture.prompt).not.toContain(
      "Rendered title must not be policy input",
    );
    expect(capture.prompt).not.toContain(
      "Rendered description must not be policy input",
    );
    expect(capture.prompt).not.toContain(key);
    const data = JSON.parse(capture.prompt!.split("\n").at(-1)!) as {
      findings: Finding[];
    };
    expect(data.findings).toEqual(findings("canonical-policy-input"));
  });

  test.each([
    ["urgent", 1],
    ["high", 2],
    ["medium", 3],
    ["low", 4],
  ] as const)("maps %s to Linear priority %s", (priority, expected) => {
    const source = issues().slice(0, 1);
    expect(
      parsePublicationEnrichment(
        source,
        LABELS,
        response([
          {
            findingId: source[0]!.findingId,
            priority,
            labelIds: [],
          },
        ]),
      )[0]!.priority,
    ).toBe(expected);
  });

  test("removes legacy metadata when no explicit policy rule applies", () => {
    const source = issues().map((issue) => ({
      ...issue,
      priority: 2 as const,
      labels: [{ ...LABELS[0] }],
    }));
    const enriched = parsePublicationEnrichment(
      source,
      LABELS,
      response(
        source.map(({ findingId }) => ({
          findingId,
          priority: "none",
          labelIds: [],
        })),
      ),
    );

    expect(enriched.every((issue) => issue.priority === undefined)).toBe(true);
    expect(enriched.every((issue) => issue.labels === undefined)).toBe(true);
  });

  test.each([
    ["malformed output", "not-json", /invalid JSON/u, LABELS],
    [
      "invalid priority",
      JSON.stringify({
        findings: issues().map(({ findingId }) => ({
          findingId,
          priority: "critical",
          labelIds: [],
          error: null,
        })),
      }),
      /invalid result/u,
      LABELS,
    ],
    [
      "missing finding",
      response([{ findingId: "finding-one", priority: "high", labelIds: [] }]),
      /did not classify every finding/u,
      LABELS,
    ],
    [
      "duplicate finding",
      response([
        { findingId: "finding-one", priority: "high", labelIds: [] },
        { findingId: "finding-one", priority: "low", labelIds: [] },
      ]),
      /repeated a finding/u,
      LABELS,
    ],
    [
      "invented finding",
      response([
        { findingId: "finding-one", priority: "high", labelIds: [] },
        { findingId: "invented", priority: "low", labelIds: [] },
      ]),
      /unknown finding/u,
      LABELS,
    ],
    [
      "invented label",
      response([
        {
          findingId: "finding-one",
          priority: "high",
          labelIds: ["invented"],
        },
        { findingId: "finding-two", priority: "none", labelIds: [] },
      ]),
      /unavailable Linear label/u,
      LABELS,
    ],
    [
      "duplicate label",
      response([
        {
          findingId: "finding-one",
          priority: "high",
          labelIds: ["label-exploit", "label-exploit"],
        },
        { findingId: "finding-two", priority: "none", labelIds: [] },
      ]),
      /repeated a Linear label/u,
      LABELS,
    ],
    [
      "mutually exclusive labels",
      response([
        {
          findingId: "finding-one",
          priority: "high",
          labelIds: ["label-customer", "label-internal"],
        },
        { findingId: "finding-two", priority: "none", labelIds: [] },
      ]),
      /mutually exclusive Linear labels/u,
      GROUPED_LABELS,
    ],
    [
      "policy conflict",
      response([
        {
          findingId: "finding-one",
          priority: "none",
          labelIds: [],
          error: "Two explicit rules conflict.",
        },
        { findingId: "finding-two", priority: "none", labelIds: [] },
      ]),
      /could not classify finding finding-one/u,
      LABELS,
    ],
  ] as const)("rejects %s", (_name, output, expected, labels) => {
    expect(() => parsePublicationEnrichment(issues(), labels, output)).toThrow(
      expected,
    );
  });

  test("rejects missing or duplicate canonical finding input before extraction", async () => {
    let prepared = false;
    const options = {
      environment: { CODEX_SECURITY_SCAN_ID: "synthetic-parent-scan" },
      async prepareKnowledgeBase() {
        prepared = true;
        throw new Error("must not extract");
      },
    };

    await expect(
      enrichPublicationIssues(issues(), LABELS, ["policy.md"], {
        ...options,
        findings: findings().slice(0, 1),
      }),
    ).rejects.toThrow(/missing a canonical finding/u);
    await expect(
      enrichPublicationIssues(issues(), LABELS, ["policy.md"], {
        ...options,
        findings: [findings()[0]!, findings()[0]!, findings()[1]!],
      }),
    ).rejects.toThrow(/duplicate canonical finding/u);
    expect(prepared).toBe(false);
  });

  test("cleans extracted policy data after cancellation", async () => {
    const directory = await mkdtemp(
      join(tmpdir(), "codex-security-publication-cancel-test-"),
    );
    temporaryDirectories.push(directory);
    await writeFile(join(directory, "0-policy.md.txt"), "Synthetic policy");
    const controller = new AbortController();
    let cleaned = false;

    await expect(
      enrichPublicationIssues(issues(), LABELS, ["C:\\policy.md"], {
        findings: findings(),
        environment: { CODEX_SECURITY_SCAN_ID: "synthetic-parent-scan" },
        signal: controller.signal,
        prepareKnowledgeBase: async () => ({
          path: directory,
          sources: ["C:\\policy.md"],
          async cleanup() {
            cleaned = true;
          },
        }),
        async runCodex() {
          controller.abort("synthetic cancellation");
          throw controller.signal.reason;
        },
      }),
    ).rejects.toBe("synthetic cancellation");
    expect(cleaned).toBe(true);
  });

  test("surfaces cleanup failures without hiding a primary enrichment error", async () => {
    for (const primaryFailure of [false, true]) {
      const directory = await mkdtemp(
        join(tmpdir(), "codex-security-publication-cleanup-test-"),
      );
      temporaryDirectories.push(directory);
      await writeFile(join(directory, "0-policy.md.txt"), "Policy");
      const error = await enrichPublicationIssues(
        issues(),
        LABELS,
        ["policy.md"],
        {
          findings: findings(),
          environment: { CODEX_SECURITY_SCAN_ID: "synthetic-parent-scan" },
          prepareKnowledgeBase: async () => ({
            path: directory,
            sources: [],
            cleanup: async () => {
              throw new Error("cleanup failed");
            },
          }),
          async runCodex() {
            if (primaryFailure) throw new Error("enrichment failed");
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
        },
      ).catch((caught: unknown) => caught);

      if (primaryFailure) {
        expect(error).toBeInstanceOf(AggregateError);
        expect((error as AggregateError).message).toBe("enrichment failed");
        expect((error as AggregateError).errors).toHaveLength(2);
      } else {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toContain("cleanup failed");
      }
    }
  });

  test("sanitizes Linear credentials and resolves configured Codex homes", async () => {
    expect(
      await publicationEnrichmentEnvironment({
        CODEX_SECURITY_SCAN_ID: "synthetic-parent-scan",
        CODEX_SECURITY_LINEAR_API_KEY: "publication-key",
        linear_api_key: "generic-key",
        LINEAR_ACCESS_TOKEN: "access-token",
        OPENAI_API_KEY: "codex-key",
      }),
    ).toEqual({
      CODEX_SECURITY_SCAN_ID: "synthetic-parent-scan",
      OPENAI_API_KEY: "codex-key",
    });
    expect(
      (
        await publicationEnrichmentEnvironment({
          CODEX_HOME: "~/.codex-publication-test",
        })
      )["CODEX_HOME"],
    ).toBe(join(homedir(), ".codex-publication-test"));
    expect(
      await publicationEnrichmentEnvironment({ codex_home: "" }),
    ).not.toHaveProperty("CODEX_HOME");
  });

  test("native execution ignores ambient integrations, credentials, and persistence", async () => {
    const codexHome = await mkdtemp(
      join(tmpdir(), "codex-security-publication-native-test-"),
    );
    temporaryDirectories.push(codexHome);
    const sessionsDirectory = join(codexHome, "sessions");
    const stateDirectory = join(codexHome, "state");
    const mcpMarker = join(codexHome, "mcp-started");
    const notifyMarker = join(codexHome, "notify-started");
    const mcpScript = join(codexHome, "mcp.cjs");
    const notifyScript = join(codexHome, "notify.cjs");
    const workspace = join(codexHome, "workspace");
    const knowledgeBase = join(workspace, "knowledge-base");
    const skillDirectory = join(codexHome, "skills", "ambient-policy");
    await mkdir(sessionsDirectory, { recursive: true });
    await mkdir(stateDirectory, { recursive: true });
    await mkdir(knowledgeBase, { recursive: true });
    await mkdir(skillDirectory, { recursive: true });
    await writeFile(join(sessionsDirectory, "existing.jsonl"), "{}\n");
    await writeFile(join(stateDirectory, "existing.txt"), "existing\n");
    await writeFile(
      mcpScript,
      `require("node:fs").writeFileSync(${JSON.stringify(mcpMarker)}, "started"); setInterval(() => {}, 1000);`,
    );
    await writeFile(
      notifyScript,
      `require("node:fs").writeFileSync(${JSON.stringify(notifyMarker)}, "started");`,
    );
    await writeFile(
      join(codexHome, "config.toml"),
      [
        `notify = [${JSON.stringify(process.execPath)}, ${JSON.stringify(notifyScript)}]`,
        'instructions = "AMBIENT_INSTRUCTIONS_MARKER"',
        '[mcp_servers."ambient.tools"]',
        `command = ${JSON.stringify(process.execPath)}`,
        `args = [${JSON.stringify(mcpScript)}]`,
      ].join("\n"),
    );

    const requests: Array<{ tools?: unknown[] }> = [];
    const policyMarker = "PRIVATE_POLICY_MARKER";
    const findingMarker = "PRIVATE_CANONICAL_FINDING_MARKER";
    const projectMarker = "AMBIENT_PROJECT_INSTRUCTIONS_MARKER";
    const skillMarker = "AMBIENT_SKILL_MARKER";
    const linearKey = "lin_api_PRIVATE_LINEAR_KEY";
    await writeFile(join(workspace, "AGENTS.md"), projectMarker);
    await writeFile(
      join(skillDirectory, "SKILL.md"),
      [
        "---",
        "name: ambient-policy",
        "description: Ambient policy probe.",
        "---",
        skillMarker,
      ].join("\n"),
    );
    await writeFile(
      join(knowledgeBase, "0-policy.md.txt"),
      `Apply no metadata. ${policyMarker}`,
    );
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
        if (request.method !== "POST") {
          return Response.json({}, { status: 404 });
        }
        requests.push((await request.json()) as { tools?: unknown[] });
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
        return new Response(
          [
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
          ]
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
      await enrichPublicationIssues(issues(), LABELS, ["unused-policy.md"], {
        findings: findings(findingMarker),
        environment: {
          ...process.env,
          CODEX_HOME: codexHome,
          CODEX_SECURITY_SCAN_ID: "synthetic-parent-scan",
          CODEX_SECURITY_LINEAR_API_KEY: linearKey,
          PUBLICATION_TEST_KEY: "synthetic",
        },
        signal: AbortSignal.timeout(15_000),
        prepareKnowledgeBase: async () => ({
          path: knowledgeBase,
          sources: [],
          cleanup: async () => undefined,
        }),
        codexConfig: {
          model: "gpt-5.5",
          model_provider: "publication_test",
          "model_providers.publication_test.name": "Publication test",
          "model_providers.publication_test.base_url": `http://127.0.0.1:${server.port}/v1`,
          "model_providers.publication_test.env_key": "PUBLICATION_TEST_KEY",
          "model_providers.publication_test.wire_api": "responses",
          "model_providers.publication_test.supports_websockets": false,
          "model_providers.publication_test.requires_openai_auth": false,
          "model_providers.publication_test.request_max_retries": 0,
          "model_providers.publication_test.stream_max_retries": 0,
        },
      });
    } finally {
      server.stop(true);
    }

    const serializedRequest = JSON.stringify(requests[0]);
    expect(requests[0]?.tools ?? []).toEqual([]);
    expect(serializedRequest).toContain(policyMarker);
    expect(serializedRequest).toContain(findingMarker);
    expect(serializedRequest).not.toContain(linearKey);
    expect(serializedRequest).not.toContain("AMBIENT_INSTRUCTIONS_MARKER");
    expect(serializedRequest).not.toContain(projectMarker);
    expect(serializedRequest).not.toContain(skillMarker);
    expect(serializedRequest).not.toContain("ambient.tools");
    expect(
      await readFile(mcpMarker, "utf8").catch(() => undefined),
    ).toBeUndefined();
    expect(
      await readFile(notifyMarker, "utf8").catch(() => undefined),
    ).toBeUndefined();

    const homeFiles = await filesUnder(codexHome);
    const sessionFiles = homeFiles.filter((path) =>
      relative(codexHome, path).startsWith(
        `sessions${process.platform === "win32" ? "\\" : "/"}`,
      ),
    );
    expect(sessionFiles).toEqual([join(sessionsDirectory, "existing.jsonl")]);
    const persistedFiles = homeFiles.filter((path) => {
      const local = relative(codexHome, path).toLowerCase();
      return (
        local.startsWith(
          `sessions${process.platform === "win32" ? "\\" : "/"}`,
        ) ||
        local.startsWith(`state${process.platform === "win32" ? "\\" : "/"}`) ||
        local.includes("state_") ||
        local.endsWith(".sqlite") ||
        local.endsWith(".sqlite3")
      );
    });
    const persisted = Buffer.concat(
      await Promise.all(persistedFiles.map((path) => readFile(path))),
    ).toString("utf8");
    expect(persisted).not.toContain(policyMarker);
    expect(persisted).not.toContain(findingMarker);
  });
});

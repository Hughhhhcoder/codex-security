import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline";
import { describe, expect, test } from "bun:test";
import { loadBundledRuntime, PLUGIN_ROOT } from "./plugin-root.js";

type Location = {
  path: string;
  startLine: number;
  endLine?: number;
  role?: string;
};

type Finding = {
  ruleId: string;
  title: string;
  identity: { anchor: string; instance?: string };
  locations: Location[];
  findingId?: string;
  occurrenceId?: string;
  fingerprints?: unknown;
  [key: string]: unknown;
};

type Coverage = {
  completeness: "complete" | "partial" | "unknown";
  surfaces: Array<{
    id?: string;
    label: string;
    disposition: string;
  }>;
  explicitExclusions: Array<{ pattern: string; reason: string }>;
  deferred: Array<{
    id?: string;
    candidateId?: string;
    reason: string;
    paths?: string[];
    surfaceIds?: string[];
  }>;
  openQuestions?: Array<string | { question: string }>;
};

type ThreatModel = {
  summary: string;
  assets?: string[];
  trustBoundaries?: string[];
  attackerCapabilities?: string[];
  securityObjectives?: string[];
  assumptions?: string[];
};

type ScanDraft = {
  scanId: string;
  findings: Finding[];
  coverage: Coverage;
  threatModel?: ThreatModel;
};

type ReducerResponse = {
  accepted: boolean;
  message: string;
  saved?: ScanDraft;
};

const scanId = randomUUID();
const exampleFinding = (
  JSON.parse(
    readFileSync(
      join(PLUGIN_ROOT, "examples/completed-scan/findings.json"),
      "utf8",
    ),
  ) as { findings: Finding[] }
).findings[0]!;

function finding(name: string, line: number): Finding {
  const result = structuredClone(exampleFinding);
  delete result.findingId;
  delete result.occurrenceId;
  delete result.fingerprints;
  result.ruleId = `synthetic.${name}`;
  result.title = `Synthetic ${name} vulnerability`;
  result.identity = { anchor: `synthetic-${name}` };
  result.locations[0] = {
    path: `src/${name}.ts`,
    startLine: line,
    endLine: line,
    role: "sink",
  };
  return result;
}

function coverage(overrides: Partial<Coverage> = {}): Coverage {
  return {
    completeness: "complete",
    surfaces: [],
    explicitExclusions: [],
    deferred: [],
    ...overrides,
  };
}

function draft(
  findings: Finding[],
  scanCoverage = coverage(),
  threatModel?: ThreatModel,
): ScanDraft {
  return {
    scanId,
    findings,
    coverage: scanCoverage,
    ...(threatModel === undefined ? {} : { threatModel }),
  };
}

function writeJson(path: string, value: unknown): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(value));
}

async function recordReduction(
  sources: ScanDraft[],
  reduction: ScanDraft,
  previous?: ScanDraft,
): Promise<ReducerResponse> {
  const node = Bun.which("node");
  expect(node).not.toBeNull();
  const root = realpathSync(
    mkdtempSync(join(tmpdir(), "codex-security-reducer-integrity-")),
  );
  const repository = join(root, "repository");
  const scanRoot = join(root, "scan");
  const reducerRoot = join(
    scanRoot,
    "artifacts/deep_discovery/dedup/reducer/output",
  );
  mkdirSync(repository);
  mkdirSync(reducerRoot, { recursive: true });

  try {
    const claimedWorkers = sources.map((source, index) => {
      const id = `worker-${index + 1}`;
      const resultPath = join(
        scanRoot,
        "artifacts/deep_discovery/workers",
        id,
        "output/result.json",
      );
      writeJson(resultPath, source);
      return { id, resultPath };
    });
    const reducerContext: {
      scanRoot: string;
      claimedWorkers: typeof claimedWorkers;
      previousReducerResultPath?: string;
    } = { scanRoot, claimedWorkers };
    if (previous) {
      reducerContext.previousReducerResultPath = join(
        scanRoot,
        "artifacts/deep_discovery/dedup/previous/output/result.json",
      );
      writeJson(reducerContext.previousReducerResultPath, previous);
    }

    const child = spawn(
      node!,
      [join(PLUGIN_ROOT, "mcp/server.mjs"), "--artifact-writer", "--stdio"],
      {
        stdio: ["pipe", "pipe", "pipe"],
        env: {
          ...process.env,
          CODEX_SECURITY_ARTIFACT_ROOT: reducerRoot,
          CODEX_SECURITY_REPO_ROOT: repository,
          CODEX_SECURITY_ARTIFACT_LAYOUT: "reducer",
          CODEX_SECURITY_SCAN_ID: scanId,
          CODEX_SECURITY_PLUGIN_ROOT: PLUGIN_ROOT,
          CODEX_SECURITY_REDUCER_CONTEXT_JSON: JSON.stringify(reducerContext),
        },
      },
    );
    const messages = createInterface({ input: child.stdout })[
      Symbol.asyncIterator
    ]();
    let errors = "";
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk: string) => {
      errors += chunk;
    });
    let requestId = 0;

    async function request(
      method: string,
      params: Record<string, unknown>,
    ): Promise<Record<string, unknown>> {
      const id = ++requestId;
      child.stdin.write(
        `${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`,
      );

      while (true) {
        const message = await messages.next();
        if (message.done) {
          throw new Error(
            `The reducer server exited before replying: ${errors}`,
          );
        }
        const response = JSON.parse(message.value) as Record<string, unknown>;
        if (response["id"] === id) return response;
      }
    }

    try {
      await request("initialize", {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: {
          name: "codex-security-reducer-integrity-test",
          version: "1.0.0",
        },
      });
      child.stdin.write(
        `${JSON.stringify({
          jsonrpc: "2.0",
          method: "notifications/initialized",
          params: {},
        })}\n`,
      );
      const response = await request("tools/call", {
        name: "record_codex_security_deep_reduction",
        arguments: reduction,
      });
      const result = response["result"] as
        | {
            isError?: boolean;
            content?: Array<{ text?: string }>;
          }
        | undefined;
      const accepted = response["error"] === undefined && !result?.isError;
      const message = result?.content?.[0]?.text ?? JSON.stringify(response);

      return {
        accepted,
        message,
        ...(accepted
          ? {
              saved: JSON.parse(
                readFileSync(join(reducerRoot, "result.json"), "utf8"),
              ) as ScanDraft,
            }
          : {}),
      };
    } finally {
      child.stdin.end();
      await new Promise<void>((resolve) => {
        child.once("close", () => resolve());
      });
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

describe("Deep scan reducer finding retention", () => {
  test("rejects one omitted finding from an accepted Standard scan", async () => {
    const first = finding("first", 10);
    const second = finding("second", 20);
    const result = await recordReduction(
      [draft([first, second])],
      draft([first]),
    );

    expect(result.accepted).toBe(false);
    expect(result.message).toMatch(/omitted.*accepted.*finding/iu);
  });

  test("rejects new findings omitted after a previous accepted reduction", async () => {
    const first = finding("first", 10);
    const second = finding("second", 20);
    const result = await recordReduction(
      [draft([second])],
      draft([first]),
      draft([first]),
    );

    expect(result.accepted).toBe(false);
    expect(result.message).toMatch(/omitted.*accepted.*finding/iu);
  });

  test("preserves every previously established finding identity", async () => {
    const first = finding("first", 10);
    const changed = structuredClone(first);
    changed.identity.anchor = "changed-anchor";
    const result = await recordReduction(
      [draft([changed])],
      draft([changed]),
      draft([first]),
    );

    expect(result.accepted).toBe(false);
    expect(result.message).toMatch(/previously accepted finding identity/iu);
  });

  test("accepts duplicate findings with the same stable identity", async () => {
    const first = finding("first", 10);
    const result = await recordReduction(
      [draft([first]), draft([structuredClone(first)])],
      draft([first]),
    );

    expect(result.accepted, result.message).toBe(true);
    expect(result.saved?.findings).toHaveLength(1);
  });

  test("accepts a semantic merge with the same broken root control", async () => {
    const first = finding("first", 10);
    const second = finding("first", 20);
    second.identity.anchor = "independent-worker-anchor";
    const rootControl = {
      path: "src/control.ts",
      startLine: 30,
      endLine: 32,
      role: "root_control",
    };
    first.locations.push(rootControl);
    second.locations.push(structuredClone(rootControl));
    const result = await recordReduction(
      [draft([first, second])],
      draft([first]),
    );

    expect(result.accepted, result.message).toBe(true);
    expect(result.saved?.findings).toHaveLength(1);
  });

  test("rejects merging distinct instances that do not share a root control", async () => {
    const first = finding("first", 10);
    const second = finding("first", 20);
    second.identity.anchor = "distinct-instance";
    first.locations.push({
      path: "src/first-control.ts",
      startLine: 30,
      role: "root_control",
    });
    second.locations.push({
      path: "src/second-control.ts",
      startLine: 40,
      role: "root_control",
    });
    const result = await recordReduction(
      [draft([first, second])],
      draft([first]),
    );

    expect(result.accepted).toBe(false);
    expect(result.message).toMatch(/omitted.*accepted.*finding/iu);
  });
});

describe("Deep scan reducer coverage integrity", () => {
  test("rejects upgrading a partially reviewed worker result to complete", async () => {
    const first = finding("first", 10);
    const partial = coverage({
      completeness: "partial",
      deferred: [{ reason: "The administrator endpoint was not reviewed." }],
    });
    const result = await recordReduction(
      [draft([first], partial)],
      draft([first]),
    );

    expect(result.accepted).toBe(false);
    expect(result.message).toMatch(/partial.*complete/iu);
  });

  test("does not present an unreviewed clean worker result as complete", async () => {
    const partial = coverage({
      completeness: "partial",
      deferred: [{ reason: "The request handler was not reviewed." }],
    });
    const result = await recordReduction([draft([], partial)], draft([]));

    expect(result.accepted).toBe(false);
    expect(result.message).toMatch(/partial.*complete/iu);
  });

  test("retains every deferred proof gap from accepted worker results", async () => {
    const first = finding("first", 10);
    const partial = coverage({
      completeness: "partial",
      deferred: [
        { reason: "The administrator endpoint was not reviewed." },
        { reason: "The upload endpoint was not reviewed." },
      ],
    });
    const incomplete = coverage({
      completeness: "partial",
      deferred: [partial.deferred[0]!],
    });
    const result = await recordReduction(
      [draft([first], partial)],
      draft([first], incomplete),
    );

    expect(result.accepted).toBe(false);
    expect(result.message).toMatch(/deferred/iu);
  });

  test("retains follow-up surfaces, exclusions, and open questions", async () => {
    const first = finding("first", 10);
    const partial = coverage({
      completeness: "partial",
      surfaces: [
        {
          id: "admin",
          label: "Administrator endpoint",
          disposition: "needs_follow_up",
        },
      ],
      explicitExclusions: [
        { pattern: "generated/**", reason: "Generated source was excluded." },
      ],
      openQuestions: ["Does the endpoint require authentication?"],
    });

    for (const incomplete of [
      { ...partial, surfaces: [] },
      { ...partial, explicitExclusions: [] },
      { ...partial, openQuestions: [] },
    ]) {
      const result = await recordReduction(
        [draft([first], partial)],
        draft([first], incomplete),
      );
      expect(result.accepted, result.message).toBe(false);
    }
  });

  test("preserves partial coverage from a previous accepted reduction", async () => {
    const first = finding("first", 10);
    const second = finding("second", 20);
    const partial = coverage({
      completeness: "partial",
      deferred: [{ reason: "The administrator endpoint was not reviewed." }],
    });
    const result = await recordReduction(
      [draft([second])],
      draft([first, second]),
      draft([first], partial),
    );

    expect(result.accepted).toBe(false);
    expect(result.message).toMatch(/partial.*complete/iu);
  });
});

describe("Deep scan reducer threat-model integrity", () => {
  test("rejects an aggregate that drops an accepted worker threat model", async () => {
    const first = finding("first", 10);
    const threatModel = {
      summary:
        "The public administrator endpoint is an explicit trust boundary.",
      trustBoundaries: ["administrator endpoint"],
    };
    const result = await recordReduction(
      [draft([first], coverage(), threatModel)],
      draft([first]),
    );

    expect(result.accepted).toBe(false);
    expect(result.message).toMatch(/threat model/iu);
  });

  test("preserves an unchanged shared threat model", async () => {
    const first = finding("first", 10);
    const threatModel = {
      summary:
        "The public administrator endpoint is an explicit trust boundary.",
      trustBoundaries: ["administrator endpoint"],
    };
    const rewritten = {
      summary: "A generic endpoint exists.",
      trustBoundaries: ["administrator endpoint"],
    };
    const result = await recordReduction(
      [draft([first], coverage(), threatModel)],
      draft([first], coverage(), rewritten),
    );

    expect(result.accepted).toBe(false);
    expect(result.message).toMatch(/shared threat model/iu);
  });

  test("preserves structured context when worker threat models differ", async () => {
    const first = finding("first", 10);
    const second = finding("second", 20);
    const firstThreatModel = {
      summary: "The public request boundary protects account records.",
      assets: ["account records"],
    };
    const secondThreatModel = {
      summary: "The internal job boundary protects audit records.",
      assets: ["audit records"],
    };
    const result = await recordReduction(
      [
        draft([first], coverage(), firstThreatModel),
        draft([second], coverage(), secondThreatModel),
      ],
      draft([first, second], coverage(), firstThreatModel),
    );

    expect(result.accepted).toBe(false);
    expect(result.message).toMatch(/threat.model.*assets/iu);
  });

  test("accepts a complete aggregate that preserves worker evidence", async () => {
    const first = finding("first", 10);
    const second = finding("second", 20);
    const partial = coverage({
      completeness: "partial",
      surfaces: [
        {
          id: "admin",
          label: "Administrator endpoint",
          disposition: "needs_follow_up",
        },
      ],
      explicitExclusions: [
        { pattern: "generated/**", reason: "Generated source was excluded." },
      ],
      deferred: [{ reason: "The administrator endpoint was not reviewed." }],
      openQuestions: ["Does the endpoint require authentication?"],
    });
    const threatModel = {
      summary:
        "The public administrator endpoint is an explicit trust boundary.",
      trustBoundaries: ["administrator endpoint"],
    };
    const aggregate = draft([first, second], partial, threatModel);
    const result = await recordReduction(
      [
        draft([first], partial, threatModel),
        draft([second], coverage(), threatModel),
      ],
      aggregate,
    );

    expect(result.accepted, result.message).toBe(true);
    expect(result.saved).toEqual(aggregate);
  });
});

test("revalidates every accepted worker when recovering a Deep reduction", async () => {
  const runtime = await loadBundledRuntime();
  const source =
    /async function validateReducerArtifacts\([^\n]*\) \{[\s\S]*?\n\}/u.exec(
      runtime,
    )?.[0];
  expect(source).toBeDefined();

  const first = finding("first", 10);
  const sourceDraft = draft([first]);
  const aggregate = draft([first]);
  const validatedSources: ScanDraft[][] = [];
  const validate = new Function(
    "requireRegularFile",
    "parseStoredScanDraft",
    "readJsonObject",
    "validateRetainedFindings",
    "findingIdentity",
    `${source}\nreturn validateReducerArtifacts;`,
  )(
    async () => {},
    (value: ScanDraft) => value,
    async (path: string) => (path === "worker.json" ? sourceDraft : aggregate),
    (_result: ScanDraft, sources: ScanDraft[]) => {
      validatedSources.push(sources);
    },
    (item: Finding) => item.identity.anchor,
  ) as (
    input: Record<string, unknown>,
    expectedScanId: string,
  ) => Promise<{ newFindings: number }>;

  await validate(
    {
      artifacts: { workersRoot: "workers", dedupRoot: "reducers" },
      artifactDir: "reducer",
      resultPath: "result.json",
      reducerId: "reducer",
      sourceDiscoveries: [{ resultPath: "worker.json" }],
    },
    scanId,
  );

  expect(validatedSources).toEqual([[sourceDraft]]);
});

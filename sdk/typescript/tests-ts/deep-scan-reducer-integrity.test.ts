import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { createRequire } from "node:module";
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
  summary: string;
  remediation: string;
  severity: {
    level: "critical" | "high" | "medium" | "low" | "informational";
    score?: number;
    scoringSystem?: string;
    vector?: string;
    rationale?: string;
    changeConditions?: string;
  };
  confidence: { level: "high" | "medium" | "low"; rationale: string };
  taxonomy: { category: string; cwe: string[] };
  provenance: { source: string };
  identity: { anchor: string; instance?: string };
  locations: Location[];
  attackPath?: Record<string, unknown> | null;
  rootCause?: string | { summary: string; evidenceRefs?: string[] };
  validation?: Record<string, unknown> | null;
  writeup?: { reportPath: string };
  codeEvidence?: Array<{
    id: string;
    label: string;
    path: string;
    startLine: number;
    code: string;
    explanation: string;
  }>;
  extensions?: Record<string, unknown>;
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
    receiptRefs?: string[];
    riskArea?: string;
    notes?: string;
  }>;
  explicitExclusions: Array<{ pattern: string; reason: string }>;
  deferred: Array<{
    id?: string;
    candidateId?: string;
    reason: string;
    paths?: string[];
    surfaceIds?: string[];
  }>;
  openQuestions?: Array<string | { question: string; followUpPrompt?: string }>;
};

type ThreatModel = {
  summary: string;
  assets?: string[];
  trustBoundaries?: string[];
  attackerCapabilities?: string[];
  securityObjectives?: string[];
  assumptions?: string[];
};

type Scope = {
  summary?: string;
  artifactsReviewed?: string[];
  runtimeStatus?: string;
  validationMode?: string;
  context?: string;
  limitations?: string[];
};

type ScanDraft = {
  scanId: string;
  findings: Finding[];
  coverage: Coverage;
  threatModel?: ThreatModel;
  scope?: Scope;
};

type ReducerResponse = {
  accepted: boolean;
  message: string;
  saved?: ScanDraft;
  writeups?: Record<string, string>;
  receipts?: Record<string, string>;
};

const scanId = randomUUID();
const validateAcceptedReduction = createRequire(import.meta.url)(
  join(PLUGIN_ROOT, "mcp/deep-reducer-integrity.cjs"),
).validateDeepReduction as (
  result: ScanDraft,
  sources: ScanDraft[],
  previous: ScanDraft | undefined,
  findingIdentity: (entry: Finding) => string,
) => void;
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
  scope?: Scope,
): ScanDraft {
  return {
    scanId,
    findings,
    coverage: scanCoverage,
    ...(threatModel === undefined ? {} : { threatModel }),
    ...(scope === undefined ? {} : { scope }),
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
  prepare?: (context: {
    scanRoot: string;
    claimedWorkers: Array<{ id: string; resultPath: string }>;
  }) => void,
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
      for (const sourceFinding of source.findings) {
        if (sourceFinding.writeup === undefined) continue;
        const reportPath = join(
          dirname(resultPath),
          sourceFinding.writeup.reportPath,
        );
        mkdirSync(dirname(reportPath), { recursive: true });
        writeFileSync(reportPath, `# ${sourceFinding.title}\n`);
      }
      for (const surface of source.coverage.surfaces) {
        for (const receipt of surface.receiptRefs ?? []) {
          const receiptPath = join(dirname(resultPath), receipt);
          mkdirSync(dirname(receiptPath), { recursive: true });
          writeFileSync(
            receiptPath,
            JSON.stringify({ worker: id, surface: surface.label }),
          );
        }
      }
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
      for (const previousFinding of previous.findings) {
        if (previousFinding.writeup === undefined) continue;
        const reportPath = join(scanRoot, previousFinding.writeup.reportPath);
        mkdirSync(dirname(reportPath), { recursive: true });
        writeFileSync(reportPath, `# ${previousFinding.title}\n`);
      }
      for (const surface of previous.coverage.surfaces) {
        for (const receipt of surface.receiptRefs ?? []) {
          const receiptPath = join(scanRoot, receipt);
          mkdirSync(dirname(receiptPath), { recursive: true });
          writeFileSync(
            receiptPath,
            JSON.stringify({ worker: "previous", surface: surface.label }),
          );
        }
      }
    }
    prepare?.({ scanRoot, claimedWorkers });

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
      const saved = accepted
        ? (JSON.parse(
            readFileSync(join(reducerRoot, "result.json"), "utf8"),
          ) as ScanDraft)
        : undefined;
      if (saved !== undefined) {
        validateAcceptedReduction(saved, sources, previous, (entry) => {
          if (entry.identity !== undefined) {
            return JSON.stringify([
              entry.ruleId,
              entry.identity.anchor,
              entry.identity.instance ?? null,
            ]);
          }
          const location = entry.locations[0]!;
          return JSON.stringify([
            entry.ruleId,
            [location.path, location.startLine, location.endLine ?? null],
          ]);
        });
      }

      return {
        accepted,
        message,
        ...(saved !== undefined
          ? {
              saved,
              writeups: Object.fromEntries(
                saved.findings.some(
                  (sourceFinding) => sourceFinding.writeup !== undefined,
                )
                  ? readdirSync(join(scanRoot, "findings"), {
                      recursive: true,
                    })
                      .filter((entry) => String(entry).endsWith(".md"))
                      .map((entry) => {
                        const path = `findings/${String(entry).replaceAll("\\", "/")}`;
                        return [
                          path,
                          readFileSync(join(scanRoot, path), "utf8"),
                        ];
                      })
                  : [],
              ),
              receipts: Object.fromEntries(
                saved.coverage.surfaces.flatMap((surface) =>
                  (surface.receiptRefs ?? []).map((receipt) => [
                    receipt,
                    readFileSync(join(scanRoot, receipt), "utf8"),
                  ]),
                ),
              ),
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
  test("rejects findings never accepted by a Standard scan worker", async () => {
    const accepted = finding("first", 10);
    const invented = finding("invented", 20);
    const result = await recordReduction(
      [draft([accepted])],
      draft([accepted, invented]),
    );

    expect(result.accepted).toBe(false);
    expect(result.message).toMatch(/unsupported.*finding/iu);
  });

  test("rejects invented findings when every worker returned a clean result", async () => {
    const invented = finding("invented", 20);
    const result = await recordReduction([draft([])], draft([invented]));

    expect(result.accepted).toBe(false);
    expect(result.message).toMatch(/unsupported.*finding/iu);
  });

  test("rejects duplicate aggregate finding identities", async () => {
    const accepted = finding("first", 10);
    const result = await recordReduction(
      [draft([accepted])],
      draft([accepted, structuredClone(accepted)]),
    );

    expect(result.accepted).toBe(false);
    expect(result.message).toMatch(/duplicate.*finding identity/iu);
  });

  test("rejects unsupported changes to accepted finding titles", async () => {
    const accepted = finding("first", 10);
    const changed = {
      ...accepted,
      title: "Invented production compromise and credential exfiltration",
    };

    const result = await recordReduction([draft([accepted])], draft([changed]));

    expect(result.accepted).toBe(false);
    expect(result.message).toMatch(/unsupported|evidence/iu);
  });

  test("combines differing accepted titles without inventing finding claims", async () => {
    const first = finding("first", 10);
    const second = structuredClone(first);
    second.title = "Missing administrator authorization";
    const merged = {
      ...first,
      title: `${first.title}; ${second.title}`,
    };

    const result = await recordReduction(
      [draft([first]), draft([second])],
      draft([merged]),
    );

    expect(result.accepted, result.message).toBe(true);
    expect(result.saved?.findings[0]?.title).toBe(merged.title);
  });

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

  test("retains distinct evidence when workers share a finding identity", async () => {
    const first = finding("first", 10);
    const second = finding("first", 20);
    const result = await recordReduction(
      [draft([first]), draft([second])],
      draft([first]),
    );

    expect(result.accepted).toBe(false);
    expect(result.message).toMatch(/evidence/iu);
  });

  test("accepts shared identities after merging every affected location", async () => {
    const first = finding("first", 10);
    const second = finding("first", 20);
    const merged = structuredClone(first);
    merged.locations.push(second.locations[0]!);
    const result = await recordReduction(
      [draft([first]), draft([second])],
      draft([merged]),
    );

    expect(result.accepted, result.message).toBe(true);
    expect(result.saved?.findings[0]?.locations).toHaveLength(2);
  });

  test("retains source attack-path and remediation evidence during merging", async () => {
    const first = finding("first", 10);
    const second = structuredClone(first);
    second.attackPath = {
      summary: "An external request reaches the privileged handler.",
    };
    second.remediation =
      "Enforce authentication before the privileged handler.";

    for (const merged of [
      { ...first, remediation: second.remediation },
      { ...first, attackPath: second.attackPath },
    ]) {
      const result = await recordReduction(
        [draft([first]), draft([second])],
        draft([merged]),
      );
      expect(result.accepted, result.message).toBe(false);
      expect(result.message).toMatch(/evidence/iu);
    }
  });

  test("preserves distinct code-evidence records for a shared finding", async () => {
    const first = finding("first", 10);
    const second = structuredClone(first);
    second.codeEvidence = [
      {
        id: "administrator-control",
        label: "Administrator control",
        path: "src/first.ts",
        startLine: 10,
        code: "handleAdministratorRequest(request)",
        explanation: "The privileged request reaches the handler unchecked.",
      },
    ];
    const result = await recordReduction(
      [draft([first]), draft([second])],
      draft([first]),
    );

    expect(result.accepted).toBe(false);
    expect(result.message).toMatch(/evidence/iu);
  });

  test("retains validated scan-local finding writeups", async () => {
    const source = finding("first", 10);
    source.writeup = {
      reportPath: "findings/first-finding/first-finding.md",
    };
    const changed = structuredClone(source);
    delete changed.writeup;
    const result = await recordReduction([draft([source])], draft([changed]));

    expect(result.accepted).toBe(false);
    expect(result.message).toMatch(/evidence/iu);
  });

  test("relocates accepted worker finding writeups into the parent scan", async () => {
    const source = finding("first", 10);
    source.writeup = {
      reportPath: "findings/first-finding/first-finding.md",
    };

    const result = await recordReduction([draft([source])], draft([source]));

    expect(result.accepted, result.message).toBe(true);
    expect(result.writeups?.[source.writeup.reportPath]).toBe(
      `# ${source.title}\n`,
    );
    expect(result.saved?.findings[0]?.writeup).toEqual(source.writeup);
  });

  test("retains writeups copied by a previous accepted Deep reduction", async () => {
    const previous = finding("first", 10);
    previous.writeup = {
      reportPath: "findings/first-finding/first-finding.md",
    };
    const current = structuredClone(previous);
    delete current.writeup;

    const result = await recordReduction(
      [draft([current])],
      draft([previous]),
      draft([previous]),
    );

    expect(result.accepted, result.message).toBe(true);
    expect(result.writeups?.[previous.writeup.reportPath]).toBe(
      `# ${previous.title}\n`,
    );
  });

  test("preserves conflicting worker writeups under distinct parent-local paths", async () => {
    const first = finding("first", 10);
    first.writeup = {
      reportPath: "findings/first-finding/first-finding.md",
    };
    const second = structuredClone(first);
    second.title = "A different accepted writeup for the same finding";

    const result = await recordReduction(
      [draft([first]), draft([second])],
      draft([{ ...first, title: `${first.title}; ${second.title}` }]),
    );

    expect(result.accepted, result.message).toBe(true);
    expect(result.writeups).toEqual({
      "findings/first-finding/first-finding.md": `# ${first.title}\n`,
      "findings/first-finding-2/first-finding-2.md": `# ${second.title}\n`,
    });
  });

  test("remaps a writeup path shared by distinct accepted findings", async () => {
    const first = finding("first", 10);
    first.writeup = {
      reportPath: "findings/shared-finding/shared-finding.md",
    };
    const second = finding("second", 20);
    second.writeup = structuredClone(first.writeup);

    const result = await recordReduction(
      [draft([first]), draft([second])],
      draft([first, second]),
    );

    expect(result.accepted, result.message).toBe(true);
    expect(
      result.saved?.findings.map((entry) => entry.writeup?.reportPath),
    ).toEqual([
      "findings/shared-finding/shared-finding.md",
      "findings/shared-finding-2/shared-finding-2.md",
    ]);
    expect(result.writeups).toEqual({
      "findings/shared-finding/shared-finding.md": `# ${first.title}\n`,
      "findings/shared-finding-2/shared-finding-2.md": `# ${second.title}\n`,
    });
  });

  test("rejects accepted worker writeups that escape their worker directory", async () => {
    const source = finding("first", 10);
    source.writeup = {
      reportPath: "findings/first-finding/first-finding.md",
    };

    const result = await recordReduction(
      [draft([source])],
      draft([source]),
      undefined,
      ({ scanRoot, claimedWorkers }) => {
        const workerFindings = join(
          dirname(claimedWorkers[0]!.resultPath),
          "findings",
        );
        const outsideWorker = join(scanRoot, "outside-worker");
        const redirectedFinding = join(outsideWorker, "first-finding");
        mkdirSync(redirectedFinding, { recursive: true });
        writeFileSync(
          join(redirectedFinding, "first-finding.md"),
          "# Outside the accepted worker\n",
        );
        rmSync(workerFindings, { recursive: true });
        symlinkSync(
          outsideWorker,
          workerFindings,
          process.platform === "win32" ? "junction" : "dir",
        );
      },
    );

    expect(result.accepted).toBe(false);
    expect(result.message).toMatch(/escaped|symlink|canonical/iu);
  });

  test("rejects parent finding directories that redirect writeups outside the scan", async () => {
    const source = finding("first", 10);
    source.writeup = {
      reportPath: "findings/first-finding/first-finding.md",
    };

    const result = await recordReduction(
      [draft([source])],
      draft([source]),
      undefined,
      ({ scanRoot }) => {
        const outsideScan = join(dirname(scanRoot), "outside-scan");
        mkdirSync(outsideScan);
        symlinkSync(
          outsideScan,
          join(scanRoot, "findings"),
          process.platform === "win32" ? "junction" : "dir",
        );
      },
    );

    expect(result.accepted).toBe(false);
    expect(result.message).toMatch(/escaped|symlink|canonical/iu);
  });

  test("combines explanations for the same canonical source evidence", async () => {
    const first = finding("first", 10);
    const second = finding("first", 10);
    const baseEvidence = {
      id: "administrator-control",
      path: "src/first.ts",
      startLine: 10,
      code: "handleAdministratorRequest(request)",
    };
    first.codeEvidence = [
      {
        ...baseEvidence,
        label: "Unchecked administrator operation",
        explanation: "The request reaches an administrator operation.",
      },
    ];
    second.codeEvidence = [
      {
        ...baseEvidence,
        label: "Missing authorization guard",
        explanation: "The operation does not check authorization.",
      },
    ];
    const merged: Finding = {
      ...first,
      codeEvidence: [
        {
          ...baseEvidence,
          label: `${first.codeEvidence[0]!.label}; ${second.codeEvidence[0]!.label}`,
          explanation: `${first.codeEvidence[0]!.explanation} ${second.codeEvidence[0]!.explanation}`,
        },
      ],
    };
    const result = await recordReduction(
      [draft([first]), draft([second])],
      draft([merged]),
    );

    expect(result.accepted, result.message).toBe(true);
  });

  test("rejects unsupported severity changes and discarded rating details", async () => {
    const source = finding("first", 10);
    source.severity = {
      level: "medium",
      score: 5,
      scoringSystem: "CVSS:3.1",
      vector: "CVSS:3.1/AV:N/AC:H",
      rationale: "Exploitation requires an authenticated request.",
      changeConditions: "Impact increases only if authentication is removed.",
    };

    for (const changed of [
      { ...source.severity, level: "critical" as const },
      { ...source.severity, score: 9 },
      { ...source.severity, scoringSystem: "CVSS:4.0" },
      { ...source.severity, vector: "CVSS:3.1/AV:N/AC:L" },
      { ...source.severity, rationale: "No supporting rationale." },
      { ...source.severity, changeConditions: "No relevant conditions." },
    ]) {
      const result = await recordReduction(
        [draft([source])],
        draft([{ ...source, severity: changed }]),
      );
      expect(result.accepted, result.message).toBe(false);
      expect(result.message).toMatch(/evidence/iu);
    }
  });

  test("rejects unsupported confidence promotion", async () => {
    const source = finding("first", 10);
    source.confidence = {
      level: "low",
      rationale: "Only incomplete static evidence is available.",
    };
    const changed: Finding = {
      ...source,
      confidence: { ...source.confidence, level: "high" },
    };
    const result = await recordReduction([draft([source])], draft([changed]));

    expect(result.accepted).toBe(false);
    expect(result.message).toMatch(/evidence/iu);
  });

  test("reconciles conflicting accepted severity and confidence ratings", async () => {
    const lower = finding("first", 10);
    lower.severity = {
      level: "medium",
      score: 5,
      scoringSystem: "CVSS:3.1",
      rationale: "The initial worker observed a limited security impact.",
      changeConditions: "Impact increases if privileged input is reachable.",
    };
    lower.confidence = {
      level: "low",
      rationale: "The initial worker had incomplete reachability evidence.",
    };
    const higher = structuredClone(lower);
    higher.severity = {
      level: "high",
      score: 8,
      scoringSystem: "CVSS:3.1",
      vector: "CVSS:3.1/AV:N/AC:L",
      rationale: "The second worker confirmed privileged account impact.",
      changeConditions: "The vulnerable route is reachable without login.",
    };
    higher.confidence = {
      level: "high",
      rationale: "The second worker verified the complete source-to-sink path.",
    };
    const merged: Finding = {
      ...higher,
      severity: {
        ...higher.severity,
        rationale: `${lower.severity.rationale} ${higher.severity.rationale}`,
        changeConditions: `${lower.severity.changeConditions} ${higher.severity.changeConditions}`,
      },
      confidence: {
        ...higher.confidence,
        rationale: `${lower.confidence.rationale} ${higher.confidence.rationale}`,
      },
    };

    for (const sources of [
      [draft([lower]), draft([higher])],
      [draft([higher]), draft([lower])],
    ]) {
      const result = await recordReduction(sources, draft([merged]));
      expect(result.accepted, result.message).toBe(true);
      expect(result.saved?.findings[0]?.severity.level).toBe("high");
      expect(result.saved?.findings[0]?.confidence.level).toBe("high");
    }
  });

  test("rejects weaker duplicate ratings after a stronger worker result", async () => {
    const lower = finding("first", 10);
    lower.severity = { level: "medium", rationale: "Limited initial impact." };
    lower.confidence = {
      level: "low",
      rationale: "Initial validation was incomplete.",
    };
    const higher = structuredClone(lower);
    higher.severity = {
      level: "high",
      rationale: "Confirmed privileged impact.",
    };
    higher.confidence = {
      level: "high",
      rationale: "The vulnerable request was validated.",
    };

    for (const changed of [
      {
        ...higher,
        severity: {
          ...lower.severity,
          rationale: `${lower.severity.rationale} ${higher.severity.rationale}`,
        },
        confidence: {
          ...higher.confidence,
          rationale: `${lower.confidence.rationale} ${higher.confidence.rationale}`,
        },
      },
      {
        ...higher,
        severity: {
          ...higher.severity,
          rationale: `${lower.severity.rationale} ${higher.severity.rationale}`,
        },
        confidence: {
          ...lower.confidence,
          rationale: `${lower.confidence.rationale} ${higher.confidence.rationale}`,
        },
      },
    ]) {
      const result = await recordReduction(
        [draft([lower]), draft([higher])],
        draft([changed]),
      );
      expect(result.accepted).toBe(false);
      expect(result.message).toMatch(/evidence/iu);
    }
  });

  test("retains the strongest accepted score when duplicate severity levels match", async () => {
    const lower = finding("first", 10);
    lower.severity = {
      level: "high",
      score: 7,
      scoringSystem: "CVSS:3.1",
      rationale: "The first worker calculated a lower score.",
    };
    const higher = structuredClone(lower);
    higher.severity = {
      level: "high",
      score: 8,
      scoringSystem: "CVSS:3.1",
      rationale: "The second worker identified additional impact.",
    };
    const merged: Finding = {
      ...higher,
      severity: {
        ...higher.severity,
        rationale: `${lower.severity.rationale} ${higher.severity.rationale}`,
      },
    };

    const accepted = await recordReduction(
      [draft([lower]), draft([higher])],
      draft([merged]),
    );
    expect(accepted.accepted, accepted.message).toBe(true);

    const rejected = await recordReduction(
      [draft([lower]), draft([higher])],
      draft([{ ...merged, severity: { ...merged.severity, score: 7 } }]),
    );
    expect(rejected.accepted).toBe(false);
    expect(rejected.message).toMatch(/evidence/iu);
  });

  test("reconciles conflicting accepted taxonomy and provenance deterministically", async () => {
    const lower = finding("first", 10);
    lower.severity = { ...lower.severity, level: "medium" };
    lower.taxonomy = {
      category: "missing-authentication",
      cwe: ["CWE-306"],
    };
    lower.provenance = { source: "initial_review" };
    const higher = structuredClone(lower);
    higher.severity = { ...higher.severity, level: "high" };
    higher.taxonomy = {
      category: "missing-authorization",
      cwe: ["CWE-862"],
    };
    higher.provenance = { source: "validated_review" };
    const merged: Finding = {
      ...higher,
      taxonomy: {
        category: "missing-authorization",
        cwe: ["CWE-306", "CWE-862"],
      },
    };

    for (const sources of [
      [draft([lower]), draft([higher])],
      [draft([higher]), draft([lower])],
    ]) {
      const result = await recordReduction(sources, draft([merged]));
      expect(result.accepted, result.message).toBe(true);
      expect(result.saved?.findings[0]?.taxonomy).toEqual(merged.taxonomy);
      expect(result.saved?.findings[0]?.provenance).toEqual(higher.provenance);
    }

    const unsupported = await recordReduction(
      [draft([lower]), draft([higher])],
      draft([
        {
          ...merged,
          taxonomy: { category: "invented-control", cwe: ["CWE-306"] },
        },
      ]),
    );
    expect(unsupported.accepted).toBe(false);
    expect(unsupported.message).toMatch(/unsupported|evidence/iu);
  });

  test("rejects invented validation and attack paths for explicit null evidence", async () => {
    const source = finding("first", 10);
    source.validation = null;
    source.attackPath = null;

    for (const changed of [
      {
        ...source,
        validation: { summary: "Invented dynamic validation." },
      },
      {
        ...source,
        attackPath: { summary: "Invented attacker reachability." },
      },
    ]) {
      const result = await recordReduction([draft([source])], draft([changed]));
      expect(result.accepted, result.message).toBe(false);
      expect(result.message).toMatch(/evidence/iu);
    }
  });

  test("rejects invented finding proof omitted by every accepted worker", async () => {
    const source = finding("first", 10);
    delete source.validation;
    delete source.attackPath;
    delete source.rootCause;

    for (const changed of [
      {
        ...source,
        validation: { summary: "Invented dynamic validation." },
      },
      {
        ...source,
        attackPath: { summary: "Invented attacker reachability." },
      },
      {
        ...source,
        rootCause: "Invented root-cause evidence.",
      },
      {
        ...source,
        writeup: { reportPath: "findings/invented/invented.md" },
      },
    ]) {
      const result = await recordReduction([draft([source])], draft([changed]));
      expect(result.accepted).toBe(false);
      expect(result.message).toMatch(/unsupported|evidence/iu);
    }
  });

  test("accepts omitted proof when another matching worker established it", async () => {
    const incomplete = finding("first", 10);
    delete incomplete.validation;
    delete incomplete.attackPath;
    delete incomplete.rootCause;
    const validated = structuredClone(incomplete);
    validated.validation = {
      method: "Static source trace.",
      summary: "The privileged request reaches the unchecked handler.",
    };
    validated.attackPath = {
      summary: "An external request reaches the privileged handler.",
    };
    validated.rootCause =
      "The privileged handler does not check authorization.";

    const result = await recordReduction(
      [draft([incomplete]), draft([validated])],
      draft([validated]),
    );

    expect(result.accepted, result.message).toBe(true);
    expect(result.saved?.findings[0]?.validation).toEqual(validated.validation);
    expect(result.saved?.findings[0]?.attackPath).toEqual(validated.attackPath);
    expect(result.saved?.findings[0]?.rootCause).toEqual(validated.rootCause);
  });

  test("rejects invented proof appended to accepted validation and attack paths", async () => {
    const source = finding("first", 10);
    source.validation = {
      method: "Static source review.",
      summary: "The administrator route reaches a privileged handler.",
    };
    source.attackPath = {
      summary: "A crafted request reaches a privileged operation.",
      reachability: { attacker: "An external unauthenticated caller." },
    };

    for (const changed of [
      {
        ...source,
        validation: {
          ...source.validation,
          exploitExecuted: "An exploit was executed against a live endpoint.",
        },
      },
      {
        ...source,
        attackPath: {
          ...source.attackPath,
          reachability: {
            ...(source.attackPath["reachability"] as object),
            exploitExecuted: "A live administrator account was modified.",
          },
        },
      },
    ]) {
      const result = await recordReduction([draft([source])], draft([changed]));
      expect(result.accepted).toBe(false);
      expect(result.message).toMatch(/unsupported|evidence/iu);
    }
  });

  test("rejects invented claims added to accepted finding narratives", async () => {
    const source = finding("first", 10);
    source.validation = {
      method: "Static source review.",
      summary: "The administrator route reaches a privileged handler.",
    };
    source.attackPath = {
      summary: "A request reaches a privileged operation.",
      reachability: { attacker: "An authenticated internal caller." },
    };
    source.rootCause = "The handler lacks a role check.";
    source.severity = {
      ...source.severity,
      rationale: "Static source review found a missing role check.",
    };

    for (const changed of [
      {
        ...source,
        summary: `Dynamic exploitation succeeded. ${source.summary}`,
      },
      {
        ...source,
        remediation: `Delete production credentials. ${source.remediation}`,
      },
      {
        ...source,
        validation: {
          ...source.validation,
          summary: `Dynamic exploitation succeeded. ${source.validation["summary"]}`,
        },
      },
      {
        ...source,
        attackPath: {
          ...source.attackPath,
          reachability: {
            attacker: `An unauthenticated remote attacker. ${(source.attackPath["reachability"] as { attacker: string }).attacker}`,
          },
        },
      },
      {
        ...source,
        rootCause: `Production exploitation succeeded. ${source.rootCause}`,
      },
      {
        ...source,
        severity: {
          ...source.severity,
          rationale: `Live exploitation was confirmed. ${source.severity.rationale}`,
        },
      },
      {
        ...source,
        confidence: {
          ...source.confidence,
          rationale: `Live exploitation was confirmed. ${source.confidence.rationale}`,
        },
      },
    ]) {
      const result = await recordReduction([draft([source])], draft([changed]));
      expect(result.accepted).toBe(false);
      expect(result.message).toMatch(/unsupported|evidence/iu);
    }
  });

  test("rejects unaccepted locations and code-evidence records", async () => {
    const source = finding("first", 10);

    for (const changed of [
      {
        ...source,
        locations: [
          ...source.locations,
          { path: "src/invented.ts", startLine: 90, role: "sink" },
        ],
      },
      {
        ...source,
        codeEvidence: [
          {
            id: "invented-code-evidence",
            label: "Invented privileged operation",
            path: "src/invented.ts",
            startLine: 90,
            code: "performInventedOperation(request)",
            explanation: "This operation was not accepted by any worker.",
          },
        ],
      },
    ]) {
      const result = await recordReduction([draft([source])], draft([changed]));
      expect(result.accepted).toBe(false);
      expect(result.message).toMatch(/unsupported|evidence/iu);
    }
  });

  test("accepts validation already established by another matching worker", async () => {
    const unvalidated = finding("first", 10);
    unvalidated.validation = null;
    const validated = structuredClone(unvalidated);
    validated.validation = {
      method: "Static source trace.",
      summary: "The privileged request reaches the unchecked handler.",
    };

    const result = await recordReduction(
      [draft([unvalidated]), draft([validated])],
      draft([validated]),
    );

    expect(result.accepted, result.message).toBe(true);
    expect(result.saved?.findings[0]?.validation).toEqual(validated.validation);
  });

  test("merges distinct canonical attack-path narratives without changing decisions", async () => {
    const first = finding("first", 10);
    const second = finding("first", 10);
    first.attackPath = {
      summary: "The public request reaches the administrator route.",
      dataflow: {
        source: "An untrusted request parameter.",
        sink: "The administrator operation.",
      },
      reachability: {
        attacker: "An external unauthenticated caller.",
        entrypoint: "The public request endpoint.",
      },
      impact: { level: "high", why: "The account record is modified." },
    };
    second.attackPath = {
      summary: "A crafted request reaches the privileged operation.",
      dataflow: {
        source: "A crafted administrator request.",
        sink: "The privileged account update.",
      },
      reachability: {
        attacker: "A caller outside the administrator trust boundary.",
        entrypoint: "The externally reachable administrator route.",
      },
      impact: { level: "high", why: "Administrator state is overwritten." },
    };
    const firstDataflow = first.attackPath["dataflow"] as Record<
      string,
      string
    >;
    const secondDataflow = second.attackPath["dataflow"] as Record<
      string,
      string
    >;
    const firstReachability = first.attackPath["reachability"] as Record<
      string,
      string
    >;
    const secondReachability = second.attackPath["reachability"] as Record<
      string,
      string
    >;
    const firstImpact = first.attackPath["impact"] as Record<string, string>;
    const secondImpact = second.attackPath["impact"] as Record<string, string>;
    const merged: Finding = {
      ...first,
      attackPath: {
        summary: `${first.attackPath["summary"]} ${second.attackPath["summary"]}`,
        dataflow: {
          source: `${firstDataflow["source"]} ${secondDataflow["source"]}`,
          sink: `${firstDataflow["sink"]} ${secondDataflow["sink"]}`,
        },
        reachability: {
          attacker: `${firstReachability["attacker"]} ${secondReachability["attacker"]}`,
          entrypoint: `${firstReachability["entrypoint"]} ${secondReachability["entrypoint"]}`,
        },
        impact: {
          level: "high",
          why: `${firstImpact["why"]} ${secondImpact["why"]}`,
        },
      },
    };

    const accepted = await recordReduction(
      [draft([first]), draft([second])],
      draft([merged]),
    );
    expect(accepted.accepted, accepted.message).toBe(true);

    const changedDecision: Finding = {
      ...merged,
      attackPath: {
        ...merged.attackPath,
        impact: { ...(merged.attackPath!["impact"] as object), level: "low" },
      },
    };
    const rejected = await recordReduction(
      [draft([first]), draft([second])],
      draft([changedDecision]),
    );
    expect(rejected.accepted).toBe(false);
    expect(rejected.message).toMatch(/evidence/iu);
  });

  test("preserves the accepted source-to-sink order in attack-path steps", async () => {
    const source = finding("first", 10);
    source.attackPath = {
      summary: "An external request reaches the privileged handler.",
      steps: [
        { description: "Read the untrusted request parameter." },
        {
          description: "Forward the parameter into the administrator handler.",
        },
        { description: "Perform the privileged account operation." },
      ],
    };

    const reversed: Finding = {
      ...source,
      attackPath: {
        ...source.attackPath,
        steps: [...(source.attackPath["steps"] as object[])].reverse(),
      },
    };
    const result = await recordReduction([draft([source])], draft([reversed]));

    expect(result.accepted).toBe(false);
    expect(result.message).toMatch(/evidence/iu);
  });

  test("merges ordered worker attack-path steps without reversing either trace", async () => {
    const first = finding("first", 10);
    first.attackPath = {
      summary: "The request reaches a privileged account operation.",
      steps: [
        "Read the external request.",
        "Perform the privileged operation.",
      ],
    };
    const second = structuredClone(first);
    second.attackPath = {
      summary: first.attackPath["summary"],
      steps: [
        "Validate the request shape.",
        "Perform the privileged operation.",
      ],
    };
    const merged: Finding = {
      ...first,
      attackPath: {
        ...first.attackPath,
        steps: [
          "Read the external request.",
          "Validate the request shape.",
          "Perform the privileged operation.",
        ],
      },
    };

    const result = await recordReduction(
      [draft([first]), draft([second])],
      draft([merged]),
    );

    expect(result.accepted, result.message).toBe(true);
  });

  test("combines plain-text and structured root-cause representations", async () => {
    const plain = finding("first", 10);
    plain.rootCause = "The external request reaches a privileged handler.";
    const structured = finding("first", 10);
    structured.codeEvidence = [
      {
        id: "administrator-control",
        label: "Administrator control",
        path: "src/first.ts",
        startLine: 10,
        code: "handleAdministratorRequest(request)",
        explanation: "The handler omits its authorization check.",
      },
    ];
    structured.rootCause = {
      summary: "The privileged handler omits its authorization check.",
      evidenceRefs: ["administrator-control"],
    };
    const merged: Finding = {
      ...structured,
      rootCause: {
        summary: `${plain.rootCause} ${structured.rootCause.summary}`,
        evidenceRefs: ["administrator-control"],
      },
    };
    const result = await recordReduction(
      [draft([plain]), draft([structured])],
      draft([merged]),
    );

    expect(result.accepted, result.message).toBe(true);
    expect(result.saved?.findings[0]?.rootCause).toEqual(merged.rootCause);
  });

  test("remaps colliding code-evidence identifiers and every evidence reference", async () => {
    const first = finding("first", 10);
    const second = finding("first", 10);
    const firstEvidence = {
      id: "shared-evidence",
      label: "Request source",
      path: "src/first.ts",
      startLine: 10,
      code: "const request = readRequest();",
      explanation: "An untrusted request supplies the input.",
    };
    const secondEvidence = {
      id: "shared-evidence",
      label: "Privileged sink",
      path: "src/first.ts",
      startLine: 20,
      code: "runPrivilegedOperation(request);",
      explanation: "The request reaches a privileged operation.",
    };
    first.codeEvidence = [firstEvidence];
    second.codeEvidence = [secondEvidence];
    first.rootCause = {
      summary: "The source accepts untrusted requests.",
      evidenceRefs: [firstEvidence.id],
    };
    second.rootCause = {
      summary: "The sink omits its authorization guard.",
      evidenceRefs: [secondEvidence.id],
    };
    first.attackPath = {
      summary: "A request enters the application.",
      evidenceRefs: [firstEvidence.id],
    };
    second.attackPath = {
      summary: "The request reaches the privileged operation.",
      evidenceRefs: [secondEvidence.id],
    };

    const renamedEvidence = {
      ...secondEvidence,
      id: "shared-evidence-sink",
    };
    const merged: Finding = {
      ...first,
      codeEvidence: [firstEvidence, renamedEvidence],
      rootCause: {
        summary: `${first.rootCause.summary} ${second.rootCause.summary}`,
        evidenceRefs: [firstEvidence.id, renamedEvidence.id],
      },
      attackPath: {
        summary: `${first.attackPath["summary"]} ${second.attackPath["summary"]}`,
        evidenceRefs: [firstEvidence.id, renamedEvidence.id],
      },
    };

    const missingReference: Finding = {
      ...merged,
      attackPath: {
        ...merged.attackPath,
        evidenceRefs: [firstEvidence.id],
      },
    };
    const rejected = await recordReduction(
      [draft([first]), draft([second])],
      draft([missingReference]),
    );
    expect(rejected.accepted).toBe(false);
    expect(rejected.message).toMatch(/evidence/iu);

    const accepted = await recordReduction(
      [draft([first]), draft([second])],
      draft([merged]),
    );
    expect(accepted.accepted, accepted.message).toBe(true);
    expect(accepted.saved?.findings[0]?.codeEvidence).toHaveLength(2);
  });

  test("preserves the ordered source-to-sink evidence trace", async () => {
    const source = finding("first", 10);
    source.codeEvidence = [
      {
        id: "request-source",
        label: "Request source",
        path: "src/first.ts",
        startLine: 10,
        code: "const request = readRequest();",
        explanation: "The request comes from an external caller.",
      },
      {
        id: "privileged-sink",
        label: "Privileged sink",
        path: "src/first.ts",
        startLine: 20,
        code: "runPrivilegedOperation(request);",
        explanation: "The request reaches the privileged operation.",
      },
    ];
    source.rootCause = {
      summary: "The external request reaches a privileged operation.",
      evidenceRefs: ["request-source", "privileged-sink"],
    };
    const reversed: Finding = {
      ...source,
      rootCause: {
        ...source.rootCause,
        evidenceRefs: ["privileged-sink", "request-source"],
      },
    };
    const result = await recordReduction([draft([source])], draft([reversed]));

    expect(result.accepted).toBe(false);
    expect(result.message).toMatch(/evidence/iu);
  });

  test("retains canonical finding identities carried in extensions", async () => {
    const source = finding("first", 10);
    delete (source as { identity?: Finding["identity"] }).identity;
    source.extensions = { candidateId: "candidate-external-admin" };
    const changed: Finding = { ...source, extensions: {} };
    const rejected = await recordReduction([draft([source])], draft([changed]));

    expect(rejected.accepted).toBe(false);
    expect(rejected.message).toMatch(/evidence/iu);

    const accepted = await recordReduction([draft([source])], draft([source]));
    expect(accepted.accepted, accepted.message).toBe(true);
    expect(accepted.saved?.findings[0]?.extensions).toEqual(source.extensions);
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
    const merged = structuredClone(first);
    merged.locations.push(second.locations[0]!);
    const result = await recordReduction(
      [draft([first, second])],
      draft([merged]),
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
  test("rejects coverage entries never accepted by a Standard worker", async () => {
    const accepted = coverage({
      completeness: "partial",
      surfaces: [
        {
          id: "admin",
          label: "Administrator endpoint",
          disposition: "needs_follow_up",
        },
      ],
      explicitExclusions: [
        { pattern: "generated/**", reason: "Generated code was excluded." },
      ],
      deferred: [
        {
          id: "follow-up-admin",
          reason: "The administrator endpoint needs review.",
          surfaceIds: ["admin"],
        },
      ],
      openQuestions: ["Does the administrator route require authentication?"],
    });

    for (const changed of [
      {
        ...accepted,
        surfaces: [
          ...accepted.surfaces,
          {
            id: "invented",
            label: "Invented reviewed endpoint",
            disposition: "no_issue_found",
          },
        ],
      },
      {
        ...accepted,
        explicitExclusions: [
          ...accepted.explicitExclusions,
          { pattern: "src/admin/**", reason: "Invented exclusion." },
        ],
      },
      {
        ...accepted,
        deferred: [
          ...accepted.deferred,
          { id: "invented-deferred", reason: "Invented proof gap." },
        ],
      },
      {
        ...accepted,
        openQuestions: [
          ...(accepted.openQuestions ?? []),
          "Was an invented security surface reviewed?",
        ],
      },
    ]) {
      const result = await recordReduction(
        [draft([], accepted)],
        draft([], changed),
      );
      expect(result.accepted).toBe(false);
      expect(result.message).toMatch(/unsupported|invented/iu);
    }
  });

  test("relocates accepted worker coverage receipts into the parent scan", async () => {
    const reviewed = coverage({
      surfaces: [
        {
          id: "admin",
          label: "Administrator endpoint",
          disposition: "no_issue_found",
          receiptRefs: ["artifacts/reviews/admin.json"],
        },
      ],
    });

    const result = await recordReduction(
      [draft([], reviewed)],
      draft([], structuredClone(reviewed)),
    );

    expect(result.accepted, result.message).toBe(true);
    expect(result.receipts?.["artifacts/reviews/admin.json"]).toBe(
      JSON.stringify({ worker: "worker-1", surface: "Administrator endpoint" }),
    );
  });

  test("remaps colliding coverage receipts without changing reviewed surfaces", async () => {
    const administrator = coverage({
      surfaces: [
        {
          id: "admin",
          label: "Administrator endpoint",
          disposition: "no_issue_found",
          receiptRefs: ["artifacts/reviews/shared.json"],
        },
      ],
    });
    const upload = coverage({
      surfaces: [
        {
          id: "upload",
          label: "Upload endpoint",
          disposition: "no_issue_found",
          receiptRefs: ["artifacts/reviews/shared.json"],
        },
      ],
    });
    const merged = coverage({
      surfaces: [
        structuredClone(administrator.surfaces[0]!),
        structuredClone(upload.surfaces[0]!),
      ],
    });

    const result = await recordReduction(
      [draft([], administrator), draft([], upload)],
      draft([], merged),
    );

    expect(result.accepted, result.message).toBe(true);
    expect(
      result.saved?.coverage.surfaces.map((surface) => surface.receiptRefs),
    ).toEqual([
      ["artifacts/reviews/shared.json"],
      ["artifacts/reviews/shared-2.json"],
    ]);
    expect(result.receipts).toEqual({
      "artifacts/reviews/shared.json": JSON.stringify({
        worker: "worker-1",
        surface: "Administrator endpoint",
      }),
      "artifacts/reviews/shared-2.json": JSON.stringify({
        worker: "worker-2",
        surface: "Upload endpoint",
      }),
    });
  });

  test("remaps colliding surface identifiers and their deferred references", async () => {
    const administrator = coverage({
      completeness: "partial",
      surfaces: [
        {
          id: "shared",
          label: "Administrator endpoint",
          disposition: "needs_follow_up",
        },
      ],
      deferred: [
        {
          id: "follow-up-admin",
          reason: "Administrator authorization is not confirmed.",
          surfaceIds: ["shared"],
        },
      ],
    });
    const upload = coverage({
      completeness: "partial",
      surfaces: [
        {
          id: "shared",
          label: "Upload endpoint",
          disposition: "needs_follow_up",
        },
      ],
      deferred: [
        {
          id: "follow-up-upload",
          reason: "Upload validation is not confirmed.",
          surfaceIds: ["shared"],
        },
      ],
    });
    const merged = coverage({
      completeness: "partial",
      surfaces: [
        structuredClone(administrator.surfaces[0]!),
        { ...upload.surfaces[0]!, id: "shared-2" },
      ],
      deferred: [
        structuredClone(administrator.deferred[0]!),
        { ...upload.deferred[0]!, surfaceIds: ["shared-2"] },
      ],
    });

    const accepted = await recordReduction(
      [draft([], administrator), draft([], upload)],
      draft([], merged),
    );
    expect(accepted.accepted, accepted.message).toBe(true);
    expect(accepted.saved?.coverage.deferred[1]?.surfaceIds).toEqual([
      "shared-2",
    ]);

    const mismatched = structuredClone(merged);
    mismatched.deferred[1]!.surfaceIds = ["shared"];
    const rejected = await recordReduction(
      [draft([], administrator), draft([], upload)],
      draft([], mismatched),
    );
    expect(rejected.accepted).toBe(false);
    expect(rejected.message).toMatch(/deferred/iu);
  });

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

  test("keeps known partial coverage from becoming unknown", async () => {
    const partial = coverage({ completeness: "partial" });
    const unknown = coverage({ completeness: "unknown" });
    const result = await recordReduction(
      [draft([], partial)],
      draft([], unknown),
    );

    expect(result.accepted).toBe(false);
    expect(result.message).toMatch(/partial.*unknown/iu);
  });

  test("does not upgrade unknown worker coverage to complete", async () => {
    const unknown = coverage({ completeness: "unknown" });
    const result = await recordReduction([draft([], unknown)], draft([]));

    expect(result.accepted).toBe(false);
    expect(result.message).toMatch(/unknown.*complete/iu);
  });

  test("does not invent partial coverage when only unknown coverage exists", async () => {
    const unknown = coverage({ completeness: "unknown" });
    const partial = coverage({ completeness: "partial" });
    const result = await recordReduction(
      [draft([], unknown)],
      draft([], partial),
    );

    expect(result.accepted).toBe(false);
    expect(result.message).toMatch(/unknown.*partial/iu);
  });

  test("keeps fully reviewed worker coverage complete", async () => {
    for (const completeness of ["partial", "unknown"] as const) {
      const result = await recordReduction(
        [draft([])],
        draft([], coverage({ completeness })),
      );
      expect(result.accepted, result.message).toBe(false);
      expect(result.message).toMatch(/complete/iu);
    }
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

  test("preserves deferred-item evidence when its identifier is unchanged", async () => {
    const first = finding("first", 10);
    const item = {
      id: "follow-up-admin",
      reason: "The administrator endpoint was not reviewed.",
      paths: ["src/admin.ts"],
      surfaceIds: ["admin"],
    };
    const partial = coverage({
      completeness: "partial",
      deferred: [item],
    });

    for (const changed of [
      { ...item, reason: "A different review was postponed." },
      { ...item, paths: [] },
      { ...item, surfaceIds: [] },
    ]) {
      const result = await recordReduction(
        [draft([first], partial)],
        draft(
          [first],
          coverage({ completeness: "partial", deferred: [changed] }),
        ),
      );
      expect(result.accepted, result.message).toBe(false);
      expect(result.message).toMatch(/deferred/iu);
    }
  });

  test("preserves matched surface dispositions and review evidence", async () => {
    const first = finding("first", 10);
    const surface = {
      id: "admin",
      label: "Administrator endpoint",
      disposition: "reported",
      receiptRefs: ["artifacts/reviews/admin.json"],
      riskArea: "Authentication",
      notes: "The administrator authentication guard was inspected.",
    };
    const reviewed = coverage({ surfaces: [surface] });

    for (const changed of [
      { ...surface, label: "Different endpoint" },
      { ...surface, disposition: "no_issue_found" },
      { ...surface, receiptRefs: [] },
      { ...surface, riskArea: "Unrelated risk" },
      { ...surface, notes: "No useful notes." },
    ]) {
      const result = await recordReduction(
        [draft([first], reviewed)],
        draft([first], coverage({ surfaces: [changed] })),
      );
      expect(result.accepted, result.message).toBe(false);
      expect(result.message).toMatch(/surface/iu);
    }
  });

  test("preserves concrete follow-up instructions in open questions", async () => {
    const first = finding("first", 10);
    const question = {
      question: "Does the endpoint require authentication?",
      followUpPrompt: "Trace the middleware chain before accepting requests.",
    };
    const partial = coverage({
      completeness: "partial",
      openQuestions: [question],
    });

    for (const changed of [
      question.question,
      { ...question, followUpPrompt: "Perform a different review." },
    ]) {
      const result = await recordReduction(
        [draft([first], partial)],
        draft(
          [first],
          coverage({ completeness: "partial", openQuestions: [changed] }),
        ),
      );
      expect(result.accepted, result.message).toBe(false);
      expect(result.message).toMatch(/question/iu);
    }
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
  test("rejects a threat model never accepted by a Standard worker", async () => {
    const first = finding("first", 10);
    const invented = {
      summary: "Invented attack surface and trust boundary.",
      trustBoundaries: ["an unreviewed administrator endpoint"],
    };

    const result = await recordReduction(
      [draft([first])],
      draft([first], coverage(), invented),
    );

    expect(result.accepted).toBe(false);
    expect(result.message).toMatch(/unsupported.*threat model/iu);
  });

  test("rejects invented evidence appended to differing threat models", async () => {
    const first = finding("first", 10);
    const second = finding("second", 20);
    const firstModel = {
      summary: "Review the administrator trust boundary.",
      trustBoundaries: ["administrator endpoint"],
    };
    const secondModel = {
      summary: "Review the upload trust boundary.",
      trustBoundaries: ["upload endpoint"],
    };
    const invented = {
      summary: `${firstModel.summary} ${secondModel.summary}`,
      trustBoundaries: [
        ...firstModel.trustBoundaries,
        ...secondModel.trustBoundaries,
        "invented unreviewed endpoint",
      ],
    };

    const result = await recordReduction(
      [
        draft([first], coverage(), firstModel),
        draft([second], coverage(), secondModel),
      ],
      draft([first, second], coverage(), invented),
    );

    expect(result.accepted).toBe(false);
    expect(result.message).toMatch(/unsupported.*threat.model/iu);
  });

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
      draft([first, second], coverage(), {
        summary: `${firstThreatModel.summary} ${secondThreatModel.summary}`,
        assets: firstThreatModel.assets,
      }),
    );

    expect(result.accepted).toBe(false);
    expect(result.message).toMatch(/threat.model.*assets/iu);
  });

  test("preserves every source summary when threat models differ", async () => {
    const first = finding("first", 10);
    const second = finding("second", 20);
    const firstThreatModel = {
      summary: "The public request boundary protects account records.",
    };
    const secondThreatModel = {
      summary: "The internal job boundary protects audit records.",
    };
    const result = await recordReduction(
      [
        draft([first], coverage(), firstThreatModel),
        draft([second], coverage(), secondThreatModel),
      ],
      draft([first, second], coverage(), firstThreatModel),
    );

    expect(result.accepted).toBe(false);
    expect(result.message).toMatch(/threat.model.*summary/iu);
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

describe("Deep scan reducer scope integrity", () => {
  test("rejects scope evidence never accepted by a Standard worker", async () => {
    const first = finding("first", 10);
    const invented = {
      summary: "Invented a review outside the assigned scan scope.",
      artifactsReviewed: ["src/unreviewed.ts"],
    };

    const result = await recordReduction(
      [draft([first])],
      draft([first], coverage(), undefined, invented),
    );

    expect(result.accepted).toBe(false);
    expect(result.message).toMatch(/unsupported.*scope/iu);
  });

  test("rejects unreviewed artifacts appended to accepted scope evidence", async () => {
    const first = finding("first", 10);
    const accepted = {
      summary: "Review the administrator endpoint.",
      artifactsReviewed: ["src/admin.ts"],
    };
    const invented = {
      ...accepted,
      artifactsReviewed: [...accepted.artifactsReviewed, "src/unreviewed.ts"],
    };

    const result = await recordReduction(
      [draft([first], coverage(), undefined, accepted)],
      draft([first], coverage(), undefined, invented),
    );

    expect(result.accepted).toBe(false);
    expect(result.message).toMatch(/unsupported.*scope/iu);
  });

  test("rejects omitted worker scope metadata", async () => {
    const first = finding("first", 10);
    const scope = {
      summary: "Review the authentication boundary.",
      artifactsReviewed: ["src/admin.ts"],
      runtimeStatus: "Static review only.",
      validationMode: "Source-backed validation.",
      context: "The administrator handler accepts external requests.",
      limitations: ["The identity provider was unavailable."],
    };
    const result = await recordReduction(
      [draft([first], coverage(), undefined, scope)],
      draft([first]),
    );

    expect(result.accepted).toBe(false);
    expect(result.message).toMatch(/scope/iu);
  });

  test("preserves shared reviewed artifacts and runtime limitations", async () => {
    const first = finding("first", 10);
    const scope = {
      summary: "Review the authentication boundary.",
      artifactsReviewed: ["src/admin.ts"],
      limitations: ["The identity provider was unavailable."],
    };
    const result = await recordReduction(
      [draft([first], coverage(), undefined, scope)],
      draft([first], coverage(), undefined, { ...scope, limitations: [] }),
    );

    expect(result.accepted).toBe(false);
    expect(result.message).toMatch(/scope/iu);
  });

  test("combines distinct worker scope evidence without dropping limitations", async () => {
    const first = finding("first", 10);
    const second = finding("second", 20);
    const firstScope = {
      summary: "Review the request handler.",
      artifactsReviewed: ["src/handler.ts"],
      limitations: ["The identity provider was unavailable."],
    };
    const secondScope = {
      summary: "Review the administrator endpoint.",
      artifactsReviewed: ["src/admin.ts"],
      limitations: ["The deployment configuration was unavailable."],
    };

    const incomplete = await recordReduction(
      [
        draft([first], coverage(), undefined, firstScope),
        draft([second], coverage(), undefined, secondScope),
      ],
      draft([first, second], coverage(), undefined, firstScope),
    );
    expect(incomplete.accepted).toBe(false);
    expect(incomplete.message).toMatch(/scope/iu);

    const combined = {
      summary: `${firstScope.summary} ${secondScope.summary}`,
      artifactsReviewed: [
        ...firstScope.artifactsReviewed,
        ...secondScope.artifactsReviewed,
      ],
      limitations: [...firstScope.limitations, ...secondScope.limitations],
    };
    const accepted = await recordReduction(
      [
        draft([first], coverage(), undefined, firstScope),
        draft([second], coverage(), undefined, secondScope),
      ],
      draft([first, second], coverage(), undefined, combined),
    );
    expect(accepted.accepted, accepted.message).toBe(true);
    expect(accepted.saved?.scope).toEqual(combined);
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

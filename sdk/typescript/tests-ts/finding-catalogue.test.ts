import { createHash } from "node:crypto";
import { describe, expect, test } from "bun:test";
import {
  compactFinding,
  findingCatalogue,
  type ComparisonFinding,
} from "../src/finding-catalogue.js";
import {
  matchScanFindings,
  type ScanComparisonInput,
  type ScanComparisonOptions,
  type ScanComparisonResult,
} from "../src/scan-comparison.js";

const empty = { matches: [], uncertain: [] } satisfies ScanComparisonResult;
const finding = (
  occurrenceId: string,
  details: Record<string, unknown> = {},
): ComparisonFinding => ({ occurrenceId, ...details });
const data = <T>(prompt: string): T =>
  JSON.parse(prompt.slice(prompt.lastIndexOf("\n") + 1)) as T;
type CatalogueData = { findings: ScanComparisonInput };
type EvidenceData = { content: string; nextOffset: number | null };
const characters = (value: string): number => Array.from(value).length;

function conversation(
  respond: (prompt: string, index: number) => unknown | Promise<unknown>,
) {
  const prompts: string[] = [];
  let threads = 0;
  const codex: NonNullable<ScanComparisonOptions["codex"]> = {
    startThread() {
      threads += 1;
      return {
        async run(prompt) {
          prompts.push(prompt);
          const response = await respond(prompt, prompts.length - 1);
          return { finalResponse: JSON.stringify(response) };
        },
      };
    },
  };
  return { codex, prompts, threads: () => threads };
}

describe("finding catalogue", () => {
  test("keeps root-control metadata and leaves full evidence out of cards", () => {
    const entry = finding("old", {
      title: "Synthetic missing ownership check",
      identity: { anchor: "document-access", instance: "read-document" },
      root_cause: {
        summary: "The shared control omits ownership",
        code: "FULL_CODE",
      },
      remediation: "Check ownership in the shared control",
      codeEvidence: [{ code: "FULL_CODE" }],
      locations: [
        { path: "route.ts", startLine: 2, role: "entrypoint" },
        { path: "access.ts", startLine: 8, role: "root_control" },
      ],
      attackPath: {
        data_flow: {
          source: "document ID",
          sink: "readDocument",
          transformations: ["FULL_FLOW"],
        },
        reachability: {
          attacker: "signed-in user",
          entrypoint: "GET /documents/:id",
        },
      },
    });

    expect(compactFinding(entry)).toMatchObject({
      occurrenceId: "old",
      rootCause: "The shared control omits ownership",
      locations: [{ path: "access.ts", startLine: 8, role: "root_control" }],
      attackPath: { dataFlow: { source: "document ID", sink: "readDocument" } },
    });
    expect(JSON.stringify(compactFinding(entry))).not.toContain("FULL_CODE");
    expect(JSON.stringify(compactFinding(entry))).not.toContain("FULL_FLOW");
  });

  test("groups only stable identities and confirmed aliases", () => {
    const common = {
      rootCause: "The shared control",
      remediation: "Fix the shared control",
    };
    const entries = [
      finding("first", {
        ...common,
        findingId: "identity-a",
        title: "First description",
      }),
      finding("same", {
        ...common,
        findingId: "identity-a",
        title: "Same identity",
      }),
      finding("renamed", {
        ...common,
        findingId: "identity-c",
        title: "Renamed description",
      }),
      finding("independent", {
        findingId: "identity-d",
        title: "Same identity",
      }),
    ];
    const catalogue = findingCatalogue(entries, [
      ["identity-a", "identity-b"],
      ["identity-b", "identity-c"],
    ]);

    expect([...catalogue.keys()]).toEqual(["renamed", "independent"]);
    expect(
      catalogue.get("renamed")?.occurrences.map((item) => item.occurrenceId),
    ).toEqual(["first", "same", "renamed"]);
    expect(catalogue.get("renamed")?.card).toMatchObject({
      issueId: "identity-a",
      occurrenceCount: 3,
    });
    expect(catalogue.get("renamed")?.card["earlierDescriptions"]).toEqual([
      { title: "First description" },
      { title: "Same identity" },
    ]);
  });

  test("lets Codex inspect a selected issue and expands its saved occurrences", async () => {
    const before = [
      finding("old-a", {
        findingId: "identity-a",
        title: "Old title",
        codeEvidence: [{ code: "EARLIER_EVIDENCE" }],
      }),
      finding("old-b", {
        findingId: "identity-b",
        title: "New title",
        codeEvidence: [{ code: "LATEST_EVIDENCE" }],
      }),
      finding("unrelated", {
        findingId: "identity-c",
        codeEvidence: [{ code: "UNREQUESTED_EVIDENCE" }],
      }),
    ];
    const after = [
      finding("new", {
        title: "Current title",
        codeEvidence: [{ code: "CURRENT_EVIDENCE" }],
      }),
    ];
    const observed = conversation((prompt, index) => {
      if (index === 0) {
        expect(data<CatalogueData>(prompt).findings.before).toHaveLength(2);
        expect(prompt).not.toContain("EARLIER_EVIDENCE");
        return {
          ...empty,
          request: {
            kind: "evidence",
            beforeOccurrenceIds: ["old-b"],
            afterOccurrenceIds: ["new"],
            offset: 0,
          },
        };
      }
      const evidence = JSON.parse(
        data<EvidenceData>(prompt).content,
      ) as ScanComparisonInput;
      expect(evidence.before.map((item) => item.occurrenceId)).toEqual([
        "old-a",
        "old-b",
      ]);
      expect(prompt).toContain("EARLIER_EVIDENCE");
      expect(prompt).toContain("CURRENT_EVIDENCE");
      expect(prompt).not.toContain("UNREQUESTED_EVIDENCE");
      return {
        matches: [
          {
            beforeOccurrenceIds: ["old-b"],
            afterOccurrenceIds: ["new"],
            confidence: "high",
            reason: "Same shared control.",
          },
        ],
        uncertain: [],
      };
    });

    const result = await matchScanFindings(
      { before, after, knownFindingGroups: [["identity-a", "identity-b"]] },
      {
        codex: observed.codex,
        onProgress() {
          throw new Error("Optional observer");
        },
      },
    );
    expect(result.matches[0]?.beforeOccurrenceIds).toEqual(["old-a", "old-b"]);
    expect(observed.threads()).toBe(1);
    expect(observed.prompts).toHaveLength(2);
  });

  test("delivers every oversized catalogue page before accepting a result", async () => {
    const input = {
      before: [
        finding("a", { rootCause: "a".repeat(600_000) }),
        finding("b", { rootCause: "b".repeat(600_000) }),
      ],
      after: [finding("c", { rootCause: "c".repeat(600_000) })],
    };
    const observed = conversation(() => empty);
    expect(await matchScanFindings(input, { codex: observed.codex })).toEqual(
      empty,
    );
    expect(observed.threads()).toBe(1);
    expect(observed.prompts.length).toBeGreaterThan(1);
    const seen = observed.prompts.flatMap((prompt) => {
      expect(characters(prompt)).toBeLessThanOrEqual(1 << 20);
      const page = data<CatalogueData>(prompt).findings;
      return [...page.before, ...page.after].map((item) => item.occurrenceId);
    });
    expect(seen).toEqual(["a", "b", "c"]);
  });

  test("pages a single oversized evidence record without losing Unicode", async () => {
    const original = finding("large", {
      rootCause: "x".repeat(1 << 20) + "🙂",
    });
    const pieces: string[] = [];
    const request = (offset: number) => ({
      ...empty,
      request: {
        kind: "evidence",
        beforeOccurrenceIds: ["large"],
        afterOccurrenceIds: [],
        offset,
      },
    });
    const observed = conversation((prompt, index) => {
      expect(characters(prompt)).toBeLessThanOrEqual(1 << 20);
      if (index === 0) {
        expect(data<CatalogueData>(prompt).findings.before).toEqual([
          { occurrenceId: "large", detailsOmitted: true },
        ]);
        return request(0);
      }
      const payload = data<EvidenceData>(prompt);
      pieces.push(payload.content);
      return payload.nextOffset === null ? empty : request(payload.nextOffset);
    });
    await matchScanFindings(
      { before: [original], after: [finding("new")] },
      { codex: observed.codex },
    );
    const hash = (value: string) =>
      createHash("sha256").update(value).digest("hex");
    expect(pieces.length).toBeGreaterThan(1);
    expect(hash(pieces.join(""))).toBe(
      hash(JSON.stringify({ before: [original], after: [] })),
    );
  });

  test.each([
    [
      "another finding",
      {
        kind: "evidence",
        beforeOccurrenceIds: ["outside"],
        afterOccurrenceIds: [],
        offset: 0,
      },
      "outside its findings",
    ],
    [
      "an invalid offset",
      {
        kind: "evidence",
        beforeOccurrenceIds: ["old"],
        afterOccurrenceIds: [],
        offset: 999,
      },
      "invalid evidence offset",
    ],
    [
      "an unknown page",
      { kind: "catalogue", page: 9 },
      "unknown catalogue page",
    ],
  ])("rejects requests for %s", async (_label, request, message) => {
    const observed = conversation(() => ({ ...empty, request }));
    await expect(
      matchScanFindings(
        { before: [finding("old")], after: [finding("new")] },
        { codex: observed.codex },
      ),
    ).rejects.toThrow(message);
    expect(observed.prompts).toHaveLength(1);
  });

  test("stops a repeated request and honors cancellation between turns", async () => {
    const request = {
      kind: "evidence",
      beforeOccurrenceIds: ["old"],
      afterOccurrenceIds: [],
      offset: 0,
    };
    const repeated = conversation(() => ({ ...empty, request }));
    const input = { before: [finding("old")], after: [finding("new")] };
    await expect(
      matchScanFindings(input, { codex: repeated.codex }),
    ).rejects.toThrow("without making progress");
    expect(repeated.prompts).toHaveLength(2);

    const controller = new AbortController();
    const canceled = conversation(() => ({ ...empty, request }));
    await expect(
      matchScanFindings(input, {
        codex: canceled.codex,
        signal: controller.signal,
        onProgress(progress) {
          if (progress.phase === "evidence")
            controller.abort(new Error("Canceled"));
        },
      }),
    ).rejects.toThrow("Canceled");
    expect(canceled.prompts).toHaveLength(1);
  });

  test("keeps related findings separate from confirmed and uncertain pairs", async () => {
    const input = {
      before: [finding("old")],
      after: [finding("same"), finding("different")],
    };
    const match = {
      beforeOccurrenceIds: ["old"],
      afterOccurrenceIds: ["same"],
      confidence: "high" as const,
      reason: "Same control.",
    };
    const related = {
      beforeOccurrenceId: "old",
      afterOccurrenceId: "different",
      reason: "Independent controls in the same component.",
    };
    const response = { matches: [match], uncertain: [], related: [related] };
    expect(
      await matchScanFindings(input, {
        codex: conversation(() => response).codex,
      }),
    ).toEqual(response);
    for (const invalid of [
      { ...response, related: [related, related] },
      { ...response, related: [{ ...related, afterOccurrenceId: "same" }] },
      { ...empty, uncertain: [related], related: [related] },
      { ...empty, related: [{ ...related, beforeOccurrenceId: "outside" }] },
    ]) {
      await expect(
        matchScanFindings(input, { codex: conversation(() => invalid).codex }),
      ).rejects.toThrow("invalid related pair");
    }
  });
});

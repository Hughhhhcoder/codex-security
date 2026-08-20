import { stripVTControlCharacters } from "node:util";
import { describe, expect, test } from "bun:test";
import { renderScanHistory } from "../src/scan-history-renderer.js";

describe("scan history renderer", () => {
  test("separates finished execution from canonical requested-scope coverage", () => {
    for (const completeness of ["complete", "partial", "unknown"] as const) {
      const text = renderScanHistory(
        {
          targetPath: "/demo/repository",
          scanId: "scan-1",
          mode: "standard",
          progress: { status: "complete" },
          coverage: {
            mode: "scoped_path",
            completeness,
            includePaths: ["src/parser"],
            excludePaths: [],
          },
          findings: [],
        },
        "show",
        { color: false },
      );
      expect(text).toContain("FINISHED");
      expect(text).toContain("scoped paths: src/parser");
      expect(text).toContain(`${completeness} for requested scope`);
    }
    const legacy = renderScanHistory(
      {
        targetPath: "/demo/repository",
        scanId: "scan-old",
        mode: "standard",
        scope: "src/parser",
        progress: { status: "complete" },
        findings: [],
      },
      "show",
      { color: false },
    );
    expect(legacy).toContain("FINISHED");
    expect(legacy).toContain("src/parser");
    expect(legacy).toContain("COVERAGE  not available");
    expect(legacy).not.toContain("complete for requested scope");
  });

  test("shows both canonical exclusion sources in completed history", () => {
    const text = renderScanHistory(
      {
        targetPath: "/demo/repository",
        scanId: "scan-1",
        mode: "standard",
        progress: { status: "complete" },
        coverage: {
          mode: "scoped_path",
          completeness: "complete",
          includePaths: ["src"],
          excludePaths: ["src/vendor"],
          explicitExclusions: [
            { pattern: "src/vendor", reason: "Excluded dependency source." },
            {
              pattern: "src/generated/**",
              reason: "Excluded generated source.",
            },
          ],
        },
        findings: [],
      },
      "show",
      { color: false, columns: 120 },
    );
    expect(text.replace(/\s+/g, " ")).toContain(
      "scoped paths: src; excluding src/vendor, src/generated/**",
    );
    expect(text.split("src/vendor")).toHaveLength(2);
    expect(text).toContain("complete for requested scope");
  });

  test("shows exact recorded paths for a multi-path history entry", () => {
    const text = renderScanHistory(
      {
        scans: [
          {
            scanId: "scan-1",
            targetPath: "/demo/repository",
            mode: "standard",
            scope: ".",
            scopePaths: ["src/parser", "tests/parser"],
            progress: { status: "complete" },
            findingCount: 0,
            startedAt: "2026-08-01T00:00:00Z",
          },
        ],
      },
      "list",
      { color: false },
    );
    expect(text).toContain("EXECUTION");
    expect(text).toContain("FINISHED");
    expect(text).toContain("src/parser, tests/parser");
    expect(text).not.toContain("SCOPE  .");
  });

  test("wraps multi-path scopes in narrow scan history", () => {
    const paths = Array.from(
      { length: 8 },
      (_, index) => `src/component-${index}`,
    );
    const text = renderScanHistory(
      {
        scans: [
          {
            scanId: "scan-1",
            targetPath: "/demo/repository",
            mode: "standard",
            scopePaths: paths,
            progress: { status: "complete" },
            findingCount: 0,
            startedAt: "2026-08-01T00:00:00Z",
          },
        ],
      },
      "list",
      { color: false, columns: 48 },
    );
    const lines = text.split("\n");
    const first = lines.findIndex((line) => line.includes("SCOPE"));
    expect(first).toBeGreaterThanOrEqual(0);
    const scopeLines = lines.slice(first).filter((line) => line.trim() !== "");
    expect(scopeLines.length).toBeGreaterThan(1);
    expect(scopeLines.every((line) => line.length <= 48)).toBe(true);
    expect(scopeLines.join(" ").replace(/\s+/g, " ")).toContain(
      paths.join(", "),
    );
  });

  test("keeps whitespace inside recorded scope paths while wrapping", () => {
    const paths = ["src/a  b.ts", "src/a b.ts", "src/trailing "];
    const scan = {
      targetPath: "/demo/repository",
      scanId: "scan-1",
      mode: "standard",
      scope: ".",
      scopePaths: paths,
      progress: { status: "complete" },
      findingCount: 0,
      startedAt: "2026-08-01T00:00:00Z",
      findings: [],
    };
    const options = { color: false, columns: 48 };
    const outputs = [
      renderScanHistory({ scans: [scan] }, "list", options),
      renderScanHistory(
        { ...scan, contract: { scope: { requiredIncludePaths: paths } } },
        "show",
        options,
      ),
    ];
    for (const output of outputs) {
      for (const path of paths) expect(output).toContain(path);
      const lines = output.split("\n");
      const first = lines.findIndex((line) => line.includes("SCOPE"));
      expect(first).toBeGreaterThanOrEqual(0);
      expect(lines[first]?.length).toBeLessThanOrEqual(48);
    }
    expect(
      renderScanHistory(
        { ...scan, scope: "src/legacy  path " },
        "show",
        options,
      ),
    ).toContain("src/legacy  path ");
  });

  test("keeps canonical include and exclusion path whitespace intact", () => {
    const text = renderScanHistory(
      {
        targetPath: "/demo/repository",
        scanId: "scan-1",
        mode: "standard",
        progress: { status: "complete" },
        coverage: {
          mode: "scoped_path",
          completeness: "complete",
          includePaths: ["src/a  b.ts", "src/trailing "],
          excludePaths: ["vendor/a  b"],
          explicitExclusions: [
            { pattern: "generated/trailing ", reason: "Generated source." },
          ],
        },
        findings: [],
      },
      "show",
      { color: false, columns: 48 },
    );
    for (const path of [
      "src/a  b.ts",
      "src/trailing ",
      "vendor/a  b",
      "generated/trailing ",
    ]) {
      expect(text).toContain(path);
    }
    expect(text).toContain("complete for requested scope");
  });

  test("does not invent repository scope for legacy diff scans", () => {
    const scan = {
      targetPath: "/demo/repository",
      scanId: "scan-diff",
      mode: "diff",
      scope: ".",
      progress: { status: "complete" },
      findingCount: 0,
      startedAt: "2026-08-01T00:00:00Z",
      findings: [],
    };
    const options = { color: false };
    expect(renderScanHistory({ scans: [scan] }, "list", options)).not.toContain(
      "SCOPE",
    );
    const legacy = renderScanHistory(scan, "show", options);
    expect(legacy).not.toContain("SCOPE");
    expect(legacy).toContain("COVERAGE  not available");
    expect(
      renderScanHistory(
        {
          ...scan,
          coverage: {
            mode: "branch_diff",
            completeness: "complete",
            includePaths: ["src/parser.ts"],
            excludePaths: [],
          },
        },
        "show",
        options,
      ),
    ).toContain("branch diff: src/parser.ts");
  });

  test("escapes scope delimiters and Unicode separators in history", () => {
    const path = "src; excluding tests\u2028COVERAGE forged";
    const scan = {
      targetPath: "/demo/repository",
      scanId: "scan-1",
      mode: "standard",
      scope: path,
      scopePaths: [path],
      progress: { status: "complete" },
      findingCount: 0,
      startedAt: "2026-08-01T00:00:00Z",
      findings: [],
    };
    const options = { color: false, columns: 120 };
    const outputs = [
      renderScanHistory({ scans: [scan] }, "list", options),
      renderScanHistory(scan, "show", options),
      renderScanHistory(
        {
          ...scan,
          coverage: {
            mode: "scoped_path",
            completeness: "complete",
            includePaths: [path],
            excludePaths: ["vendor\u2029forged"],
          },
        },
        "show",
        options,
      ),
    ];
    for (const output of outputs) {
      expect(output).not.toMatch(/[\u0085\u2028\u2029]/u);
      expect(output).toContain('"src; excluding tests\\u2028COVERAGE forged"');
    }
    expect(outputs[2]).toContain('"vendor\\u2029forged"');
  });

  test("separates current repository findings from earlier observations", () => {
    const text = renderScanHistory(
      {
        repository: "/repo",
        findings: [true, false].map((confirmed) => ({
          title: confirmed ? "Current finding" : "Earlier finding",
          severity: { level: "high" },
          locationPath: "source.ts",
          confirmedInLatestScan: confirmed,
        })),
      },
      "findings",
      { color: false },
    );
    expect(text).toMatch(
      /Seen this scan[\s\S]*Current finding[\s\S]*Not confirmed in latest scan[\s\S]*Earlier finding/,
    );
  });

  test("leads comparisons with the outcome and groups root causes", () => {
    const text = stripVTControlCharacters(
      renderScanHistory(
        {
          repository: "/demo/juice-shop",
          beforeScanId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
          afterScanId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
          comparable: true,
          coverage: { afterCompleteness: "complete" },
          summary: {
            new: 1,
            persisting: 2,
            resolved: 2,
            reopened: 0,
            unknown: 2,
          },
          findings: [
            {
              findingId: "internal-persisting-id",
              status: "persisting",
              severity: "high",
              title: "Basket ownership check is missing",
              path: "routes/basket.ts",
              beforeOccurrenceIds: ["before-one", "before-two"],
              afterOccurrenceIds: ["after-one"],
              matchReason:
                "Both routes share the same unchecked basket lookup.",
            },
            {
              status: "persisting",
              severity: "high",
              title: "Basket modification omits the ownership check",
              path: "routes/basket.ts",
            },
            {
              status: "new",
              severity: "medium",
              title: "Order input is evaluated",
              path: "routes/b2bOrder.ts",
            },
            {
              status: "resolved",
              severity: "informational",
              title: "Informational cookie observation",
              path: "routes/session.ts",
            },
            {
              status: "resolved",
              severity: "critical",
              title: "Login SQL injection bypasses authentication",
              path: "routes/login.ts",
              beforeOccurrenceId: "before-resolved",
            },
            {
              status: "unknown",
              severity: "high",
              title: "Complaint upload can overwrite trusted files",
              path: "routes/fileUpload.ts",
              reason:
                "The affected path was excluded or outside the later scope.",
            },
            {
              status: "unknown",
              severity: "medium",
              title: "Session handling might match an earlier finding",
              path: "routes/session.ts",
              reason: "The two findings describe different session flows.",
            },
          ],
        },
        "compare",
      ),
    );

    expect(text).toContain("CODEX SECURITY");
    expect(text).toMatch(
      /SCAN COMPARISON[\s\S]*━━ ✓ Resolved \(2 findings\) ━+[\s\S]*━━ \+ New \(1 finding\) ━+[\s\S]*━━ ● Persisting \(2 findings\) ━+[\s\S]*━━ ○ Not rescanned \(1 finding\) ━+[\s\S]*━━ \? Unknown \(1 finding\) ━+/,
    );
    expect(
      text.indexOf("Login SQL injection bypasses authentication"),
    ).toBeLessThan(text.indexOf("Informational cookie observation"));
    for (const expected of [
      "Complaint upload can overwrite trusted files",
      "Outside follow-up scan coverage",
      "Session handling might match an earlier finding",
      "The two findings describe different session flows.",
      "juice-shop",
      "aaaaaaaa → bbbbbbbb",
      "CRITICAL",
      "2 → 1",
      "Both routes share the same unchecked basket lookup.",
    ]) {
      expect(text).toContain(expected);
    }
    for (const hidden of [
      "follow-up scope",
      "internal-persisting-id",
      "before-resolved",
      "NOT_RESCANNED",
      "REOPENED",
    ]) {
      expect(text).not.toContain(hidden);
    }
  });

  test("reserves dim styling for finding and knowledge-base paths", () => {
    const output = renderScanHistory(
      {
        targetPath: "/demo/juice-shop",
        scanId: "scan-1",
        progress: { status: "complete" },
        mode: "standard",
        recipe: { knowledgeBasePaths: ["/demo/threat-model.md"] },
        findings: [
          {
            severity: "HIGH",
            title: "Missing auth",
            path: "routes/login.ts",
          },
        ],
      },
      "show",
    );
    expect(output).toContain("\u001B[1mKNOWLEDGE BASE\u001B[0m");
    expect(
      [...output.matchAll(/\u001B\[90m([^\u001B]*)\u001B\[0m/g)].map(
        ([, value]) => value,
      ),
    ).toEqual(["/demo/threat-model.md", "routes/login.ts"]);
    for (const coverage of ["partial", "unknown", "complete"]) {
      const comparison = renderScanHistory(
        {
          beforeScanId: "before-scan",
          afterScanId: "after-scan",
          coverage: { afterCompleteness: coverage },
          summary: {},
          findings: [],
        },
        "compare",
        { color: false },
      );
      if (coverage === "complete") {
        expect(comparison).not.toContain("Follow-up coverage");
      } else {
        expect(comparison).toContain(
          `⚠ Follow-up coverage is ${coverage}; resolved findings cannot be confirmed.`,
        );
      }
    }
  });

  test("keeps repositories visible at narrow and wide terminal widths", () => {
    const scans = [
      {
        scanId: "11111111-1111-4111-8111-111111111111",
        targetPath: "/demo/juice-shop",
        mode: "standard",
        progress: { status: "complete" },
        findingCount: 8,
        startedAt: "2026-07-24T12:00:00Z",
      },
      {
        scanId: "22222222-2222-4222-8222-222222222222",
        targetPath: "/demo/payment-service",
        mode: "deep",
        progress: { status: "complete" },
        findingCount: 2,
        startedAt: "2026-07-23T12:00:00Z",
      },
    ];

    for (const columns of [72, 100]) {
      const output = stripVTControlCharacters(
        renderScanHistory({ scans }, "list", {
          columns,
          scanRoot: "/demo/results",
        }),
      );
      expect(output).toContain("results");
      expect(output).toContain("juice-shop");
      expect(output).toContain("payment-service");
      expect(output).toContain(scans[0]!.scanId);
      expect(output).toContain(scans[1]!.scanId);
      if (columns >= 96) expect(output).toContain("REPOSITORY");
    }
  });

  test("shows bounded findings, saved configuration, and failure reasons", () => {
    const scan = {
      scanId: "12345678-abcd-4567-abcd-1234567890ab",
      parentScanId: "87654321-abcd-4567-abcd-1234567890ab",
      targetPath: "/demo/juice-shop",
      mode: "standard",
      progress: {
        status: "complete",
        coverage: { closedRows: 12, worklistRows: 15, filesTotal: 9 },
      },
      findingCount: 75,
      findingsTruncated: true,
      artifacts: { markdownReport: "/demo/results/report.md" },
      recipe: {
        config: {
          model: "gpt-5.6-sol",
          model_reasoning_effort: "high",
          features: { goals: true, multi_agent_v2: { enabled: true } },
          trusted_paths: ["src", "packages/core"],
        },
      },
      findings: Array.from({ length: 20 }, (_, index) => ({
        severity: { level: "high" },
        title: `Finding ${index + 1}`,
        locations: [{ path: "routes/login.ts", startLine: index + 1 }],
      })),
    };
    const output = stripVTControlCharacters(renderScanHistory(scan, "show"));
    for (const expected of [
      "FINDINGS  20 of 75",
      "PARENT SCAN  87654321",
      "CONFIGURATION",
      "model=gpt-5.6-sol",
      'features={"goals":true,"multi_agent_v2":{"enabled":true}}',
      'trusted_paths=["src","packages/core"]',
      "COVERAGE",
      "12 of 15 reviewed",
      "9 files",
      "ARTIFACTS",
      "/demo/results/report.md",
    ]) {
      expect(output).toContain(expected);
    }

    const failed = stripVTControlCharacters(
      renderScanHistory(
        {
          ...scan,
          progress: { status: "failed" },
          failureMessage: "Repository checkout became unavailable.",
          findings: [],
        },
        "show",
      ),
    );
    expect(failed).toContain("ERROR  Repository checkout became unavailable.");
  });

  test("shows saved completion warnings without marking a scan failed", () => {
    const output = stripVTControlCharacters(
      renderScanHistory(
        {
          scanId: "12345678-abcd-4567-abcd-1234567890ab",
          targetPath: "/demo/juice-shop",
          mode: "standard",
          progress: { status: "complete" },
          findings: [],
          warnings: [
            "Repository HEAD changed while the scan was running; results were saved for the original revision.",
          ],
        },
        "show",
      ),
    );

    expect(output).toContain("FINISHED");
    expect(output).toContain("WARNING");
    expect(output).toContain(
      "Repository HEAD changed while the scan was running",
    );
    expect(output).not.toContain("ERROR");
  });

  test("renders match-all results from the original workbench data", () => {
    const output = stripVTControlCharacters(
      renderScanHistory(
        {
          repository: "/demo/juice-shop",
          scanCount: 5,
          unavailableScans: 2,
          matchedPairs: 0,
          findingMatches: 0,
        },
        "match-all",
      ),
    );
    for (const expected of [
      "MATCH RESULTS",
      "juice-shop",
      "5 scans",
      "0 comparisons",
      "0 root-cause matches",
      "2 scans unavailable",
    ]) {
      expect(output).toContain(expected);
    }
  });
});

import { describe, expect, test } from "bun:test";
import {
  formatCoverageScope,
  formatScopePath,
} from "../src/coverage-presentation.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

function projectScope(scope: {
  includePaths: string[];
  excludePaths: string[];
  explicitExclusions: Array<{ pattern: string; reason: string }>;
}): string {
  const python = Bun.which("python3") ?? Bun.which("python");
  expect(python).not.toBeNull();
  const script = [
    "import json, pathlib, runpy, sys",
    "plugin = pathlib.Path(sys.argv[1])",
    "examples = plugin / 'examples' / 'completed-scan'",
    "manifest, findings, coverage = [json.loads((examples / name).read_text()) for name in ('scan-manifest.json', 'findings.json', 'coverage.json')]",
    "scope = json.loads(sys.argv[2])",
    "manifest['scan']['scope'].update({key: scope[key] for key in ('includePaths', 'excludePaths')})",
    "manifest['scan']['scope']['artifactsReviewed'] = scope['includePaths']",
    "coverage.update(scope)",
    "coverage.update({'mode': 'scoped_path', 'completeness': 'partial', 'surfaces': [], 'deferred': [{'id': 'source-review', 'reason': 'Source review remains unfinished.', 'paths': scope['includePaths']}]})",
    "findings['findings'] = []",
    "projection = runpy.run_path(str(plugin / 'scripts' / 'report_projection.py'))",
    "sys.stdout.buffer.write(projection['generate_report_markdown'](manifest, findings, coverage))",
  ].join("\n");
  const result = Bun.spawnSync(
    [python!, "-I", "-B", "-c", script, PLUGIN_ROOT, JSON.stringify(scope)],
    { stdout: "pipe", stderr: "pipe" },
  );
  expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
  return new TextDecoder().decode(result.stdout);
}

describe("coverage scope presentation", () => {
  test("distinguishes path text from include and exclusion delimiters", () => {
    const included = formatCoverageScope({
      mode: "scoped_path",
      includePaths: ["src; excluding tests"],
      excludePaths: [],
    });
    const excluded = formatCoverageScope({
      mode: "scoped_path",
      includePaths: ["src"],
      excludePaths: ["tests"],
    });
    expect(included).toBe('scoped paths: "src; excluding tests"');
    expect(excluded).toBe("scoped paths: src; excluding tests");
    expect(included).not.toBe(excluded);
    expect(
      formatCoverageScope({
        mode: "scoped_path",
        includePaths: ["src, tests", "src/parser.ts"],
        excludePaths: [],
      }),
    ).toBe('scoped paths: "src, tests", src/parser.ts');
  });

  test("round-trips ambiguous paths without emitting terminal controls", () => {
    const paths = [
      "src/a  b.ts",
      "src/trailing ",
      'src/"quoted"',
      "src/back\\slash",
      "src/line\nfeed",
      "src/\u001b[31m",
      "src/\u009b31m",
      "src/\u0085\u2028\u2029COVERAGE forged",
      "src/\ufeffname",
    ];
    for (const path of paths) {
      const encoded = formatScopePath(path);
      expect(encoded).not.toMatch(
        /[\u0000-\u001f\u007f-\u009f\u2028\u2029\ufeff]/u,
      );
      expect(JSON.parse(encoded)).toBe(path);
    }
    expect(formatScopePath("src/parser.ts")).toBe("src/parser.ts");
    expect(formatScopePath("src/generated/**")).toBe("src/generated/**");
  });

  test("escapes default-ignorable characters in terminal and Markdown paths", () => {
    const controls =
      "\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b\u180e\u180f" +
      "\u200b\u200c\u200d\u200e\u200f\u202a\u202b\u202c\u202d\u202e" +
      "\u2060\u2061\u2066\u2067\u2068\u2069\u206f\u3164\ufe00\ufe0f" +
      "\ufeff\uffa0\ufff0\ufff8\u{1bca0}\u{1bca3}\u{1d173}\u{1d17a}" +
      "\u{e0000}\u{e0100}\u{e0fff}";
    const paths = [...controls].flatMap((control) => [
      `src/${control}name`,
      `src/a ${control}name`,
    ]);
    for (const path of paths) {
      const encoded = formatScopePath(path);
      expect(encoded).not.toMatch(/\p{Default_Ignorable_Code_Point}/u);
      expect(JSON.parse(encoded)).toBe(path);
    }
    const report = projectScope({
      includePaths: paths,
      excludePaths: [],
      explicitExclusions: [],
    });
    expect(report).not.toMatch(/\p{Default_Ignorable_Code_Point}/u);
    const includedLine =
      report.split("\n").find((line) => line.startsWith("- Included paths:")) ??
      "";
    expect(includedLine).toEndWith(
      paths.map((path) => `\`${formatScopePath(path)}\``).join(", "),
    );
  });

  test("preserves exact paths in Markdown scope and deferred work", () => {
    const included = [
      ["src/a  b.ts", '`"src/a  b.ts"`'],
      ["src/trailing ", '`"src/trailing "`'],
      ["src,tests", '`"src,tests"`'],
      ["src/line\nfeed", '`"src/line\\nfeed"`'],
      ["src/\u202eforged", '`"src/\\u202eforged"`'],
      ["src/\ufeffname", '`"src/\\ufeffname"`'],
      ["src/\u2028\u2029next", '`"src/\\u2028\\u2029next"`'],
      ["src/[name]*_<tag>.ts", "`src/[name]*_<tag>.ts`"],
      ["src/a`b.ts", "``src/a`b.ts``"],
      ["`edge`", "`` `edge` ``"],
      ["src/naïve.ts", "`src/naïve.ts`"],
    ] as const;
    const excluded = [
      ["vendor/a  b", '`"vendor/a  b"`'],
      ["vendor,tests", '`"vendor,tests"`'],
    ] as const;
    const pattern = "generated/\u2066[omitted]*`";
    const report = projectScope({
      includePaths: included.map(([path]) => path),
      excludePaths: excluded.map(([path]) => path),
      explicitExclusions: [{ pattern, reason: "Synthetic exclusion." }],
    });
    const row = (label: string) =>
      report.split("\n").find((line) => line.startsWith(label)) ?? "";
    const expectedIncludes = included.map(([, encoded]) => encoded).join(", ");
    expect(row("- Included paths:")).toEndWith(expectedIncludes);
    expect(row("- Excluded paths:")).toEndWith(
      excluded.map(([, encoded]) => encoded).join(", "),
    );
    expect(row("- Artifacts reviewed:")).toEndWith(expectedIncludes);
    expect(row("  - Paths:")).toEndWith(expectedIncludes);
    expect(report).toContain(
      'Excluded ``"generated/\\u2066[omitted]*`"``: Synthetic exclusion.',
    );
    expect(report).not.toMatch(
      /[\u007f-\u009f\u2028\u2029\p{Default_Ignorable_Code_Point}]/u,
    );
  });
});

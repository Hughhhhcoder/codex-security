import { describe, expect, test } from "bun:test";
import {
  formatCoverageScope,
  formatScopePathParts,
} from "../src/coverage-presentation.js";

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
    expect(formatScopePathParts(["src, tests", "src/parser.ts"])).toEqual([
      '"src, tests",',
      "src/parser.ts",
    ]);
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
    ];
    const parts = formatScopePathParts(paths);
    for (const [index, part] of parts.entries()) {
      const encoded = index < parts.length - 1 ? part.slice(0, -1) : part;
      expect(encoded).not.toMatch(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/u);
      expect(JSON.parse(encoded)).toBe(paths[index]);
    }
    expect(formatScopePathParts(["src/parser.ts", "src/generated/**"])).toEqual(
      ["src/parser.ts,", "src/generated/**"],
    );
  });
});

import type { CoverageCompleteness, CoverageDocument } from "./models.js";

export type CoverageSummary = Pick<
  CoverageDocument,
  "mode" | "completeness" | "includePaths" | "excludePaths"
>;

export function formatCoverageScope(
  coverage: Pick<CoverageSummary, "mode" | "includePaths">,
): string {
  const mode =
    coverage.mode === "scoped_path"
      ? "scoped paths"
      : coverage.mode.replaceAll("_", " ");
  return `${mode}: ${coverage.includePaths.join(", ") || "(no included paths)"}`;
}

export function formatCoverageCompleteness(
  completeness: CoverageCompleteness,
): string {
  return `${completeness} for requested scope`;
}

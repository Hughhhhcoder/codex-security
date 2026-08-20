import type { CoverageCompleteness, CoverageDocument } from "./models.js";

export type CoverageSummary = Pick<
  CoverageDocument,
  "mode" | "completeness" | "includePaths" | "excludePaths"
> &
  Partial<Pick<CoverageDocument, "explicitExclusions">>;

export function formatCoverageScope(
  coverage: Omit<CoverageSummary, "completeness">,
): string {
  const mode =
    coverage.mode === "scoped_path"
      ? "scoped paths"
      : coverage.mode.replaceAll("_", " ");
  const scope = `${mode}: ${coverage.includePaths.join(", ") || "(no included paths)"}`;
  const exclusions = [
    ...new Set([
      ...coverage.excludePaths,
      ...(coverage.explicitExclusions ?? []).map(({ pattern }) => pattern),
    ]),
  ];
  return exclusions.length > 0
    ? `${scope}; excluding ${exclusions.join(", ")}`
    : scope;
}

export function formatCoverageCompleteness(
  completeness: CoverageCompleteness,
): string {
  return `${completeness} for requested scope`;
}

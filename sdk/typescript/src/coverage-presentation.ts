import type { CoverageCompleteness, CoverageDocument } from "./models.js";

export type CoverageSummary = Pick<
  CoverageDocument,
  "mode" | "completeness" | "includePaths" | "excludePaths"
> &
  Partial<Pick<CoverageDocument, "explicitExclusions">>;

export function formatScopePath(path: string): string {
  if (path.length > 0 && !/[\s,;'"\\\u0000-\u001f\u007f-\u009f]/u.test(path)) {
    return path;
  }
  return JSON.stringify(path).replace(
    /[\u007f-\u009f\u2028\u2029]/gu,
    (character) =>
      `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
}

export function formatScopePathParts(
  paths: readonly string[],
  finalSuffix = "",
): string[] {
  return paths.map(
    (path, index) =>
      `${formatScopePath(path)}${index < paths.length - 1 ? "," : finalSuffix}`,
  );
}

export function formatCoverageScopeParts(
  coverage: Omit<CoverageSummary, "completeness">,
): string[] {
  const mode =
    coverage.mode === "scoped_path"
      ? "scoped paths"
      : coverage.mode.replaceAll("_", " ");
  const exclusions = [
    ...new Set([
      ...coverage.excludePaths,
      ...(coverage.explicitExclusions ?? []).map(({ pattern }) => pattern),
    ]),
  ];
  const suffix = exclusions.length > 0 ? ";" : "";
  return [
    `${mode}:`,
    ...(coverage.includePaths.length > 0
      ? formatScopePathParts(coverage.includePaths, suffix)
      : [`(no included paths)${suffix}`]),
    ...(exclusions.length > 0
      ? ["excluding", ...formatScopePathParts(exclusions)]
      : []),
  ];
}

export function formatCoverageScope(
  coverage: Omit<CoverageSummary, "completeness">,
): string {
  return formatCoverageScopeParts(coverage).join(" ");
}

export function formatCoverageCompleteness(
  completeness: CoverageCompleteness,
): string {
  return `${completeness} for requested scope`;
}

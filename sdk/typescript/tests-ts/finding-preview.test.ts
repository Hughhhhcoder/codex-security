import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

function sourceScopeProbe(scenario: string): Record<string, unknown> {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  expect(python).not.toBeNull();
  const result = Bun.spawnSync(
    [
      python!,
      "-I",
      "-B",
      fileURLToPath(new URL("./fixtures/source_scopes.py", import.meta.url)),
      join(PLUGIN_ROOT, "scripts"),
      scenario,
    ],
    { stdout: "pipe", stderr: "pipe" },
  );
  expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
  return JSON.parse(new TextDecoder().decode(result.stdout)) as Record<
    string,
    unknown
  >;
}

describe("bundled finding previews", () => {
  test("reads only the immutable source objects selected for the scan", () => {
    expect(sourceScopeProbe("boundaries")).toEqual({
      selected: "1  public source",
      outside: null,
      additional: "1  selected file",
      repository: "1  private source",
      fileDescendant: null,
      traversal: null,
      absolute: null,
      redirected: null,
      escaped: null,
      legacyScoped: "1  public source",
      legacyUnmarkedFile: "1  selected file",
      legacyUnmarkedFileDescendant: null,
      legacyRoot: "1  private source",
      legacyKnownDirectory: "1  public source",
      legacyKnownFile: "1  selected file",
      legacyFileDescendant: null,
      emptyAuthority: null,
      dirty: null,
      fallback: "1  public source",
      rootControl: "1  public source",
      replacedFile: "1  selected file",
      replacedFileDescendant: null,
      removedDirectory: "1  nested source",
      offline: "1  public source",
      missingObject: null,
    });
  });

  test("keeps captured filesystem aliases usable after their source paths disappear", () => {
    expect(sourceScopeProbe("aliases")).toEqual({
      case: expect.any(Boolean),
      unicode: expect.any(Boolean),
      nonAscii: expect.any(Boolean),
      collisionChecked: true,
    });
  });

  test("ignores replacement refs during source capture and immutable reads", () => {
    expect(sourceScopeProbe("replacements")).toEqual({
      savedObjectsUnchanged: true,
      captureIgnoresReplacements: true,
    });
  });

  test("omits source authority when replacement refs changed the scanned tree", () => {
    expect(sourceScopeProbe("replacement_snapshot")).toEqual({
      mismatchedCaptureOmitted: true,
      ambiguousLegacyViewOmitted: true,
    });
  });

  test("does not treat links or reparse points as filesystem alias evidence", () => {
    expect(sourceScopeProbe("alias_evidence")).toEqual({
      ordinary: true,
      hardlink: false,
      symlink: false,
      reparse: false,
    });
  });

  test("keeps subdirectory and linked-worktree targets bound to their selected tree", () => {
    expect(sourceScopeProbe("worktrees")).toEqual({
      subdirectoryBound: true,
      linkedWorktreeBound: true,
    });
  });

  test("records source authority through every scan-start path without changing launch recipes", () => {
    expect(sourceScopeProbe("writers")).toEqual({
      writers: 5,
      nativeRecipesUnchanged: true,
      cliRecipeUnchanged: true,
      legacyExactScopesPreserved: true,
    });
  });

  test("preserves legacy scans and separately owned migration history", () => {
    expect(sourceScopeProbe("migration")).toEqual({
      legacyAuthorityUnset: true,
      otherMigrationsPreserved: true,
      conflictRejected: true,
    });
  });

  test("normalizes attack-path assessments without changing stored finding details", () => {
    const python =
      Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
    expect(python).not.toBeNull();

    const original = {
      scalar: {
        attackPath: { impact: "high", likelihood: "medium" },
      },
      structured: {
        attackPath: {
          impact: { level: "low", rationale: "Synthetic assessment." },
          likelihood: null,
        },
      },
      absentAssessments: {
        attackPath: { narrative: "Synthetic attack path." },
      },
      absentAttackPath: {
        rootCause: { summary: "Synthetic root cause." },
      },
    };
    const program = [
      "import json, sys",
      "sys.path.insert(0, sys.argv[1])",
      "from finding_preview import bounded_finding_details",
      "original = json.loads(sys.argv[2])",
      "projected = {name: bounded_finding_details(details) for name, details in original.items()}",
      "print(json.dumps({'projected': projected, 'original': original}))",
    ].join("\n");
    const result = Bun.spawnSync(
      [
        python!,
        "-I",
        "-B",
        "-c",
        program,
        join(PLUGIN_ROOT, "scripts"),
        JSON.stringify(original),
      ],
      { stdout: "pipe", stderr: "pipe" },
    );

    expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
    expect(JSON.parse(new TextDecoder().decode(result.stdout))).toEqual({
      projected: {
        scalar: {
          attackPath: {
            impact: { level: "high" },
            likelihood: { level: "medium" },
          },
        },
        structured: original.structured,
        absentAssessments: original.absentAssessments,
        absentAttackPath: original.absentAttackPath,
      },
      original,
    });
  });
});

const { isDeepStrictEqual } = require("node:util");

const FINDING_TEXT_FIELDS = ["summary", "remediation", "rootCause"];
const FINDING_LIST_FIELDS = ["remediationTests", "preventiveControls"];
const MERGEABLE_TEXT_FIELDS = new Set([
  "summary",
  "remediation",
  "rootCause",
  "reason",
  "rationale",
  "notes",
  "context",
  "runtimeStatus",
  "validationMode",
  "followUpPrompt",
]);
const SEVERITY_LEVELS = [
  "informational",
  "low",
  "medium",
  "high",
  "critical",
];
const CONFIDENCE_LEVELS = ["low", "medium", "high"];

function validateDeepReduction(result, sources, previous, findingIdentity) {
  const currentFindingIds = new Set(result.findings.map(findingIdentity));

  for (const finding of previous?.findings ?? []) {
    if (currentFindingIds.has(findingIdentity(finding))) continue;
    throw Object.assign(
      new Error(
        "Deep reduction discarded or changed a previously accepted finding identity.",
      ),
      { code: "merge_traceability_unstable_candidate_id" },
    );
  }

  const inputs = previous === undefined ? sources : [...sources, previous];

  for (const source of inputs) {
    for (const finding of source.findings) {
      const matches = result.findings.filter((retained) =>
        representsFinding(retained, finding, findingIdentity),
      );
      if (matches.length === 0) {
        throw Object.assign(
          new Error(
            `Deep reduction omitted an accepted Standard scan finding (${finding.ruleId}). Preserve its identity or merge only findings with the same rule and root control.`,
          ),
          { code: "merge_traceability_omitted_source_candidates" },
        );
      }
      if (matches.some((retained) => retainsFindingEvidence(retained, finding))) {
        continue;
      }
      throw Object.assign(
        new Error(
          `Deep reduction discarded accepted finding evidence (${finding.ruleId}). Preserve every location, code-evidence item, attack path, validation detail, and remediation.`,
        ),
        { code: "merge_traceability_omitted_source_candidates" },
      );
    }
  }

  validateRetainedCoverage(result.coverage, inputs);
  validateRetainedThreatModel(result.threatModel, inputs);
  validateRetainedScope(result.scope, inputs);
}

function representsFinding(retained, source, findingIdentity) {
  if (findingIdentity(retained) === findingIdentity(source)) return true;
  if (retained.ruleId !== source.ruleId) return false;

  return source.locations.some(
    (sourceLocation) =>
      sourceLocation.role === "root_control" &&
      retained.locations.some(
        (retainedLocation) =>
          retainedLocation.role === "root_control" &&
          retainedLocation.path === sourceLocation.path &&
          retainedLocation.startLine === sourceLocation.startLine &&
          (retainedLocation.endLine ?? null) ===
            (sourceLocation.endLine ?? null),
      ),
  );
}

function retainsFindingEvidence(retained, source) {
  for (const location of source.locations) {
    if (
      retained.locations.some((candidate) =>
        retainsStructuredValue(candidate, location),
      )
    ) {
      continue;
    }
    return false;
  }

  for (const evidence of source.codeEvidence ?? []) {
    if (
      (retained.codeEvidence ?? []).some((candidate) =>
        retainsStructuredValue(candidate, evidence),
      )
    ) {
      continue;
    }
    return false;
  }

  for (const field of FINDING_TEXT_FIELDS) {
    if (source[field] === undefined || source[field] === null) continue;
    if (!retainsStructuredValue(retained[field], source[field], field)) {
      return false;
    }
  }

  for (const field of FINDING_LIST_FIELDS) {
    if (!retainsStructuredValue(retained[field] ?? [], source[field] ?? [])) {
      return false;
    }
  }

  for (const field of ["attackPath", "validation", "taxonomy", "provenance"]) {
    if (source[field] === undefined || source[field] === null) continue;
    if (!retainsStructuredValue(retained[field], source[field])) return false;
  }

  if (
    SEVERITY_LEVELS.indexOf(retained.severity.level) <
    SEVERITY_LEVELS.indexOf(source.severity.level)
  ) {
    return false;
  }
  if (
    CONFIDENCE_LEVELS.indexOf(retained.confidence.level) <
    CONFIDENCE_LEVELS.indexOf(source.confidence.level)
  ) {
    return false;
  }
  if (
    !retainsStructuredValue(
      retained.confidence.rationale,
      source.confidence.rationale,
      "rationale",
    )
  ) {
    return false;
  }

  return true;
}

function validateRetainedCoverage(result, inputs) {
  for (const input of inputs) {
    const coverage = input.coverage;
    if (
      (coverage.completeness === "partial" &&
        result.completeness !== "partial") ||
      (coverage.completeness === "unknown" &&
        result.completeness === "complete")
    ) {
      throw new Error(
        `Deep reduction changed ${coverage.completeness} Standard scan coverage to ${result.completeness}.`,
      );
    }

    for (const source of coverage.deferred) {
      if (result.deferred.some((retained) => sameDeferred(retained, source))) {
        continue;
      }
      throw new Error(
        "Deep reduction discarded deferred Standard scan coverage.",
      );
    }

    for (const source of coverage.surfaces) {
      const retained = result.surfaces.some((surface) =>
        retainsStructuredValue(surface, source),
      );
      if (!retained) {
        throw new Error(
          "Deep reduction discarded an accepted Standard scan coverage surface or its review evidence.",
        );
      }
    }

    for (const source of coverage.explicitExclusions) {
      const retained = result.explicitExclusions.some((exclusion) =>
        retainsStructuredValue(exclusion, source),
      );
      if (!retained) {
        throw new Error(
          "Deep reduction discarded an explicit Standard scan exclusion.",
        );
      }
    }

    const resultQuestions = result.openQuestions ?? [];
    for (const source of coverage.openQuestions ?? []) {
      if (
        resultQuestions.some((retained) => retainsOpenQuestion(retained, source))
      ) {
        continue;
      }
      throw new Error(
        "Deep reduction discarded an open Standard scan coverage question.",
      );
    }
  }
}

function sameDeferred(retained, source) {
  return retainsStructuredValue(retained, source);
}

function retainsOpenQuestion(retained, source) {
  if (typeof source === "string") {
    return (
      (typeof retained === "string" ? retained : retained.question) === source
    );
  }
  return retainsStructuredValue(retained, source);
}

function validateRetainedThreatModel(result, inputs) {
  const models = inputs.flatMap((input) =>
    input.threatModel === undefined ? [] : [input.threatModel],
  );
  if (models.length === 0) return;

  if (result === undefined) {
    throw new Error("Deep reduction discarded an accepted Standard scan threat model.");
  }

  if (models.every((model) => isDeepStrictEqual(model, models[0]))) {
    if (!isDeepStrictEqual(result, models[0])) {
      throw new Error("Deep reduction changed the shared threat model.");
    }
    return;
  }

  for (const model of models) {
    for (const [field, value] of Object.entries(model)) {
      if (retainsStructuredValue(result[field], value, field)) continue;
      throw new Error(
        `Deep reduction discarded an accepted threat-model ${field} entry.`,
      );
    }
  }
}

function validateRetainedScope(result, inputs) {
  for (const input of inputs) {
    if (input.scope === undefined) continue;
    if (retainsStructuredValue(result, input.scope)) continue;
    throw new Error(
      "Deep reduction discarded accepted Standard scan scope details or limitations.",
    );
  }
}

function retainsStructuredValue(retained, source, field) {
  if (source === null) return retained === null;
  if (typeof source === "string") {
    return (
      typeof retained === "string" &&
      (retained === source ||
        (MERGEABLE_TEXT_FIELDS.has(field) && retained.includes(source)))
    );
  }
  if (Array.isArray(source)) {
    return (
      Array.isArray(retained) &&
      source.every((entry) =>
        retained.some((candidate) => retainsStructuredValue(candidate, entry)),
      )
    );
  }
  if (typeof source === "object") {
    if (typeof retained !== "object" || retained === null) return false;
    return Object.entries(source).every(([key, value]) =>
      retainsStructuredValue(retained[key], value, key),
    );
  }
  return Object.is(retained, source);
}

module.exports = { validateDeepReduction };

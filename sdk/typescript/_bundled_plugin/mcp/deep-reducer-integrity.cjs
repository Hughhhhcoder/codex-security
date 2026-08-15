const { isDeepStrictEqual } = require("node:util");

const THREAT_MODEL_LISTS = [
  "assets",
  "trustBoundaries",
  "attackerCapabilities",
  "securityObjectives",
  "assumptions",
];

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

  for (const source of sources) {
    for (const finding of source.findings) {
      const represented = result.findings.some((retained) =>
        representsFinding(retained, finding, findingIdentity),
      );
      if (represented) continue;
      throw Object.assign(
        new Error(
          `Deep reduction omitted an accepted Standard scan finding (${finding.ruleId}). Preserve its identity or merge only findings with the same rule and root control.`,
        ),
        { code: "merge_traceability_omitted_source_candidates" },
      );
    }
  }

  const inputs = previous === undefined ? sources : [...sources, previous];
  validateRetainedCoverage(result.coverage, inputs);
  validateRetainedThreatModel(result.threatModel, inputs);
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

function validateRetainedCoverage(result, inputs) {
  for (const input of inputs) {
    const coverage = input.coverage;
    if (
      coverage.completeness !== "complete" &&
      result.completeness === "complete"
    ) {
      throw new Error(
        `Deep reduction changed ${coverage.completeness} Standard scan coverage to complete.`,
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
      const retained = result.surfaces.find(
        (surface) =>
          (source.id !== undefined && surface.id === source.id) ||
          surface.label === source.label,
      );
      if (!retained) {
        throw new Error(
          "Deep reduction discarded an accepted Standard scan coverage surface.",
        );
      }
      if (
        source.disposition === "needs_follow_up" &&
        retained.disposition !== "needs_follow_up"
      ) {
        throw new Error(
          "Deep reduction discarded an unresolved Standard scan follow-up surface.",
        );
      }
    }

    for (const source of coverage.explicitExclusions) {
      const retained = result.explicitExclusions.some(
        (exclusion) =>
          exclusion.pattern === source.pattern &&
          exclusion.reason === source.reason,
      );
      if (!retained) {
        throw new Error(
          "Deep reduction discarded an explicit Standard scan exclusion.",
        );
      }
    }

    const resultQuestions = result.openQuestions ?? [];
    for (const source of coverage.openQuestions ?? []) {
      const sourceQuestion = questionText(source);
      if (
        resultQuestions.some(
          (retained) => questionText(retained) === sourceQuestion,
        )
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
  if (source.id !== undefined && retained.id === source.id) return true;
  if (
    source.candidateId !== undefined &&
    retained.candidateId === source.candidateId
  ) {
    return true;
  }

  return (
    retained.reason === source.reason &&
    sameTextList(retained.paths, source.paths) &&
    sameTextList(retained.surfaceIds, source.surfaceIds)
  );
}

function sameTextList(left = [], right = []) {
  return isDeepStrictEqual([...left].sort(), [...right].sort());
}

function questionText(question) {
  return typeof question === "string" ? question : question.question;
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
    for (const field of THREAT_MODEL_LISTS) {
      const retained = result[field] ?? [];
      for (const value of model[field] ?? []) {
        if (retained.includes(value)) continue;
        throw new Error(
          `Deep reduction discarded an accepted threat-model ${field} entry.`,
        );
      }
    }
  }
}

module.exports = { validateDeepReduction };

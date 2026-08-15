const { constants: fileConstants, promises: fileSystem } = require("node:fs");
const { dirname, join, posix, relative, resolve, sep } = require("node:path");
const { isDeepStrictEqual } = require("node:util");

const FINDING_TEXT_FIELDS = ["summary", "remediation", "rootCause"];
const FINDING_LIST_FIELDS = ["remediationTests", "preventiveControls"];
const SEVERITY_LEVELS = ["informational", "low", "medium", "high", "critical"];
const CONFIDENCE_LEVELS = ["low", "medium", "high"];
const RATING_NARRATIVE_FIELDS = new Set(["rationale", "changeConditions"]);
const ORDERED_EVIDENCE_FIELDS = new Set([
  "evidenceRefs",
  "steps",
  "trace",
  "sequence",
  "chain",
  "hops",
  "stages",
  "dataflow",
  "path",
]);
const MERGEABLE_TEXT_FIELDS = new Set([
  "summary",
  "remediation",
  "rootCause",
  "reason",
  "rationale",
  "changeConditions",
  "notes",
  "context",
  "runtimeStatus",
  "validationMode",
  "followUpPrompt",
]);
const NARRATIVE_TEXT_FIELDS = new Set([
  "access",
  "accessRequirements",
  "assumptions",
  "attacker",
  "boundary",
  "consequence",
  "constraints",
  "control",
  "description",
  "entrypoint",
  "evidence",
  "explanation",
  "impact",
  "label",
  "limitation",
  "limitations",
  "method",
  "outcome",
  "precondition",
  "preconditions",
  "requirements",
  "risk",
  "sink",
  "source",
  "steps",
  "threat",
  "transformation",
  "transformations",
  "trigger",
  "why",
]);
const NARRATIVE_SECTIONS = new Set([
  "attackPath",
  "codeEvidence",
  "rootCause",
  "validation",
]);
function validateDeepReduction(result, sources, previous, findingIdentity) {
  const currentFindingIds = new Set(result.findings.map(findingIdentity));
  if (currentFindingIds.size !== result.findings.length) {
    throw Object.assign(
      new Error(
        "Deep reduction returned a duplicate accepted finding identity.",
      ),
      { code: "merge_traceability_duplicate_candidate_id" },
    );
  }

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
  const acceptedFindings = inputs.flatMap((input) => input.findings);

  for (const retained of result.findings) {
    const supported =
      containsOnlyAcceptedFindingEvidence(
        retained,
        acceptedFindings,
        findingIdentity,
      ) &&
      acceptedFindings.some(
        (finding) =>
          representsFinding(retained, finding, findingIdentity) &&
          retainsFindingEvidence(
            retained,
            finding,
            acceptedFindings,
            findingIdentity,
          ),
      );
    if (supported) continue;
    throw Object.assign(
      new Error(
        `Deep reduction returned an unsupported finding (${retained.ruleId}) without complete evidence from an accepted Standard worker.`,
      ),
      { code: "merge_traceability_invented_candidate" },
    );
  }

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
      if (
        matches.some((retained) =>
          retainsFindingEvidence(
            retained,
            finding,
            acceptedFindings,
            findingIdentity,
          ),
        )
      ) {
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

function containsOnlyAcceptedFindingEvidence(
  retained,
  acceptedFindings,
  findingIdentity,
) {
  const matching = acceptedFindings.filter((source) =>
    representsFinding(retained, source, findingIdentity),
  );
  if (matching.length === 0) return false;

  const supportedLocations = retained.locations.every((location) =>
    matching.some((source) =>
      source.locations.some(
        (accepted) =>
          retainsStructuredValue(location, accepted) &&
          containsOnlyAcceptedStructuredFields(location, [accepted]),
      ),
    ),
  );
  if (!supportedLocations) return false;

  const supportedCodeEvidence = (retained.codeEvidence ?? []).every(
    (evidence) => {
      const { id: _retainedIdentifier, ...retainedDetails } = evidence;
      const acceptedRecords = matching.flatMap((source) =>
        (source.codeEvidence ?? []).flatMap((accepted) => {
          const { id: _acceptedIdentifier, ...acceptedDetails } = accepted;
          return retainsStructuredValue(
            retainedDetails,
            acceptedDetails,
            "codeEvidence",
          )
            ? [acceptedDetails]
            : [];
        }),
      );
      return containsOnlyAcceptedStructuredFields(
        retainedDetails,
        acceptedRecords,
        "codeEvidence",
      );
    },
  );
  if (!supportedCodeEvidence) return false;

  for (const field of ["summary", "remediation"]) {
    if (
      !containsOnlyAcceptedStructuredFields(
        retained[field],
        matching.map((source) => source[field]),
        field,
      )
    ) {
      return false;
    }
  }

  for (const field of [
    "attackPath",
    "validation",
    "rootCause",
    "taxonomy",
    "provenance",
    "extensions",
  ]) {
    if (retained[field] === undefined || retained[field] === null) continue;
    const accepted = matching.flatMap((source) => {
      if (source[field] === undefined || source[field] === null) return [];
      const identifiers = matchCodeEvidence(retained, source);
      if (identifiers === null) return [];
      const value = remapEvidenceReferences(source[field], identifiers);
      return [
        field === "rootCause" &&
        typeof value === "string" &&
        typeof retained[field] === "object"
          ? { summary: value }
          : value,
      ];
    });
    if (
      !containsOnlyAcceptedStructuredFields(retained[field], accepted, field)
    ) {
      return false;
    }
  }

  return FINDING_LIST_FIELDS.every((field) =>
    (retained[field] ?? []).every((entry) =>
      matching.some((source) => (source[field] ?? []).includes(entry)),
    ),
  );
}

function retainsFindingEvidence(
  retained,
  source,
  acceptedFindings,
  findingIdentity,
) {
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

  const evidenceIdentifiers = matchCodeEvidence(retained, source);
  if (evidenceIdentifiers === null) return false;

  for (const field of FINDING_TEXT_FIELDS) {
    if (source[field] === undefined || source[field] === null) {
      if (retained[field] === source[field]) continue;
      if (
        hasAcceptedEvidence(retained, field, acceptedFindings, findingIdentity)
      ) {
        continue;
      }
      return false;
    }
    const expected = remapEvidenceReferences(
      source[field],
      evidenceIdentifiers,
    );
    const retainedValue =
      field === "rootCause" &&
      typeof expected === "string" &&
      typeof retained[field] === "object" &&
      retained[field] !== null
        ? retained[field].summary
        : retained[field];
    if (!retainsStructuredValue(retainedValue, expected, field)) {
      return false;
    }
  }

  for (const field of FINDING_LIST_FIELDS) {
    if (!retainsStructuredValue(retained[field] ?? [], source[field] ?? [])) {
      return false;
    }
  }

  for (const field of ["attackPath", "validation", "extensions", "writeup"]) {
    if (source[field] === undefined) {
      if (retained[field] === undefined) continue;
      if (
        hasAcceptedEvidence(retained, field, acceptedFindings, findingIdentity)
      ) {
        continue;
      }
      return false;
    }
    if (source[field] === null) {
      if (retained[field] === null) continue;
      if (
        hasAcceptedEvidence(retained, field, acceptedFindings, findingIdentity)
      ) {
        continue;
      }
      return false;
    }
    const expected = remapEvidenceReferences(
      source[field],
      evidenceIdentifiers,
    );
    if (field === "writeup") {
      if (
        !retainsFindingWriteup(
          retained,
          source,
          acceptedFindings,
          findingIdentity,
        )
      ) {
        return false;
      }
    } else if (!retainsStructuredValue(retained[field], expected, field)) {
      return false;
    }
  }

  for (const field of ["taxonomy", "provenance"]) {
    if (
      !retainsCategoricalFindingMetadata(
        retained,
        source,
        field,
        acceptedFindings,
        findingIdentity,
      )
    ) {
      return false;
    }
  }

  for (const field of ["severity", "confidence"]) {
    if (
      !retainsStrongestFindingRating(
        retained,
        source,
        field,
        acceptedFindings,
        findingIdentity,
      )
    ) {
      return false;
    }
  }

  return true;
}

function retainsCategoricalFindingMetadata(
  retained,
  source,
  field,
  acceptedFindings,
  findingIdentity,
) {
  const matching = acceptedFindings
    .filter((finding) => representsFinding(retained, finding, findingIdentity))
    .sort((first, second) => {
      const severity =
        SEVERITY_LEVELS.indexOf(second.severity.level) -
        SEVERITY_LEVELS.indexOf(first.severity.level);
      if (severity !== 0) return severity;
      const score =
        (second.severity.score ?? -1) - (first.severity.score ?? -1);
      if (score !== 0) return score;
      const confidence =
        CONFIDENCE_LEVELS.indexOf(second.confidence.level) -
        CONFIDENCE_LEVELS.indexOf(first.confidence.level);
      if (confidence !== 0) return confidence;
      return JSON.stringify(first[field]).localeCompare(
        JSON.stringify(second[field]),
      );
    });

  for (const [key, value] of Object.entries(source[field])) {
    if (Array.isArray(value)) {
      if (!retainsStructuredValue(retained[field][key], value, key))
        return false;
      continue;
    }
    if (value !== null && typeof value === "object") {
      if (!retainsStructuredValue(retained[field][key], value, key))
        return false;
      continue;
    }
    const preferred = matching.find((finding) =>
      Object.hasOwn(finding[field], key),
    );
    if (!Object.is(retained[field][key], preferred[field][key])) return false;
  }
  return true;
}

function retainsFindingWriteup(
  retained,
  source,
  acceptedFindings,
  findingIdentity,
) {
  const expected = source.writeup.reportPath;
  const actual = retained.writeup?.reportPath;
  if (
    retained.writeup === undefined ||
    !retainsStructuredValue(
      { ...retained.writeup, reportPath: expected },
      source.writeup,
      "writeup",
    )
  ) {
    return false;
  }
  if (actual === expected) return true;
  if (!isRemappedFindingWriteup(actual, expected)) return false;
  const collisions = acceptedFindings.filter(
    (finding) => finding.writeup?.reportPath === expected,
  );
  return (
    collisions.length > 1 &&
    collisions.some((finding) =>
      representsFinding(retained, finding, findingIdentity),
    )
  );
}

function isRemappedFindingWriteup(actual, expected) {
  const source = /^findings\/([^/]+)\/\1\.md$/u.exec(expected);
  const candidate = /^findings\/([^/]+)\/\1\.md$/u.exec(actual ?? "");
  if (source === null || candidate === null) return false;
  const prefix = `${source[1]}-`;
  return (
    candidate[1].startsWith(prefix) &&
    /^\d+$/u.test(candidate[1].slice(prefix.length))
  );
}

function retainsStrongestFindingRating(
  retained,
  source,
  field,
  acceptedFindings,
  findingIdentity,
) {
  const levels = field === "severity" ? SEVERITY_LEVELS : CONFIDENCE_LEVELS;
  const candidates = acceptedFindings
    .filter((finding) => representsFinding(retained, finding, findingIdentity))
    .map((finding) => finding[field]);
  const strongestLevel = Math.max(
    ...candidates.map((rating) => levels.indexOf(rating.level)),
  );
  const matchingLevel = candidates.filter(
    (rating) => levels.indexOf(rating.level) === strongestLevel,
  );
  const strongestScore =
    field === "severity"
      ? Math.max(...matchingLevel.map((rating) => rating.score ?? -1))
      : undefined;
  const supported = matchingLevel.some((candidate) => {
    if (field === "severity" && (candidate.score ?? -1) !== strongestScore) {
      return false;
    }
    if (!retainsStructuredValue(retained[field], candidate, field)) {
      return false;
    }
    return Object.entries(retained[field]).every(
      ([key, value]) =>
        RATING_NARRATIVE_FIELDS.has(key) ||
        (Object.hasOwn(candidate, key) &&
          isDeepStrictEqual(value, candidate[key])),
    );
  });
  if (!supported) return false;

  for (const key of RATING_NARRATIVE_FIELDS) {
    if (retained[field][key] === undefined) continue;
    const narratives = candidates.flatMap((rating) =>
      rating[key] === undefined ? [] : [rating[key]],
    );
    if (
      !containsOnlyAcceptedStructuredFields(
        retained[field][key],
        narratives,
        key,
      )
    ) {
      return false;
    }
  }

  return [...RATING_NARRATIVE_FIELDS].every((key) =>
    source[field][key] === undefined
      ? true
      : retainsStructuredValue(retained[field][key], source[field][key], key),
  );
}

function hasAcceptedEvidence(
  retained,
  field,
  acceptedFindings,
  findingIdentity,
) {
  return acceptedFindings.some((candidate) => {
    if (!representsFinding(retained, candidate, findingIdentity)) return false;
    if (candidate[field] === undefined) return false;
    if (candidate[field] === null) return retained[field] === null;
    if (field === "writeup") {
      return retainsFindingWriteup(
        retained,
        candidate,
        acceptedFindings,
        findingIdentity,
      );
    }
    const identifiers = matchCodeEvidence(retained, candidate);
    if (identifiers === null) return false;
    const expected = remapEvidenceReferences(candidate[field], identifiers);
    const retainedValue =
      field === "rootCause" &&
      typeof expected === "string" &&
      typeof retained[field] === "object" &&
      retained[field] !== null
        ? retained[field].summary
        : retained[field];
    return retainsStructuredValue(retainedValue, expected, field);
  });
}

function matchCodeEvidence(retained, source) {
  const identifiers = new Map();

  for (const evidence of source.codeEvidence ?? []) {
    const { id, ...details } = evidence;
    const candidates = (retained.codeEvidence ?? []).filter((candidate) => {
      const { id: _candidateId, ...candidateDetails } = candidate;
      return retainsStructuredValue(candidateDetails, details, "codeEvidence");
    });
    const matching =
      candidates.find((candidate) => candidate.id === id) ?? candidates[0];
    if (matching === undefined) return null;
    identifiers.set(id, matching.id);
  }

  return identifiers;
}

function remapEvidenceReferences(value, identifiers) {
  if (Array.isArray(value)) {
    return value.map((entry) => remapEvidenceReferences(entry, identifiers));
  }
  if (typeof value !== "object" || value === null) return value;

  return Object.fromEntries(
    Object.entries(value).map(([key, entry]) => [
      key,
      key === "evidenceRefs" && Array.isArray(entry)
        ? entry.map((identifier) => identifiers.get(identifier) ?? identifier)
        : remapEvidenceReferences(entry, identifiers),
    ]),
  );
}

function validateRetainedCoverage(result, inputs) {
  if (inputs.length > 0) {
    const expected = inputs.some(
      (input) => input.coverage.completeness === "partial",
    )
      ? "partial"
      : inputs.some((input) => input.coverage.completeness === "unknown")
        ? "unknown"
        : "complete";
    if (result.completeness !== expected) {
      throw new Error(
        `Deep reduction changed ${expected} Standard scan coverage to ${result.completeness}.`,
      );
    }
  }

  const acceptedSurfaces = inputs.flatMap((input) => input.coverage.surfaces);
  const retainedSurfaceIds = new Set();
  for (const surface of result.surfaces) {
    if (surface.id !== undefined && retainedSurfaceIds.has(surface.id)) {
      throw new Error(
        "Deep reduction returned a duplicate accepted coverage surface identifier.",
      );
    }
    if (surface.id !== undefined) retainedSurfaceIds.add(surface.id);
    if (
      acceptedSurfaces.some((source) =>
        retainsCoverageSurface(surface, source, acceptedSurfaces),
      )
    ) {
      continue;
    }
    throw new Error(
      "Deep reduction returned an unsupported Standard scan coverage surface.",
    );
  }

  const coverageMappings = new Map();
  for (const input of inputs) {
    const coverage = input.coverage;
    const surfaceIdentifiers = new Map();
    for (const source of coverage.surfaces) {
      const retained = result.surfaces.find((surface) =>
        retainsCoverageSurface(surface, source, acceptedSurfaces),
      );
      if (retained === undefined) {
        throw new Error(
          "Deep reduction discarded an accepted Standard scan coverage surface or its review evidence.",
        );
      }
      if (source.id !== undefined) {
        surfaceIdentifiers.set(source.id, retained.id ?? source.id);
      }
    }
    coverageMappings.set(input, surfaceIdentifiers);

    for (const source of coverage.deferred) {
      if (
        result.deferred.some((retained) =>
          sameDeferred(retained, source, surfaceIdentifiers),
        )
      ) {
        continue;
      }
      throw new Error(
        "Deep reduction discarded deferred Standard scan coverage.",
      );
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
        resultQuestions.some((retained) =>
          retainsOpenQuestion(retained, source),
        )
      ) {
        continue;
      }
      throw new Error(
        "Deep reduction discarded an open Standard scan coverage question.",
      );
    }
  }

  for (const retained of result.deferred) {
    const supported = inputs.some((input) =>
      input.coverage.deferred.some((source) =>
        sameDeferred(retained, source, coverageMappings.get(input)),
      ),
    );
    if (!supported) {
      throw new Error(
        "Deep reduction returned unsupported deferred Standard scan coverage.",
      );
    }
  }

  for (const retained of result.explicitExclusions) {
    const supported = inputs.some((input) =>
      input.coverage.explicitExclusions.some(
        (source) =>
          retainsStructuredValue(retained, source) &&
          containsOnlyAcceptedStructuredFields(retained, [source]),
      ),
    );
    if (!supported) {
      throw new Error(
        "Deep reduction returned an unsupported Standard scan exclusion.",
      );
    }
  }

  for (const retained of result.openQuestions ?? []) {
    const supported = inputs.some((input) =>
      (input.coverage.openQuestions ?? []).some((source) => {
        if (!retainsOpenQuestion(retained, source)) return false;
        if (typeof retained === "string") return true;
        const expected =
          typeof source === "string" ? { question: source } : source;
        return containsOnlyAcceptedStructuredFields(retained, [expected]);
      }),
    );
    if (!supported) {
      throw new Error(
        "Deep reduction returned an unsupported Standard scan open question.",
      );
    }
  }
}

function retainsCoverageSurface(retained, source, acceptedSurfaces) {
  const {
    id: sourceIdentifier,
    receiptRefs: sourceReceipts,
    ...sourceDetails
  } = source;
  const {
    id: retainedIdentifier,
    receiptRefs: retainedReceipts,
    ...retainedDetails
  } = retained;
  if (!retainsStructuredValue(retainedDetails, sourceDetails)) return false;
  if (
    !containsOnlyAcceptedStructuredFields(
      retainedDetails,
      acceptedSurfaces
        .filter((candidate) => candidate.label === source.label)
        .map(({ id: _id, receiptRefs: _receipts, ...details }) => details),
    )
  ) {
    return false;
  }
  if (
    sourceIdentifier !== undefined &&
    retainedIdentifier !== sourceIdentifier &&
    !isRemappedCoverageSurface(
      retainedIdentifier,
      sourceIdentifier,
      acceptedSurfaces,
    )
  ) {
    return false;
  }

  for (const receipt of sourceReceipts ?? []) {
    if (
      (retainedReceipts ?? []).some((candidate) =>
        isAcceptedCoverageReceipt(candidate, receipt, acceptedSurfaces),
      )
    ) {
      continue;
    }
    return false;
  }
  return (retainedReceipts ?? []).every((receipt) =>
    acceptedSurfaces.some((candidate) =>
      (candidate.receiptRefs ?? []).some((accepted) =>
        isAcceptedCoverageReceipt(receipt, accepted, acceptedSurfaces),
      ),
    ),
  );
}

function isRemappedCoverageSurface(actual, expected, acceptedSurfaces) {
  if (typeof actual !== "string" || !actual.startsWith(`${expected}-`)) {
    return false;
  }
  if (!/^\d+$/u.test(actual.slice(expected.length + 1))) return false;
  return (
    acceptedSurfaces.filter((surface) => surface.id === expected).length > 1
  );
}

function isAcceptedCoverageReceipt(actual, expected, acceptedSurfaces) {
  if (actual === expected) return true;
  const source = posix.parse(expected);
  const candidate = posix.parse(actual);
  if (source.dir !== candidate.dir || source.ext !== candidate.ext)
    return false;
  if (!candidate.name.startsWith(`${source.name}-`)) return false;
  if (!/^\d+$/u.test(candidate.name.slice(source.name.length + 1)))
    return false;
  return (
    acceptedSurfaces.filter((surface) =>
      (surface.receiptRefs ?? []).includes(expected),
    ).length > 1
  );
}

function sameDeferred(retained, source, surfaceIdentifiers) {
  const expected =
    source.surfaceIds === undefined
      ? source
      : {
          ...source,
          surfaceIds: source.surfaceIds.map(
            (identifier) => surfaceIdentifiers?.get(identifier) ?? identifier,
          ),
        };
  return (
    retainsStructuredValue(retained, expected) &&
    containsOnlyAcceptedStructuredFields(retained, [expected])
  );
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
  if (models.length === 0) {
    if (result !== undefined) {
      throw new Error(
        "Deep reduction returned an unsupported Standard scan threat model.",
      );
    }
    return;
  }

  if (result === undefined) {
    throw new Error(
      "Deep reduction discarded an accepted Standard scan threat model.",
    );
  }

  if (models.every((model) => isDeepStrictEqual(model, models[0]))) {
    if (!isDeepStrictEqual(result, models[0])) {
      throw new Error("Deep reduction changed the shared threat model.");
    }
    return;
  }

  if (!containsOnlyAcceptedStructuredFields(result, models, "threatModel")) {
    throw new Error(
      "Deep reduction returned unsupported Standard scan threat-model evidence.",
    );
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
  const scopes = inputs.flatMap((input) =>
    input.scope === undefined ? [] : [input.scope],
  );
  if (scopes.length === 0) {
    if (result !== undefined) {
      throw new Error(
        "Deep reduction returned unsupported Standard scan scope evidence.",
      );
    }
    return;
  }
  if (
    result !== undefined &&
    !containsOnlyAcceptedStructuredFields(result, scopes, "scope")
  ) {
    throw new Error(
      "Deep reduction returned unsupported Standard scan scope evidence.",
    );
  }
  for (const input of inputs) {
    if (input.scope === undefined) continue;
    if (retainsStructuredValue(result, input.scope)) continue;
    throw new Error(
      "Deep reduction discarded accepted Standard scan scope details or limitations.",
    );
  }
}

function retainsStructuredValue(retained, source, field, section = field) {
  if (source === null) return retained === null;
  if (typeof source === "string") {
    return (
      typeof retained === "string" &&
      (retained === source ||
        ((MERGEABLE_TEXT_FIELDS.has(field) ||
          (NARRATIVE_SECTIONS.has(section) &&
            NARRATIVE_TEXT_FIELDS.has(field))) &&
          retained.includes(source)))
    );
  }
  if (Array.isArray(source)) {
    if (!Array.isArray(retained)) return false;
    if (
      field === "evidenceRefs" ||
      (NARRATIVE_SECTIONS.has(section) && ORDERED_EVIDENCE_FIELDS.has(field))
    ) {
      let nextIndex = 0;
      return source.every((entry) => {
        while (nextIndex < retained.length) {
          if (
            retainsStructuredValue(
              retained[nextIndex++],
              entry,
              undefined,
              section,
            )
          ) {
            return true;
          }
        }
        return false;
      });
    }
    return source.every((entry) =>
      retained.some((candidate) =>
        retainsStructuredValue(candidate, entry, undefined, section),
      ),
    );
  }
  if (typeof source === "object") {
    if (typeof retained !== "object" || retained === null) return false;
    return Object.entries(source).every(([key, value]) =>
      retainsStructuredValue(retained[key], value, key, section),
    );
  }
  return Object.is(retained, source);
}

function containsOnlyAcceptedStructuredFields(
  retained,
  accepted,
  field,
  section = field,
) {
  if (accepted.length === 0) return false;
  if (typeof retained === "string") {
    return containsOnlyAcceptedNarrative(retained, accepted, field, section);
  }
  if (retained === null || typeof retained !== "object") {
    return accepted.some((source) =>
      retainsStructuredValue(retained, source, field, section),
    );
  }

  if (Array.isArray(retained)) {
    const entries = accepted.flatMap((source) =>
      Array.isArray(source) ? source : [],
    );
    return retained.every((entry) =>
      entries.some((source) =>
        containsOnlyAcceptedStructuredFields(
          entry,
          [source],
          undefined,
          section,
        ),
      ),
    );
  }

  return Object.entries(retained).every(([key, value]) => {
    const supported = accepted.flatMap((source) =>
      source !== null &&
      typeof source === "object" &&
      !Array.isArray(source) &&
      Object.hasOwn(source, key)
        ? [source[key]]
        : [],
    );
    return containsOnlyAcceptedStructuredFields(value, supported, key, section);
  });
}

function containsOnlyAcceptedNarrative(retained, accepted, field, section) {
  const narratives = [...new Set(accepted)].filter(
    (source) => typeof source === "string" && retained.includes(source),
  );
  if (narratives.some((source) => retained === source)) return true;
  if (
    !MERGEABLE_TEXT_FIELDS.has(field) &&
    !(NARRATIVE_SECTIONS.has(section) && NARRATIVE_TEXT_FIELDS.has(field))
  ) {
    return false;
  }

  let remaining = retained;
  for (const narrative of narratives.sort(
    (first, second) => second.length - first.length,
  )) {
    remaining = remaining.split(narrative).join("");
  }
  return /^(?:[\s\p{P}\p{S}]|and|or)*$/iu.test(remaining);
}

async function relocateDeepReductionWriteups(
  reduction,
  inputs,
  state,
  findingIdentity,
  requireRegularFile,
) {
  const scanRoot = await fileSystem.realpath(state.scanRoot);
  const workers = new Map(
    state.claimedWorkers.map((worker) => [worker.id, worker]),
  );
  const acceptedFindings = inputs.discoveries.flatMap(
    (discovery) => discovery.result.findings,
  );
  if (inputs.previous !== null && inputs.previous !== undefined) {
    acceptedFindings.push(...inputs.previous.findings);
  }
  const acceptedSurfaces = inputs.discoveries.flatMap(
    (discovery) => discovery.result.coverage.surfaces,
  );
  if (inputs.previous !== null && inputs.previous !== undefined) {
    acceptedSurfaces.push(...inputs.previous.coverage.surfaces);
  }
  const writeupPaths = new Set();
  for (const finding of reduction.findings) {
    if (finding.writeup === undefined) continue;
    if (writeupPaths.has(finding.writeup.reportPath)) {
      finding.writeup = {
        ...finding.writeup,
        reportPath: nextAcceptedArtifactPath(
          finding.writeup.reportPath,
          "writeup",
          writeupPaths,
        ),
      };
    }
    writeupPaths.add(finding.writeup.reportPath);
  }
  const receiptPaths = new Set(
    reduction.coverage.surfaces.flatMap((surface) => surface.receiptRefs ?? []),
  );
  const copiedSurfaceReceipts = new Map();

  for (const discovery of inputs.discoveries) {
    const worker = workers.get(discovery.workerId);
    const workerRoot = dirname(worker.resultPath);
    for (const source of discovery.result.findings) {
      if (source.writeup === undefined) continue;
      const retained = reduction.findings.find(
        (candidate) =>
          representsFinding(candidate, source, findingIdentity) &&
          retainsFindingWriteup(
            candidate,
            source,
            acceptedFindings,
            findingIdentity,
          ),
      );
      if (retained === undefined) continue;

      await copyAcceptedScanArtifact({
        scanRoot,
        workerRoot,
        source: source.writeup.reportPath,
        destination: retained.writeup.reportPath,
        kind: "writeup",
        reserved: writeupPaths,
        requireRegularFile,
      });
    }

    for (const source of discovery.result.coverage.surfaces) {
      const retained = reduction.coverage.surfaces.find((candidate) =>
        retainsCoverageSurface(candidate, source, acceptedSurfaces),
      );
      if (retained === undefined) continue;
      let copied = copiedSurfaceReceipts.get(retained);
      if (copied === undefined) {
        copied = new Set();
        copiedSurfaceReceipts.set(retained, copied);
      }

      for (const receipt of source.receiptRefs ?? []) {
        const preferred = (retained.receiptRefs ?? []).find((candidate) =>
          isAcceptedCoverageReceipt(candidate, receipt, acceptedSurfaces),
        );
        if (preferred === undefined) continue;
        const relocated = await copyAcceptedScanArtifact({
          scanRoot,
          workerRoot,
          source: receipt,
          destination: preferred,
          kind: "receipt",
          reserved: receiptPaths,
          requireRegularFile,
        });
        if (relocated !== preferred) {
          if (copied.has(preferred)) {
            retained.receiptRefs.push(relocated);
          } else {
            const position = retained.receiptRefs.indexOf(preferred);
            retained.receiptRefs[position] = relocated;
          }
        }
        copied.add(relocated);
      }
    }
  }

  for (const finding of reduction.findings) {
    if (finding.writeup === undefined) continue;
    await requireRegularFile(
      join(scanRoot, finding.writeup.reportPath),
      scanRoot,
    );
  }
  for (const surface of reduction.coverage.surfaces) {
    for (const receipt of surface.receiptRefs ?? []) {
      await requireRegularFile(join(scanRoot, receipt), scanRoot);
    }
  }
}

async function copyAcceptedScanArtifact({
  scanRoot,
  workerRoot,
  source,
  destination,
  kind,
  reserved,
  requireRegularFile,
}) {
  const sourcePath = join(workerRoot, source);
  await requireRegularFile(sourcePath, workerRoot);
  let relativeDestination = destination;

  while (true) {
    const destinationPath = join(scanRoot, relativeDestination);
    await ensureScanLocalWriteupDirectory(scanRoot, dirname(destinationPath));
    try {
      await fileSystem.copyFile(
        sourcePath,
        destinationPath,
        fileConstants.COPYFILE_EXCL,
      );
      await requireRegularFile(destinationPath, scanRoot);
      return relativeDestination;
    } catch (error) {
      if (error?.code !== "EEXIST") throw error;
      await requireRegularFile(destinationPath, scanRoot);
      const [existing, accepted] = await Promise.all([
        fileSystem.readFile(destinationPath),
        fileSystem.readFile(sourcePath),
      ]);
      if (existing.equals(accepted)) return relativeDestination;
      relativeDestination = nextAcceptedArtifactPath(
        destination,
        kind,
        reserved,
      );
      reserved.add(relativeDestination);
    }
  }
}

function nextAcceptedArtifactPath(original, kind, reserved) {
  const parsed = posix.parse(original);
  const slug = kind === "writeup" ? parsed.name : undefined;
  let suffix = 2;
  while (true) {
    const candidate =
      kind === "writeup"
        ? `findings/${slug}-${suffix}/${slug}-${suffix}.md`
        : posix.join(parsed.dir, `${parsed.name}-${suffix}${parsed.ext}`);
    if (!reserved.has(candidate)) return candidate;
    suffix += 1;
  }
}

async function ensureScanLocalWriteupDirectory(scanRoot, destination) {
  const relativeDestination = relative(scanRoot, resolve(destination));
  if (
    relativeDestination === ".." ||
    relativeDestination.startsWith(`..${sep}`)
  ) {
    throw new Error("Deep finding writeup escaped its parent scan directory.");
  }

  let current = scanRoot;
  for (const component of relativeDestination.split(sep)) {
    if (component === "") continue;
    current = join(current, component);
    try {
      const directory = await fileSystem.lstat(current);
      if (directory.isSymbolicLink() || !directory.isDirectory()) {
        throw new Error(
          "Deep finding writeup cannot use a symlinked or non-directory parent.",
        );
      }
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
      await fileSystem.mkdir(current, { mode: 0o700 });
    }
  }
}

module.exports = { validateDeepReduction, relocateDeepReductionWriteups };

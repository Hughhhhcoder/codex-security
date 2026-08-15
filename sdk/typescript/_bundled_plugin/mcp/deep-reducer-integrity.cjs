const { constants: fileConstants, promises: fileSystem } = require("node:fs");
const { dirname, join, relative, resolve, sep } = require("node:path");
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
    const supported = acceptedFindings.some(
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
    if (source[field] === undefined || source[field] === null) continue;
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

  for (const field of [
    "attackPath",
    "validation",
    "taxonomy",
    "provenance",
    "extensions",
    "writeup",
  ]) {
    if (source[field] === undefined) continue;
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
    if (!retainsStructuredValue(retained[field], expected, field)) return false;
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
    if (candidate[field] === undefined || candidate[field] === null)
      return false;
    if (!representsFinding(retained, candidate, findingIdentity)) return false;
    const identifiers = matchCodeEvidence(retained, candidate);
    if (identifiers === null) return false;
    const expected = remapEvidenceReferences(candidate[field], identifiers);
    return retainsStructuredValue(retained[field], expected, field);
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

  for (const input of inputs) {
    const coverage = input.coverage;
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
  const writeupPaths = new Set();
  for (const finding of reduction.findings) {
    if (finding.writeup === undefined) continue;
    if (writeupPaths.has(finding.writeup.reportPath)) {
      throw new Error(
        "Deep reduction returned a duplicate accepted finding writeup.",
      );
    }
    writeupPaths.add(finding.writeup.reportPath);
  }

  for (const discovery of inputs.discoveries) {
    const worker = workers.get(discovery.workerId);
    for (const source of discovery.result.findings) {
      if (source.writeup === undefined) continue;
      const retained = reduction.findings.find(
        (candidate) =>
          representsFinding(candidate, source, findingIdentity) &&
          candidate.writeup?.reportPath === source.writeup.reportPath,
      );
      if (retained === undefined) continue;

      const workerRoot = dirname(worker.resultPath);
      const sourcePath = join(workerRoot, source.writeup.reportPath);
      await requireRegularFile(sourcePath, workerRoot);
      const destinationPath = join(scanRoot, source.writeup.reportPath);
      await ensureScanLocalWriteupDirectory(scanRoot, dirname(destinationPath));
      try {
        await fileSystem.copyFile(
          sourcePath,
          destinationPath,
          fileConstants.COPYFILE_EXCL,
        );
      } catch (error) {
        if (error?.code !== "EEXIST") throw error;
        await requireRegularFile(destinationPath, scanRoot);
        const [existing, accepted] = await Promise.all([
          fileSystem.readFile(destinationPath),
          fileSystem.readFile(sourcePath),
        ]);
        if (!existing.equals(accepted)) {
          throw new Error(
            "Deep reduction cannot overwrite a conflicting accepted finding writeup.",
          );
        }
      }
      await requireRegularFile(destinationPath, scanRoot);
    }
  }

  for (const finding of reduction.findings) {
    if (finding.writeup === undefined) continue;
    await requireRegularFile(
      join(scanRoot, finding.writeup.reportPath),
      scanRoot,
    );
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

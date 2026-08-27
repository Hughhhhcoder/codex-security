#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

PLUGIN_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_PATH = PLUGIN_ROOT / "schemas" / "patch-risk-assessment.schema.json"
NON_APPLICABLE = {"no_live_effect", "wrong_owner", "duplicate", "superseded"}
SUPPORTED_SCHEMA_KEYS = {
    "$defs",
    "$id",
    "$ref",
    "$schema",
    "additionalProperties",
    "const",
    "enum",
    "items",
    "maxItems",
    "minItems",
    "minLength",
    "minProperties",
    "pattern",
    "properties",
    "required",
    "title",
    "type",
    "uniqueItems",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate a patch-risk assessment.")
    parser.add_argument("assessment", help="Assessment JSON path, or - for stdin.")
    return parser.parse_args()


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object key: {key}")
        value[key] = item
    return value


def read_object(path: str) -> dict[str, Any]:
    try:
        text = sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8")
        value = json.loads(text, object_pairs_hook=reject_duplicate_keys)
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read assessment: {error}") from error
    if not isinstance(value, dict):
        raise ValueError("assessment must be a JSON object")
    return value


def read_schema() -> dict[str, Any]:
    try:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read patch-risk schema: {error}") from error
    if not isinstance(schema, dict):
        raise ValueError("patch-risk schema must be an object")
    require_supported_schema(schema, "$")
    return schema


def require_supported_schema(schema: dict[str, Any], path: str) -> None:
    unsupported = set(schema) - SUPPORTED_SCHEMA_KEYS
    if unsupported:
        names = ", ".join(sorted(unsupported))
        raise ValueError(f"unsupported patch-risk schema keyword at {path}: {names}")
    for keyword in ("$defs", "properties"):
        children = schema.get(keyword, {})
        if not isinstance(children, dict):
            raise ValueError(f"patch-risk schema {path}.{keyword} must be an object")
        for name, child in children.items():
            if not isinstance(child, dict):
                raise ValueError(f"patch-risk schema {path}.{keyword}.{name} must be an object")
            require_supported_schema(child, f"{path}.{keyword}.{name}")
    for keyword in ("additionalProperties", "items"):
        child = schema.get(keyword)
        if isinstance(child, dict):
            require_supported_schema(child, f"{path}.{keyword}")


def json_value_key(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def json_values_equal(left: Any, right: Any) -> bool:
    if (
        isinstance(left, (int, float))
        and not isinstance(left, bool)
        and isinstance(right, (int, float))
        and not isinstance(right, bool)
    ):
        return left == right
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(
            json_values_equal(left[key], right[key]) for key in left
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            json_values_equal(left_item, right_item)
            for left_item, right_item in zip(left, right, strict=True)
        )
    return left == right


def matches_type(value: Any, expected: str) -> bool:
    return {
        "array": isinstance(value, list),
        "boolean": isinstance(value, bool),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "null": value is None,
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "object": isinstance(value, dict),
        "string": isinstance(value, str),
    }.get(expected, False)


def validate_schema_value(
    value: Any,
    schema: dict[str, Any],
    root: dict[str, Any],
    path: str,
) -> list[str]:
    errors: list[str] = []
    reference = schema.get("$ref")
    if reference is not None:
        prefix = "#/$defs/"
        if not isinstance(reference, str) or not reference.startswith(prefix):
            raise ValueError(f"unsupported patch-risk schema reference at {path}")
        target = root.get("$defs", {}).get(reference.removeprefix(prefix))
        if not isinstance(target, dict):
            raise ValueError(f"unresolved patch-risk schema reference at {path}: {reference}")
        errors.extend(validate_schema_value(value, target, root, path))

    expected_type = schema.get("type")
    if isinstance(expected_type, str) and not matches_type(value, expected_type):
        return [f"{path}: expected {expected_type}"]
    if "const" in schema and not json_values_equal(value, schema["const"]):
        errors.append(f"{path}: value does not match const")
    if "enum" in schema and all(
        not json_values_equal(value, candidate) for candidate in schema["enum"]
    ):
        errors.append(f"{path}: value is not in enum")

    if isinstance(value, dict):
        required = schema.get("required", [])
        for name in required:
            if name not in value:
                errors.append(f"{path}.{name}: required property is missing")
        properties = schema.get("properties", {})
        additional = schema.get("additionalProperties", True)
        for name, child_value in value.items():
            child_path = f"{path}.{name}"
            child_schema = properties.get(name)
            if isinstance(child_schema, dict):
                errors.extend(validate_schema_value(child_value, child_schema, root, child_path))
            elif additional is False:
                errors.append(f"{child_path}: additional property is not allowed")
            elif isinstance(additional, dict):
                errors.extend(validate_schema_value(child_value, additional, root, child_path))
        minimum = schema.get("minProperties")
        if isinstance(minimum, int) and len(value) < minimum:
            errors.append(f"{path}: expected at least {minimum} properties")

    if isinstance(value, list):
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                errors.extend(validate_schema_value(item, item_schema, root, f"{path}[{index}]"))
        minimum = schema.get("minItems")
        if isinstance(minimum, int) and len(value) < minimum:
            errors.append(f"{path}: expected at least {minimum} items")
        maximum = schema.get("maxItems")
        if isinstance(maximum, int) and len(value) > maximum:
            errors.append(f"{path}: expected at most {maximum} items")
        if schema.get("uniqueItems") is True:
            keys = [json_value_key(item) for item in value]
            if len(keys) != len(set(keys)):
                errors.append(f"{path}: items must be unique")

    if isinstance(value, str):
        minimum = schema.get("minLength")
        if isinstance(minimum, int) and len(value) < minimum:
            errors.append(f"{path}: expected at least {minimum} characters")
        pattern = schema.get("pattern")
        if isinstance(pattern, str):
            match = re.search(pattern, value)
            if match is None or (
                pattern.startswith("^")
                and pattern.endswith("$")
                and match.span() != (0, len(value))
            ):
                errors.append(f"{path}: value does not match pattern")
    return errors


def schema_errors(value: dict[str, Any]) -> list[str]:
    schema = read_schema()
    return validate_schema_value(value, schema, schema, "$")


def semantic_errors(value: dict[str, Any]) -> list[str]:
    recommendation = value["recommendation"]
    workflow_label = value["workflowLabel"]
    unknowns = value["unknowns"]
    evidence_plan = value["evidencePlan"]
    boundaries = value["materialBoundaries"]
    applicability_status = value["applicability"]["status"]
    affirmative_failure = (
        value["regressionLikelihood"]["rating"] == "critical"
        or any(item["result"] == "contradicted" for item in boundaries)
        or any(item["status"] == "failed" for item in value["validation"])
    )
    errors: list[str] = []

    if recommendation == "merge":
        if workflow_label not in {"auto_merge_candidate", "human_review_required"}:
            errors.append("merge requires an auto-merge or human-review workflow label")
        if value["applicability"]["status"] != "confirmed":
            errors.append("merge requires confirmed applicability")
        if any(item["decisionCritical"] for item in unknowns):
            errors.append("merge cannot retain a decision-critical unknown")
        if any(item["result"] != "supported" for item in boundaries):
            errors.append("merge requires every material boundary to be supported")
        if any(item["status"] == "failed" for item in value["validation"]):
            errors.append("merge cannot retain a failed validation")
        if evidence_plan:
            errors.append("merge cannot retain an evidence plan")
    elif workflow_label != recommendation:
        errors.append("non-merge workflow label must match the recommendation")

    if recommendation == "hold_for_evidence":
        if not any(item["decisionCritical"] for item in unknowns):
            errors.append("hold_for_evidence requires a decision-critical unknown")
        if not evidence_plan:
            errors.append("hold_for_evidence requires a bounded evidence plan")
        if affirmative_failure:
            errors.append("hold_for_evidence cannot defer an established defect")
    elif evidence_plan:
        errors.append("only hold_for_evidence may include an evidence plan")

    if recommendation == "no_op":
        if applicability_status not in NON_APPLICABLE:
            errors.append("no_op requires an established non-applicable disposition")
        if any(item["decisionCritical"] for item in unknowns):
            errors.append("no_op cannot retain a decision-critical unknown")
    elif applicability_status in NON_APPLICABLE:
        errors.append("an established non-applicable disposition requires no_op")

    if recommendation in {"revise", "block"}:
        if not affirmative_failure:
            errors.append(f"{recommendation} requires affirmative failure evidence")

    if workflow_label == "auto_merge_candidate":
        auto_merge_requirements = {
            "impact.rating": value["impact"]["rating"] == "low",
            "regressionLikelihood.rating": value["regressionLikelihood"]["rating"] == "low",
            "regressionProtection.rating": value["regressionProtection"]["rating"] == "strong",
            "regressionProtection.exactHeadChecksPassed": value["regressionProtection"][
                "exactHeadChecksPassed"
            ],
            "recoverability.rating": value["recoverability"]["rating"] == "easy",
            "confidence.rating": value["confidence"]["rating"] == "high",
            "applicability.status": value["applicability"]["status"] == "confirmed",
            "affectedRuntimeRoots": bool(value["affectedRuntimeRoots"]),
            "statusQuoRisk.rating": value["statusQuoRisk"]["rating"] != "unknown",
            "autoMergeExclusions": not value["autoMergeExclusions"],
            "unknowns": not unknowns,
            "validation": all(item["status"] == "passed" for item in value["validation"]),
        }
        for field, passed in auto_merge_requirements.items():
            if not passed:
                errors.append(f"auto_merge_candidate gate failed: {field}")

    return errors


def validate(value: dict[str, Any]) -> list[str]:
    errors = schema_errors(value)
    if errors:
        return errors
    return semantic_errors(value)


def main() -> int:
    args = parse_args()
    try:
        value = read_object(args.assessment)
        errors = validate(value)
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

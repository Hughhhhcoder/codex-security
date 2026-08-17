"""Compare Bun JUnit inventories before changing the required CI runner."""

import argparse
from collections import Counter
from glob import glob
from pathlib import Path
import sys
import xml.etree.ElementTree as ET


def read_report(path: Path) -> tuple[Counter, float]:
    root = ET.parse(path).getroot()
    cases = Counter()
    identities = set()
    for case in root.iter("testcase"):
        status = "passed"
        if case.find("skipped") is not None:
            status = "skipped"
        if case.find("failure") is not None or case.find("error") is not None:
            status = "failed"
        identity = (
            case.get("file", "").replace("\\", "/").removeprefix("./"),
            case.get("classname", ""),
            case.get("name", ""),
        )
        if identity in identities:
            raise ValueError(f"{path}: duplicate test identity: {' > '.join(identity)}")
        identities.add(identity)
        cases[(*identity, status)] += 1
    if not cases:
        raise ValueError(f"{path}: no test cases")
    if int(root.get("tests", str(sum(cases.values())))) != sum(cases.values()):
        raise ValueError(f"{path}: reported test count does not match test cases")
    if any(key[-1] == "failed" for key in cases) or any(
        int(node.get(field, "0"))
        for node in root.iter()
        if node.tag in ("testsuite", "testsuites")
        for field in ("failures", "errors")
    ):
        raise ValueError(f"{path}: test run failed")
    seconds = float(root.get("time", "0"))
    skipped = sum(count for key, count in cases.items() if key[-1] == "skipped")
    print(f"| {path.name} | {sum(cases.values())} | {skipped} | {seconds:.2f} |")
    return cases, seconds


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidates", nargs="+", help="JUnit files or glob patterns")
    args = parser.parse_args()
    print("| Report | Cases | Skipped | Seconds |")
    print("| --- | ---: | ---: | ---: |")
    baseline, _ = read_report(args.baseline)
    candidates = Counter()
    durations = []
    for pattern in args.candidates:
        paths = sorted(glob(pattern))
        if not paths:
            raise ValueError(f"No reports match {pattern}")
        for path in paths:
            cases, seconds = read_report(Path(path))
            candidates.update(cases)
            durations.append(seconds)
    missing, extra = baseline - candidates, candidates - baseline
    if missing or extra:
        for label, difference in (("Missing", missing), ("Extra", extra)):
            for identity, count in sorted(difference.items()):
                print(f"{label} ({count}): {' > '.join(identity)}", file=sys.stderr)
        return 1
    print(f"\nIdentical test inventory and outcomes. Slowest candidate: {max(durations):.2f}s; combined test time: {sum(durations):.2f}s.\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, ET.ParseError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)

import { spawnSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, test } from "bun:test";

const directories: string[] = [];
afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function fixtures() {
  const root = await mkdtemp(join(tmpdir(), "codex-security-test-reports-"));
  directories.push(root);
  return {
    root,
    async report(
      name: string,
      cases: string[],
      failures = 0,
      count = cases.length,
    ) {
      const path = join(root, name);
      await writeFile(
        path,
        `<testsuites tests="${count}" failures="${failures}" time="1.25"><testsuite>${cases.join("")}</testsuite></testsuites>`,
      );
      return path;
    },
  };
}

function testcase(name: string, status = "") {
  return `<testcase file="tests-ts/example.test.ts" classname="example" name="${name}">${status}</testcase>`;
}

function compare(baseline: string, ...candidates: string[]) {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  if (python === null) throw new Error("A Python interpreter is required.");
  return spawnSync(
    python,
    [
      "-I",
      "-B",
      fileURLToPath(
        new URL("../scripts/compare-test-reports.py", import.meta.url),
      ),
      baseline,
      ...candidates,
    ],
    { encoding: "utf8" },
  );
}

describe("JUnit inventory comparison", () => {
  test("merges native shards without depending on test order", async () => {
    const fixture = await fixtures();
    const passed = testcase("accepts &amp; preserves");
    const skipped = testcase("platform-only", "<skipped/>");
    const baseline = await fixture.report("baseline.xml", [passed, skipped]);
    await fixture.report("shard-1.xml", [skipped]);
    await fixture.report("shard-2.xml", [passed]);
    const result = compare(baseline, join(fixture.root, "shard-*.xml"));
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("Identical test inventory and outcomes");
    expect(result.stdout).toContain("combined test time: 2.50s");
  });

  test("rejects ambiguous test identities even when totals match", async () => {
    const fixture = await fixtures();
    const first = testcase("same parameterized name");
    for (const [name, repeated] of [
      ["same-outcome", first],
      ["different-outcome", testcase("same parameterized name", "<skipped/>")],
    ] as const) {
      const baseline = await fixture.report(`${name}-baseline.xml`, [
        first,
        repeated,
      ]);
      const candidate = await fixture.report(`${name}-candidate.xml`, [
        first,
        repeated,
      ]);
      const result = compare(baseline, candidate);
      expect(result.status).toBe(1);
      expect(result.stderr).toContain("duplicate test identity");
    }
  });

  test("rejects dropped, duplicated, skipped, failed, or incomplete results", async () => {
    const fixture = await fixtures();
    const first = testcase("first");
    const second = testcase("second");
    const baseline = await fixture.report("baseline.xml", [first, second]);
    for (const [name, cases, failures, count] of [
      ["missing", [first], 0, 1],
      ["duplicate", [first, second, second], 0, 3],
      ["skipped", [first, testcase("second", "<skipped/>")], 0, 2],
      ["failed", [first, testcase("second", "<failure/>")], 1, 2],
      ["summary-failed", [first, second], 1, 2],
      ["incomplete", [first], 0, 2],
      ["empty", [], 0, 0],
    ] as const) {
      const candidate = await fixture.report(
        `${name}.xml`,
        [...cases],
        failures,
        count,
      );
      expect(compare(baseline, candidate).status, name).toBe(1);
    }
    expect(compare(baseline, join(fixture.root, "absent-*.xml")).status).toBe(
      1,
    );
  });
});

import { stripVTControlCharacters } from "node:util";
import { describe, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import { capture, dependencies, fakeResult } from "./cli-fixtures.js";

describe("CLI scan progress", () => {
  test("uses plain scan progress in headless, CI, and noninteractive terminals", async () => {
    for (const { options, environment, isTTY } of [
      { options: ["--headless"], environment: {}, isTTY: true },
      { options: [], environment: { CI: "true" }, isTTY: true },
      { options: [], environment: { TERM: "dumb" }, isTTY: true },
      { options: [], environment: {}, isTTY: false },
    ]) {
      const stdout = capture();
      const stderr = capture(isTTY);
      const result = fakeResult([], "complete", {
        input_tokens: 1_250,
        cached_input_tokens: 200,
        output_tokens: 30,
      });
      let timers = 0;
      const deps = dependencies({
        environment,
        result,
        costUpdates: [result.cost!],
        scanProgress: [
          { phase: "discovery", filesCompleted: 3, filesTotal: 8 },
        ],
        workerStatuses: [
          { kind: "dispatch", phase: "file_review", planned: 2, started: 2 },
        ],
      });
      deps.setInterval = () => {
        timers += 1;
        return {} as NodeJS.Timeout;
      };

      expect(
        await main(
          ["scan", ".", ...options],
          stdout.stream,
          stderr.stream,
          deps,
        ),
      ).toBe(0);
      expect(stderr.text()).toContain("[00:00] Preparing scan");
      expect(stderr.text()).toContain(
        "Scan phase: reviewing files (3/8 files).",
      );
      expect(stderr.text()).toContain(
        "Scan phase: reviewing files (2 workers).",
      );
      expect(stderr.text()).toContain(
        "Running scan: reviewing files | Workers: 2/2 | Files: 3/8 | Tokens: 1,250 input, 200 cached, 30 output | Cost: $0.00625",
      );
      expect(stderr.text()).not.toContain("CODEX SECURITY");
      expect(stderr.text()).not.toContain("\u001B");
      expect(stderr.text()).not.toContain("\r");
      expect(timers).toBe(0);
    }
  });

  test("uses plain progress when rerunning scans in CI", async () => {
    const stdout = capture();
    const stderr = capture(true);

    expect(
      await main(
        ["scans", "rerun", "scan-original"],
        stdout.stream,
        stderr.stream,
        dependencies({
          environment: { CI: "true" },
          onWorkbench: () => ({
            recipe: {
              repository: "/original/repository",
              target: { kind: "repository", paths: [] },
              mode: "standard",
              config: {},
            },
          }),
          scanProgress: [
            { phase: "discovery", filesCompleted: 3, filesTotal: 8 },
          ],
        }),
      ),
    ).toBe(0);
    expect(stderr.text()).toContain("[00:00] Preparing scan");
    expect(stderr.text()).toContain("Scan phase: reviewing files (3/8 files).");
    expect(stderr.text()).not.toContain("\u001B");
    expect(stderr.text()).not.toContain("\r");
  });

  test("keeps terminal scans in one live dashboard", async () => {
    const stdout = capture();
    const stderr = capture(true);
    const result = fakeResult([], "complete", {
      input_tokens: 17_985,
      cached_input_tokens: 10_496,
      output_tokens: 236,
    });

    expect(
      await main(
        [
          "scan",
          "/code/juice-shop",
          "--model",
          "gpt-5.6-terra",
          "--codex",
          'model_reasoning_effort="low"',
          "--max-cost",
          "2",
        ],
        stdout.stream,
        stderr.stream,
        dependencies({
          environment: { NO_COLOR: "1" },
          result,
          activities: [
            {
              id: "read-1",
              kind: "command",
              status: "running",
              description:
                'nl -ba "$CODEX_SECURITY_REPOSITORY/routes/login.ts"',
              paths: ["routes/login.ts"],
            },
            {
              id: "worker-1:read-1",
              kind: "command",
              status: "running",
              description:
                'rg -n "password" "$CODEX_SECURITY_REPOSITORY/routes/login.ts"',
              paths: ["routes/login.ts"],
              worker: 1,
            },
            {
              id: "worker-1:thinking-1",
              kind: "reasoning",
              status: "completed",
              description: "Following the login request into the SQL query.",
              paths: [],
              worker: 1,
            },
            {
              id: "worker-1:message-1",
              kind: "message",
              status: "completed",
              description: "The request reaches the query without validation.",
              paths: [],
              worker: 1,
            },
            {
              id: "request-1",
              kind: "command",
              status: "running",
              description:
                'curl -H "Authorization: Bearer sk-proj-SYNTHETIC_OPENAI_VALUE_123"',
              paths: [],
            },
          ],
          costUpdates: [result.cost!],
          scanProgress: [
            { phase: "preflight", filesCompleted: 0, filesTotal: 1_258 },
            { phase: "discovery", filesCompleted: 3, filesTotal: 1_258 },
          ],
          workerStatuses: [
            { kind: "dispatch", phase: "file_review", planned: 6, started: 3 },
          ],
        }),
      ),
    ).toBe(0);

    const text = stripVTControlCharacters(stderr.text());
    expect(text).toContain(
      "CODEX SECURITY  ·  juice-shop  ·  gpt-5.6-terra (low)",
    );
    expect(text).not.toContain("ACTIVITY");
    expect(text).not.toContain("events · live");
    expect(text).not.toContain("WORKERS");
    expect(text).toContain("routes/login.ts");
    expect(text).toMatch(/\[\d{2}:\d{2}:\d{2}\]/u);
    expect(text).toContain(
      'worker 1 · rg -n "password" "$CODEX_SECURITY_REPOSITORY/routes/login.ts"',
    );
    expect(text).toContain(
      "worker 1 · Following the login request into the SQL query.",
    );
    expect(text).toContain(
      "worker 1 · The request reaches the query without validation.",
    );
    expect(text).not.toContain("thinking ·");
    expect(text).not.toContain("said ·");
    expect(text).toContain('curl -H "Authorization: Bearer [redacted]"');
    expect(text).not.toContain("SYNTHETIC_OPENAI_VALUE_123");
    expect(text).not.toContain("Building the file inventory");
    expect(text).not.toContain("Running a scan command");
    expect(text).toContain("3 / 1,258 reviewed");
    expect(text).not.toContain("opened");
    expect(text).not.toContain("3 / 6 active");
    expect(text).toContain("17,985 in · 10,496 cached · 236 out");
    expect(text).toContain("/ $2.00");
    expect(stderr.text()).toContain("\u001B[?1049h");
    expect(stderr.text()).toContain("\u001B[?1049l");
    expect(text).not.toContain("Running scan: preflight");
    expect(text).not.toContain("Estimated cost: $0.0248865 of $2.00 limit");
  });

  test("shows live stage, files, workers, tokens, and cost without a budget", async () => {
    const stdout = capture();
    const stderr = capture();
    const result = fakeResult([], "complete", {
      input_tokens: 1_250,
      cached_input_tokens: 200,
      output_tokens: 30,
    });

    expect(
      await main(
        ["scan", ".", "--json"],
        stdout.stream,
        stderr.stream,
        dependencies({
          result,
          costUpdates: [result.cost!],
          scanProgress: [
            { phase: "discovery", filesCompleted: 0, filesTotal: 8 },
            { phase: "discovery", filesCompleted: 3, filesTotal: 8 },
          ],
          workerStatuses: [
            { kind: "dispatch", phase: "file_review", planned: 6, started: 4 },
          ],
        }),
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(result.toJSON());
    expect(stderr.text()).toContain(
      "Tokens: 1,250 input, 200 cached, 30 output. Estimated cost: $0.00625 USD.",
    );
    expect(stderr.text()).toContain("Scan phase: reviewing files (0/8 files).");
    expect(stderr.text()).toContain("Scan phase: reviewing files (3/8 files).");
    expect(stderr.text()).toContain(
      "Running scan: reviewing files | Workers: 4/6 | Files: 3/8 | Tokens: 1,250 input, 200 cached, 30 output | Cost: $0.00625",
    );
  });

  test("deduplicates live file progress and reports later scan phases", async () => {
    const stdout = capture();
    const stderr = capture();
    const discovery = {
      phase: "discovery",
      filesCompleted: 8,
      filesTotal: 8,
    } as const;

    expect(
      await main(
        ["scan", ".", "--json"],
        stdout.stream,
        stderr.stream,
        dependencies({
          scanProgress: [
            discovery,
            discovery,
            { phase: "validation", filesCompleted: 8, filesTotal: 8 },
            { phase: "reporting", filesCompleted: 8, filesTotal: 8 },
          ],
        }),
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(fakeResult().toJSON());
    expect(
      stderr.text().match(/Scan phase: reviewing files \(8\/8 files\)/g),
    ).toHaveLength(1);
    expect(stderr.text()).toContain(
      "Scan phase: validating findings (8/8 files).",
    );
    expect(stderr.text()).toContain("Scan phase: writing report (8/8 files).");
  });
});

import { spawnSync } from "node:child_process";
import * as fsPromises from "node:fs/promises";
import {
  appendFile,
  chmod,
  mkdir,
  mkdtemp,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, mock, spyOn, test } from "bun:test";
import { estimateScanCost, ScanCostTracker } from "../src/cost.js";
import type { ScanActivity } from "../src/scan-activity.js";
import type { ScanProgress } from "../src/worker-progress.js";
import { runMockInSubprocess } from "./support/isolated-mock.js";

const temporaryDirectories: string[] = [];
const testPosix =
  process.platform === "win32" || process.geteuid?.() === 0 ? test.skip : test;

async function waitFor(check: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (check()) return;
    await new Promise<void>((resolve) => setTimeout(resolve, 5));
  }
  throw new Error("Timed out waiting for the cost tracker.");
}

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

async function codexHome(): Promise<string> {
  const directory = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-cost-")),
  );
  temporaryDirectories.push(directory);
  return directory;
}

async function writeSession(
  home: string,
  threadId: string,
  usage: Record<string, number> | null,
  parentThreadId?: string,
  workingDirectory?: string,
  timestamp?: string,
  completed = false,
): Promise<string> {
  const directory = join(home, "sessions", "2026", "07", "26");
  await mkdir(directory, { recursive: true });
  const path = join(directory, `rollout-${threadId}.jsonl`);
  await writeFile(
    path,
    [
      JSON.stringify({
        type: "session_meta",
        payload: {
          id: threadId,
          ...(workingDirectory === undefined ? {} : { cwd: workingDirectory }),
          ...(timestamp === undefined ? {} : { timestamp }),
          ...(parentThreadId === undefined
            ? {}
            : {
                source: {
                  subagent: {
                    thread_spawn: { parent_thread_id: parentThreadId },
                  },
                },
              }),
        },
      }),
      ...(completed ? [taskEvent("task_started")] : []),
      ...(usage === null
        ? []
        : [
            JSON.stringify({
              type: "event_msg",
              payload: {
                type: "token_count",
                info: { total_token_usage: usage },
              },
            }),
          ]),
      ...(completed ? [taskEvent("task_complete")] : []),
      "",
    ].join("\n"),
  );
  return path;
}

function taskEvent(
  type: "task_started" | "task_complete" | "turn_complete" | "turn_aborted",
): string {
  return JSON.stringify({
    type: "event_msg",
    payload: {
      type,
      turn_id: "fixture-turn",
      started_at: 1_785_067_320,
      ...(type === "task_started" ? {} : { completed_at: 1_785_067_321 }),
      ...(type === "turn_aborted" ? { reason: "interrupted" } : {}),
    },
  });
}

type MockAccountingEvent = Readonly<Record<string, unknown>> | Error;

function accountingEvent(
  usage: Readonly<Record<string, number>>,
): MockAccountingEvent {
  return {
    type: "event_msg",
    payload: { type: "token_count", info: { total_token_usage: usage } },
  };
}

function accountingSession(
  threadId: string,
  events: readonly MockAccountingEvent[],
  parentThreadId?: string,
  metadata: Readonly<Record<string, unknown>> = {},
): MockAccountingEvent[] {
  return [
    {
      type: "session_meta",
      payload: { ...metadata, id: threadId, parent_thread_id: parentThreadId },
    },
    ...events,
    { type: "event_msg", payload: { type: "task_complete" } },
  ];
}

async function withMockAccountingSessions(
  sessions: Readonly<Record<string, readonly MockAccountingEvent[]>>,
  options: Omit<ConstructorParameters<typeof ScanCostTracker>[0], "codexHome">,
  check: (
    tracker: ScanCostTracker,
    append: (threadId: string, events: readonly MockAccountingEvent[]) => void,
  ) => Promise<void>,
): Promise<void> {
  const home = join(tmpdir(), "codex-security-mock-cost");
  const directory = join(home, "sessions");
  const files = new Map<string, Buffer>();
  const events = new Map<string, MockAccountingEvent>();
  const append = (
    threadId: string,
    next: readonly MockAccountingEvent[],
  ): void => {
    const path = join(directory, `rollout-${threadId}.jsonl`);
    const lines = next.map((event) => {
      // The reader sees valid markers; decoded events and errors stay in memory.
      const marker = JSON.stringify({ mockSessionEvent: events.size });
      events.set(marker, event);
      return `${marker}\n`;
    });
    files.set(
      path,
      Buffer.concat([
        files.get(path) ?? Buffer.alloc(0),
        Buffer.from(lines.join("")),
      ]),
    );
  };
  for (const [threadId, initial] of Object.entries(sessions)) {
    append(threadId, initial);
  }
  const originalOpen = fsPromises.open;
  const originalReaddir = fsPromises.readdir;
  const originalParse = JSON.parse;
  mock.module("node:fs/promises", () => ({
    ...fsPromises,
    readdir: async (path: unknown) => {
      if (String(path) !== directory)
        throw new Error("Unexpected session directory");
      return [...files.keys()].map((path) => ({
        name: path.slice(directory.length + 1),
        isDirectory: () => false,
        isFile: () => true,
      }));
    },
    open: async (path: unknown) => {
      const contents = files.get(String(path));
      if (contents === undefined) throw new Error("Unexpected session file");
      return {
        read: async (
          buffer: Buffer,
          offset: number,
          length: number,
          position: number,
        ) => ({
          bytesRead:
            position >= contents.length
              ? 0
              : contents.copy(buffer, offset, position, position + length),
          buffer,
        }),
        close: async () => {},
      };
    },
  }));
  const parse = spyOn(JSON, "parse").mockImplementation((text, reviver) => {
    const event = events.get(text);
    if (event instanceof Error) throw event;
    return event ?? originalParse(text, reviver);
  });
  const tracker = new ScanCostTracker({ ...options, codexHome: home });
  tracker.start("scan-thread");
  try {
    await check(tracker, append);
  } finally {
    await tracker.stop().catch(() => {});
    parse.mockRestore();
    mock.module("node:fs/promises", () => ({
      ...fsPromises,
      open: originalOpen,
      readdir: originalReaddir,
    }));
  }
}

async function workerScan({
  rootUsage = { input_tokens: 100, output_tokens: 10 },
  workerUsage = { input_tokens: 100, output_tokens: 10 },
  workerCompleted = true,
  maxCostUsd,
  onCost,
}: {
  rootUsage?: Record<string, number> | null;
  workerUsage?: Record<string, number> | null;
  workerCompleted?: boolean;
  maxCostUsd?: number;
  onCost?: (cost: { estimatedUsd: number }) => void;
} = {}): Promise<{
  home: string;
  root: string;
  worker: string;
  tracker: ScanCostTracker;
}> {
  const home = await codexHome();
  const root = await writeSession(home, "scan-thread", rootUsage);
  const worker = await writeSession(
    home,
    "worker-thread",
    workerUsage,
    "scan-thread",
    undefined,
    undefined,
    workerCompleted,
  );
  const tracker = new ScanCostTracker({
    codexHome: home,
    model: "gpt-5.6-terra",
    maxCostUsd,
    onCost,
  });
  tracker.start("scan-thread");
  return { home, root, worker, tracker };
}

async function appendSessionItem(
  path: string,
  payload: Readonly<Record<string, unknown>>,
): Promise<void> {
  await appendFile(
    path,
    `${JSON.stringify({ type: "response_item", payload })}\n`,
  );
}

async function appendIncompleteTokenUsage(path: string): Promise<void> {
  const event = JSON.stringify({
    type: "event_msg",
    payload: {
      type: "token_count",
      info: {
        total_token_usage: { input_tokens: 10_000, output_tokens: 1_000 },
      },
    },
  });
  await appendFile(path, event.slice(0, -1));
}

function progressMessage(
  filesCompleted: number,
  filesTotal = 8,
  phase: ScanProgress["phase"] = "discovery",
): Record<string, unknown> {
  return {
    type: "message",
    role: "assistant",
    content: [
      {
        type: "output_text",
        text: `CODEX_SECURITY_SCAN_PROGRESS ${JSON.stringify({
          phase,
          filesCompleted,
          filesTotal,
        })}`,
      },
    ],
  };
}

describe("scan cost", () => {
  test.each([
    [{ cache_write_tokens: 15 }, 15],
    [{ cache_write_input_tokens: 0, cache_write_tokens: 15 }, 15],
    [{ cache_write_input_tokens: 0, cache_write_tokens: 80 }, 0],
  ] as const)(
    "keeps workbench cache-write normalization aligned with SDK usage",
    async (cacheWrites, expectedCacheWrites) => {
      const { PLUGIN_ROOT } = await import("./plugin-root.js");
      const python = Bun.which("python3") ?? Bun.which("python");
      expect(python).not.toBeNull();
      const usage = {
        input_tokens: 100,
        cached_input_tokens: 40,
        ...cacheWrites,
        output_tokens: 20,
        reasoning_output_tokens: 5,
        total_tokens: 120,
      };
      const probe = [
        "import json, sys",
        "sys.path.insert(0, sys.argv[1])",
        "import workbench_scan_usage",
        "payload = {'info': {'total_token_usage': json.loads(sys.argv[2])}}",
        "print(json.dumps(workbench_scan_usage._token_snapshot(payload)))",
      ].join("\n");
      const result = spawnSync(
        python!,
        [
          "-I",
          "-B",
          "-c",
          probe,
          join(PLUGIN_ROOT, "scripts"),
          JSON.stringify(usage),
        ],
        { encoding: "utf8" },
      );

      expect(result.status, result.stderr).toBe(0);
      expect(JSON.parse(result.stdout)).toMatchObject({
        inputTokens: 100,
        cachedInputTokens: 40,
        cacheWriteInputTokens: expectedCacheWrites,
        outputTokens: 20,
        totalTokens: 120,
      });
    },
  );

  test("uses published GPT-5.6 model rates", () => {
    const usage = { input_tokens: 1_000_000, output_tokens: 1_000_000 };

    expect(estimateScanCost("gpt-5.6", usage)?.estimatedUsd).toBe(35);
    expect(estimateScanCost("gpt-5.6-sol", usage)?.estimatedUsd).toBe(35);
    expect(estimateScanCost("gpt-5.6-terra", usage)?.estimatedUsd).toBe(14);
    expect(estimateScanCost("gpt-5.6-luna", usage)?.estimatedUsd).toBe(1.4);
  });

  test("uses canonical OpenAI pricing for Amazon Bedrock model identifiers", () => {
    const usage = { input_tokens: 1_000_000, output_tokens: 1_000_000 };

    for (const [model, expectedUsd] of [
      ["openai.gpt-5.6", 35],
      ["openai.gpt-5.6-sol", 35],
      ["openai.gpt-5.6-terra", 14],
      ["openai.gpt-5.6-luna", 1.4],
    ] as const) {
      expect(estimateScanCost(model, usage)).toMatchObject({
        model,
        estimatedUsd: expectedUsd,
      });
    }

    expect(estimateScanCost("openai.unknown-model", usage)).toBeNull();
  });

  test("uses current Terra and Luna input, cache, and output rates", () => {
    for (const [model, input, cached, write, output] of [
      ["gpt-5.6-terra", 2, 0.2, 2.5, 12],
      ["gpt-5.6-luna", 0.2, 0.02, 0.25, 1.2],
    ] as const) {
      expect(
        estimateScanCost(model, {
          input_tokens: 1_000_000,
          output_tokens: 0,
        })?.estimatedUsd,
      ).toBe(input);
      expect(
        estimateScanCost(model, {
          input_tokens: 1_000_000,
          cached_input_tokens: 1_000_000,
          output_tokens: 0,
        })?.estimatedUsd,
      ).toBe(cached);
      expect(
        estimateScanCost(model, {
          input_tokens: 1_000_000,
          cache_write_input_tokens: 1_000_000,
          output_tokens: 0,
        })?.estimatedUsd,
      ).toBe(write);
      expect(
        estimateScanCost(model, {
          input_tokens: 0,
          output_tokens: 1_000_000,
        })?.estimatedUsd,
      ).toBe(output);
    }
  });

  test("charges cached input at its discounted rate", () => {
    expect(
      estimateScanCost("gpt-5.6-sol", {
        input_tokens: 1_250,
        cached_input_tokens: 200,
        output_tokens: 30,
      }),
    ).toEqual({
      model: "gpt-5.6-sol",
      inputTokens: 1_250,
      cachedInputTokens: 200,
      cacheWriteInputTokens: 0,
      outputTokens: 30,
      estimatedUsd: 0.00625,
    });
  });

  test("charges GPT-5.6 cache writes at their published rate", () => {
    expect(
      estimateScanCost("gpt-5.6-sol", {
        input_tokens: 1_000,
        cached_input_tokens: 100,
        cache_write_input_tokens: 200,
        output_tokens: 10,
      })?.estimatedUsd,
    ).toBe(0.0051);
  });

  test("preserves legacy cache writes after SDK normalization adds zero", () => {
    expect(
      estimateScanCost("gpt-5.6-sol", {
        input_tokens: 1_000,
        cached_input_tokens: 100,
        cache_write_input_tokens: 0,
        cache_write_tokens: 200,
        output_tokens: 10,
      }),
    ).toMatchObject({ cacheWriteInputTokens: 200, estimatedUsd: 0.0051 });
  });

  test("ignores impossible legacy cache writes while retaining canonical usage", () => {
    expect(
      estimateScanCost("gpt-5.6-sol", {
        input_tokens: 1_000,
        cached_input_tokens: 100,
        cache_write_input_tokens: 0,
        cache_write_tokens: 1_001,
        output_tokens: 10,
      }),
    ).toMatchObject({ cacheWriteInputTokens: 0, estimatedUsd: 0.00485 });
  });

  test("does not double-charge reasoning tokens included in output", () => {
    expect(
      estimateScanCost("gpt-5.6-sol", {
        input_tokens: 1_000,
        output_tokens: 10,
        reasoning_output_tokens: 9,
      })?.estimatedUsd,
    ).toBe(0.0053);
  });

  test("does not invent prices for unknown models or incomplete usage", () => {
    for (const [model, usage] of [
      ["unknown-model", { input_tokens: 1, output_tokens: 1 }],
      ["gpt-5.6-sol", null],
      ["gpt-5.6-sol", {}],
      ["gpt-5.6-sol", { input_tokens: -1, output_tokens: 1 }],
      ["gpt-5.6-sol", { input_tokens: 1.5, output_tokens: 1 }],
      [
        "gpt-5.6-sol",
        { input_tokens: 1, cached_input_tokens: 2, output_tokens: 1 },
      ],
      [
        "gpt-5.6-sol",
        {
          input_tokens: Number.MAX_SAFE_INTEGER,
          output_tokens: Number.MAX_SAFE_INTEGER,
        },
      ],
    ] as const) {
      expect(estimateScanCost(model, usage)).toBeNull();
    }
  });
});

describe("live scan cost tracking", () => {
  test("coalesces overlapping polling ticks and bounds final work", async () => {
    const home = await codexHome();
    await writeSession(home, "scan-thread", {
      input_tokens: 100,
      output_tokens: 10,
    });
    const releases: Array<() => void> = [];
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
      maxCostUsd: 1,
    });
    const refresh = tracker.refresh.bind(tracker);
    tracker.refresh = async () => {
      await new Promise<void>((resolve) => releases.push(resolve));
      return refresh();
    };
    tracker.start("scan-thread");

    await new Promise<void>((resolve) => setTimeout(resolve, 350));
    expect(releases).toHaveLength(1);

    const stopped = tracker.stop();
    expect(releases).toHaveLength(2);
    releases[0]!();
    releases[1]!();

    expect((await stopped).cost?.inputTokens).toBe(100);
    expect(releases).toHaveLength(2);
  });

  test("retries one coalesced poll after a failed refresh", async () => {
    const home = await codexHome();
    await writeSession(home, "scan-thread", {
      input_tokens: 100,
      output_tokens: 10,
    });
    const errors: string[] = [];
    let traversals = 0;
    let release: (() => void) | undefined;
    const blocked = new Promise<void>((resolve) => {
      release = resolve;
    });
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
      maxCostUsd: 1,
      onError: (error) => {
        if (error instanceof Error) errors.push(error.message);
      },
    });
    const refresh = tracker.refresh.bind(tracker);
    tracker.refresh = async () => {
      traversals += 1;
      if (traversals === 1) {
        await blocked;
        throw new Error("session read failed");
      }
      return refresh();
    };
    tracker.start("scan-thread");

    await new Promise<void>((resolve) => setTimeout(resolve, 250));
    expect(traversals).toBe(1);
    release!();
    await waitFor(() => traversals === 2);

    expect(errors).toEqual(["session read failed"]);
    expect(traversals).toBe(2);
    expect((await tracker.stop()).cost?.inputTokens).toBe(100);
  });

  test("reports live token use and cost without a spending limit", async () => {
    const home = await codexHome();
    await writeSession(home, "scan-thread", {
      input_tokens: 1_250,
      cached_input_tokens: 200,
      output_tokens: 30,
    });
    let reportCost!: (cost: unknown) => void;
    const reportedCost = new Promise<unknown>((resolve) => {
      reportCost = resolve;
    });
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
      onCost: reportCost,
    });
    tracker.start("scan-thread");

    try {
      await expect(reportedCost).resolves.toEqual({
        model: "gpt-5.6-sol",
        inputTokens: 1_250,
        cachedInputTokens: 200,
        cacheWriteInputTokens: 0,
        outputTokens: 30,
        estimatedUsd: 0.00625,
      });
    } finally {
      await tracker.stop();
    }
  });

  test("counts the scan and delegated workers without including other scans", async () => {
    const home = await codexHome();
    await writeSession(home, "scan-thread", {
      input_tokens: 1_000,
      cached_input_tokens: 100,
      cache_write_input_tokens: 200,
      output_tokens: 10,
      reasoning_output_tokens: 2,
    });
    await writeSession(
      home,
      "worker-thread",
      {
        input_tokens: 250,
        cached_input_tokens: 50,
        output_tokens: 5,
        reasoning_output_tokens: 1,
      },
      "scan-thread",
    );
    await writeSession(home, "unrelated-thread", {
      input_tokens: 1_000_000,
      output_tokens: 1_000_000,
    });
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
    });
    tracker.start("scan-thread");

    expect(await tracker.stop()).toEqual({
      usage: {
        input_tokens: 1_250,
        cached_input_tokens: 150,
        cache_write_input_tokens: 200,
        output_tokens: 15,
        reasoning_output_tokens: 3,
        total_tokens: 1_265,
      },
      cost: {
        model: "gpt-5.6-sol",
        inputTokens: 1_250,
        cachedInputTokens: 150,
        cacheWriteInputTokens: 200,
        outputTokens: 15,
        estimatedUsd: 0.006275,
      },
    });
  });

  test("counts independent Deep workers inside the scan directory only", async () => {
    const home = await codexHome();
    const scanDirectory = join(home, "scans", "current");
    await writeSession(
      home,
      "scan-thread",
      { input_tokens: 1_000, output_tokens: 10 },
      undefined,
      scanDirectory,
      "2026-07-26T12:00:00Z",
    );
    await writeSession(
      home,
      "deep-worker",
      { input_tokens: 250, output_tokens: 2 },
      undefined,
      join(
        scanDirectory,
        "artifacts",
        "deep_discovery",
        "workers",
        "worker",
        "output",
      ),
      "2026-07-26T12:01:00Z",
    );
    await writeSession(
      home,
      "deep-reducer",
      { input_tokens: 125, output_tokens: 1 },
      undefined,
      join(scanDirectory, "artifacts"),
      "2026-07-26T12:02:00Z",
    );
    await writeSession(
      home,
      "deep-worker-child",
      { input_tokens: 50, output_tokens: 1 },
      "deep-worker",
    );
    await writeSession(
      home,
      "unrelated-thread",
      { input_tokens: 1_000_000, output_tokens: 1_000_000 },
      undefined,
      `${scanDirectory}-other`,
    );
    await writeSession(
      home,
      "previous-scan",
      { input_tokens: 1_000_000, output_tokens: 1_000_000 },
      undefined,
      join(scanDirectory, "artifacts", "deep_discovery", "previous-worker"),
      "2026-07-26T11:59:00Z",
    );
    await writeSession(
      home,
      "unknown-start",
      { input_tokens: 1_000_000, output_tokens: 1_000_000 },
      undefined,
      join(
        scanDirectory,
        "artifacts",
        "deep_discovery",
        "workers",
        "stale",
        "output",
      ),
    );
    await writeSession(
      home,
      "nested-scan",
      { input_tokens: 1_000_000, output_tokens: 1_000_000 },
      undefined,
      join(scanDirectory, "nested", "artifacts"),
      "2026-07-26T12:03:00Z",
    );
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
      scanDirectory,
    });
    tracker.start("scan-thread");

    expect((await tracker.stop()).usage).toMatchObject({
      input_tokens: 1_425,
      output_tokens: 14,
    });
  });

  test.each([
    ["root metadata is missing", "missing", "independent", 1, true],
    ["root timing is missing", "untimed", "independent", 1, true],
    ["root timing is invalid", "invalid", "independent", 1, true],
    ["worker timing is missing", "timed", "untimed", 1, true],
    ["worker timing is invalid", "timed", "invalid", 1, true],
    ["the worker parent is unobserved", "missing", "orphaned", 1, true],
    ["the worker has a parent", "missing", "parented", 1, false],
    ["the worker is unrelated", "missing", "unrelated", 1, false],
    ["tracking is optional", "missing", "independent", undefined, false],
    ["no worker needs attribution", "missing", "none", 1, false],
  ] as const)(
    "verifies independent Deep worker ownership when %s",
    async (_scenario, rootState, workerState, maxCostUsd, shouldReject) => {
      const home = await codexHome();
      const scanDirectory = join(home, "scans", "current");
      if (rootState !== "missing") {
        await writeSession(
          home,
          "scan-thread",
          { input_tokens: 100, output_tokens: 10 },
          undefined,
          scanDirectory,
          rootState === "timed"
            ? "2026-07-26T12:00:00Z"
            : rootState === "invalid"
              ? "not a timestamp"
              : undefined,
        );
      }
      if (workerState !== "none") {
        await writeSession(
          home,
          "deep-worker",
          { input_tokens: 1_000, output_tokens: 100 },
          workerState === "parented"
            ? "scan-thread"
            : workerState === "orphaned"
              ? "unobserved-coordinator"
              : undefined,
          workerState === "unrelated"
            ? join(home, "another-scan", "artifacts")
            : join(
                scanDirectory,
                "artifacts",
                "deep_discovery",
                "workers",
                "worker",
                "output",
              ),
          workerState === "untimed"
            ? undefined
            : workerState === "invalid"
              ? "not a timestamp"
              : "2026-07-26T12:01:00Z",
          true,
        );
      }
      const tracker = new ScanCostTracker({
        codexHome: home,
        model: "gpt-5.6-terra",
        scanDirectory,
        maxCostUsd,
      });
      tracker.start("scan-thread");
      await tracker.refresh();

      const completed = tracker.stop({ input_tokens: 100, output_tokens: 10 });
      if (shouldReject) {
        await expect(completed).rejects.toThrow(
          "The scan cost limit could not be verified",
        );
      } else {
        await expect(completed).resolves.toMatchObject({
          cost: {
            inputTokens: workerState === "parented" ? 1_100 : 100,
          },
        });
      }
    },
  );

  test("resolves mocked worker ancestry before directory attribution", async () => {
    if (
      runMockInSubprocess(
        import.meta.path,
        "resolves mocked worker ancestry before directory attribution",
      )
    ) {
      return;
    }
    const scanDirectory = join(tmpdir(), "codex-security-mock-scan");
    const artifacts = join(scanDirectory, "artifacts");
    const workerDirectory = join(
      artifacts,
      "deep_discovery",
      "workers",
      "worker",
      "output",
    );
    const rootUsage = { input_tokens: 100, output_tokens: 10 };
    const session = (
      id: string,
      parent?: string,
      cwd?: string,
      timestamp?: string,
      input = 1_000,
    ) =>
      accountingSession(
        id,
        [accountingEvent({ input_tokens: input, output_tokens: input / 10 })],
        parent,
        { cwd, timestamp },
      );
    const roots = {
      "scan-thread": session(
        "scan-thread",
        undefined,
        scanDirectory,
        "2026-07-26T12:00:00Z",
        100,
      ),
      "previous-root": session(
        "previous-root",
        undefined,
        scanDirectory,
        "2026-07-26T11:00:00Z",
      ),
    };
    const previousWorkers = {
      "previous-coordinator": session(
        "previous-coordinator",
        "previous-root",
        artifacts,
      ),
      "previous-worker": session(
        "previous-worker",
        "previous-coordinator",
        workerDirectory,
        "invalid timestamp",
      ),
      "resumed-previous-worker": session(
        "resumed-previous-worker",
        "previous-root",
        workerDirectory,
        "2026-07-26T12:02:00Z",
      ),
      "older-independent": session(
        "older-independent",
        undefined,
        workerDirectory,
        "2026-07-26T11:59:00Z",
      ),
      "older-orphan": session(
        "older-orphan",
        "missing-parent",
        workerDirectory,
        "2026-07-26T11:59:00Z",
      ),
      "older-cycle-a": session(
        "older-cycle-a",
        "older-cycle-b",
        workerDirectory,
        "2026-07-26T11:59:00Z",
      ),
      "older-cycle-b": session("older-cycle-b", "older-cycle-a"),
    };
    await withMockAccountingSessions(
      {
        ...roots,
        ...previousWorkers,
        "current-child": session(
          "current-child",
          "current-independent",
          workerDirectory,
          "2026-07-26T11:59:00Z",
          300,
        ),
        "current-independent": session(
          "current-independent",
          undefined,
          artifacts,
          "2026-07-26T12:01:00Z",
          200,
        ),
        "unrelated-conflict-a": session("unrelated-conflict", "previous-root"),
        "unrelated-conflict-b": session("unrelated-conflict", "missing-parent"),
      },
      { model: "gpt-5.6-terra", maxCostUsd: 1, scanDirectory },
      async (tracker) => {
        expect((await tracker.stop(rootUsage)).cost).toMatchObject({
          inputTokens: 600,
          outputTokens: 60,
        });
      },
    );
    await withMockAccountingSessions(
      {
        ...roots,
        ...previousWorkers,
        "scan-thread": [
          new SyntaxError("mock parser diagnostic"),
          ...roots["scan-thread"],
        ],
      },
      { model: "gpt-5.6-terra", maxCostUsd: 1, scanDirectory },
      async (tracker) => {
        expect((await tracker.stop(rootUsage)).cost?.inputTokens).toBe(100);
      },
    );
    const unresolvedWorkers: Array<Record<string, MockAccountingEvent[]>> = [
      {
        orphan: session(
          "orphan",
          "missing-parent",
          workerDirectory,
          "2026-07-26T12:01:00Z",
        ),
      },
      { orphan: session("orphan", "missing-parent", workerDirectory) },
      {
        "cycle-a": session("cycle-a", "cycle-b", workerDirectory),
        "cycle-b": session("cycle-b", "cycle-a"),
      },
      {
        "conflict-a": session(
          "conflict",
          "scan-thread",
          workerDirectory,
          "2026-07-26T11:59:00Z",
        ),
        "conflict-b": session("conflict", "previous-root"),
      },
      {
        "conflict-a": session("conflict", "scan-thread"),
        "conflict-b": session("conflict", "previous-root"),
      },
    ];
    for (const workers of unresolvedWorkers) {
      await withMockAccountingSessions(
        { ...roots, ...workers },
        { model: "gpt-5.6-terra", maxCostUsd: 1, scanDirectory },
        async (tracker) => {
          await expect(tracker.stop(rootUsage)).rejects.toThrow(
            "The scan cost limit could not be verified",
          );
        },
      );
    }
  });

  test("limits mocked worker-directory attribution to contained output paths", async () => {
    if (
      runMockInSubprocess(
        import.meta.path,
        "limits mocked worker-directory attribution to contained output paths",
      )
    ) {
      return;
    }
    const scanDirectory = join(tmpdir(), "codex-security-mock-scan");
    const artifacts = join(scanDirectory, "artifacts");
    const workers = join(artifacts, "deep_discovery", "workers");
    const timestamp = "2026-07-26T12:01:00Z";
    const rootUsage = { input_tokens: 100, output_tokens: 10 };
    for (const [cwd, startedAt, expectedInput] of [
      [artifacts, timestamp, 1_100],
      [join(workers, "worker", "output"), timestamp, 1_100],
      [join(workers, "worker", "output"), undefined, null],
      [join(artifacts, "deep_discovery", "output"), undefined, 100],
      [join(artifacts, "deep_discovery", "output"), timestamp, 100],
      [
        join(artifacts, "deep_discovery", "workers-other", "worker", "output"),
        undefined,
        100,
      ],
    ] as const) {
      await withMockAccountingSessions(
        {
          "scan-thread": accountingSession(
            "scan-thread",
            [accountingEvent(rootUsage)],
            undefined,
            {
              cwd: scanDirectory,
              timestamp: "2026-07-26T12:00:00Z",
            },
          ),
          worker: accountingSession(
            "worker",
            [accountingEvent({ input_tokens: 1_000, output_tokens: 100 })],
            undefined,
            {
              cwd,
              timestamp: startedAt,
            },
          ),
        },
        { model: "gpt-5.6-terra", maxCostUsd: 1, scanDirectory },
        async (tracker) => {
          const stopped = tracker.stop(rootUsage);
          if (expectedInput === null) {
            await expect(stopped).rejects.toThrow(
              "The scan cost limit could not be verified",
            );
          } else {
            expect((await stopped).cost?.inputTokens).toBe(expectedInput);
          }
        },
      );
    }
  });

  test("keeps mocked replay errors outside owned accounting", async () => {
    if (
      runMockInSubprocess(
        import.meta.path,
        "keeps mocked replay errors outside owned accounting",
      )
    ) {
      return;
    }
    const rootUsage = { input_tokens: 100, output_tokens: 10 };
    for (const location of ["replay", "owned-before", "owned-after"] as const) {
      const costs: number[] = [];
      await withMockAccountingSessions(
        {
          "scan-thread": accountingSession("scan-thread", [
            accountingEvent(rootUsage),
          ]),
          "worker-thread": [
            {
              type: "session_meta",
              payload: {
                id: "worker-thread",
                parent_thread_id: "scan-thread",
                timestamp: "2026-07-26T12:02:00Z",
              },
            },
            ...(location === "owned-before"
              ? [new SyntaxError("mock owned parser diagnostic")]
              : []),
            { type: "session_meta", payload: { id: "scan-thread" } },
            new SyntaxError("mock replay parser diagnostic"),
            accountingEvent({ input_tokens: 1_000, output_tokens: 100 }),
            {
              type: "event_msg",
              payload: { type: "task_started", started_at: 1_785_067_320 },
            },
            ...(location === "owned-after"
              ? [new SyntaxError("mock owned parser diagnostic")]
              : []),
            accountingEvent({ input_tokens: 1_200, output_tokens: 120 }),
            { type: "event_msg", payload: { type: "task_complete" } },
          ],
        },
        {
          model: "gpt-5.6-terra",
          maxCostUsd: 1,
          onCost: (cost) => costs.push(cost.estimatedUsd),
        },
        async (tracker) => {
          const stopped = tracker.stop(rootUsage);
          if (location === "replay") {
            await expect(stopped).resolves.toMatchObject({
              usage: { input_tokens: 300, output_tokens: 30 },
              cost: { estimatedUsd: 0.00096 },
            });
          } else {
            await expect(stopped).rejects.toThrow(
              "tracked session record could not be read",
            );
          }
          expect(costs).toEqual([0.00096]);
        },
      );
    }
  });

  test("ignores replayed parent history in forked worker sessions", async () => {
    const home = await codexHome();
    const inherited = {
      input_tokens: 1_000,
      cached_input_tokens: 500,
      cache_write_input_tokens: 100,
      output_tokens: 100,
      reasoning_output_tokens: 20,
    };
    await writeSession(home, "scan-thread", inherited);
    const worker = await writeSession(home, "worker-thread", inherited);
    const command =
      'rg "password" "$CODEX_SECURITY_REPOSITORY/routes/login.ts"';

    await writeFile(
      worker,
      [
        {
          type: "session_meta",
          payload: {
            id: "worker-thread",
            timestamp: "2026-07-26T12:02:00.250Z",
            source: {
              subagent: {
                thread_spawn: { parent_thread_id: "scan-thread" },
              },
            },
          },
        },
        {
          type: "session_meta",
          payload: {
            id: "scan-thread",
            timestamp: "2026-07-26T12:00:00.000Z",
            source: "exec",
          },
        },
        {
          type: "event_msg",
          payload: { type: "task_started", started_at: 1_785_067_200 },
        },
        {
          type: "event_msg",
          payload: {
            type: "agent_message",
            message: "Inherited parent commentary.",
          },
        },
        {
          type: "response_item",
          payload: {
            type: "function_call",
            name: "exec_command",
            call_id: "inherited-search",
            arguments: JSON.stringify({ cmd: command }),
          },
        },
        { type: "response_item", payload: progressMessage(7) },
        {
          type: "event_msg",
          payload: {
            type: "token_count",
            info: { total_token_usage: inherited },
          },
        },
        {
          type: "event_msg",
          payload: { type: "task_started", started_at: 1_785_067_320 },
        },
        {
          type: "event_msg",
          timestamp: "2026-07-26T12:02:01.000Z",
          payload: {
            type: "agent_message",
            message: "Reviewing the login query.",
          },
        },
        {
          type: "response_item",
          payload: {
            type: "function_call",
            name: "exec_command",
            call_id: "worker-search",
            arguments: JSON.stringify({ cmd: command }),
          },
        },
        {
          type: "response_item",
          payload: {
            type: "function_call_output",
            call_id: "worker-search",
            output:
              "Batch reviewed.\n" +
              'CODEX_SECURITY_SCAN_PROGRESS {"phase":"discovery","filesCompleted":3,"filesTotal":8}',
          },
        },
        {
          type: "event_msg",
          payload: {
            type: "token_count",
            info: {
              total_token_usage: {
                input_tokens: 1_300,
                cached_input_tokens: 650,
                cache_write_input_tokens: 150,
                output_tokens: 130,
                reasoning_output_tokens: 30,
              },
            },
          },
        },
      ]
        .map((event) => JSON.stringify(event))
        .join("\n") + "\n",
    );

    const activities: ScanActivity[] = [];
    const progress: ScanProgress[] = [];
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-terra",
      repository: "/code/juice-shop",
      expectedFilesTotal: 8,
      onActivity: (activity) => activities.push(activity),
      onProgress: (update) => progress.push(update),
    });
    tracker.start("scan-thread");

    expect(await tracker.stop()).toEqual({
      usage: {
        input_tokens: 1_300,
        cached_input_tokens: 650,
        cache_write_input_tokens: 150,
        output_tokens: 130,
        reasoning_output_tokens: 30,
        total_tokens: 1_430,
      },
      cost: {
        model: "gpt-5.6-terra",
        inputTokens: 1_300,
        cachedInputTokens: 650,
        cacheWriteInputTokens: 150,
        outputTokens: 130,
        estimatedUsd: 0.003065,
      },
    });
    expect(activities).toEqual([
      expect.objectContaining({
        kind: "message",
        description: "Reviewing the login query.",
        worker: 1,
      }),
      expect.objectContaining({
        id: "worker-thread:worker-search",
        kind: "command",
        status: "running",
        worker: 1,
      }),
      expect.objectContaining({
        id: "worker-thread:worker-search",
        kind: "command",
        status: "completed",
        worker: 1,
      }),
    ]);
    expect(progress).toEqual([
      { phase: "discovery", filesCompleted: 3, filesTotal: 8 },
    ]);
  });

  test("forwards actions from this scan's delegated workers only", async () => {
    const home = await codexHome();
    const usage = { input_tokens: 100, output_tokens: 10 };
    const parentPath = await writeSession(home, "scan-thread", usage);
    const workerPath = await writeSession(
      home,
      "worker-thread",
      usage,
      "scan-thread",
    );
    const unrelatedPath = await writeSession(home, "unrelated-thread", usage);
    const command =
      'rg -n "password" "$CODEX_SECURITY_REPOSITORY/routes/login.ts"';

    for (const [path, callId] of [
      [parentPath, "parent-command"],
      [workerPath, "worker-command"],
      [unrelatedPath, "unrelated-command"],
    ] as const) {
      await appendSessionItem(path, {
        type: "function_call",
        name: "exec_command",
        call_id: callId,
        arguments: JSON.stringify({ cmd: command }),
      });
      await appendSessionItem(path, {
        type: "function_call_output",
        call_id: callId,
      });
    }

    const activities: ScanActivity[] = [];
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
      repository: "/code/juice-shop",
      onActivity: (activity) => activities.push(activity),
    });
    tracker.start("scan-thread");
    await tracker.stop();

    expect(activities).toEqual([
      {
        id: "worker-thread:worker-command",
        kind: "command",
        status: "running",
        description: command,
        paths: ["routes/login.ts"],
        worker: 1,
      },
      {
        id: "worker-thread:worker-command",
        kind: "command",
        status: "completed",
        description: command,
        paths: ["routes/login.ts"],
        worker: 1,
      },
    ]);
  });

  test("forwards genuine worker reasoning and transcript text", async () => {
    const home = await codexHome();
    const usage = { input_tokens: 100, output_tokens: 10 };
    await writeSession(home, "scan-thread", usage);
    const path = await writeSession(
      home,
      "worker-thread",
      usage,
      "scan-thread",
    );
    await appendSessionItem(path, {
      id: "thinking-1",
      type: "reasoning",
      summary: [{ type: "summary_text", text: "Following the login query." }],
      encrypted_content: "do-not-display",
    });
    await appendSessionItem(path, {
      id: "message-1",
      type: "message",
      role: "assistant",
      content: [{ type: "output_text", text: "The query uses request input." }],
    });

    const activities: ScanActivity[] = [];
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
      repository: "/code/juice-shop",
      onActivity: (activity) => activities.push(activity),
    });
    tracker.start("scan-thread");
    await tracker.stop();

    expect(activities).toEqual([
      {
        id: "worker-thread:thinking-1",
        kind: "reasoning",
        status: "completed",
        description: "Following the login query.",
        paths: [],
        worker: 1,
      },
      {
        id: "worker-thread:message-1",
        kind: "message",
        status: "completed",
        description: "The query uses request input.",
        paths: [],
        worker: 1,
      },
    ]);
  });

  test("streams worker reasoning and commentary from live session events once", async () => {
    const home = await codexHome();
    const usage = { input_tokens: 100, output_tokens: 10 };
    await writeSession(home, "scan-thread", usage);
    const worker = await writeSession(
      home,
      "worker-thread",
      usage,
      "scan-thread",
    );
    await appendFile(
      worker,
      [
        JSON.stringify({
          type: "event_msg",
          timestamp: "2026-07-26T12:00:00.000Z",
          payload: {
            type: "agent_reasoning",
            text: "Tracing the login query.",
          },
        }),
        JSON.stringify({
          type: "response_item",
          payload: {
            id: "reasoning-1",
            type: "reasoning",
            summary: [
              { type: "summary_text", text: "Tracing the login query." },
            ],
            encrypted_content: "must-never-be-displayed",
          },
        }),
        JSON.stringify({
          type: "event_msg",
          timestamp: "2026-07-26T12:00:01.000Z",
          payload: {
            type: "agent_message",
            message:
              "Reviewed the login query.\n" +
              'CODEX_SECURITY_SCAN_PROGRESS {"phase":"discovery","filesCompleted":3,"filesTotal":8}',
          },
        }),
        JSON.stringify({
          type: "response_item",
          payload: {
            id: "message-1",
            type: "message",
            role: "assistant",
            content: [
              { type: "output_text", text: "Reviewed the login query." },
            ],
          },
        }),
        "",
      ].join("\n"),
    );

    const activities: ScanActivity[] = [];
    const updates: ScanProgress[] = [];
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
      repository: "/code/juice-shop",
      expectedFilesTotal: 8,
      onActivity: (activity) => activities.push(activity),
      onProgress: (progress) => updates.push(progress),
    });
    tracker.start("scan-thread");
    await tracker.stop();

    expect(activities).toEqual([
      expect.objectContaining({
        kind: "reasoning",
        description: "Tracing the login query.",
        worker: 1,
      }),
      expect.objectContaining({
        kind: "message",
        description: "Reviewed the login query.",
        worker: 1,
      }),
    ]);
    expect(updates).toEqual([
      { phase: "discovery", filesCompleted: 3, filesTotal: 8 },
    ]);
  });

  test("expands streamed worker reasoning without duplicating summaries or exposing encrypted content", async () => {
    const home = await codexHome();
    const usage = { input_tokens: 100, output_tokens: 10 };
    await writeSession(home, "scan-thread", usage);
    const worker = await writeSession(
      home,
      "worker-thread",
      usage,
      "scan-thread",
    );
    const details = `${"The query reaches a privileged tenant boundary. ".repeat(30)}Final authorization check.`;
    const raw = `**The route builds SQL from request parameters.** ${details}`;
    await appendFile(
      worker,
      [
        {
          type: "event_msg",
          payload: {
            type: "agent_reasoning_delta",
            delta: "Checking whether ",
          },
        },
        {
          type: "event_msg",
          payload: {
            type: "agent_reasoning_delta",
            delta: "the login query escapes user input.",
          },
        },
        {
          type: "event_msg",
          payload: {
            type: "agent_reasoning",
            text: "Checking whether the login query escapes user input.",
          },
        },
        {
          type: "event_msg",
          payload: {
            type: "agent_reasoning_raw_content_delta",
            delta: "The route builds SQL ",
          },
        },
        {
          type: "event_msg",
          payload: {
            type: "agent_reasoning_raw_content_delta",
            delta: "from request parameters.",
          },
        },
        {
          type: "event_msg",
          payload: {
            type: "agent_reasoning_raw_content",
            text: raw,
          },
        },
        {
          type: "event_msg",
          payload: {
            type: "agent_reasoning",
            text: "This summary must not replace public raw reasoning.",
          },
        },
        {
          type: "response_item",
          payload: {
            id: "reasoning-1",
            type: "reasoning",
            summary: [
              {
                type: "summary_text",
                text: "Checking whether the login query escapes user input.",
              },
              { type: "summary_text", text: "Preparing SQL validation." },
            ],
            encrypted_content: "never-display-encrypted-reasoning",
          },
        },
        "",
      ]
        .map((event) =>
          typeof event === "string" ? event : JSON.stringify(event),
        )
        .join("\n"),
    );

    const activities: ScanActivity[] = [];
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
      repository: "/code/juice-shop",
      onActivity: (activity) => activities.push(activity),
    });
    tracker.start("scan-thread");
    await tracker.stop();

    expect(new Set(activities.map((activity) => activity.id))).toEqual(
      new Set(["worker-thread:reasoning-1"]),
    );
    expect(activities).toContainEqual(
      expect.objectContaining({
        kind: "reasoning",
        status: "running",
        description: "Checking whether the login query escapes user input.",
        worker: 1,
      }),
    );
    expect(activities.at(-1)).toEqual({
      id: "worker-thread:reasoning-1",
      kind: "reasoning",
      status: "completed",
      description: `The route builds SQL from request parameters. ${details}`,
      paths: [],
      worker: 1,
    });
    expect(activities.at(-1)!.description.length).toBeGreaterThan(1_000);
    expect(JSON.stringify(activities)).not.toContain("encrypted-reasoning");
  });

  test("keeps distinct streamed worker reasoning summaries separate", async () => {
    const home = await codexHome();
    const usage = { input_tokens: 100, output_tokens: 10 };
    await writeSession(home, "scan-thread", usage);
    const worker = await writeSession(
      home,
      "worker-thread",
      usage,
      "scan-thread",
    );
    const summaries = [
      "**Planning discovery worker tasks**",
      "**Preparing thorough file batch reading**",
      "**Verifying repository read access and tools**",
    ];
    await appendFile(
      worker,
      [
        ...summaries.map((text) => ({
          type: "event_msg",
          payload: { type: "agent_reasoning", text },
        })),
        {
          type: "response_item",
          payload: {
            id: "reasoning-1",
            type: "reasoning",
            summary: summaries.map((text) => ({ type: "summary_text", text })),
            encrypted_content: "must-never-be-displayed",
          },
        },
        "",
      ]
        .map((event) =>
          typeof event === "string" ? event : JSON.stringify(event),
        )
        .join("\n"),
    );

    const activities: ScanActivity[] = [];
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
      repository: "/code/juice-shop",
      onActivity: (activity) => activities.push(activity),
    });
    tracker.start("scan-thread");
    await tracker.stop();

    expect(activities).toEqual(
      summaries.map((text, index) => ({
        id: `worker-thread:reasoning-${index + 1}`,
        kind: "reasoning",
        status: "completed",
        description: text.replaceAll("**", ""),
        paths: [],
        worker: 1,
      })),
    );
  });

  test("splits worker reasoning summaries without streamed events", async () => {
    const home = await codexHome();
    const usage = { input_tokens: 100, output_tokens: 10 };
    await writeSession(home, "scan-thread", usage);
    const worker = await writeSession(
      home,
      "worker-thread",
      usage,
      "scan-thread",
    );
    await appendSessionItem(worker, {
      id: "reasoning-1",
      type: "reasoning",
      summary: [
        { type: "summary_text", text: "**Planning discovery worker tasks**" },
        {
          type: "summary_text",
          text: "**Preparing thorough file batch reading**",
        },
      ],
      encrypted_content: "must-never-be-displayed",
    });

    const activities: ScanActivity[] = [];
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
      repository: "/code/juice-shop",
      onActivity: (activity) => activities.push(activity),
    });
    tracker.start("scan-thread");
    await tracker.stop();

    expect(activities).toEqual([
      {
        id: "worker-thread:reasoning-1:0",
        kind: "reasoning",
        status: "completed",
        description: "Planning discovery worker tasks",
        paths: [],
        worker: 1,
      },
      {
        id: "worker-thread:reasoning-1:1",
        kind: "reasoning",
        status: "completed",
        description: "Preparing thorough file batch reading",
        paths: [],
        worker: 1,
      },
    ]);
    expect(JSON.stringify(activities)).not.toContain("must-never-be-displayed");
  });

  test("forwards reviewed-file progress from descendant workers only", async () => {
    const home = await codexHome();
    const usage = { input_tokens: 100, output_tokens: 10 };
    const parent = await writeSession(home, "scan-thread", usage);
    const worker = await writeSession(
      home,
      "worker-thread",
      usage,
      "scan-thread",
    );
    const descendant = await writeSession(
      home,
      "nested-worker-thread",
      usage,
      "worker-thread",
    );
    const unrelated = await writeSession(home, "unrelated-thread", usage);

    await appendSessionItem(parent, progressMessage(1));
    await appendSessionItem(worker, progressMessage(3));
    await appendSessionItem(worker, progressMessage(4, 9));
    await appendSessionItem(descendant, progressMessage(5));
    await appendSessionItem(unrelated, progressMessage(7));

    const updates: ScanProgress[] = [];
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
      expectedFilesTotal: 8,
      onProgress: (progress) => updates.push(progress),
    });
    tracker.start("scan-thread");
    await tracker.stop();

    expect(updates).toEqual([
      { phase: "discovery", filesCompleted: expect.any(Number), filesTotal: 8 },
      { phase: "discovery", filesCompleted: 8, filesTotal: 8 },
    ]);
    expect([3, 5]).toContain(updates[0]!.filesCompleted);
  });

  test("aggregates worker progress without regressing or changing assigned shards", async () => {
    const home = await codexHome();
    const usage = { input_tokens: 100, output_tokens: 10 };
    const parent = await writeSession(home, "scan-thread", usage);
    const worker = await writeSession(
      home,
      "worker-thread",
      usage,
      "scan-thread",
    );
    const otherWorker = await writeSession(
      home,
      "other-worker-thread",
      usage,
      "scan-thread",
    );
    const unrelated = await writeSession(home, "unrelated-thread", usage);
    const updates: ScanProgress[] = [];
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
      expectedFilesTotal: 1_258,
      onProgress: (progress) => updates.push(progress),
    });
    tracker.start("scan-thread");
    await tracker.refresh();

    await appendSessionItem(worker, progressMessage(3, 1_249));
    await tracker.refresh();

    await appendSessionItem(otherWorker, progressMessage(2, 2));
    await appendSessionItem(otherWorker, progressMessage(3, 3));
    await appendSessionItem(otherWorker, progressMessage(1, 1_259));
    await appendSessionItem(parent, progressMessage(1_200, 1_258));
    await appendSessionItem(unrelated, progressMessage(1_200, 1_258));

    const marker = `CODEX_SECURITY_SCAN_PROGRESS ${JSON.stringify({
      phase: "discovery",
      filesCompleted: 1_200,
      filesTotal: 1_249,
    })}`;
    await appendSessionItem(otherWorker, {
      type: "custom_tool_call_output",
      call_id: "failed-shard-review",
      status: "failed",
      output: [{ type: "input_text", text: marker }],
    });
    await appendSessionItem(otherWorker, {
      type: "custom_tool_call_output",
      call_id: "documented-shard-example",
      status: "completed",
      output: [{ type: "input_text", text: `\`\`\`text\n${marker}\n\`\`\`` }],
    });
    await tracker.refresh();

    await appendSessionItem(worker, progressMessage(1_249, 1_249));
    await tracker.refresh();
    await appendSessionItem(
      worker,
      progressMessage(1_249, 1_249, "validation"),
    );
    await tracker.refresh();
    await tracker.stop();

    expect(updates).toEqual([
      { phase: "discovery", filesCompleted: 3, filesTotal: 1_258 },
      { phase: "discovery", filesCompleted: 5, filesTotal: 1_258 },
      { phase: "discovery", filesCompleted: 1_251, filesTotal: 1_258 },
      { phase: "validation", filesCompleted: 1_251, filesTotal: 1_258 },
    ]);
  });

  test("adds reviewed files from independent delegated-worker shards", async () => {
    const home = await codexHome();
    const usage = { input_tokens: 100, output_tokens: 10 };
    await writeSession(home, "scan-thread", usage);
    const first = await writeSession(home, "worker-a", usage, "scan-thread");
    const second = await writeSession(home, "worker-b", usage, "scan-thread");
    const unrelated = await writeSession(home, "unrelated-worker", usage);
    const updates: ScanProgress[] = [];
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
      expectedFilesTotal: 4_198,
      onProgress: (progress) => updates.push(progress),
    });
    tracker.start("scan-thread");
    await tracker.refresh();

    await appendSessionItem(first, progressMessage(250, 840));
    await tracker.refresh();
    await appendSessionItem(second, progressMessage(100, 839));
    await tracker.refresh();
    await appendSessionItem(unrelated, progressMessage(839, 839));
    await appendSessionItem(first, progressMessage(840, 840));
    await tracker.refresh();
    await appendSessionItem(second, progressMessage(839, 839));
    await tracker.refresh();
    await tracker.stop();

    expect(updates).toEqual([
      { phase: "discovery", filesCompleted: 250, filesTotal: 4_198 },
      { phase: "discovery", filesCompleted: 350, filesTotal: 4_198 },
      { phase: "discovery", filesCompleted: 940, filesTotal: 4_198 },
      { phase: "discovery", filesCompleted: 1_679, filesTotal: 4_198 },
    ]);
  });

  test("counts only explicit successful worker review receipts", async () => {
    const home = await codexHome();
    const usage = { input_tokens: 100, output_tokens: 10 };
    await writeSession(home, "scan-thread", usage);
    const worker = await writeSession(
      home,
      "worker-thread",
      usage,
      "scan-thread",
    );
    const marker = (filesCompleted: number) =>
      `CODEX_SECURITY_SCAN_PROGRESS ${JSON.stringify({
        phase: "discovery",
        filesCompleted,
        filesTotal: 8,
      })}`;

    for (const payload of [
      {
        type: "function_call",
        name: "exec_command",
        call_id: "search",
        arguments: JSON.stringify({
          cmd: 'rg -n "password" "$CODEX_SECURITY_REPOSITORY/routes/login.ts"',
        }),
      },
      {
        type: "function_call_output",
        call_id: "search",
        output: "routes/login.ts:12: const password = request.body.password;",
      },
      {
        type: "function_call_output",
        call_id: "failed-review",
        status: "failed",
        output: marker(2),
      },
      {
        type: "function_call_output",
        call_id: "malformed-review",
        output:
          'CODEX_SECURITY_SCAN_PROGRESS {"phase":"discovery","filesCompleted":}',
      },
      {
        type: "function_call_output",
        call_id: "completed-review",
        output: `Batch reviewed.\n${marker(3)}`,
      },
      {
        type: "custom_tool_call_output",
        call_id: "documented-example",
        output: [
          { type: "input_text", text: "Example:" },
          { type: "input_text", text: `\`\`\`text\n${marker(4)}\n\`\`\`` },
        ],
      },
      {
        type: "custom_tool_call_output",
        call_id: "completed-structured-review",
        status: "completed",
        output: [
          { type: "input_text", text: "Batch reviewed." },
          { type: "input_text", text: marker(4) },
        ],
      },
      {
        type: "custom_tool_call_output",
        call_id: "completed-custom-review",
        output: marker(5),
      },
      progressMessage(9),
    ]) {
      await appendSessionItem(worker, payload);
    }

    const updates: ScanProgress[] = [];
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
      expectedFilesTotal: 8,
      onProgress: (progress) => updates.push(progress),
    });
    tracker.start("scan-thread");
    await tracker.stop();

    expect(updates).toEqual([
      { phase: "discovery", filesCompleted: 3, filesTotal: 8 },
      { phase: "discovery", filesCompleted: 4, filesTotal: 8 },
      { phase: "discovery", filesCompleted: 5, filesTotal: 8 },
    ]);
  });

  test("polls worker file progress without another observer", async () => {
    const home = await codexHome();
    const usage = { input_tokens: 100, output_tokens: 10 };
    await writeSession(home, "scan-thread", usage);
    const worker = await writeSession(
      home,
      "worker-thread",
      usage,
      "scan-thread",
    );
    await appendSessionItem(worker, progressMessage(3));

    let reportProgress!: (progress: ScanProgress) => void;
    const reportedProgress = new Promise<ScanProgress>((resolve) => {
      reportProgress = resolve;
    });
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
      expectedFilesTotal: 8,
      onProgress: reportProgress,
    });
    tracker.start("scan-thread");

    try {
      await expect(reportedProgress).resolves.toEqual({
        phase: "discovery",
        filesCompleted: 3,
        filesTotal: 8,
      });
    } finally {
      await tracker.stop();
    }
  });

  test("reports newly completed worker batches once per progress update", async () => {
    const home = await codexHome();
    const usage = { input_tokens: 100, output_tokens: 10 };
    await writeSession(home, "scan-thread", usage);
    const worker = await writeSession(
      home,
      "worker-thread",
      usage,
      "scan-thread",
    );
    const updates: ScanProgress[] = [];
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
      expectedFilesTotal: 8,
      onProgress: (progress) => updates.push(progress),
    });
    tracker.start("scan-thread");
    await tracker.refresh();

    await appendSessionItem(worker, progressMessage(3));
    await tracker.refresh();
    await appendSessionItem(worker, progressMessage(3));
    await tracker.refresh();
    await appendSessionItem(worker, progressMessage(5));
    await tracker.refresh();
    await tracker.stop();

    expect(updates).toEqual([
      { phase: "discovery", filesCompleted: 3, filesTotal: 8 },
      { phase: "discovery", filesCompleted: 5, filesTotal: 8 },
    ]);
  });

  test("uses each session's final cumulative usage without double counting", async () => {
    const home = await codexHome();
    const path = await writeSession(home, "scan-thread", {
      input_tokens: 100,
      output_tokens: 10,
    });
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-terra",
    });
    tracker.start("scan-thread");
    expect((await tracker.refresh()).cost?.estimatedUsd).toBe(0.00032);

    const latest = JSON.stringify({
      type: "event_msg",
      payload: {
        type: "token_count",
        info: {
          total_token_usage: { input_tokens: 250, output_tokens: 20 },
        },
      },
    });
    await appendFile(path, `${latest}\n${latest}\n`);

    expect((await tracker.stop()).cost).toEqual({
      model: "gpt-5.6-terra",
      inputTokens: 250,
      cachedInputTokens: 0,
      cacheWriteInputTokens: 0,
      outputTokens: 20,
      estimatedUsd: 0.00074,
    });
  });

  test("retains the larger observed cost after a token-counter reset", async () => {
    const home = await codexHome();
    const root = await writeSession(home, "scan-thread", {
      input_tokens: 1_000,
      output_tokens: 100,
    });
    const costs: number[] = [];
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-terra",
      maxCostUsd: 0.001,
      onCost: (cost) => costs.push(cost.estimatedUsd),
    });
    tracker.start("scan-thread");
    expect((await tracker.refresh()).cost?.estimatedUsd).toBe(0.0032);
    await appendFile(
      root,
      `${JSON.stringify({
        type: "event_msg",
        payload: {
          type: "token_count",
          info: {
            total_token_usage: { input_tokens: 500, output_tokens: 50 },
          },
        },
      })}\n`,
    );

    expect((await tracker.stop()).cost?.estimatedUsd).toBe(0.0032);
    expect(costs).toEqual([0.0032]);
  });

  test("keeps mocked parse errors scoped to included budgeted sessions", async () => {
    if (
      runMockInSubprocess(
        import.meta.path,
        "keeps mocked parse errors scoped to included budgeted sessions",
      )
    ) {
      return;
    }
    const rootUsage = { input_tokens: 100, output_tokens: 10 };
    const workerUsage = { input_tokens: 200, output_tokens: 20 };
    for (const [
      failedSession,
      withWorker,
      maxCostUsd,
      authoritative,
      rejects,
    ] of [
      ["worker-thread", true, 1, true, true],
      ["scan-thread", true, 1, true, true],
      ["unrelated-thread", true, 1, true, false],
      ["worker-thread", true, undefined, true, false],
      ["scan-thread", false, undefined, false, false],
      ["scan-thread", false, 1, true, false],
      ["scan-thread", false, 1, false, true],
    ] as const) {
      const sessions: Record<string, MockAccountingEvent[]> = {
        "scan-thread": accountingSession("scan-thread", [
          accountingEvent(rootUsage),
        ]),
        "unrelated-thread": accountingSession("unrelated-thread", [
          accountingEvent(workerUsage),
        ]),
      };
      if (withWorker) {
        sessions["worker-thread"] = accountingSession(
          "worker-thread",
          [accountingEvent(workerUsage)],
          "scan-thread",
        );
      }
      sessions[failedSession]!.unshift(
        new SyntaxError("mock parser diagnostic"),
      );
      const costs: number[] = [];
      await withMockAccountingSessions(
        sessions,
        {
          model: "gpt-5.6-terra",
          maxCostUsd,
          onCost: (cost) => costs.push(cost.estimatedUsd),
        },
        async (tracker) => {
          const refresh = tracker.refresh();
          if (
            maxCostUsd !== undefined &&
            failedSession !== "unrelated-thread"
          ) {
            await expect(refresh).rejects.toThrow(
              "tracked session record could not be read",
            );
          } else {
            await expect(refresh).resolves.toMatchObject({
              cost: { inputTokens: withWorker ? 300 : 100 },
            });
          }
          const completed = tracker.stop(authoritative ? rootUsage : undefined);
          if (rejects) {
            await expect(completed).rejects.toThrow(
              "tracked session record could not be read",
            );
          } else {
            await expect(completed).resolves.toMatchObject({
              cost: { inputTokens: withWorker ? 300 : 100 },
            });
          }
          expect(costs).toEqual([withWorker ? 0.00096 : 0.00032]);
        },
      );
    }
  });

  test("retains mocked per-session priced high-water snapshots", async () => {
    if (
      runMockInSubprocess(
        import.meta.path,
        "retains mocked per-session priced high-water snapshots",
      )
    ) {
      return;
    }
    const inherited = {
      input_tokens: 1_000,
      cached_input_tokens: 500,
      cache_write_input_tokens: 100,
      output_tokens: 100,
      reasoning_output_tokens: 20,
    };
    const completed = { type: "event_msg", payload: { type: "task_complete" } };
    const costs: number[] = [];
    await withMockAccountingSessions(
      {
        "scan-thread": accountingSession("scan-thread", [
          accountingEvent({ input_tokens: 100, output_tokens: 100 }),
          accountingEvent({
            input_tokens: 1_000,
            cached_input_tokens: 1_000,
            output_tokens: 0,
          }),
        ]),
        "worker-thread": [
          {
            type: "session_meta",
            payload: {
              id: "worker-thread",
              parent_thread_id: "scan-thread",
              timestamp: "2026-07-26T12:02:00.000Z",
            },
          },
          { type: "session_meta", payload: { id: "scan-thread" } },
          accountingEvent(inherited),
          {
            type: "event_msg",
            payload: { type: "task_started", started_at: 1_785_067_320 },
          },
          accountingEvent({
            input_tokens: 1_200,
            cached_input_tokens: 500,
            cache_write_input_tokens: 150,
            output_tokens: 120,
            reasoning_output_tokens: 25,
          }),
          accountingEvent({
            input_tokens: 1_500,
            cached_input_tokens: 1_000,
            cache_write_input_tokens: 100,
            output_tokens: 101,
            reasoning_output_tokens: 20,
          }),
          completed,
        ],
      },
      {
        model: "gpt-5.6-terra",
        maxCostUsd: 0.001,
        onCost: (cost) => costs.push(cost.estimatedUsd),
      },
      async (tracker, append) => {
        const initialUsage = {
          input_tokens: 300,
          cached_input_tokens: 0,
          cache_write_input_tokens: 50,
          output_tokens: 120,
          reasoning_output_tokens: 5,
          total_tokens: 420,
        };
        const initial = await tracker.refresh();
        expect(initial.usage).toEqual(initialUsage);
        expect(initial.cost?.estimatedUsd).toBe(0.002065);
        expect((await tracker.stop()).usage).toEqual(initialUsage);

        append("worker-thread", [
          accountingEvent({
            input_tokens: 1_300,
            cached_input_tokens: 600,
            cache_write_input_tokens: 150,
            output_tokens: 140,
            reasoning_output_tokens: 30,
          }),
          completed,
        ]);
        const final = await tracker.stop({
          input_tokens: 200,
          output_tokens: 200,
        });
        expect(final.usage).toEqual({
          input_tokens: 500,
          cached_input_tokens: 100,
          cache_write_input_tokens: 50,
          output_tokens: 240,
          reasoning_output_tokens: 10,
          total_tokens: 740,
        });
        expect(final.cost?.estimatedUsd).toBe(0.003725);
        expect(await tracker.stop()).toEqual(final);
        expect(costs).toEqual([0.002065, 0.002325, 0.003725]);
      },
    );
  });

  test("keeps mocked unverified evidence separate from known cost floors", async () => {
    if (
      runMockInSubprocess(
        import.meta.path,
        "keeps mocked unverified evidence separate from known cost floors",
      )
    ) {
      return;
    }
    const rootUsage = { input_tokens: 100, output_tokens: 10 };
    const unpriceable = accountingEvent({
      input_tokens: Number.MAX_SAFE_INTEGER,
      output_tokens: 0,
    });
    for (const evidence of [
      new SyntaxError("mock parser diagnostic"),
      unpriceable,
    ]) {
      const reports: Array<number | "error"> = [];
      await withMockAccountingSessions(
        {
          "scan-thread": accountingSession("scan-thread", [
            accountingEvent(rootUsage),
          ]),
          "worker-thread": accountingSession(
            "worker-thread",
            [
              accountingEvent({ input_tokens: 1_000, output_tokens: 100 }),
              evidence,
              accountingEvent(rootUsage),
            ],
            "scan-thread",
          ),
        },
        {
          model: "gpt-5.6-terra",
          maxCostUsd: 0.001,
          onCost: (cost) => reports.push(cost.estimatedUsd),
          onError: () => reports.push("error"),
        },
        async (tracker) => {
          await expect(tracker.stop(rootUsage)).rejects.toThrow(
            "The scan cost limit could not be verified",
          );
          expect((await tracker.stop()).cost).toMatchObject({
            inputTokens: 1_100,
            outputTokens: 110,
            estimatedUsd: 0.00352,
          });
          expect(reports[0]).toBe(0.00352);
          expect(reports).toContain("error");
        },
      );
    }
    await withMockAccountingSessions(
      {
        "scan-thread": accountingSession("scan-thread", [
          accountingEvent(rootUsage),
          unpriceable,
        ]),
      },
      { model: "gpt-5.6-terra", maxCostUsd: 1 },
      async (tracker) => {
        expect(
          (await tracker.stop({ input_tokens: 1_000, output_tokens: 100 })).cost
            ?.estimatedUsd,
        ).toBe(0.0032);
      },
    );
    await withMockAccountingSessions(
      {
        "scan-thread": accountingSession("scan-thread", [
          accountingEvent(rootUsage),
          accountingEvent({ input_tokens: 200, output_tokens: 20 }),
        ]),
      },
      { model: "unknown-model" },
      async (tracker) => {
        expect(await tracker.stop(undefined)).toMatchObject({
          usage: { input_tokens: 200, output_tokens: 20 },
          cost: null,
        });
      },
    );
  });

  test("retains a partial event across incremental reads", async () => {
    const home = await codexHome();
    const path = await writeSession(home, "scan-thread", {
      input_tokens: 100,
      output_tokens: 10,
    });
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-terra",
    });
    tracker.start("scan-thread");
    await tracker.refresh();

    const event = JSON.stringify({
      type: "event_msg",
      payload: {
        type: "token_count",
        info: {
          total_token_usage: { input_tokens: 250, output_tokens: 20 },
        },
      },
    });
    const padding = " ".repeat(128 * 1_024);
    await appendFile(path, `${padding}${event.slice(0, 40)}`);
    expect((await tracker.refresh()).cost?.inputTokens).toBe(100);

    await appendFile(path, `${event.slice(40)}\n`);
    expect((await tracker.stop()).cost?.inputTokens).toBe(250);
  });

  test("reads session events larger than 16 MiB", async () => {
    const home = await codexHome();
    const path = await writeSession(home, "scan-thread", {
      input_tokens: 100,
      output_tokens: 10,
    });
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-terra",
    });
    tracker.start("scan-thread");

    const event = JSON.stringify({
      type: "event_msg",
      payload: {
        type: "token_count",
        info: {
          total_token_usage: { input_tokens: 250, output_tokens: 20 },
        },
        details: "x".repeat(16 * 1_024 * 1_024 + 1),
      },
    });
    await appendFile(path, event.slice(0, -10));
    expect((await tracker.refresh()).cost?.inputTokens).toBe(100);

    await appendFile(path, `${event.slice(-10)}\n`);
    expect((await tracker.stop()).cost?.inputTokens).toBe(250);
  });

  testPosix(
    "quarantines unreadable unrelated sessions after one failure",
    async () => {
      const home = await codexHome();
      const unreadable = await writeSession(home, "unrelated-thread", {
        input_tokens: 99,
        output_tokens: 1,
      });
      await writeSession(home, "scan-thread", {
        input_tokens: 100,
        output_tokens: 10,
      });
      const tracker = new ScanCostTracker({
        codexHome: home,
        model: "gpt-5.6-terra",
      });
      tracker.start("scan-thread");
      await chmod(unreadable, 0o000);

      try {
        await expect(tracker.refresh()).rejects.toThrow();
        expect((await tracker.refresh()).cost?.inputTokens).toBe(100);
        expect((await tracker.stop()).cost?.inputTokens).toBe(100);
      } finally {
        await chmod(unreadable, 0o600);
      }
    },
  );

  testPosix(
    "keeps budgeted worker sessions fail-closed after they become unreadable",
    async () => {
      const { worker, tracker } = await workerScan({
        workerUsage: { input_tokens: 250, output_tokens: 20 },
        maxCostUsd: 1,
      });
      expect((await tracker.refresh()).cost?.inputTokens).toBe(350);
      await chmod(worker, 0o000);

      try {
        await expect(tracker.refresh()).rejects.toThrow();
        await expect(tracker.refresh()).rejects.toThrow();
        await expect(
          tracker.stop({ input_tokens: 100, output_tokens: 10 }),
        ).rejects.toThrow();
      } finally {
        await chmod(worker, 0o600);
      }
    },
  );

  testPosix(
    "rejects root-only budget fallback when the scan also has delegated workers",
    async () => {
      const { root, tracker } = await workerScan({
        workerUsage: { input_tokens: 250, output_tokens: 20 },
        maxCostUsd: 1,
      });
      expect((await tracker.refresh()).cost?.inputTokens).toBe(350);
      await chmod(root, 0o000);

      try {
        await expect(
          tracker.stop({ input_tokens: 1_000, output_tokens: 100 }),
        ).rejects.toThrow();
      } finally {
        await chmod(root, 0o600);
      }
    },
  );

  testPosix.each(["parented", "independent"] as const)(
    "rejects budget fallback for a newly discovered %s worker during a failed refresh",
    async (workerKind) => {
      const home = await codexHome();
      const scanDirectory = join(home, "scan");
      const active = await writeSession(home, "scan-thread", {
        input_tokens: 100,
        output_tokens: 10,
      });
      const tracker = new ScanCostTracker({
        codexHome: home,
        model: "gpt-5.6-terra",
        scanDirectory,
        maxCostUsd: 0.001,
      });
      tracker.start("scan-thread");
      await tracker.refresh();
      await writeSession(
        home,
        "worker-thread",
        { input_tokens: 10_000, output_tokens: 1_000 },
        workerKind === "parented" ? "scan-thread" : undefined,
        workerKind === "independent"
          ? join(scanDirectory, "artifacts")
          : undefined,
        "2026-07-26T12:01:00Z",
      );
      await chmod(active, 0o000);

      try {
        await expect(
          tracker.stop({ input_tokens: 100, output_tokens: 10 }),
        ).rejects.toThrow();
      } finally {
        await chmod(active, 0o600);
      }
    },
  );

  testPosix(
    "rejects budget fallback when an unreadable session cannot be attributed",
    async () => {
      const home = await codexHome();
      const unreadable = await writeSession(home, "unidentified-thread", {
        input_tokens: 100,
        output_tokens: 10,
      });
      await chmod(unreadable, 0o000);
      const tracker = new ScanCostTracker({
        codexHome: home,
        model: "gpt-5.6-terra",
        maxCostUsd: 1,
      });
      tracker.start("scan-thread");

      try {
        await expect(
          tracker.stop({ input_tokens: 1_000, output_tokens: 100 }),
        ).rejects.toThrow();
      } finally {
        await chmod(unreadable, 0o600);
      }
    },
  );

  test.each(["scan-thread", "worker-thread"] as const)(
    "rejects a budgeted scan when its tracked %s session disappears",
    async (missingThread) => {
      const { root, worker, tracker } = await workerScan({ maxCostUsd: 1 });
      await tracker.refresh();
      await rm(missingThread === "scan-thread" ? root : worker);

      await expect(
        tracker.stop({ input_tokens: 1_000, output_tokens: 100 }),
      ).rejects.toThrow(
        "A tracked scan session disappeared before its cost could be verified.",
      );
    },
  );

  test("ignores unrelated disappearing sessions when enforcing a budget", async () => {
    const home = await codexHome();
    await writeSession(home, "scan-thread", {
      input_tokens: 100,
      output_tokens: 10,
    });
    const unrelated = await writeSession(home, "unrelated-thread", {
      input_tokens: 1_000,
      output_tokens: 100,
    });
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-terra",
      maxCostUsd: 1,
    });
    tracker.start("scan-thread");
    await tracker.refresh();
    await rm(unrelated);

    expect((await tracker.stop()).cost?.inputTokens).toBe(100);
  });

  test("preserves known usage when an optional worker session disappears", async () => {
    const { worker, tracker } = await workerScan();
    await tracker.refresh();
    await rm(worker);

    expect(
      (await tracker.stop({ input_tokens: 1_000, output_tokens: 100 })).cost,
    ).toMatchObject({ inputTokens: 1_100, outputTokens: 110 });
  });

  test("reports a changed running cost only once", async () => {
    const home = await codexHome();
    await writeSession(home, "scan-thread", {
      input_tokens: 1_250,
      cached_input_tokens: 200,
      output_tokens: 30,
    });
    const updates: number[] = [];
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
      maxCostUsd: 0.005,
      onCost: (cost) => updates.push(cost.estimatedUsd),
    });
    tracker.start("scan-thread");

    await tracker.stop();

    expect(updates).toEqual([0.00625]);
  });

  test("falls back to the completed turn when session logs are unavailable", async () => {
    const tracker = new ScanCostTracker({
      codexHome: await codexHome(),
      model: "gpt-5.6-luna",
    });
    const usage = { input_tokens: 1_000, output_tokens: 20 };
    tracker.start("scan-thread");

    expect(await tracker.stop(usage)).toEqual({
      usage,
      cost: {
        model: "gpt-5.6-luna",
        inputTokens: 1_000,
        cachedInputTokens: 0,
        cacheWriteInputTokens: 0,
        outputTokens: 20,
        estimatedUsd: 0.000224,
      },
    });
  });

  test.each([
    ["missing", undefined],
    ["null", null],
    ["malformed", {}],
  ] as const)(
    "rejects a budgeted scan when completed-turn usage is %s",
    async (_description, usage) => {
      const tracker = new ScanCostTracker({
        codexHome: await codexHome(),
        model: "gpt-5.6-terra",
        maxCostUsd: 1,
      });
      tracker.start("scan-thread");

      await expect(tracker.stop(usage)).rejects.toThrow(
        "The scan cost limit could not be verified because model pricing or token usage is unavailable.",
      );
    },
  );

  test.each([
    ["missing", undefined],
    ["null", null],
    ["malformed", {}],
  ] as const)(
    "requires completed root-session evidence when final usage is %s",
    async (_description, usage) => {
      const home = await codexHome();
      const root = await writeSession(home, "scan-thread", {
        input_tokens: 100,
        output_tokens: 10,
      });
      const tracker = new ScanCostTracker({
        codexHome: home,
        model: "gpt-5.6-terra",
        maxCostUsd: 1,
      });
      tracker.start("scan-thread");
      expect((await tracker.refresh()).cost?.inputTokens).toBe(100);

      await expect(tracker.stop(usage)).rejects.toThrow(
        "The scan cost limit could not be verified",
      );
      await appendFile(root, `${taskEvent("task_complete")}\n`);
      expect((await tracker.stop(usage)).cost).toMatchObject({
        inputTokens: 100,
        outputTokens: 10,
      });
    },
  );

  test("rejects a budgeted scan when the completed model cannot be priced", async () => {
    const tracker = new ScanCostTracker({
      codexHome: await codexHome(),
      model: "unknown-model",
      maxCostUsd: 1,
    });
    tracker.start("scan-thread");

    await expect(
      tracker.stop({ input_tokens: 1_000, output_tokens: 100 }),
    ).rejects.toThrow(
      "The scan cost limit could not be verified because model pricing or token usage is unavailable.",
    );
  });

  test("allows unavailable completed-turn usage without an explicit budget", async () => {
    const tracker = new ScanCostTracker({
      codexHome: await codexHome(),
      model: "gpt-5.6-terra",
    });
    tracker.start("scan-thread");

    await expect(tracker.stop(null)).resolves.toEqual({
      usage: null,
      cost: null,
    });
  });

  test("preserves unfinished root usage when tracking is optional", async () => {
    const home = await codexHome();
    await writeSession(home, "scan-thread", {
      input_tokens: 100,
      output_tokens: 10,
    });
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-terra",
    });
    tracker.start("scan-thread");

    expect((await tracker.stop(undefined)).cost).toMatchObject({
      inputTokens: 100,
      outputTokens: 10,
    });
  });

  test.each([
    ["missing", undefined],
    ["malformed", {}],
  ] as const)(
    "rejects worker-only usage when the budgeted root completion is %s",
    async (_description, completedRoot) => {
      const { tracker } = await workerScan({
        rootUsage: null,
        maxCostUsd: 1,
      });
      expect((await tracker.refresh()).cost?.inputTokens).toBe(100);

      await expect(tracker.stop(completedRoot)).rejects.toThrow(
        "The scan cost limit could not be verified because model pricing or token usage is unavailable.",
      );
    },
  );

  test.each([
    ["rejects", 1],
    ["allows", undefined],
  ] as const)(
    "%s incomplete delegated-worker usage according to the explicit budget",
    async (_result, maxCostUsd) => {
      const { tracker } = await workerScan({ workerUsage: null, maxCostUsd });
      expect((await tracker.refresh()).cost?.inputTokens).toBe(100);

      const completed = tracker.stop({
        input_tokens: 1_000,
        output_tokens: 100,
      });
      if (maxCostUsd === undefined) {
        await expect(completed).resolves.toMatchObject({
          cost: { inputTokens: 1_000, outputTokens: 100 },
        });
      } else {
        await expect(completed).rejects.toThrow(
          "The scan cost limit could not be verified because model pricing or token usage is unavailable.",
        );
      }
    },
  );

  test.each([
    ["still-running worker", "running", 1, true],
    ["completed worker", "task_complete", 1, false],
    ["compatible completed worker", "turn_complete", 1, false],
    ["canceled worker", "turn_aborted", 1, false],
    ["worker restarted after completion", "task_started", 1, true],
    ["optional still-running worker", "running", undefined, false],
  ] as const)(
    "verifies final delegated-worker completion for a %s",
    async (_scenario, state, maxCostUsd, shouldReject) => {
      const { worker, tracker } = await workerScan({
        workerCompleted: false,
        maxCostUsd,
      });
      expect((await tracker.refresh()).cost?.inputTokens).toBe(200);
      if (state !== "running") {
        if (state === "task_started") {
          await appendFile(worker, `${taskEvent("task_complete")}\n`);
        }
        await appendFile(worker, `${taskEvent(state)}\n`);
      }
      expect((await tracker.refresh()).cost?.inputTokens).toBe(200);

      const completed = tracker.stop({ input_tokens: 100, output_tokens: 10 });
      if (shouldReject) {
        await expect(completed).rejects.toThrow(
          "The scan cost limit could not be verified",
        );
      } else {
        await expect(completed).resolves.toMatchObject({
          cost: { inputTokens: 200, outputTokens: 20 },
        });
      }
    },
  );

  test("preserves observed active-worker costs during budget failure cleanup", async () => {
    const { tracker } = await workerScan({
      workerCompleted: false,
      maxCostUsd: 1,
    });
    expect((await tracker.refresh()).cost?.inputTokens).toBe(200);

    expect((await tracker.stop()).cost).toMatchObject({
      inputTokens: 200,
      outputTokens: 20,
    });
  });

  test.each([
    ["null", null],
    ["undefined", undefined],
  ] as const)(
    "rejects an active worker when completed-turn usage is %s",
    async (_description, usage) => {
      const { tracker } = await workerScan({
        workerCompleted: false,
        maxCostUsd: 1,
      });
      expect((await tracker.refresh()).cost?.inputTokens).toBe(200);

      await expect(tracker.stop(usage)).rejects.toThrow(
        "The scan cost limit could not be verified",
      );
    },
  );

  test.each([
    ["budgeted root", "root", 0.001, true],
    ["budgeted delegated worker", "worker", 0.001, true],
    ["budgeted unrelated session", "unrelated", 0.001, false],
    ["unbudgeted delegated worker", "worker", undefined, false],
  ] as const)(
    "handles an incomplete final event from a %s",
    async (_description, session, maxCostUsd, shouldReject) => {
      const { home, root, worker, tracker } = await workerScan({ maxCostUsd });
      expect((await tracker.refresh()).cost?.inputTokens).toBe(200);
      const path =
        session === "root"
          ? root
          : session === "worker"
            ? worker
            : await writeSession(home, "unrelated-thread", {
                input_tokens: 100,
                output_tokens: 10,
              });
      await appendIncompleteTokenUsage(path);
      expect((await tracker.refresh()).cost?.inputTokens).toBe(200);

      const completed = tracker.stop({ input_tokens: 100, output_tokens: 10 });
      if (shouldReject) {
        await expect(completed).rejects.toThrow(
          "The scan cost limit could not be verified because model pricing or token usage is unavailable.",
        );
      } else {
        await expect(completed).resolves.toMatchObject({
          cost: { inputTokens: 200, outputTokens: 20 },
        });
      }
    },
  );

  test("rejects an incomplete final root event without delegated workers", async () => {
    const home = await codexHome();
    const root = await writeSession(home, "scan-thread", {
      input_tokens: 100,
      output_tokens: 10,
    });
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-terra",
      maxCostUsd: 0.001,
    });
    tracker.start("scan-thread");
    await appendIncompleteTokenUsage(root);
    expect((await tracker.refresh()).cost?.inputTokens).toBe(100);

    await expect(
      tracker.stop({ input_tokens: 100, output_tokens: 10 }),
    ).rejects.toThrow("The scan cost limit could not be verified");
  });

  test("keeps final budget enforcement stable when cleanup stops tracking twice", async () => {
    const budget = 0.001;
    const exceeded = new AbortController();
    const reportedCosts: number[] = [];
    const { tracker } = await workerScan({
      maxCostUsd: budget,
      onCost: (cost) => {
        reportedCosts.push(cost.estimatedUsd);
        if (cost.estimatedUsd > budget) exceeded.abort();
      },
    });
    expect((await tracker.refresh()).cost?.inputTokens).toBe(200);

    expect(
      (await tracker.stop({ input_tokens: 1_000, output_tokens: 100 })).cost,
    ).toMatchObject({ inputTokens: 1_100, outputTokens: 110 });
    expect((await tracker.stop()).cost).toMatchObject({
      inputTokens: 1_100,
      outputTokens: 110,
    });
    expect(reportedCosts).toEqual([0.00064, 0.00352]);
    expect(exceeded.signal.aborted).toBe(true);
  });

  test.each(["incomplete", "unfinished", "unreadable"] as const)(
    "preserves a definitive overage when final worker evidence is %s",
    async (evidence) => {
      const reportedCosts: number[] = [];
      const { worker, tracker } = await workerScan({
        workerCompleted: evidence !== "unfinished",
        maxCostUsd: 0.001,
        onCost: (cost) => reportedCosts.push(cost.estimatedUsd),
      });
      const refresh = tracker.refresh.bind(tracker);
      expect((await tracker.refresh()).cost?.inputTokens).toBe(200);
      if (evidence === "incomplete") {
        await appendIncompleteTokenUsage(worker);
      } else if (evidence === "unreadable") {
        tracker.refresh = async () => {
          throw new Error("session read failed");
        };
      }

      await expect(
        tracker.stop({ input_tokens: 1_000, output_tokens: 100 }),
      ).rejects.toThrow(
        evidence === "unreadable"
          ? "session read failed"
          : "The scan cost limit could not be verified",
      );
      expect(reportedCosts).toEqual([0.00064, 0.00352]);
      expect((await tracker.stop()).cost).toMatchObject({
        inputTokens: 1_100,
        outputTokens: 110,
        estimatedUsd: 0.00352,
      });
      tracker.refresh = refresh;
      if (evidence !== "incomplete") {
        await appendIncompleteTokenUsage(worker);
      }
      await appendFile(worker, `}\n${taskEvent("task_complete")}\n`);
      expect((await tracker.stop()).cost).toMatchObject({
        inputTokens: 11_000,
        outputTokens: 1_100,
        estimatedUsd: 0.0352,
      });
      expect(reportedCosts.at(-1)).toBe(0.0352);
    },
  );

  test("returns a definitive overage first discovered during failure cleanup", async () => {
    const { worker, tracker } = await workerScan({
      rootUsage: { input_tokens: 1_000, output_tokens: 100 },
      maxCostUsd: 0.001,
    });
    await appendIncompleteTokenUsage(worker);

    expect((await tracker.stop()).cost).toMatchObject({
      inputTokens: 1_100,
      outputTokens: 110,
      estimatedUsd: 0.00352,
    });
  });

  test("preserves higher observed root usage when completed-turn usage is stale", async () => {
    const { tracker } = await workerScan({
      rootUsage: { input_tokens: 1_000, output_tokens: 100 },
      maxCostUsd: 1,
    });

    expect(
      (await tracker.stop({ input_tokens: 100, output_tokens: 10 })).cost,
    ).toMatchObject({ inputTokens: 1_100, outputTokens: 110 });
  });

  test("combines worker-only observations with a valid completed root", async () => {
    const budget = 0.001;
    const exceeded = new AbortController();
    const { tracker } = await workerScan({
      rootUsage: null,
      maxCostUsd: budget,
      onCost: (cost) => {
        if (cost.estimatedUsd > budget) exceeded.abort();
      },
    });
    expect((await tracker.refresh()).cost?.inputTokens).toBe(100);

    expect(
      (await tracker.stop({ input_tokens: 1_000, output_tokens: 100 })).cost,
    ).toMatchObject({ inputTokens: 1_100, outputTokens: 110 });
    expect(exceeded.signal.aborted).toBe(true);
  });

  test("uses completed-turn usage when the final session refresh fails", async () => {
    const home = await codexHome();
    await writeSession(home, "scan-thread", {
      input_tokens: 100,
      output_tokens: 10,
    });
    const reportedCosts: number[] = [];
    const reportedErrors: unknown[] = [];
    const refreshError = new Error("session read failed");
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-terra",
      onCost: (cost) => reportedCosts.push(cost.estimatedUsd),
      onError: (error) => reportedErrors.push(error),
    });
    tracker.start("scan-thread");
    expect((await tracker.refresh()).cost?.estimatedUsd).toBe(0.00032);
    tracker.refresh = async () => {
      throw refreshError;
    };
    const usage = { input_tokens: 1_000, output_tokens: 100 };

    expect(await tracker.stop(usage)).toMatchObject({
      usage,
      cost: { inputTokens: 1_000, estimatedUsd: 0.0032 },
    });
    expect(reportedCosts).toEqual([0.00032, 0.0032]);
    expect(reportedErrors).toEqual([refreshError]);
  });

  test("adds observed worker usage to the completed root after a failed refresh", async () => {
    const { tracker } = await workerScan();
    expect((await tracker.refresh()).cost?.inputTokens).toBe(200);
    tracker.refresh = async () => {
      throw new Error("session read failed");
    };

    expect(
      (await tracker.stop({ input_tokens: 1_000, output_tokens: 100 })).cost,
    ).toMatchObject({ inputTokens: 1_100, outputTokens: 110 });
  });

  testPosix(
    "enforces a budget with completed-turn usage when only its root session is unreadable",
    async () => {
      const home = await codexHome();
      const active = await writeSession(home, "scan-thread", {
        input_tokens: 100,
        output_tokens: 10,
      });
      const budget = 0.001;
      const exceeded = new AbortController();
      const tracker = new ScanCostTracker({
        codexHome: home,
        model: "gpt-5.6-terra",
        maxCostUsd: budget,
        onCost: (cost) => {
          if (cost.estimatedUsd > budget) exceeded.abort();
        },
      });
      tracker.start("scan-thread");
      await tracker.refresh();
      await chmod(active, 0o000);

      try {
        await expect(tracker.refresh()).rejects.toThrow();
        expect(
          (await tracker.stop({ input_tokens: 1_000, output_tokens: 100 }))
            .cost,
        ).toMatchObject({ estimatedUsd: 0.0032 });
        expect(exceeded.signal.aborted).toBe(true);
      } finally {
        await chmod(active, 0o600);
      }
    },
  );

  testPosix(
    "uses completed-turn usage when an unrelated session cannot be opened",
    async () => {
      const home = await codexHome();
      const unreadable = await writeSession(home, "unrelated-thread", {
        input_tokens: 99,
        output_tokens: 1,
      });
      await chmod(unreadable, 0o000);
      const tracker = new ScanCostTracker({
        codexHome: home,
        model: "gpt-5.6-luna",
      });
      tracker.start("scan-thread");
      const usage = { input_tokens: 1_000, output_tokens: 20 };

      try {
        expect(await tracker.stop(usage)).toMatchObject({
          usage,
          cost: { inputTokens: 1_000, estimatedUsd: 0.000224 },
        });
      } finally {
        await chmod(unreadable, 0o600);
      }
    },
  );
});

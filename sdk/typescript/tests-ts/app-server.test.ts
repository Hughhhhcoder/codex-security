import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { CodexAppServer, type ThreadEvent } from "../src/app-server.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

describe("Codex app-server transport", () => {
  test("keeps one app-server session for scan turns and maps SDK events", async () => {
    const fixture = await fakeAppServer();
    const codex = new CodexAppServer({
      codexPathOverride: process.execPath,
      codexArgsPrefix: [fixture.script],
      env: {
        CODEX_HOME: fixture.codexHome,
        PATH: process.env["PATH"] ?? "",
      },
      config: { default_permissions: "codex_security_scan" },
    });
    try {
      const thread = codex.startThread({
        workingDirectory: fixture.workingDirectory,
        approvalPolicy: "never",
      });
      const first = await collect(
        (await thread.runStreamed("first scan prompt")).events,
      );
      const second = await collect(
        (await thread.runStreamed("post-scan prompt")).events,
      );

      expect(thread.id).toBe("thread-1");
      expect(first.map((event) => event.type)).toEqual([
        "thread.started",
        "turn.started",
        "item.started",
        "item.completed",
        "item.completed",
        "turn.completed",
      ]);
      expect(first[3]).toMatchObject({
        type: "item.completed",
        item: {
          type: "mcp_tool_call",
          server: "codex-security",
          tool: "complete_codex_security_scan",
          status: "completed",
        },
      });
      expect(first.at(-1)).toEqual({
        type: "turn.completed",
        usage: {
          input_tokens: 11,
          cached_input_tokens: 2,
          cache_write_input_tokens: 1,
          output_tokens: 5,
          reasoning_output_tokens: 3,
          total_tokens: 19,
        },
      });
      expect(second.map((event) => event.type)).toEqual([
        "turn.started",
        "item.completed",
        "turn.completed",
      ]);

      const messages = (await readFile(fixture.marker, "utf8"))
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line) as Record<string, unknown>);
      expect(messages.map((message) => message["method"])).toEqual([
        "initialize",
        "thread/start",
        "turn/start",
        "turn/start",
      ]);
      expect(messages[1]).toMatchObject({
        params: {
          cwd: fixture.workingDirectory,
          approvalPolicy: "never",
          config: { default_permissions: "codex_security_scan" },
        },
      });
      expect(messages[2]).toMatchObject({
        params: {
          threadId: "thread-1",
          input: [
            { type: "text", text: "first scan prompt", text_elements: [] },
          ],
        },
      });
    } finally {
      await codex.close();
    }
  });

  test("interrupts an active app-server turn when the scan aborts", async () => {
    const fixture = await fakeAppServer();
    const codex = new CodexAppServer({
      codexPathOverride: process.execPath,
      codexArgsPrefix: [fixture.script],
      env: { CODEX_HOME: fixture.codexHome },
    });
    const controller = new AbortController();
    try {
      const thread = codex.startThread({
        workingDirectory: fixture.workingDirectory,
      });
      const { events } = await thread.runStreamed("BLOCK", {
        signal: controller.signal,
      });
      const iterator = events[Symbol.asyncIterator]();
      await iterator.next();
      await iterator.next();
      controller.abort(new DOMException("scan canceled", "AbortError"));
      await expect(iterator.next()).rejects.toMatchObject({
        name: "AbortError",
      });
      await waitForMarkerMethod(fixture.marker, "turn/interrupt");
    } finally {
      await codex.close();
    }
  });
});

async function collect(
  events: AsyncGenerator<ThreadEvent>,
): Promise<ThreadEvent[]> {
  const collected: ThreadEvent[] = [];
  for await (const event of events) collected.push(event);
  return collected;
}

async function fakeAppServer(): Promise<{
  root: string;
  script: string;
  marker: string;
  codexHome: string;
  workingDirectory: string;
}> {
  const root = await mkdtemp(join(tmpdir(), "codex-security-app-server-"));
  temporaryDirectories.push(root);
  const script = join(root, "app-server-fixture.mjs");
  const marker = join(root, "messages.jsonl");
  const codexHome = join(root, "codex-home");
  const workingDirectory = join(root, "scan");
  await writeFile(
    script,
    [
      'import { appendFileSync } from "node:fs";',
      'import { createInterface } from "node:readline";',
      `const marker = ${JSON.stringify(marker)};`,
      "let turn = 0;",
      "const send = (message) => process.stdout.write(`${JSON.stringify(message)}\\n`);",
      "const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });",
      "lines.on('line', (line) => {",
      "  const message = JSON.parse(line);",
      "  appendFileSync(marker, `${line}\\n`);",
      "  if (message.method === 'initialize') { send({ id: message.id, result: { userAgent: 'fixture', codexHome: process.env.CODEX_HOME, platformFamily: 'unix', platformOs: 'linux' } }); return; }",
      "  if (message.method === 'thread/start') { send({ id: message.id, result: { thread: { id: 'thread-1' } } }); return; }",
      "  if (message.method === 'turn/interrupt') { send({ id: message.id, result: {} }); return; }",
      "  if (message.method !== 'turn/start') return;",
      "  turn += 1;",
      "  const turnId = `turn-${turn}`;",
      "  send({ id: message.id, result: { turn: { id: turnId } } });",
      "  if (message.params.input[0].text === 'BLOCK') return;",
      "  if (turn === 1) {",
      "    send({ method: 'thread/tokenUsage/updated', params: { threadId: 'thread-1', turnId, tokenUsage: { total: { inputTokens: 11, cachedInputTokens: 2, cacheWriteInputTokens: 1, outputTokens: 5, reasoningOutputTokens: 3, totalTokens: 19 } } } });",
      "    send({ method: 'item/started', params: { threadId: 'thread-1', turnId, item: { id: 'command-1', type: 'commandExecution', command: 'python scan.py', aggregatedOutput: '', exitCode: null, status: 'inProgress' } } });",
      "    send({ method: 'item/completed', params: { threadId: 'thread-1', turnId, item: { id: 'tool-1', type: 'mcpToolCall', server: 'codex-security', tool: 'complete_codex_security_scan', arguments: {}, status: 'completed' } } });",
      "  }",
      "  send({ method: 'item/completed', params: { threadId: 'thread-1', turnId, item: { id: `message-${turn}`, type: 'agentMessage', text: `response-${turn}` } } });",
      "  send({ method: 'turn/completed', params: { threadId: 'thread-1', turn: { id: turnId, status: 'completed', error: null } } });",
      "});",
    ].join("\n"),
  );
  return { root, script, marker, codexHome, workingDirectory };
}

async function waitForMarkerMethod(
  marker: string,
  method: string,
): Promise<void> {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    const text = await readFile(marker, "utf8").catch(() => "");
    if (text.includes(`\"method\":\"${method}\"`)) return;
    await Bun.sleep(10);
  }
  throw new Error(`Fixture did not receive ${method}.`);
}

import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createInterface } from "node:readline";

export type ModelReasoningEffort =
  | "minimal"
  | "low"
  | "medium"
  | "high"
  | "xhigh"
  | "ultra";

export type CodexConfigValue =
  | string
  | number
  | boolean
  | CodexConfigValue[]
  | CodexConfigObject;

export interface CodexConfigObject {
  readonly [key: string]: CodexConfigValue;
}

export interface CodexOptions {
  codexPathOverride?: string;
  codexArgsPrefix?: readonly string[];
  baseUrl?: string;
  apiKey?: string;
  config?: CodexConfigObject;
  env?: Record<string, string>;
}

export type ApprovalMode = "never" | "on-request" | "untrusted";
export type SandboxMode =
  | "read-only"
  | "workspace-write"
  | "danger-full-access";
export type WebSearchMode = "disabled" | "cached" | "live";

export interface ThreadOptions {
  model?: string;
  sandboxMode?: SandboxMode;
  workingDirectory?: string;
  skipGitRepoCheck?: boolean;
  modelReasoningEffort?: ModelReasoningEffort;
  networkAccessEnabled?: boolean;
  webSearchMode?: WebSearchMode;
  webSearchEnabled?: boolean;
  approvalPolicy?: ApprovalMode;
  additionalDirectories?: string[];
}

export interface TurnOptions {
  outputSchema?: unknown;
  signal?: AbortSignal;
}

export type ThreadItem = Record<string, unknown> & {
  id: string;
  type: string;
};

export type McpToolCallItem = ThreadItem & {
  type: "mcp_tool_call";
  server: string;
  tool: string;
  arguments: unknown;
  status: "in_progress" | "completed" | "failed";
};

export type Usage = {
  input_tokens: number;
  cached_input_tokens: number;
  cache_write_input_tokens?: number;
  output_tokens: number;
  reasoning_output_tokens: number;
  total_tokens?: number;
};

export type ThreadEvent =
  | { type: "thread.started"; thread_id: string }
  | { type: "turn.started" }
  | { type: "turn.completed"; usage: Usage | null }
  | { type: "turn.failed"; error: { message: string } }
  | { type: "item.started"; item: ThreadItem }
  | { type: "item.updated"; item: ThreadItem }
  | { type: "item.completed"; item: ThreadItem }
  | { type: "error"; message: string };

export interface Turn {
  items: ThreadItem[];
  finalResponse: string;
  usage: Usage | null;
}

export interface StreamedTurn {
  events: AsyncGenerator<ThreadEvent>;
}

interface JsonRpcRequest {
  id: string;
  method: string;
  params: Record<string, unknown>;
}

interface JsonRpcResponse {
  id: string | number;
  result?: unknown;
  error?: { message?: unknown };
}

interface JsonRpcNotification {
  method: string;
  params?: unknown;
}

interface ActiveTurn {
  threadId: string;
  turnId: string | null;
  queue: EventQueue;
  usage: Usage | null;
}

interface PendingRequest {
  resolve(value: unknown): void;
  reject(error: Error): void;
}

const CLIENT_INFO = {
  name: "codex_security_sdk",
  title: "Codex Security SDK",
  version: "1",
};
const APP_SERVER_ORIGINATOR = "codex_security_sdk";
const INITIALIZE_TIMEOUT_MS = 30_000;

/**
 * Minimal, package-local client for the stable app-server JSON-RPC surface.
 *
 * Codex Security intentionally keeps its scan contract in the existing
 * ThreadEvent shape. That lets the workbench, progress observers, and result
 * validation stay transport-neutral while app-server owns thread lifecycle.
 */
export class CodexAppServer {
  readonly #options: CodexOptions;
  #process: ChildProcessWithoutNullStreams | null = null;
  #initialized: Promise<void> | null = null;
  #closed = false;
  #requestSequence = 0;
  #pending = new Map<string, PendingRequest>();
  #activeTurn: ActiveTurn | null = null;

  public constructor(options: CodexOptions = {}) {
    this.#options = options;
  }

  public startThread(options: ThreadOptions = {}): AppServerThread {
    return new AppServerThread(this, options);
  }

  public resumeThread(
    id: string,
    options: ThreadOptions = {},
  ): AppServerThread {
    return new AppServerThread(this, options, id);
  }

  public async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    const error = new Error("Codex app-server client is closed.");
    for (const pending of this.#pending.values()) pending.reject(error);
    this.#pending.clear();
    this.#activeTurn?.queue.fail(error);
    this.#activeTurn = null;
    const process = this.#process;
    this.#process = null;
    if (process !== null && !process.killed && process.exitCode === null) {
      process.kill();
    }
  }

  async startOrResumeThread(
    options: ThreadOptions,
    resumeThreadId: string | null,
    signal?: AbortSignal,
  ): Promise<string> {
    await this.#ensureInitialized(signal);
    const params = threadParams(this.#options, options);
    const response = await this.#request(
      resumeThreadId === null ? "thread/start" : "thread/resume",
      resumeThreadId === null
        ? params
        : { ...params, threadId: resumeThreadId },
      signal,
    );
    const thread = recordValue(response, "thread");
    const threadId = stringValue(thread, "id");
    if (threadId === null) {
      throw new Error("Codex app-server returned no thread ID.");
    }
    return threadId;
  }

  async runTurn(
    threadId: string,
    input: string,
    options: TurnOptions,
  ): Promise<AsyncGenerator<ThreadEvent>> {
    if (this.#activeTurn !== null) {
      throw new Error("Codex app-server already has an active turn.");
    }
    await this.#ensureInitialized(options.signal);
    const active: ActiveTurn = {
      threadId,
      turnId: null,
      queue: new EventQueue(),
      usage: null,
    };
    this.#activeTurn = active;
    void this.#request("turn/start", {
      threadId,
      input: [{ type: "text", text: input, text_elements: [] }],
      ...(options.outputSchema === undefined
        ? {}
        : { outputSchema: options.outputSchema }),
    })
      .then((response) => {
        const turn = recordValue(response, "turn");
        active.turnId = stringValue(turn, "id");
        if (active.turnId === null) {
          active.queue.fail(new Error("Codex app-server returned no turn ID."));
        } else if (options.signal?.aborted) {
          void this.#request("turn/interrupt", {
            threadId: active.threadId,
            turnId: active.turnId,
          }).catch(() => undefined);
        }
      })
      .catch((error: unknown) => active.queue.fail(asError(error)));
    return this.#events(active, options.signal);
  }

  async *#events(
    active: ActiveTurn,
    signal?: AbortSignal,
  ): AsyncGenerator<ThreadEvent> {
    const onAbort = (): void => {
      if (active.turnId !== null) {
        void this.#request("turn/interrupt", {
          threadId: active.threadId,
          turnId: active.turnId,
        }).catch(() => undefined);
      }
      active.queue.fail(abortError(signal));
    };
    signal?.addEventListener("abort", onAbort, { once: true });
    if (signal?.aborted) onAbort();
    try {
      while (true) {
        const event = await active.queue.shift();
        if (event === null) return;
        yield event;
        if (event.type === "turn.completed" || event.type === "turn.failed") {
          return;
        }
      }
    } finally {
      signal?.removeEventListener("abort", onAbort);
      if (this.#activeTurn === active) this.#activeTurn = null;
    }
  }

  async #ensureInitialized(signal?: AbortSignal): Promise<void> {
    if (this.#closed) throw new Error("Codex app-server client is closed.");
    if (this.#initialized === null) {
      this.#startProcess();
      this.#initialized = this.#request(
        "initialize",
        {
          clientInfo: CLIENT_INFO,
          capabilities: { experimentalApi: true },
        },
        AbortSignal.timeout(INITIALIZE_TIMEOUT_MS),
      ).then(() => undefined);
    }
    await withAbort(this.#initialized, signal);
  }

  #startProcess(): void {
    if (this.#process !== null) return;
    const executable = this.#options.codexPathOverride ?? "codex";
    const environment = {
      ...(this.#options.env ?? processEnvironment()),
      ...(this.#options.apiKey === undefined
        ? {}
        : { CODEX_API_KEY: this.#options.apiKey }),
      CODEX_INTERNAL_ORIGINATOR_OVERRIDE:
        this.#options.env?.["CODEX_INTERNAL_ORIGINATOR_OVERRIDE"] ??
        APP_SERVER_ORIGINATOR,
    };
    const child = spawn(
      executable,
      [...(this.#options.codexArgsPrefix ?? []), "app-server", "--stdio"],
      { env: environment, stdio: ["pipe", "pipe", "pipe"], windowsHide: true },
    );
    this.#process = child;
    child.once("error", (error) => this.#fail(asError(error)));
    child.once("exit", (code, exitSignal) => {
      if (!this.#closed) {
        this.#endStream(
          new Error(
            `Codex app-server exited before shutdown (${exitSignal === null ? `code ${code ?? 1}` : `signal ${exitSignal}`}).`,
          ),
        );
      }
    });
    // Drain diagnostics without retaining repository output or credentials.
    child.stderr.resume();
    const lines = createInterface({ input: child.stdout, crlfDelay: Infinity });
    lines.on("line", (line) => this.#handleLine(line));
  }

  #handleLine(line: string): void {
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      this.#fail(new Error("Codex app-server returned invalid JSON."));
      return;
    }
    if (!isRecord(parsed)) return;
    const id = parsed["id"];
    if (
      (typeof id === "string" || typeof id === "number") &&
      ("result" in parsed || "error" in parsed)
    ) {
      const error =
        "error" in parsed
          ? isRecord(parsed["error"])
            ? parsed["error"]
            : {}
          : undefined;
      this.#handleResponse({
        id,
        ...("result" in parsed ? { result: parsed["result"] } : {}),
        ...(error === undefined ? {} : { error }),
      });
      return;
    }
    const method = parsed["method"];
    if (typeof method !== "string") return;
    if ("id" in parsed) {
      this.#replyUnsupportedRequest(id);
      return;
    }
    this.#handleNotification({ method, params: parsed["params"] });
  }

  #handleResponse(response: JsonRpcResponse): void {
    const id = String(response.id);
    const pending = this.#pending.get(id);
    if (pending === undefined) return;
    this.#pending.delete(id);
    if (response.error !== undefined) {
      const message =
        typeof response.error.message === "string"
          ? response.error.message
          : "Codex app-server request failed.";
      pending.reject(new Error(message));
      return;
    }
    pending.resolve(response.result);
  }

  #handleNotification(notification: JsonRpcNotification): void {
    const active = this.#activeTurn;
    if (active === null || !isRecord(notification.params)) return;
    const params = notification.params;
    if (stringValue(params, "threadId") !== active.threadId) return;
    const turnId = stringValue(params, "turnId");
    if (active.turnId !== null && turnId !== null && turnId !== active.turnId) {
      return;
    }
    switch (notification.method) {
      case "thread/tokenUsage/updated": {
        active.usage = usageFromNotification(params);
        return;
      }
      case "item/started":
      case "item/completed": {
        const item = appServerItem(params["item"]);
        if (item !== null) {
          active.queue.push({
            type:
              notification.method === "item/started"
                ? "item.started"
                : "item.completed",
            item,
          });
        }
        return;
      }
      case "error": {
        const error = recordValue(params, "error");
        const message = stringValue(error, "message");
        if (message !== null) active.queue.push({ type: "error", message });
        return;
      }
      case "turn/completed": {
        const turn = recordValue(params, "turn");
        const status = stringValue(turn, "status");
        const error = recordValue(turn, "error");
        if (status === "failed" || status === "interrupted") {
          active.queue.push({
            type: "turn.failed",
            error: {
              message:
                stringValue(error, "message") ??
                (status === "interrupted"
                  ? "Codex app-server turn was interrupted."
                  : "Codex app-server turn failed."),
            },
          });
        } else {
          active.queue.push({ type: "turn.completed", usage: active.usage });
        }
        active.queue.close();
        return;
      }
      default:
        return;
    }
  }

  #replyUnsupportedRequest(id: unknown): void {
    if (typeof id !== "string" && typeof id !== "number") return;
    this.#write({
      id,
      error: {
        code: -32601,
        message:
          "Codex Security does not support app-server initiated requests.",
      },
    });
  }

  #request(
    method: string,
    params: Record<string, unknown>,
    signal?: AbortSignal,
  ): Promise<unknown> {
    if (this.#closed)
      return Promise.reject(new Error("Codex app-server client is closed."));
    signal?.throwIfAborted();
    const id = String(++this.#requestSequence);
    const request: JsonRpcRequest = { id, method, params };
    const promise = new Promise<unknown>((resolve, reject) => {
      this.#pending.set(id, { resolve, reject });
    });
    const onAbort = (): void => {
      const pending = this.#pending.get(id);
      if (pending === undefined) return;
      this.#pending.delete(id);
      pending.reject(abortError(signal));
    };
    signal?.addEventListener("abort", onAbort, { once: true });
    this.#write(request);
    return promise.finally(() => signal?.removeEventListener("abort", onAbort));
  }

  #write(message: object): void {
    const input = this.#process?.stdin;
    if (input === undefined || input.destroyed) {
      this.#fail(new Error("Codex app-server stdin is unavailable."));
      return;
    }
    input.write(`${JSON.stringify(message)}\n`);
  }

  #fail(error: Error): void {
    for (const pending of this.#pending.values()) pending.reject(error);
    this.#pending.clear();
    this.#activeTurn?.queue.fail(error);
  }

  #endStream(error: Error): void {
    for (const pending of this.#pending.values()) pending.reject(error);
    this.#pending.clear();
    this.#activeTurn?.queue.close();
  }
}

class AppServerThread {
  readonly #client: CodexAppServer;
  readonly #options: ThreadOptions;
  #id: string | null;
  #started = false;

  public constructor(
    client: CodexAppServer,
    options: ThreadOptions,
    id: string | null = null,
  ) {
    this.#client = client;
    this.#options = options;
    this.#id = id;
  }

  public get id(): string | null {
    return this.#id;
  }

  public async runStreamed(
    input: string,
    options: TurnOptions = {},
  ): Promise<StreamedTurn> {
    const firstTurn = !this.#started;
    if (firstTurn) {
      this.#id = await this.#client.startOrResumeThread(
        this.#options,
        this.#id,
        options.signal,
      );
      this.#started = true;
    }
    const threadId = this.#id;
    if (threadId === null)
      throw new Error("Codex app-server thread is unavailable.");
    const turnEvents = await this.#client.runTurn(threadId, input, options);
    return { events: prependThreadEvents(turnEvents, firstTurn, threadId) };
  }

  public async run(input: string, options: TurnOptions = {}): Promise<Turn> {
    const { events } = await this.runStreamed(input, options);
    const items: ThreadItem[] = [];
    let finalResponse = "";
    let usage: Usage | null = null;
    for await (const event of events) {
      if (event.type === "item.completed") {
        items.push(event.item);
        if (
          event.item.type === "agent_message" &&
          typeof event.item["text"] === "string"
        ) {
          finalResponse = event.item["text"];
        }
      } else if (event.type === "turn.completed") {
        usage = event.usage;
      } else if (event.type === "turn.failed") {
        throw new Error(event.error.message);
      }
    }
    return { items, finalResponse, usage };
  }
}

async function* prependThreadEvents(
  events: AsyncGenerator<ThreadEvent>,
  firstTurn: boolean,
  threadId: string,
): AsyncGenerator<ThreadEvent> {
  if (firstTurn) yield { type: "thread.started", thread_id: threadId };
  yield { type: "turn.started" };
  yield* events;
}

class EventQueue {
  readonly #values: ThreadEvent[] = [];
  readonly #waiters: Array<{
    resolve(value: ThreadEvent | null): void;
    reject(error: Error): void;
  }> = [];
  #closed = false;
  #failure: Error | null = null;

  public push(value: ThreadEvent): void {
    if (this.#closed || this.#failure !== null) return;
    const waiter = this.#waiters.shift();
    if (waiter === undefined) this.#values.push(value);
    else waiter.resolve(value);
  }

  public close(): void {
    if (this.#closed || this.#failure !== null) return;
    this.#closed = true;
    for (const waiter of this.#waiters.splice(0)) waiter.resolve(null);
  }

  public fail(error: Error): void {
    if (this.#closed || this.#failure !== null) return;
    this.#failure = error;
    for (const waiter of this.#waiters.splice(0)) waiter.reject(error);
  }

  public async shift(): Promise<ThreadEvent | null> {
    if (this.#values.length > 0) return this.#values.shift()!;
    if (this.#failure !== null) throw this.#failure;
    if (this.#closed) return null;
    return await new Promise((resolve, reject) => {
      this.#waiters.push({ resolve, reject });
    });
  }
}

function threadParams(
  codex: CodexOptions,
  thread: ThreadOptions,
): Record<string, unknown> {
  const config: Record<string, unknown> = {
    ...(codex.config ?? {}),
    ...(codex.baseUrl === undefined ? {} : { openai_base_url: codex.baseUrl }),
    ...(thread.modelReasoningEffort === undefined
      ? {}
      : { model_reasoning_effort: thread.modelReasoningEffort }),
    ...(thread.networkAccessEnabled === undefined
      ? {}
      : {
          "sandbox_workspace_write.network_access": thread.networkAccessEnabled,
        }),
    ...(thread.webSearchMode === undefined
      ? thread.webSearchEnabled === undefined
        ? {}
        : { web_search: thread.webSearchEnabled ? "live" : "disabled" }
      : { web_search: thread.webSearchMode }),
  };
  const cwd = thread.workingDirectory ?? process.cwd();
  return {
    ...(thread.model === undefined ? {} : { model: thread.model }),
    cwd,
    ...(thread.approvalPolicy === undefined
      ? {}
      : { approvalPolicy: thread.approvalPolicy }),
    ...(thread.sandboxMode === undefined
      ? {}
      : { sandbox: thread.sandboxMode }),
    ...(thread.additionalDirectories?.length
      ? { runtimeWorkspaceRoots: [cwd, ...thread.additionalDirectories] }
      : {}),
    config,
  };
}

function appServerItem(value: unknown): ThreadItem | null {
  if (!isRecord(value)) return null;
  const id = stringValue(value, "id");
  const type = stringValue(value, "type");
  if (id === null || type === null) return null;
  switch (type) {
    case "agentMessage":
      return {
        id,
        type: "agent_message",
        text: stringValue(value, "text") ?? "",
      };
    case "reasoning": {
      const summary = stringArray(value["summary"]);
      const content = stringArray(value["content"]);
      return {
        id,
        type: "reasoning",
        text: [...summary, ...content].join("\n"),
      };
    }
    case "commandExecution":
      return {
        id,
        type: "command_execution",
        command: stringValue(value, "command") ?? "",
        aggregated_output: stringValue(value, "aggregatedOutput") ?? "",
        ...(numberValue(value, "exitCode") === null
          ? {}
          : { exit_code: numberValue(value, "exitCode") }),
        status: itemStatus(stringValue(value, "status")),
      };
    case "mcpToolCall":
      return {
        id,
        type: "mcp_tool_call",
        server: stringValue(value, "server") ?? "",
        tool: stringValue(value, "tool") ?? "",
        arguments: value["arguments"],
        ...(value["result"] === undefined ? {} : { result: value["result"] }),
        ...(value["error"] === undefined ? {} : { error: value["error"] }),
        status: itemStatus(stringValue(value, "status")),
      };
    case "fileChange":
      return {
        id,
        type: "file_change",
        changes: Array.isArray(value["changes"]) ? value["changes"] : [],
        status: itemStatus(stringValue(value, "status")),
      };
    case "webSearch":
      return {
        id,
        type: "web_search",
        query: stringValue(value, "query") ?? "",
      };
    default:
      return { id, type: camelToSnake(type), ...value };
  }
}

function usageFromNotification(params: Record<string, unknown>): Usage | null {
  const tokenUsage = recordValue(params, "tokenUsage");
  const total = recordValue(tokenUsage, "total");
  if (total === null) return null;
  const input = numberValue(total, "inputTokens");
  const cached = numberValue(total, "cachedInputTokens");
  const cacheWrite = numberValue(total, "cacheWriteInputTokens");
  const output = numberValue(total, "outputTokens");
  const reasoning = numberValue(total, "reasoningOutputTokens");
  const tokens = numberValue(total, "totalTokens");
  if (
    input === null ||
    cached === null ||
    output === null ||
    reasoning === null
  ) {
    return null;
  }
  return {
    input_tokens: input,
    cached_input_tokens: cached,
    ...(cacheWrite === null ? {} : { cache_write_input_tokens: cacheWrite }),
    output_tokens: output,
    reasoning_output_tokens: reasoning,
    ...(tokens === null ? {} : { total_tokens: tokens }),
  };
}

function processEnvironment(): Record<string, string> {
  return Object.fromEntries(
    Object.entries(process.env).filter(
      (entry): entry is [string, string] => entry[1] !== undefined,
    ),
  );
}

function itemStatus(
  value: string | null,
): "in_progress" | "completed" | "failed" {
  if (value === "completed") return "completed";
  if (value === "failed" || value === "declined") return "failed";
  return "in_progress";
}

function camelToSnake(value: string): string {
  return value.replaceAll(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase();
}

function recordValue(
  value: unknown,
  key: string,
): Record<string, unknown> | null {
  if (!isRecord(value) || !isRecord(value[key])) return null;
  return value[key];
}

function stringValue(value: unknown, key: string): string | null {
  return isRecord(value) && typeof value[key] === "string" ? value[key] : null;
}

function numberValue(value: unknown, key: string): number | null {
  return isRecord(value) && typeof value[key] === "number" ? value[key] : null;
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

function abortError(signal?: AbortSignal): Error {
  const reason = signal?.reason;
  if (reason instanceof Error) return reason;
  return new DOMException("The operation was aborted.", "AbortError");
}

async function withAbort<T>(
  promise: Promise<T>,
  signal?: AbortSignal,
): Promise<T> {
  if (signal === undefined) return await promise;
  signal.throwIfAborted();
  let onAbort: (() => void) | undefined;
  const aborted = new Promise<T>((_resolve, reject) => {
    onAbort = () => reject(abortError(signal));
    signal.addEventListener("abort", onAbort, { once: true });
  });
  try {
    return await Promise.race([promise, aborted]);
  } finally {
    if (onAbort !== undefined) signal.removeEventListener("abort", onAbort);
  }
}

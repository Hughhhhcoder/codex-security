import { Cli, Help, Skill, z } from "incur";
import {
  DEFAULT_CODEX_CONFIG,
  scanModelConfiguration,
  type JsonObject,
} from "./config.js";
import {
  BUNDLED_PLUGIN_VERSION,
  CODEX_EXECUTABLE_VERSION,
  CODEX_SDK_VERSION,
  VERSION,
} from "./version.js";

interface Manifest {
  commands: { name: string }[];
}

interface InputSchema {
  required?: string[];
  properties?: Record<string, InputField>;
}

interface InputField {
  type?: string;
  const?: unknown;
  enum?: unknown[];
  default?: unknown;
  minimum?: number;
  exclusiveMinimum?: number;
  maximum?: number;
  exclusiveMaximum?: number;
  minLength?: number;
  maxLength?: number;
}

export function isFullMarkdownManifest(argv: readonly string[]): boolean {
  if (!argv.includes("--llms-full") || argv.includes("--mcp")) return false;
  let format: string | undefined;
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === "--json") format = "json";
    else if (argv[index] === "--format") format = argv[++index];
    else if (argv[index]?.startsWith("--format=")) {
      format = argv[index]!.slice("--format=".length);
    }
  }
  return format === undefined || format === "md";
}

/** Render a documentation-only view; keep Incur's parsed schemas unchanged. */
export function renderFullMarkdownManifest(
  cli: Cli.Cli,
  manifest: Manifest,
): string {
  const selected = new Set(manifest.commands.map(({ name }) => name));
  const commands = Cli.collectSkillCommands(
    Cli.toCommands.get(cli)!,
    [],
    new Map(),
  )
    .filter((command) => selected.has(command.name!))
    .map((command) => ({
      ...command,
      args: documentInputs(command.args, false),
      options: documentInputs(command.options, true),
    }));
  const defaults = scanModelConfiguration(DEFAULT_CODEX_CONFIG);
  const features = DEFAULT_CODEX_CONFIG["features"] as JsonObject;
  const multiAgent = features["multi_agent_v2"] as JsonObject;
  const threadLimit = multiAgent["max_concurrent_threads_per_session"];

  return [
    Skill.index(cli.name, commands, cli.description),
    `CLI/SDK version: ${VERSION}. Bundled plugin: ${BUNDLED_PLUGIN_VERSION}. ` +
      `Codex runtime: ${CODEX_EXECUTABLE_VERSION}. Codex SDK: ${CODEX_SDK_VERSION}. ` +
      `Default model: ${defaults.model}; reasoning effort: ${defaults.reasoningEffort}.`,
    "## Operating notes",
    "Scan only repositories you own or have permission to assess. " +
      "Reports, findings, source excerpts, and verbose logs can be sensitive. " +
      "Keep scan state and artifacts outside the repository and share them only with authorized reviewers.",
    "### Authentication and local state",
    "Use `codex-security login` for ChatGPT sign-in, or set `OPENAI_API_KEY` or `CODEX_API_KEY` for CI. " +
      "`OPENAI_API_KEY` takes precedence when both keys are present. Noninteractive scans prefer an environment API key; " +
      "interactive scans can ask when a ChatGPT sign-in is also available. Use `scan --auth chatgpt` or " +
      "`scan --auth api-key` to select explicitly. Environment API keys are not stored; " +
      "`login --with-api-key` explicitly stores a key read from stdin. " +
      "External providers require an explicit model: OpenRouter uses `OPENROUTER_API_KEY`, " +
      "Fireworks uses `FIREWORKS_API_KEY`, and Amazon Bedrock uses `AWS_BEARER_TOKEN_BEDROCK` or the AWS credential chain.",
    "`CODEX_SECURITY_STATE_DIR` overrides the workbench, history, and default artifact directory. " +
      "Otherwise state is under `$CODEX_HOME/state/plugins/codex-security`, with `CODEX_HOME` defaulting to `~/.codex`. " +
      "Python-backed commands require Python 3.10 or later; Python 3.10 also needs `tomli`. " +
      "Use `--python` where offered, or set `PYTHON`. " +
      "`CODEX_SECURITY_LOG_LEVEL=debug` enables CLI diagnostics; `LOG_LEVEL` is its fallback. " +
      "Set `CODEX_SECURITY_NO_UPDATE_NOTICE=1` to suppress update notices.",
    "### Configuration and workers",
    "Scans use isolated Codex configuration. Repeat `--codex KEY=VALUE` for TOML overrides; " +
      "quote string values as TOML. Do not set the same model or effort with both a dedicated flag and `--codex`. " +
      "Plugin loading is managed by Codex Security; select a different plugin with `--plugin-path`. " +
      "`validate` and `patch` accept only the `model` and `model_reasoning_effort` override keys.",
    "Deep scans read `[deep_scan]` in `$CODEX_HOME/codex-security/config.toml`; " +
      "explicit scan options override that configuration, which overrides the bundled defaults listed below. " +
      "`stop_after_consecutive_errors` is configurable in that file, not through a CLI flag. " +
      "`scan --workers` limits discovery workers within one deep scan; `bulk-scan --workers` limits concurrent repositories. " +
      "Both are separate from `features.multi_agent_v2.max_concurrent_threads_per_session`, " +
      `whose default is ${threadLimit} total session threads including the parent.`,
    "### Scan inputs and results",
    "`--path`, `--diff`, and `--working-tree` are mutually exclusive. " +
      "`--head` requires `--diff`; `--base` requires `--working-tree`. " +
      "Deep-scan settings require `--mode deep`, which supports repository and path targets only. " +
      "`scan --dry-run` validates local inputs and configuration without starting Codex, loading credentials, " +
      "or checking the plugin or Python. It does not verify authentication or model access.",
    "Use `scan --json` for machine-readable results on stdout; progress and diagnostics go to stderr. " +
      "A completed result includes `manifest`, `findings`, `coverage`, `repositoryFindings`, `scanDir`, " +
      "`reportPath`, `artifactsDir`, `sarifPath`, `threadId`, `cost`, and `turn`. " +
      "`findings` describes this scan; `repositoryFindings`, when available, includes open findings across scans. " +
      "Scan results support `--format toon|json|yaml|jsonl` and `--full-output`, but not Markdown or `--filter-output`. " +
      "`validate`, `patch`, `login`, and `logout` do not produce structured CLI results and reject JSON/JSONL result output. " +
      "Those restrictions do not apply to `--llms`, `--llms-full`, or `--schema` discovery. " +
      "Use `--llms-full --format json` for the original Incur manifest; schema property names are parsed option keys, " +
      "while command-line flags use kebab-case.",
    "Scan exit codes: `0` for a completed report-only scan or passing policy; `1` for a completed " +
      "`--fail-on-severity` violation; `2` for invalid input, incomplete coverage, a changed target, or a runtime error; " +
      "`130` for interruption; `143` for termination. Do not interpret an incomplete scan as a clean result. " +
      "`export` reads a completed, sealed scan without starting Codex and supports CSV, JSON, or SARIF; " +
      "CSV stdout cannot be combined with JSON result output. MCP exposes only the read-only `info` command.",
    "### Saved scans and findings",
    "History commands read the selected workbench database. `scans` and `findings` default to their `list` commands. " +
      "`scans list --scan-root` filters indexed scans; " +
      "it does not import report directories. Use `--json` for structured history results. " +
      "Scan IDs accept unique prefixes of at least eight characters. " +
      "`scans show`, `scans rerun`, and `export` default to the latest completed scan for the current repository; " +
      "`scans logs` defaults to the latest scan, including an active scan. " +
      "`scans rerun` replays a saved configuration against the current checkout. " +
      "`scans compare` defaults to the two latest completed scans; it can use a model to match findings and caches those matches. " +
      "A missing finding remains unknown " +
      "when the later scan is incomplete or did not cover its original location. " +
      "`scans logs` can include source code and credentials; review logs before sharing them.",
    "### Publishing completed scans",
    "`publish scan --to linear` creates one new Linear issue per finding from a completed scan already in local history. " +
      "Provide a scan directory for noninteractive use, or omit it to select a saved scan interactively. " +
      "Set `--linear-team` or `CODEX_SECURITY_LINEAR_TEAM`; `--project` or `CODEX_SECURITY_LINEAR_PROJECT` is optional. " +
      "By default, publication uses your existing Codex configuration and connected Linear app. " +
      "Set `CODEX_SECURITY_LINEAR_API_KEY` to use the Linear API directly without starting Codex; " +
      "prefer it to `--linear-api-key` to keep the key out of shell history and process listings. " +
      "`--linear-assignee` requires direct API mode. `--dry-run` previews issues without contacting Linear; " +
      "`--json` returns structured publication results. Repeating publication creates another set of issues. " +
      "Issue descriptions contain source code and vulnerability details, so select a destination authorized to receive them.",
    "## Global options and integrations",
    "```text\n" + Help.formatRoot(cli.name, { root: true }) + "\n```",
    "## Command reference",
    ...commands.map((command) =>
      Skill.generate(cli.name, [command]).replace(/^#/gmu, "###"),
    ),
    "",
  ].join("\n\n");
}

function documentInputs(
  schema: z.ZodObject | undefined,
  options: boolean,
): z.ZodObject | undefined {
  if (schema === undefined) return undefined;
  // Incur 0.4.13 renders schema keys as flags and omits input constraints.
  // Adapt only the Markdown view, not the parser or machine-readable schema.
  const input = z.toJSONSchema(schema, {
    io: "input",
    unrepresentable: "any",
  }) as InputSchema;
  const required = new Set(input.required);
  return z.object(
    Object.fromEntries(
      Object.entries(schema.shape).map(([name, field]) => {
        const property = input.properties?.[name] ?? {};
        const details = [field.description ?? ""];
        if (options && required.has(name)) details.push("Required.");
        const values =
          property.enum ??
          (property.const === undefined ? undefined : [property.const]);
        if (values !== undefined) {
          details.push(`Allowed values: ${values.map(codeValue).join(", ")}.`);
        }
        if (property.type === "integer") details.push("Must be an integer.");
        if (options && property.type === "array") {
          details.push("Repeat this flag for multiple values.");
          if (Array.isArray(property.default)) {
            details.push(`Default: ${codeValue(property.default)}.`);
          }
        }
        for (const [key, label] of [
          ["minimum", "Minimum"],
          ["exclusiveMinimum", "Must be greater than"],
          ["maximum", "Maximum"],
          ["exclusiveMaximum", "Must be less than"],
          ["minLength", "Minimum length"],
          ["maxLength", "Maximum length"],
        ] as const) {
          if (property[key] !== undefined) {
            details.push(`${label}: ${property[key]}.`);
          }
        }
        const key = options
          ? name.replace(/[A-Z]/gu, (letter) => `-${letter.toLowerCase()}`)
          : name;
        return [key, field.describe(details.join(" "))];
      }),
    ),
  );
}

function codeValue(value: unknown): string {
  return `\`${typeof value === "string" ? value : JSON.stringify(value)}\``;
}

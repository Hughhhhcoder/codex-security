import { readFileSync } from "node:fs";
import { Cli, Help, Skill, z } from "incur";
import { DEFAULT_CODEX_CONFIG, scanModelConfiguration } from "./config.js";
import {
  BUNDLED_PLUGIN_VERSION,
  CODEX_EXECUTABLE_VERSION,
  CODEX_SDK_VERSION,
  VERSION,
} from "./version.js";

interface Manifest {
  commands: { name: string }[];
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
  const groups = new Map<string, string>();
  const commands = Cli.collectSkillCommands(
    Cli.toCommands.get(cli)!,
    [],
    groups,
  )
    .filter((command) => selected.has(command.name!))
    .map((command) => ({
      ...command,
      args: documentInputs(command.args, false),
      options: documentInputs(command.options, true),
    }));
  const groupRows = [...groups]
    .filter(([name]) =>
      commands.some((command) => command.name?.startsWith(`${name} `)),
    )
    .map(
      ([name, description]) => `| \`${cli.name} ${name}\` | ${description} |`,
    );
  const defaults = scanModelConfiguration(DEFAULT_CODEX_CONFIG);

  return [
    Skill.index(cli.name, commands, cli.description),
    `CLI/SDK version: ${VERSION}. Bundled plugin: ${BUNDLED_PLUGIN_VERSION}. ` +
      `Codex runtime: ${CODEX_EXECUTABLE_VERSION}. Codex SDK: ${CODEX_SDK_VERSION}. ` +
      `Default model: ${defaults.model}; reasoning effort: ${defaults.reasoningEffort}.`,
    readOperatingGuide(),
    "## Global options and integrations",
    "```text\n" + Help.formatRoot(cli.name, { root: true }) + "\n```",
    ...(groupRows.length === 0
      ? []
      : [
          "## Command groups",
          [
            "| Group | Description |",
            "|-------|-------------|",
            ...groupRows,
          ].join("\n"),
        ]),
    "## Command reference",
    ...commands.map((command) =>
      Skill.generate(cli.name, [command]).replace(/^#/gmu, "###"),
    ),
    "",
  ].join("\n\n");
}

function readOperatingGuide(): string {
  return readFileSync(new URL("../README.md", import.meta.url), "utf8")
    .replace(/\r\n/gu, "\n")
    .split(/(?=^## )/mu)
    .filter((section) =>
      /^## (?:Install|Authentication|CLI|Local security model)\n/u.test(
        section,
      ),
    )
    .join("")
    .trim();
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
  });
  const required = new Set(input.required);
  return z.object(
    Object.fromEntries(
      Object.entries(schema.shape).map(([name, field]) => {
        const property = (input.properties?.[name] ??
          {}) as z.core.JSONSchema.JSONSchema;
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

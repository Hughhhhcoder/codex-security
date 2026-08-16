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

// Incur 0.4.13 omits the requested path from its structured manifest.
const MANIFEST_FLAGS = new Set([
  "--full-output",
  "--llms",
  "--llms-full",
  "--help",
  "-h",
  "--version",
  "--schema",
  "--token-count",
]);
export const INCUR_VALUE_OPTIONS = new Set([
  "--format",
  "--filter-output",
  "--token-limit",
  "--token-offset",
]);

export function fullMarkdownManifestArguments(
  argv: readonly string[],
): string[] | undefined {
  if (!argv.includes("--llms-full") || argv.includes("--mcp")) return undefined;
  let format: string | undefined;
  const commandArguments: string[] = [];
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]!;
    if (argument === "--json") format = "json";
    else if (argument === "--format") format = argv[++index];
    else if (MANIFEST_FLAGS.has(argument)) continue;
    else if (
      INCUR_VALUE_OPTIONS.has(argument) &&
      argv[index + 1] !== undefined
    ) {
      index += 1;
    } else {
      commandArguments.push(argument);
    }
  }
  return format === undefined || format === "md" ? commandArguments : undefined;
}

/** Render a documentation-only view; keep Incur's parsed schemas unchanged. */
export function renderFullMarkdownManifest(
  cli: Cli.Cli,
  manifest: Manifest,
  commandArguments: readonly string[] = [],
): string {
  const selected = new Set(manifest.commands.map(({ name }) => name));
  const groups = new Map<string, string>();
  const allCommands = Cli.collectSkillCommands(
    Cli.toCommands.get(cli)!,
    [],
    groups,
  );
  let scope = "";
  for (const argument of commandArguments) {
    const next = scope ? `${scope} ${argument}` : argument;
    if (
      !allCommands.some(
        ({ name }) => name === next || name?.startsWith(`${next} `),
      )
    ) {
      break;
    }
    scope = next;
    if (allCommands.some(({ name }) => name === scope)) break;
  }
  const commands = allCommands
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
  const scopedName = scope ? `${cli.name} ${scope}` : cli.name;
  const description = scope
    ? groups.get(scope) ??
      allCommands.find(({ name }) => name === scope)?.description
    : cli.description;

  return [
    Skill.index(cli.name, commands, description).replace(
      /^# [^\n]+/u,
      `# ${scopedName}`,
    ),
    `CLI/SDK version: ${VERSION}. Bundled plugin: ${BUNDLED_PLUGIN_VERSION}. ` +
      `Codex runtime: ${CODEX_EXECUTABLE_VERSION}. Codex SDK: ${CODEX_SDK_VERSION}. ` +
      `Default model: ${defaults.model}; reasoning effort: ${defaults.reasoningEffort}.`,
    scope
      ? `Run \`${cli.name} --llms-full\` for the operating guide.`
      : readOperatingGuide(),
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
        details.push(...describeConstraints(property));
        if (options && property.type === "array") {
          details.push("Repeat this flag for multiple values.");
          if (Array.isArray(property.default)) {
            details.push(`Default: ${codeValue(property.default)}.`);
          }
        }
        if (
          property.type === "array" &&
          typeof property.items === "object" &&
          !Array.isArray(property.items)
        ) {
          const itemDetails = describeConstraints(property.items);
          if (itemDetails.length > 0) {
            details.push(`Each value: ${itemDetails.join(" ")}`);
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

function describeConstraints(property: z.core.JSONSchema.JSONSchema): string[] {
  const details: string[] = [];
  const values =
    property.enum ??
    (property.const === undefined ? undefined : [property.const]);
  if (values !== undefined) {
    details.push(`Allowed values: ${values.map(codeValue).join(", ")}.`);
  }
  if (property.type === "integer") details.push("Must be an integer.");
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
  return details;
}

function codeValue(value: unknown): string {
  return `\`${typeof value === "string" ? value : JSON.stringify(value)}\``;
}

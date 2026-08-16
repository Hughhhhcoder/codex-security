import { describe, expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { Cli, Schema, z } from "incur";
import { main } from "../src/cli.js";
import {
  fullMarkdownManifestArguments,
  renderFullMarkdownManifest,
} from "../src/cli-manifest.js";
import { DEFAULT_CODEX_CONFIG, scanModelConfiguration } from "../src/config.js";
import {
  BUNDLED_PLUGIN_VERSION,
  CODEX_EXECUTABLE_VERSION,
  CODEX_SDK_VERSION,
  VERSION,
} from "../src/version.js";
import { capture, dependencies, fakeResult } from "./cli-fixtures.js";

interface Field {
  description?: string;
  default?: unknown;
  const?: unknown;
  enum?: unknown[];
}

interface ObjectSchema {
  properties?: Record<string, Field>;
  required?: string[];
}

interface Command {
  name: string;
  schema?: {
    args?: ObjectSchema;
    options?: ObjectSchema;
    output?: ObjectSchema;
  };
  examples?: { command: string }[];
}

interface Manifest {
  version: string;
  commands: Command[];
}

function documentationDependencies() {
  const unexpected = (): never => {
    throw new Error("Documentation must not run a command or access state.");
  };
  const deps = dependencies({
    environment: {
      OPENAI_API_KEY: "SYNTHETIC_MANIFEST_KEY",
      CODEX_SECURITY_STATE_DIR: "/synthetic/private-state",
    },
  });
  deps.createSecurity = unexpected;
  deps.prepareAuthenticationHome = unexpected;
  deps.hasStoredChatGPTSignIn = unexpected;
  deps.currentDirectory = unexpected;
  deps.runCodex = unexpected;
  deps.runWorkbench = unexpected;
  deps.matchFindings = unexpected;
  deps.exportFindings = unexpected;
  deps.publishScan = unexpected;
  deps.checkForUpdate = unexpected;
  return deps;
}

async function invoke(args: readonly string[]): Promise<string> {
  const stdout = capture();
  const stderr = capture(true);
  expect(
    await main(args, stdout.stream, stderr.stream, documentationDependencies()),
  ).toBe(0);
  expect(stderr.text()).toBe("");
  expect(stdout.text()).not.toContain("SYNTHETIC_MANIFEST_KEY");
  expect(stdout.text()).not.toContain("/synthetic/private-state");
  return stdout.text();
}

async function readManifest(args: readonly string[] = []): Promise<Manifest> {
  return JSON.parse(
    await invoke([...args, "--llms-full", "--format", "json"]),
  ) as Manifest;
}

function commandSections(markdown: string): Map<string, string> {
  return new Map(
    markdown
      .split(/^### codex-security /mu)
      .slice(1)
      .map((section) => {
        const newline = section.indexOf("\n");
        return [section.slice(0, newline), section.slice(newline + 1)];
      }),
  );
}

function flag(name: string): string {
  return `--${name.replace(/[A-Z]/gu, (letter) => `-${letter.toLowerCase()}`)}`;
}

describe("full CLI manifest", () => {
  test("documents every live command, argument, option, and allowed value", async () => {
    const manifest = await readManifest();
    const markdown = await invoke(["--llms-full"]);
    const sections = commandSections(markdown);

    expect(manifest.version).toBe("incur.v1");
    expect([...sections.keys()]).toEqual(
      manifest.commands.map(({ name }) => name),
    );
    expect(markdown).not.toMatch(/--[a-z][a-z0-9-]*[A-Z][A-Za-z0-9-]*/u);

    for (const command of manifest.commands) {
      const section = sections.get(command.name)!;
      for (const [name, field] of Object.entries(
        command.schema?.args?.properties ?? {},
      )) {
        expect(section).toContain(`| \`${name}\` |`);
        expect(section).toContain(field.description!);
      }
      for (const [name, field] of Object.entries(
        command.schema?.options?.properties ?? {},
      )) {
        const row = section
          .split("\n")
          .find((line) => line.startsWith(`| \`${flag(name)}\` |`));
        expect(row).toBeDefined();
        expect(row).toContain(field.description!);
        for (const value of field.enum ??
          (field.const === undefined ? [] : [field.const])) {
          expect(row).toContain(`\`${String(value)}\``);
        }
        const required =
          command.schema?.options?.required?.includes(name) === true &&
          field.default === undefined;
        expect(row!.includes("Required.")).toBe(required);
      }
      for (const example of command.examples ?? []) {
        expect(section).toContain(`codex-security ${example.command}`);
      }
    }

    expect(sections.get("info")).toContain("| `sdkVersion` |");
    expect(sections.get("scan")).toContain("--max-time-hours");
    expect(sections.get("scan")).toContain("Maximum: 96");
    expect(sections.get("findings false-positive")).toContain(
      "Maximum length: 2400",
    );
    expect(sections.get("bulk-scan")).toContain(
      "--output-dir /path/outside/repositories/results",
    );
    expect(sections.get("publish scan")).toContain("Allowed values: `linear`");
  });

  test("includes current metadata and the packaged operating guide", async () => {
    const markdown = await invoke(["--llms-full"]);
    const readme = (
      await readFile(new URL("../README.md", import.meta.url), "utf8")
    ).replace(/\r\n/gu, "\n");
    for (const title of [
      "Install",
      "Authentication",
      "CLI",
      "Local security model",
    ]) {
      const heading = `## ${title}\n`;
      const start = readme.indexOf(heading);
      expect(start).toBeGreaterThanOrEqual(0);
      const end = readme.indexOf("\n## ", start + heading.length);
      expect(markdown).toContain(
        readme.slice(start, end < 0 ? undefined : end).trim(),
      );
    }
    for (const title of [
      "Run a scan from TypeScript",
      "Containerized bulk scans",
    ]) {
      expect(markdown).not.toContain(`\n## ${title}\n`);
    }
    const defaults = scanModelConfiguration(DEFAULT_CODEX_CONFIG);
    for (const value of [
      VERSION,
      BUNDLED_PLUGIN_VERSION,
      CODEX_EXECUTABLE_VERSION,
      CODEX_SDK_VERSION,
      defaults.model,
      defaults.reasoningEffort,
      "--schema",
      "--mcp",
      "completions",
      "## Global options and integrations",
      "## Command groups",
      "## Command reference",
    ]) {
      expect(markdown).toContain(value);
    }
    for (const key of [...Object.keys(fakeResult().toJSON()), "warnings"]) {
      expect(markdown).toContain(`\`${key}\``);
    }
  });

  test("preserves descriptions for selected command groups", () => {
    const descriptions = {
      first: "First group metadata.",
      nested: "Nested group metadata.",
      second: "Second group metadata.",
    };
    const cli = Cli.create("sample")
      .command(
        Cli.create("first", { description: descriptions.first })
          .command("show", { run() {} })
          .command(
            Cli.create("nested", { description: descriptions.nested }).command(
              "show",
              { run() {} },
            ),
          ),
      )
      .command(
        Cli.create("second", { description: descriptions.second }).command(
          "show",
          { run() {} },
        ),
      );
    const commands = ["first show", "first nested show", "second show"].map(
      (name) => ({ name }),
    );
    const full = renderFullMarkdownManifest(cli, { commands });
    for (const description of Object.values(descriptions)) {
      expect(full).toContain(description);
    }
    const scoped = renderFullMarkdownManifest(
      cli,
      {
        commands: [{ name: "first nested show" }],
      },
      ["first", "nested"],
    );
    expect(scoped).toContain(descriptions.first);
    expect(scoped).toContain(descriptions.nested);
    expect(scoped).not.toContain(descriptions.second);
  });

  test("preserves group and leaf discovery without executing handlers", async () => {
    const root = await readManifest();
    const groups = new Set(
      root.commands.flatMap(({ name }) =>
        name.includes(" ") ? [name.split(" ")[0]!] : [],
      ),
    );
    for (const group of groups) {
      const expected = root.commands.filter(({ name }) =>
        name.startsWith(`${group} `),
      );
      expect((await readManifest([group])).commands).toEqual(expected);
      const short = JSON.parse(
        await invoke([group, "--llms", "--json"]),
      ) as Manifest;
      expect(short.commands.map(({ name }) => name)).toEqual(
        expected.map(({ name }) => name),
      );
      const markdown = await invoke([group, "--llms-full"]);
      expect(markdown).toStartWith(`# codex-security ${group}\n`);
      expect(markdown).not.toContain("\n## Authentication\n");
      expect([...commandSections(markdown).keys()]).toEqual(
        expected.map(({ name }) => name),
      );
    }
    for (const command of root.commands) {
      const args = command.name.split(" ");
      expect((await readManifest(args)).commands).toEqual([command]);
      const markdown = await invoke([...args, "--llms-full", "--format=md"]);
      expect(markdown).toStartWith(`# codex-security ${command.name}\n`);
      expect(markdown).not.toContain("\n## Authentication\n");
      expect([...commandSections(markdown).keys()]).toEqual([command.name]);
    }
  });

  test("preserves scoped paths when global discovery flags come first or between commands", async () => {
    for (const args of [
      ["--llms-full", "--format", "md", "scans", "show"],
      ["scans", "--llms-full", "--token-count", "show"],
      ["--filter-output", "scan", "scans", "show", "--llms-full"],
    ]) {
      const markdown = await invoke(args);
      expect(markdown).toStartWith("# codex-security scans show\n");
      expect([...commandSections(markdown).keys()]).toEqual(["scans show"]);
      expect(markdown).not.toContain("\n## Authentication\n");
    }
    expect(
      await invoke(["--filter-output", "scan", "--llms-full"]),
    ).toStartWith("# codex-security\n");
  });

  test("keeps schema discovery separate from execution-only format checks", async () => {
    const schema = JSON.parse(
      await invoke(["export", "--schema", "--format", "json"]),
    );
    expect(
      JSON.parse(
        await invoke([
          "export",
          "--schema",
          "--format",
          "json",
          "--output",
          "-",
          "--export-format",
          "csv",
        ]),
      ),
    ).toEqual(schema);
  });

  test("honors explicit output formats without rewriting structured manifests", async () => {
    const markdown = await invoke(["scan", "--llms-full"]);
    for (const format of [
      ["--format", "md"],
      ["--format=md"],
      ["--json", "--format", "md"],
    ]) {
      expect(await invoke(["scan", "--llms-full", ...format])).toBe(markdown);
    }
    const manifest = await readManifest(["scan"]);
    expect(
      JSON.parse(
        await invoke(["scan", "--llms-full", "--format", "md", "--json"]),
      ),
    ).toEqual(manifest);
    expect(manifest.commands[0]?.schema?.options?.properties).toHaveProperty(
      "outputDir",
    );
    expect(
      manifest.commands[0]?.schema?.options?.properties,
    ).not.toHaveProperty("output-dir");
    expect(
      fullMarkdownManifestArguments(["--llms-full", "--mcp"]),
    ).toBeUndefined();
  });

  test("does not mutate the schemas used by the command parser", () => {
    const options = z.object({
      requiredValue: z.string().min(1),
      defaultValue: z.enum(["one", "two"]).default("one"),
    });
    const before = Schema.toJsonSchema(options);
    const cli = Cli.create("sample").command("show", {
      options,
      run() {},
    });
    const markdown = renderFullMarkdownManifest(cli, {
      commands: [{ name: "show" }],
    });
    expect(markdown).toContain("--required-value");
    expect(markdown).toContain("--default-value");
    expect(Schema.toJsonSchema(options)).toEqual(before);
    expect(options.parse({ requiredValue: "value" })).toEqual({
      requiredValue: "value",
      defaultValue: "one",
    });
  });

  test("keeps unsupported result formats rejected", async () => {
    for (const args of [
      ["scan", "--format", "md"],
      ["scan", "--filter-output", "findings"],
      ["validate", "--json"],
      ["patch", "--format", "jsonl"],
      ["login", "--json"],
      ["logout", "--json"],
    ]) {
      const stdout = capture();
      const stderr = capture();
      expect(
        await main(
          args,
          stdout.stream,
          stderr.stream,
          documentationDependencies(),
        ),
      ).toBe(2);
      expect(stdout.text()).toBe("");
      expect(stderr.text()).not.toBe("");
    }
  });
});

import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import {
  AGENTS_AUTH_FILE,
  persistAgentsApiKey,
  removeStoredAgentsApiKey,
  storedAgentsApiKey,
} from "../src/agents-auth.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function credentialHome(): Promise<string> {
  const home = await mkdtemp(join(tmpdir(), "codex-security-agents-auth-"));
  temporaryDirectories.push(home);
  await chmod(home, 0o700);
  return home;
}

describe("Agents SDK stored authentication", () => {
  test("persists and removes a private API key", async () => {
    const home = await credentialHome();

    await persistAgentsApiKey(home, "synthetic-api-key");

    expect(await storedAgentsApiKey(home)).toBe("synthetic-api-key");
    expect(await readFile(join(home, AGENTS_AUTH_FILE), "utf8")).toBe(
      '{"apiKey":"synthetic-api-key"}\n',
    );
    await removeStoredAgentsApiKey(home);
    expect(await storedAgentsApiKey(home)).toBeNull();
  });

  test.skipIf(process.platform === "win32")(
    "rejects credentials accessible to other users",
    async () => {
      const home = await credentialHome();
      const path = join(home, AGENTS_AUTH_FILE);
      await writeFile(path, '{"apiKey":"synthetic-api-key"}\n', {
        mode: 0o644,
      });
      await chmod(path, 0o644);

      await expect(storedAgentsApiKey(home)).rejects.toThrow(
        "must not be accessible to other users",
      );
    },
  );

  test("treats malformed stored JSON as unavailable", async () => {
    const home = await credentialHome();
    await writeFile(join(home, AGENTS_AUTH_FILE), "{", { mode: 0o600 });

    expect(await storedAgentsApiKey(home)).toBeNull();
  });
});

import { chmod, lstat, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { CodexSecurityError, OutputDirectoryError } from "./errors.js";
import { requirePrivateCredentialFile } from "./runtime.js";

export const AGENTS_AUTH_FILE = "agents-auth.json";

export async function persistAgentsApiKey(
  credentialHome: string,
  apiKey: string,
): Promise<void> {
  if (apiKey.trim().length === 0) {
    throw new CodexSecurityError("The API key must be non-empty.");
  }
  const path = join(credentialHome, AGENTS_AUTH_FILE);
  await writeFile(path, `${JSON.stringify({ apiKey })}\n`, {
    mode: 0o600,
  });
  await chmod(path, 0o600);
}

export async function storedAgentsApiKey(
  credentialHome: string,
): Promise<string | null> {
  const path = join(credentialHome, AGENTS_AUTH_FILE);
  const metadata = await lstat(path).catch((error: unknown) => {
    if (isRecord(error) && error["code"] === "ENOENT") return null;
    throw error;
  });
  if (metadata === null) return null;
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new OutputDirectoryError(
      `Codex Security stored Agents SDK authentication is not a regular file: ${path}`,
    );
  }
  requirePrivateCredentialFile(metadata, path);
  let parsed: unknown;
  try {
    parsed = JSON.parse(await readFile(path, "utf8")) as unknown;
  } catch {
    return null;
  }
  if (!isRecord(parsed) || typeof parsed["apiKey"] !== "string") return null;
  const apiKey = parsed["apiKey"].trim();
  return apiKey === "" ? null : apiKey;
}

export async function removeStoredAgentsApiKey(
  credentialHome: string,
): Promise<void> {
  await rm(join(credentialHome, AGENTS_AUTH_FILE), { force: true });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

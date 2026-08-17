import { constants } from "node:fs";
import { access, realpath, stat } from "node:fs/promises";
import { delimiter, isAbsolute, join, relative, resolve, sep } from "node:path";

export interface TrustedExecutable {
  executable: string;
  environment: Record<string, string | undefined>;
}

export interface InspectedExecutable {
  executable: string | null;
  environment: Record<string, string | undefined>;
}

export function executableBinding(
  environment: Readonly<Record<string, string | undefined>>,
  setting: "CODEX_SECURITY_GIT" | "CODEX_SECURITY_RG",
): { keys: string[]; value: string | undefined } {
  const keys =
    process.platform === "win32"
      ? Object.keys(environment)
          .filter((name) => name.toUpperCase() === setting)
          .sort()
      : [setting];
  return { keys, value: environment[keys[0] ?? setting] };
}

export async function resolveTrustedExecutable(
  candidate: string,
  environment: Readonly<Record<string, string | undefined>>,
  protectedRoot: string,
): Promise<TrustedExecutable | null> {
  const inspected = await inspectTrustedExecutable(
    candidate,
    environment,
    protectedRoot,
  );
  return inspected.executable === null
    ? null
    : { executable: inspected.executable, environment: inspected.environment };
}

export async function inspectTrustedExecutable(
  candidate: string,
  environment: Readonly<Record<string, string | undefined>>,
  protectedRoot: string,
): Promise<InspectedExecutable> {
  const root = await realpath(protectedRoot).catch(() =>
    resolve(protectedRoot),
  );
  const pathKeys =
    process.platform === "win32"
      ? Object.keys(environment)
          .filter((name) => name.toUpperCase() === "PATH")
          .sort()
      : ["PATH"];
  const path = environment[pathKeys[0] ?? "PATH"];
  // Match child_process lookup defaults without broadening an explicit PATH.
  const searchPath =
    path ??
    (process.platform === "win32" ? process.env["PATH"] : "/usr/bin:/bin") ??
    "";
  const entries: string[] = [];
  for (const entry of searchPath.split(delimiter)) {
    if (entry.length === 0) continue;
    const canonical = await realpath(entry).catch(() => null);
    if (canonical === null || isWithin(root, canonical)) continue;
    if (!entries.includes(canonical)) entries.push(canonical);
  }

  // execFile cannot launch batch files, but their symlink targets still affect PATH trust.
  const extensions =
    process.platform === "win32"
      ? /\.(?:exe|com)$/iu.test(candidate)
        ? [{ suffix: "", runnable: true }]
        : [
            { suffix: ".exe", runnable: true },
            { suffix: ".com", runnable: true },
            { suffix: ".bat", runnable: false },
            { suffix: ".cmd", runnable: false },
            { suffix: "", runnable: false },
          ]
      : [{ suffix: "", runnable: true }];
  const pathLike = candidate.includes("/") || candidate.includes("\\");
  const candidates = pathLike
    ? [{ entry: null, path: resolve(candidate), runnable: true }]
    : entries.flatMap((entry) =>
        extensions.map((extension) => ({
          entry,
          path: join(entry, `${candidate}${extension.suffix}`),
          runnable: extension.runnable,
        })),
      );
  const unsafeEntries = new Set<string>();
  let executable: string | null = null;
  for (const current of candidates) {
    const canonical = await realpath(current.path).catch(() => null);
    if (canonical === null) continue;
    if (isWithin(root, canonical)) {
      if (current.entry !== null) unsafeEntries.add(current.entry);
      continue;
    }
    if (process.platform === "win32" && /\.(?:bat|cmd)$/iu.test(canonical)) {
      continue;
    }
    if (!current.runnable) continue;
    try {
      await access(
        canonical,
        process.platform === "win32" ? constants.F_OK : constants.X_OK,
      );
      if (!(await stat(canonical)).isFile()) continue;
      executable ??= pathLike ? canonical : current.path;
    } catch {
      continue;
    }
  }
  const sanitizedEnvironment = { ...environment };
  for (const name of pathKeys) delete sanitizedEnvironment[name];
  sanitizedEnvironment["PATH"] = entries
    .filter((entry) => !unsafeEntries.has(entry))
    .join(delimiter);
  return { executable, environment: sanitizedEnvironment };
}

function isWithin(root: string, candidate: string): boolean {
  const path = relative(root, candidate);
  return (
    path === "" ||
    (path !== ".." && !path.startsWith(`..${sep}`) && !isAbsolute(path))
  );
}

import { constants } from "node:fs";
import { access, realpath, stat } from "node:fs/promises";
import {
  delimiter,
  dirname,
  extname,
  isAbsolute,
  join,
  posix,
  relative,
  resolve,
  sep,
  win32,
} from "node:path";

export interface TrustedExecutable {
  executable: string;
  environment: Record<string, string | undefined>;
}

export interface InspectedExecutable {
  executable: string | null;
  environment: Record<string, string | undefined>;
}

export function isAbsoluteExecutablePath(candidate: string): boolean {
  if (process.platform !== "win32") return posix.isAbsolute(candidate);
  // A Windows root-relative path still depends on the current drive.
  return win32.isAbsolute(candidate) && win32.parse(candidate).root.length > 1;
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
  protectedRoots: string | readonly string[],
): Promise<TrustedExecutable | null> {
  const inspected = await inspectTrustedExecutable(
    candidate,
    environment,
    protectedRoots,
  );
  return inspected.executable === null
    ? null
    : { executable: inspected.executable, environment: inspected.environment };
}

export async function inspectTrustedExecutable(
  candidate: string,
  environment: Readonly<Record<string, string | undefined>>,
  protectedRoots: string | readonly string[],
  { preserveInvocation = false }: { preserveInvocation?: boolean } = {},
): Promise<InspectedExecutable> {
  const roots = await Promise.all(
    (typeof protectedRoots === "string"
      ? [protectedRoots]
      : protectedRoots
    ).map(async (root) => await realpath(root).catch(() => resolve(root))),
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
  for (let entry of searchPath.split(delimiter)) {
    if (
      process.platform === "win32" &&
      entry.startsWith('"') &&
      entry.endsWith('"')
    ) {
      entry = entry.slice(1, -1);
    }
    if (entry.length === 0) continue;
    const canonical = await realpath(entry).catch(() => null);
    if (canonical === null || roots.some((root) => isWithin(root, canonical))) {
      continue;
    }
    if (!entries.includes(canonical)) entries.push(canonical);
  }

  const pathLike = candidate.includes("/") || candidate.includes("\\");
  // execFile cannot launch batch files, but their symlink targets still affect PATH trust.
  // CreateProcess appends .exe to an extensionless explicit path, so inspect the file that
  // will actually run instead of rejecting an otherwise valid Windows configuration.
  const extensions =
    process.platform === "win32"
      ? /\.(?:exe|com)$/iu.test(candidate)
        ? [{ suffix: "", runnable: true }]
        : pathLike
          ? extname(candidate) === ""
            ? [{ suffix: ".exe", runnable: true }]
            : [{ suffix: "", runnable: false }]
          : [
              { suffix: ".exe", runnable: true },
              { suffix: ".com", runnable: true },
              { suffix: ".bat", runnable: false },
              { suffix: ".cmd", runnable: false },
              { suffix: "", runnable: false },
            ]
      : [{ suffix: "", runnable: true }];
  const candidates = pathLike
    ? extensions.map((extension) => ({
        entry: null,
        path: preserveInvocation
          ? `${candidate}${extension.suffix}`
          : resolve(`${candidate}${extension.suffix}`),
        runnable: extension.runnable,
      }))
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
    if (roots.some((root) => isWithin(root, canonical))) {
      if (current.entry !== null) unsafeEntries.add(current.entry);
      continue;
    }
    if (process.platform === "win32" && /\.(?:bat|cmd)$/iu.test(canonical)) {
      continue;
    }
    if (!current.runnable) continue;
    try {
      if (
        preserveInvocation &&
        (!isAbsoluteExecutablePath(candidate) ||
          (await hasProtectedAncestor(roots, current.path, canonical)))
      ) {
        continue;
      }
      await access(
        canonical,
        process.platform === "win32" ? constants.F_OK : constants.X_OK,
      );
      if (!(await stat(canonical)).isFile()) continue;
      executable ??= preserveInvocation
        ? candidate
        : pathLike
          ? canonical
          : current.path;
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

async function hasProtectedAncestor(
  roots: readonly string[],
  ...paths: string[]
): Promise<boolean> {
  // Identities cover case aliases and junctions in the original invocation.
  const protectedIdentities = await Promise.all(
    roots.map((root) => stat(root, { bigint: true })),
  );
  for (const path of paths) {
    // A local Git fetch source can itself be a file.
    for (let directory = path; ; ) {
      const identity = await stat(directory, { bigint: true });
      if (
        protectedIdentities.some(
          (protectedIdentity) =>
            identity.dev === protectedIdentity.dev &&
            identity.ino === protectedIdentity.ino,
        )
      ) {
        return true;
      }
      const parent = dirname(directory);
      if (parent === directory) break;
      directory = parent;
    }
  }
  return false;
}

function isWithin(root: string, candidate: string): boolean {
  const path = relative(root, candidate);
  return (
    path === "" ||
    (path !== ".." && !path.startsWith(`..${sep}`) && !isAbsolute(path))
  );
}

import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import {
  mkdtemp,
  open,
  readFile,
  readdir,
  rename,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test, type TestContext } from "node:test";
import { importSource } from "./import-module.ts";

const uuid = "00000000-0000-4000-8000-000000000001";
const source = path.join(import.meta.dirname, "../src/artifact-io.ts");
const io = await importSource(source, {
  plugins: [
    {
      name: "fixed-staging-token",
      setup(builder) {
        builder.onResolve({ filter: /^node:crypto$/ }, (args) =>
          args.importer === source
            ? { path: "uuid", namespace: "atomic-write-test" }
            : undefined,
        );
        builder.onLoad(
          { filter: /.*/, namespace: "atomic-write-test" },
          () => ({
            contents: `export const randomUUID = () => ${JSON.stringify(uuid)};`,
            loader: "js",
          }),
        );
      },
    },
  ],
});
const deepScanArtifacts = await importSource(
  path.join(import.meta.dirname, "../src/deep-scan/artifacts.ts"),
);

async function fixture(t: TestContext) {
  const root = await fs.realpath(
    await mkdtemp(path.join(tmpdir(), "artifact-atomic-write-")),
  );
  t.after(() => rm(root, { recursive: true, force: true }));
  const destination = await io.artifactDestination(
    { root, repoRoot: root, layout: "worker" },
    ["result.json"],
    "synthetic result",
  );
  return { root, destination, temporary: path.join(root, `.${uuid}.tmp`) };
}

for (const content of ["replacement\n", ""]) {
  test(`atomic replacement preserves ${content ? "nonempty" : "empty"} bytes and permissions`, async (t) => {
    const f = await fixture(t);
    await writeFile(f.destination, "original\n");
    await io.replaceArtifactText(f.destination, content);
    assert.equal(await readFile(f.destination, "utf8"), content);
    assert.deepEqual(await readdir(f.root), ["result.json"]);
    if (process.platform !== "win32") {
      assert.equal((await stat(f.destination)).mode & 0o777, 0o600);
    }
  });
}

test("failed exclusive creation preserves the unowned staging file", async (t) => {
  const f = await fixture(t);
  await writeFile(f.destination, "original\n");
  await writeFile(f.temporary, "another writer\n", { flag: "wx" });
  await assert.rejects(io.replaceArtifactText(f.destination, "replacement\n"), {
    code: "EEXIST",
  });
  assert.equal(await readFile(f.destination, "utf8"), "original\n");
  assert.equal(await readFile(f.temporary, "utf8"), "another writer\n");
});

test("Deep Scan JSON writes create parent directories and preserve JSON bytes", async (t) => {
  const root = await fs.realpath(
    await mkdtemp(path.join(tmpdir(), "deep-scan-json-write-")),
  );
  t.after(() => rm(root, { recursive: true, force: true }));
  const destination = path.join(root, "nested", "heartbeat.json");

  await deepScanArtifacts.writeJsonAtomic(destination, { beat: 2 });

  assert.equal(await readFile(destination, "utf8"), '{\n  "beat": 2\n}\n');
  assert.deepEqual(await readdir(path.dirname(destination)), [
    "heartbeat.json",
  ]);
  if (process.platform !== "win32") {
    assert.equal((await stat(destination)).mode & 0o777, 0o600);
  }
});

test("Deep Scan JSON writes clean up their staging file when rename fails", async (t) => {
  const root = await fs.realpath(
    await mkdtemp(path.join(tmpdir(), "deep-scan-json-write-")),
  );
  t.after(() => rm(root, { recursive: true, force: true }));
  const destination = path.join(root, "heartbeat.json");
  const original = '{"beat":1}\n';
  await writeFile(destination, original);
  const failure = Object.assign(new Error("synthetic rename failure"), {
    code: "EIO",
  });
  let attempts = 0;
  t.mock.method(fs, "rename", async () => {
    attempts++;
    throw failure;
  });

  await assert.rejects(
    deepScanArtifacts.writeJsonAtomic(destination, { beat: 2 }),
    (error: unknown) => error === failure,
  );
  assert.equal(attempts, 1);
  assert.equal(await readFile(destination, "utf8"), original);
  assert.deepEqual(await readdir(root), ["heartbeat.json"]);
});

test(
  "Deep Scan JSON writes retry transient Windows rename conflicts",
  { skip: process.platform !== "win32" },
  async (t) => {
    const root = await fs.realpath(
      await mkdtemp(path.join(tmpdir(), "deep-scan-json-retry-")),
    );
    t.after(() => rm(root, { recursive: true, force: true }));
    const destination = path.join(root, "heartbeat.json");
    const original = '{"beat":1}\n';
    await writeFile(destination, original);
    const rename = fs.rename;
    const failure = Object.assign(new Error("synthetic reader conflict"), {
      code: "EBUSY",
    });
    const stagingPaths: string[] = [];
    t.mock.method(fs, "rename", async (source: string, target: string) => {
      assert.equal(target, destination);
      stagingPaths.push(source);
      if (stagingPaths.length === 1) {
        assert.equal(await readFile(destination, "utf8"), original);
        throw failure;
      }
      await rename(source, target);
    });

    await deepScanArtifacts.writeJsonAtomic(destination, { beat: 2 });
    assert.equal(stagingPaths.length, 2);
    assert.equal(stagingPaths[0], stagingPaths[1]);
    assert.equal(await readFile(destination, "utf8"), '{\n  "beat": 2\n}\n');
    assert.deepEqual(await readdir(root), ["heartbeat.json"]);
  },
);

test("successful rename leaves a subsequent writer's staging file intact", async (t) => {
  const f = await fixture(t);
  t.mock.method(
    fs,
    "rename",
    async (...[from, to]: Parameters<typeof fs.rename>) => {
      assert.equal(from, f.temporary);
      assert.equal(to, f.destination);
      await rename(from, to);
      await writeFile(from, "next writer\n", { flag: "wx" });
    },
  );
  await io.replaceArtifactText(f.destination, "replacement\n");
  assert.equal(await readFile(f.destination, "utf8"), "replacement\n");
  assert.equal(await readFile(f.temporary, "utf8"), "next writer\n");
});

for (const failure of [
  "write",
  "close",
  "write-close",
  "rename",
  "write-close-cleanup",
]) {
  test(`atomic replacement cleans owned staging and preserves ${failure} errors`, async (t) => {
    const f = await fixture(t);
    await writeFile(f.destination, "original\n");
    const events: string[] = [];
    const writeError = failure.includes("write")
      ? Object.assign(new Error("synthetic write failure"), { code: "EIO" })
      : undefined;
    const closeError = failure.includes("close")
      ? new Error("synthetic close failure")
      : undefined;
    const renameError = failure.includes("rename")
      ? new Error("synthetic rename failure")
      : undefined;
    const cleanupError = failure.includes("cleanup")
      ? new Error("synthetic cleanup failure")
      : undefined;

    t.mock.method(fs, "open", async (...args: Parameters<typeof fs.open>) => {
      assert.deepEqual(args, [f.temporary, "wx", 0o600]);
      const handle = await open(args[0], args[1], args[2]);
      const write = handle.writeFile.bind(handle);
      const close = handle.close.bind(handle);
      t.mock.method(
        handle,
        "writeFile",
        async (content: string, encoding: BufferEncoding) => {
          events.push("write");
          await write(writeError ? content.slice(0, 3) : content, encoding);
          if (writeError) throw writeError;
        },
      );
      t.mock.method(handle, "close", async () => {
        events.push("close");
        await close();
        if (closeError) throw closeError;
      });
      return handle;
    });
    t.mock.method(
      fs,
      "rename",
      async (...args: Parameters<typeof fs.rename>) => {
        assert.deepEqual(args, [f.temporary, f.destination]);
        events.push("rename");
        if (renameError) throw renameError;
        await rename(args[0], args[1]);
      },
    );
    t.mock.method(fs, "rm", async (...args: Parameters<typeof fs.rm>) => {
      assert.deepEqual(args, [f.temporary, { force: true }]);
      events.push("remove");
      if (cleanupError) throw cleanupError;
      await rm(args[0], args[1]);
    });

    await assert.rejects(
      io.replaceArtifactText(f.destination, "replacement\n"),
      (error: unknown) => {
        if (cleanupError) assert.equal(error, cleanupError);
        else if (writeError && closeError) {
          assert.ok(error instanceof AggregateError);
          assert.deepEqual(error.errors, [writeError, closeError]);
          assert.equal(error.message, writeError.message);
          assert.equal((error as NodeJS.ErrnoException).code, writeError.code);
        } else assert.equal(error, writeError ?? closeError ?? renameError);
        return true;
      },
    );
    assert.deepEqual(events, [
      "write",
      "close",
      ...(renameError ? ["rename"] : []),
      "remove",
    ]);
    assert.equal(await readFile(f.destination, "utf8"), "original\n");
    if (cleanupError) assert.equal(await readFile(f.temporary, "utf8"), "rep");
    else assert.deepEqual(await readdir(f.root), ["result.json"]);
  });
}

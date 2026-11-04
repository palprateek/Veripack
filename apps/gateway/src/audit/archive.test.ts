import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as tar from "tar";
import { afterEach, describe, expect, it } from "vitest";
import { readArchive } from "./archive.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) =>
      rm(directory, { recursive: true, force: true }),
    ),
  );
});

async function buildArchive(): Promise<Buffer> {
  const directory = await mkdtemp(join(tmpdir(), "veripack-archive-test-"));
  temporaryDirectories.push(directory);
  await mkdir(join(directory, "package", "a", "b"), { recursive: true });
  await writeFile(
    join(directory, "package", "package.json"),
    JSON.stringify({ name: "example", version: "1.0.0" }),
  );
  const chunks: Buffer[] = [];
  const stream = tar.c(
    { cwd: directory, gzip: true, portable: true },
    ["package"],
  );
  stream.on("data", (chunk: Buffer) => chunks.push(chunk));
  await new Promise<void>((resolve, reject) => {
    stream.on("end", resolve);
    stream.on("error", reject);
  });
  return Buffer.concat(chunks);
}

describe("archive safety limits", () => {
  it("counts directory entries toward the archive entry limit", async () => {
    await expect(readArchive(await buildArchive(), { maxEntries: 2 })).rejects.toMatchObject({
      code: "limit_exceeded",
    });
  });
});

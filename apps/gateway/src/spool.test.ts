import { createHash } from "node:crypto";
import { access, mkdtemp, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { SpoolError, spoolResponseBody } from "./spool.js";

function responseOf(body: string, contentLength?: number): Response {
  return new Response(body, {
    headers: contentLength
      ? { "content-length": String(contentLength) }
      : undefined,
  });
}

describe("upstream spool", () => {
  it("streams to disk with a digest and cleans up", async () => {
    const directory = await mkdtemp(join(tmpdir(), "veripack-spool-test-"));
    const body = "bounded tarball bytes";
    const spool = await spoolResponseBody(responseOf(body), {
      directory,
      maxBytes: 1_024,
    });

    expect(spool.size).toBe(body.length);
    expect(spool.digest).toBe(
      createHash("sha256").update(body).digest("hex"),
    );
    await expect(access(spool.path)).resolves.toBeUndefined();

    await spool.cleanup();
    await expect(access(spool.path)).rejects.toThrow();
    expect(await readdir(directory)).toEqual([]);
  });

  it("rejects declared and streamed oversize bodies without leaving a file", async () => {
    const directory = await mkdtemp(join(tmpdir(), "veripack-spool-test-"));

    await expect(
      spoolResponseBody(responseOf("x", 2_048), {
        directory,
        maxBytes: 1_024,
      }),
    ).rejects.toBeInstanceOf(SpoolError);

    await expect(
      spoolResponseBody(responseOf("x".repeat(2_048)), {
        directory,
        maxBytes: 1_024,
      }),
    ).rejects.toMatchObject({ code: "too_large" });
    expect(await readdir(directory)).toEqual([]);
  });
});

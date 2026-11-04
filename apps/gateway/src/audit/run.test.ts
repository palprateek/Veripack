import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as tar from "tar";
import { afterEach, describe, expect, it } from "vitest";
import type { NpmVersionManifest } from "../npm/payload.js";
import type { SandboxResult } from "../sandbox.js";
import { DEFAULT_AUDIT_POLICY } from "./policy.js";
import { runAudit, type AuditRunInput } from "./run.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

async function buildTarball(
  files: Record<string, string | Buffer>,
): Promise<Buffer> {
  const directory = await mkdtemp(join(tmpdir(), "veripack-run-"));
  temporaryDirectories.push(directory);
  await mkdir(join(directory, "package"), { recursive: true });

  for (const [path, content] of Object.entries(files)) {
    const target = join(directory, "package", path);
    await mkdir(join(target, ".."), { recursive: true });
    await writeFile(target, content);
  }

  const chunks: Buffer[] = [];
  const stream = tar.c(
    { gzip: true, cwd: directory, portable: true },
    ["package"],
  );
  stream.on("data", (chunk: Buffer) => chunks.push(chunk));
  await new Promise<void>((resolve, reject) => {
    stream.on("end", resolve);
    stream.on("error", reject);
  });
  return Buffer.concat(chunks);
}

const manifest: NpmVersionManifest = {
  name: "@veripack/example",
  version: "1.0.0",
  trust: { intent: "Add a small helper." },
};

const sandboxResult: SandboxResult = {
  enabled: true,
  runtime: "runsc",
  image: "node:22",
  exitCode: 0,
  signal: null,
  timedOut: false,
  stdout: "ok",
  stderr: "",
  durationMs: 12,
};

async function baseInput(
  overrides: Partial<AuditRunInput> = {},
): Promise<AuditRunInput> {
  const tarball =
    overrides.tarball ??
    (await buildTarball({
      "package.json": JSON.stringify(manifest),
      "index.js": "export const value = 1;\n",
    }));

  return {
    packageName: "@veripack/example",
    version: "1.0.0",
    publisher: "alice",
    manifest,
    intent: "Add a small helper.",
    tarball,
    tarballDigest: "a".repeat(64),
    previous: null,
    firstRelease: false,
    policy: DEFAULT_AUDIT_POLICY,
    scopeKey: "private:org",
    engineVersion: "test",
    cache: null,
    sandbox: null,
    llm: null,
    ...overrides,
  };
}

describe("runAudit", () => {
  it("records sandbox evidence and keeps the sandbox result on the change set", async () => {
    const { result, sandbox } = await runAudit(
      await baseInput({ sandbox: async () => sandboxResult }),
    );

    expect(sandbox).toEqual(sandboxResult);
    expect(
      result.signals.find((signal) => signal.type === "sandbox_execution")
        ?.severity,
    ).toBe("info");
    expect(result.changeSet.sandbox).toEqual(sandboxResult);
  });

  it("degrades to a medium signal when the sandbox cannot start", async () => {
    const { result, sandbox } = await runAudit(
      await baseInput({
        sandbox: async () => {
          throw new Error("no runtime");
        },
      }),
    );

    expect(sandbox).toBeNull();
    expect(
      result.signals.find((signal) => signal.type === "sandbox_unavailable"),
    ).toMatchObject({ severity: "medium" });
    expect(result.changeSet.sandbox).toEqual({
      enabled: true,
      error: "no runtime",
    });
  });

  it("keeps deterministic evidence when the LLM reviewer fails", async () => {
    const { result, llmReview } = await runAudit(
      await baseInput({
        llm: {
          id: "fake",
          review: async () => {
            throw new Error("timeout");
          },
        },
      }),
    );

    expect(llmReview).toBeNull();
    expect(
      result.signals.find((signal) => signal.type === "llm_unavailable"),
    ).toMatchObject({ source: "llm" });
    expect(result.policyResult).not.toBe("pass");
  });

  it("reuses and stores artifact analysis through the cache port", async () => {
    let stored: unknown = null;
    const cache = {
      get: async () => null,
      put: async (_key: unknown, artifact: unknown) => {
        stored = artifact;
      },
    };

    const { result } = await runAudit(
      await baseInput({ cache: cache as AuditRunInput["cache"] }),
    );

    expect(stored).not.toBeNull();
    expect(result.signals.length).toBeGreaterThan(0);
  });

  it("does not run the sandbox or LLM after a deterministic block", async () => {
    let sandboxCalls = 0;
    let llmCalls = 0;
    const { result } = await runAudit(
      await baseInput({
        tarball: Buffer.from("not a tarball"),
        sandbox: async () => {
          sandboxCalls += 1;
          return sandboxResult;
        },
        llm: {
          id: "fake",
          review: async () => {
            llmCalls += 1;
            return null;
          },
        },
      }),
    );

    expect(result.policyResult).toBe("block");
    expect(sandboxCalls).toBe(0);
    expect(llmCalls).toBe(0);
  });
});

import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  buildInventoryManifest,
  verifyInventoryManifest,
} from "./backup.js";
import {
  checkBunLockfile,
  checkNpmLockfile,
  checkPnpmLockfile,
  detectLockfileKind,
} from "./bypass-check.js";

function fakeStore(objects: Map<string, Buffer>) {
  return {
    getBuffer: async (key: string) => {
      const value = objects.get(key);
      if (!value) throw new Error("NoSuchKey");
      return value;
    },
  };
}

describe("backup inventory manifest", () => {
  it("covers every referenced object with size and digest", async () => {
    const tarball = Buffer.from("tarball-bytes");
    const payload = Buffer.from("{}");
    const store = fakeStore(
      new Map([
        ["tarballs/a.tgz", tarball],
        ["payloads/a.json", payload],
      ]),
    );
    const db = {
      query: async () => ({
        rows: [{ tarball_key: "tarballs/a.tgz", payload_key: "payloads/a.json" }],
      }),
    } as never;

    const manifest = await buildInventoryManifest(db, store, null);
    expect(manifest.objects).toEqual([
      {
        key: "payloads/a.json",
        size: payload.length,
        sha256: createHash("sha256").update(payload).digest("hex"),
      },
      {
        key: "tarballs/a.tgz",
        size: tarball.length,
        sha256: createHash("sha256").update(tarball).digest("hex"),
      },
    ]);
    await expect(verifyInventoryManifest(store, manifest)).resolves.toEqual({
      verified: 2,
    });
  });

  it("fails verification on a digest mismatch or missing object", async () => {
    const store = fakeStore(new Map([["k", Buffer.from("actual")]]));
    const manifest = {
      createdAt: new Date().toISOString(),
      dump: null,
      objects: [{ key: "k", size: 6, sha256: "0".repeat(64) }],
    };
    await expect(verifyInventoryManifest(store, manifest)).rejects.toThrow(
      /digest mismatch/,
    );
    await expect(
      verifyInventoryManifest(store, {
        ...manifest,
        objects: [{ key: "missing", size: 1, sha256: "x" }],
      }),
    ).rejects.toThrow(/missing/);
  });
});

describe("bypass check", () => {
  const gateway = "https://registry.example.com";

  it("detects lockfile kinds", () => {
    expect(detectLockfileKind("package-lock.json")).toBe("npm");
    expect(detectLockfileKind("pnpm-lock.yaml")).toBe("pnpm");
    expect(detectLockfileKind("bun.lock")).toBe("bun");
    expect(detectLockfileKind("yarn.lock")).toBeNull();
  });

  it("flags npm resolutions outside the gateway", () => {
    const lock = JSON.stringify({
      packages: {
        "node_modules/left-pad": {
          resolved: "https://registry.npmjs.org/left-pad/-/left-pad-1.0.0.tgz",
        },
        "node_modules/@acme/widget": {
          resolved:
            "https://registry.example.com/@acme/widget/-/widget-1.0.0.tgz",
        },
      },
    });
    const findings = checkNpmLockfile(lock, "registry.example.com");
    expect(findings).toHaveLength(1);
    expect(findings[0]?.packageName).toContain("left-pad");
    void gateway;
  });

  it("flags pnpm tarball resolutions outside the gateway", () => {
    const lock = [
      "  /left-pad@1.0.0:",
      "    resolution:",
      "      tarball: https://registry.npmjs.org/left-pad/-/left-pad-1.0.0.tgz",
    ].join("\n");
    expect(checkPnpmLockfile(lock, "registry.example.com")).toHaveLength(1);
  });

  it("flags bun resolutions outside the gateway", () => {
    const lock = JSON.stringify({
      packages: {
        "left-pad": [
          "left-pad@1.0.0",
          "https://registry.npmjs.org/left-pad/-/left-pad-1.0.0.tgz",
        ],
      },
    });
    expect(checkBunLockfile(lock, "registry.example.com")).toHaveLength(1);
  });
});

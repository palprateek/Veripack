import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { parsePublishPayload, PayloadError } from "./payload.js";

const TARBALL = Buffer.from("pretend this is a gzipped tarball");

function integrityFor(buffer: Buffer): string {
  return `sha512-${createHash("sha512").update(buffer).digest("base64")}`;
}

function shasumFor(buffer: Buffer): string {
  return createHash("sha1").update(buffer).digest("hex");
}

function payload(overrides: {
  version?: string;
  manifest?: Record<string, unknown>;
  attachmentData?: string;
  attachmentLength?: number;
} = {}) {
  const version = overrides.version ?? "1.0.0";
  const manifest = {
    name: "@veripack/safe-package",
    version,
    scripts: {},
    trust: { intent: "Add a greeting helper." },
    dist: {
      integrity: integrityFor(TARBALL),
      shasum: shasumFor(TARBALL),
      tarball:
        "http://localhost:4874/@veripack/safe-package/-/safe-package-1.0.0.tgz",
    },
    ...overrides.manifest,
  };

  return {
    _id: "@veripack/safe-package",
    name: "@veripack/safe-package",
    "dist-tags": { latest: version },
    versions: { [version]: manifest },
    _attachments: {
      "@veripack/safe-package-1.0.0.tgz": {
        content_type: "application/octet-stream",
        data: overrides.attachmentData ?? TARBALL.toString("base64"),
        length: overrides.attachmentLength ?? TARBALL.length,
      },
    },
  };
}

describe("parsePublishPayload", () => {
  it("parses a valid npm publish payload", () => {
    const parsed = parsePublishPayload(payload());

    expect(parsed.packageName).toBe("@veripack/safe-package");
    expect(parsed.version).toBe("1.0.0");
    expect(parsed.intent).toBe("Add a greeting helper.");
    expect(parsed.attachmentName).toBe("safe-package-1.0.0.tgz");
    expect(parsed.tarball.equals(TARBALL)).toBe(true);
    expect(parsed.integrity).toBe(integrityFor(TARBALL));
    expect(parsed.shasum).toBe(shasumFor(TARBALL));
    expect(parsed.tarballDigest).toHaveLength(64);
  });

  it("rejects an integrity mismatch", () => {
    const body = payload();
    body.versions["1.0.0"]!.dist!.integrity = "sha512-not-the-real-integrity";

    expect(() => parsePublishPayload(body)).toThrow(PayloadError);
  });

  it("rejects a shasum mismatch", () => {
    const body = payload();
    body.versions["1.0.0"]!.dist!.shasum = "not-the-real-shasum";

    expect(() => parsePublishPayload(body)).toThrow(/shasum/i);
  });

  it("rejects a multi-version publish", () => {
    const body = payload();
    body.versions["1.0.1"] = { ...body.versions["1.0.0"]!, version: "1.0.1" };

    expect(() => parsePublishPayload(body)).toThrow(/exactly one version/i);
  });

  it("rejects an attachment length mismatch", () => {
    const body = payload({ attachmentLength: TARBALL.length + 1 });

    expect(() => parsePublishPayload(body)).toThrow(/length mismatch/i);
  });

  it("returns a null intent when none is declared", () => {
    const body = payload({
      manifest: { trust: undefined, trustIntent: undefined },
    });

    expect(parsePublishPayload(body).intent).toBeNull();
  });

  it("rejects silently-decoded invalid base64", () => {
    const body = payload({ attachmentData: "not-base64!" });

    expect(() => parsePublishPayload(body)).toThrow(/valid base64/i);
  });

  it("does not let a publish mutate an unrelated dist-tag", () => {
    const body = payload();
    body["dist-tags"]!.latest = "0.0.1";

    expect(() => parsePublishPayload(body)).toThrow(/dist-tags/i);
  });
});

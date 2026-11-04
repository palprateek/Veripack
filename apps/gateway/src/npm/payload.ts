import { createHash } from "node:crypto";

export class PayloadError extends Error {
  readonly statusCode = 400;

  constructor(message: string) {
    super(message);
    this.name = "PayloadError";
  }
}

export interface NpmAttachment {
  content_type?: string;
  data?: string;
  length?: number;
}

export interface NpmVersionManifest {
  name?: string;
  version?: string;
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  dist?: {
    integrity?: string;
    shasum?: string;
    tarball?: string;
  };
  trust?: {
    intent?: string;
  };
  trustIntent?: string;
  _npmUser?: {
    name?: string;
  };
  [key: string]: unknown;
}

export interface NpmPublishPayload {
  _id?: string;
  name?: string;
  "dist-tags"?: Record<string, string>;
  versions?: Record<string, NpmVersionManifest>;
  _attachments?: Record<string, NpmAttachment>;
  [key: string]: unknown;
}

export interface ParsedPublish {
  packageName: string;
  version: string;
  manifest: NpmVersionManifest;
  payload: NpmPublishPayload;
  attachmentName: string;
  tarball: Buffer;
  tarballDigest: string;
  integrity: string;
  shasum: string;
  intent: string | null;
  npmUser: string | null;
}

const MAX_MANIFEST_MAP_ENTRIES = 2_000;
const MAX_MANIFEST_STRING_BYTES = 64 * 1024;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function sha512Integrity(buffer: Buffer): string {
  return `sha512-${createHash("sha512").update(buffer).digest("base64")}`;
}

function sha1Shasum(buffer: Buffer): string {
  return createHash("sha1").update(buffer).digest("hex");
}

function readIntent(manifest: NpmVersionManifest): string | null {
  const fromTrust = isRecord(manifest.trust) ? manifest.trust.intent : undefined;
  const value =
    typeof fromTrust === "string"
      ? fromTrust
      : typeof manifest.trustIntent === "string"
        ? manifest.trustIntent
        : null;

  if (!value) return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  return trimmed.slice(0, 4_000);
}

function validateStringMap(
  value: unknown,
  field: string,
): string | null {
  if (value === undefined) return null;
  if (!isRecord(value)) return `${field} must be an object.`;
  const entries = Object.entries(value);
  if (entries.length > MAX_MANIFEST_MAP_ENTRIES) {
    return `${field} has too many entries.`;
  }
  for (const [name, range] of entries) {
    if (name.length > 256 || typeof range !== "string" || range.length > MAX_MANIFEST_STRING_BYTES) {
      return `${field} contains an invalid or oversized entry.`;
    }
  }
  return null;
}

export function validatePublishManifest(manifest: Record<string, unknown>): string | null {
  for (const field of [
    "scripts",
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
  ]) {
    const error = validateStringMap(manifest[field], field);
    if (error) return error;
  }
  if (
    typeof manifest.name !== "string" ||
    manifest.name.length > 214 ||
    typeof manifest.version !== "string" ||
    manifest.version.length > 128
  ) {
    return "Manifest name or version is invalid or oversized.";
  }
  if (JSON.stringify(manifest).length > 512 * 1024) {
    return "Version manifest is too large.";
  }
  return null;
}

export function parsePublishPayload(body: unknown): ParsedPublish {
  if (!isRecord(body)) {
    throw new PayloadError("Publish body must be a JSON object.");
  }

  const payload = body as NpmPublishPayload;

  if (typeof payload.name !== "string" || !payload.name) {
    throw new PayloadError("Publish body is missing the package name.");
  }
  if (payload._id !== undefined && payload._id !== payload.name) {
    throw new PayloadError("Publish body _id does not match the package name.");
  }

  if (!isRecord(payload.versions)) {
    throw new PayloadError("Publish body is missing versions.");
  }

  const versionEntries = Object.entries(payload.versions);
  if (versionEntries.length !== 1) {
    throw new PayloadError(
      `A publish must contain exactly one version (received ${versionEntries.length}).`,
    );
  }

  const [version, manifest] = versionEntries[0]!;
  if (!isRecord(manifest)) {
    throw new PayloadError("The published version manifest must be an object.");
  }
  if (manifest.name !== payload.name) {
    throw new PayloadError("Version manifest name does not match the package name.");
  }
  if (manifest.version !== version) {
    throw new PayloadError("Version manifest version does not match its key.");
  }
  const manifestError = validatePublishManifest(manifest);
  if (manifestError) throw new PayloadError(manifestError);

  if (!isRecord(payload._attachments)) {
    throw new PayloadError("Publish body is missing the tarball attachment.");
  }

  const attachments = Object.entries(payload._attachments).filter(([name]) =>
    name.toLowerCase().endsWith(".tgz"),
  );
  if (attachments.length !== 1) {
    throw new PayloadError(
      `A publish must contain exactly one .tgz attachment (received ${attachments.length}).`,
    );
  }

  const [attachmentKey, attachment] = attachments[0]!;

  // npm keys the attachment by "<package-name>-<version>.tgz", which contains
  // the scope slash for scoped packages. The file name on the wire is the
  // basename, so store that and keep the key only as a structural check.
  const keyParts = attachmentKey.split("/");
  if (
    keyParts.length > 2 ||
    keyParts.some((part) => !part || part === "." || part === "..") ||
    attachmentKey.includes("\\")
  ) {
    throw new PayloadError("Invalid tarball attachment name.");
  }
  if (
    keyParts.length === 2 &&
    (!keyParts[0]!.startsWith("@") || keyParts[0]!.length < 2)
  ) {
    throw new PayloadError("Invalid tarball attachment name.");
  }

  const attachmentName = keyParts[keyParts.length - 1]!;
  if (!attachmentName.toLowerCase().endsWith(".tgz")) {
    throw new PayloadError("Invalid tarball attachment name.");
  }
  const packageBaseName = payload.name.startsWith("@")
    ? payload.name.slice(payload.name.indexOf("/") + 1)
    : payload.name;
  if (attachmentName !== `${packageBaseName}-${version}.tgz`) {
    throw new PayloadError(
      "The tarball attachment name must match the package and published version.",
    );
  }

  if (!isRecord(attachment) || typeof attachment.data !== "string") {
    throw new PayloadError("The tarball attachment is missing base64 data.");
  }

  const encodedTarball = attachment.data.replace(/\s+/g, "");
  if (
    encodedTarball.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
      encodedTarball,
    )
  ) {
    throw new PayloadError("The tarball attachment is not valid base64.");
  }
  const tarball = Buffer.from(encodedTarball, "base64");
  if (tarball.length === 0) {
    throw new PayloadError("The tarball attachment is empty or is not valid base64.");
  }
  if (
    typeof attachment.length === "number" &&
    attachment.length !== tarball.length
  ) {
    throw new PayloadError(
      `Tarball length mismatch: attachment says ${attachment.length}, decoded ${tarball.length}.`,
    );
  }

  const integrity = sha512Integrity(tarball);
  const shasum = sha1Shasum(tarball);
  const declaredIntegrity = manifest.dist?.integrity;
  const declaredShasum = manifest.dist?.shasum;

  if (declaredIntegrity && declaredIntegrity !== integrity) {
    throw new PayloadError(
      "Tarball integrity does not match the integrity declared in the manifest.",
    );
  }
  if (declaredShasum && declaredShasum !== shasum) {
    throw new PayloadError(
      "Tarball shasum does not match the shasum declared in the manifest.",
    );
  }

  const tarballDigest = createHash("sha256").update(tarball).digest("hex");

  const distTags: Record<string, string> = {};
  if (isRecord(payload["dist-tags"])) {
    for (const [tag, tagVersion] of Object.entries(payload["dist-tags"])) {
      if (typeof tagVersion !== "string" || tagVersion !== version) {
        throw new PayloadError(
          "Publish dist-tags must point only to the version being published.",
        );
      }
      if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(tag) || tag.length > 128) {
        throw new PayloadError("Publish contains an invalid dist-tag name.");
      }
      distTags[tag] = tagVersion;
    }
  }

  const npmUser =
    typeof manifest._npmUser?.name === "string" ? manifest._npmUser.name : null;

  return {
    packageName: payload.name,
    version,
    manifest,
    payload: { ...payload, "dist-tags": distTags },
    attachmentName,
    tarball,
    tarballDigest,
    integrity,
    shasum,
    intent: readIntent(manifest),
    npmUser,
  };
}

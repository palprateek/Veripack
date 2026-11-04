import { createHash } from "node:crypto";
import type { Queryable } from "../db.js";

export interface InventoryObject {
  key: string;
  size: number;
  sha256: string;
}

export interface InventoryManifest {
  createdAt: string;
  dump: { key: string; sha256: string; bytes: number } | null;
  objects: InventoryObject[];
}

export interface ObjectStore {
  getBuffer(key: string): Promise<Buffer>;
}

/**
 * Builds the backup inventory: every object the database references, with
 * size and SHA-256, so a restore can verify content rather than row counts.
 */
export async function buildInventoryManifest(
  db: Queryable,
  store: ObjectStore,
  dump: InventoryManifest["dump"],
): Promise<InventoryManifest> {
  const result = await db.query<{ tarball_key: string; payload_key: string }>(
    "select tarball_key, payload_key from releases order by created_at asc",
  );
  const keys = new Set<string>();
  for (const row of result.rows) {
    keys.add(row.tarball_key);
    keys.add(row.payload_key);
  }

  const objects: InventoryObject[] = [];
  for (const key of [...keys].sort()) {
    const buffer = await store.getBuffer(key);
    objects.push({
      key,
      size: buffer.length,
      sha256: createHash("sha256").update(buffer).digest("hex"),
    });
  }
  return { createdAt: new Date().toISOString(), dump, objects };
}

/** Verifies every manifest object exists with the recorded size and digest. */
export async function verifyInventoryManifest(
  store: ObjectStore,
  manifest: InventoryManifest,
): Promise<{ verified: number }> {
  for (const object of manifest.objects) {
    let buffer: Buffer;
    try {
      buffer = await store.getBuffer(object.key);
    } catch {
      throw new Error(`Backup object ${object.key} is missing.`);
    }
    if (buffer.length !== object.size) {
      throw new Error(
        `Backup object ${object.key} size mismatch: manifest ${object.size}, actual ${buffer.length}.`,
      );
    }
    const digest = createHash("sha256").update(buffer).digest("hex");
    if (digest !== object.sha256) {
      throw new Error(`Backup object ${object.key} digest mismatch.`);
    }
  }
  return { verified: manifest.objects.length };
}

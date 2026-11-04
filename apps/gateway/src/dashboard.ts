import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import type { Db, Queryable } from "./db.js";

/**
 * Server-side dashboard sessions. The browser holds an opaque id in a
 * `__Host-` cookie; the database stores its hash, the encrypted gateway
 * access token, and a hashed CSRF secret.
 */

export const SESSION_IDLE_MS = 30 * 60 * 1_000;
export const SESSION_ABSOLUTE_MS = 12 * 60 * 60 * 1_000;
export const STEP_UP_MS = 15 * 60 * 1_000;
export const LOGIN_FAILURE_LIMIT = 10;
export const LOGIN_FAILURE_WINDOW_MS = 15 * 60 * 1_000;

function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function encryptionKey(secret: string): Buffer {
  return createHash("sha256").update(secret).digest();
}

export function encryptValue(secret: string, plaintext: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey(secret), iv);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  return [
    iv.toString("base64url"),
    cipher.getAuthTag().toString("base64url"),
    encrypted.toString("base64url"),
  ].join(".");
}

export function decryptValue(secret: string, stored: string): string {
  const [iv, tag, encrypted] = stored.split(".");
  if (!iv || !tag || !encrypted) throw new Error("Invalid encrypted value.");
  const decipher = createDecipheriv(
    "aes-256-gcm",
    encryptionKey(secret),
    Buffer.from(iv, "base64url"),
  );
  decipher.setAuthTag(Buffer.from(tag, "base64url"));
  return Buffer.concat([
    decipher.update(Buffer.from(encrypted, "base64url")),
    decipher.final(),
  ]).toString("utf8");
}

export async function recordAuthEvent(
  db: Queryable,
  input: {
    subject: string;
    actor?: string;
    action: string;
    success?: boolean;
    metadata?: Record<string, unknown>;
  },
): Promise<void> {
  await db.query(
    `insert into auth_events (subject, actor, action, success, metadata)
     values ($1, $2, $3, $4, $5)`,
    [
      input.subject,
      input.actor ?? input.subject,
      input.action,
      input.success ?? true,
      JSON.stringify(input.metadata ?? {}),
    ],
  );
}

/** True when recent login failures for the subject hit the rate limit. */
export async function isLoginRateLimited(
  db: Queryable,
  subject: string,
  now: Date = new Date(),
): Promise<boolean> {
  const result = await db.query<{ count: string }>(
    `select count(*)::text as count
       from auth_events
      where subject = $1
        and action = 'login'
        and success = false
        and created_at > $2::timestamptz`,
    [subject, new Date(now.getTime() - LOGIN_FAILURE_WINDOW_MS)],
  );
  return Number(result.rows[0]?.count ?? "0") >= LOGIN_FAILURE_LIMIT;
}

export interface DashboardSessionRow {
  id_hash: string;
  subject: string;
  display_name: string | null;
  role: string;
  encrypted_access_token: string;
  csrf_secret_hash: string;
  mfa_level: "none" | "totp";
  step_up_deadline: Date | null;
  created_at: Date;
  last_seen_at: Date;
  idle_expires_at: Date;
  absolute_expires_at: Date;
  revoked_at: Date | null;
  revocation_reason: string | null;
}

export interface CreatedSession {
  sessionId: string;
  csrfToken: string;
  idleExpiresAt: Date;
  absoluteExpiresAt: Date;
}

export async function createDashboardSession(
  db: Db,
  secret: string,
  input: {
    subject: string;
    displayName?: string | null;
    role: string;
    accessToken: string;
    mfaLevel: "none" | "totp";
    now?: Date;
  },
): Promise<CreatedSession> {
  const now = input.now ?? new Date();
  const sessionId = randomBytes(32).toString("base64url");
  const csrfToken = randomBytes(32).toString("base64url");
  const idleExpiresAt = new Date(now.getTime() + SESSION_IDLE_MS);
  const absoluteExpiresAt = new Date(now.getTime() + SESSION_ABSOLUTE_MS);

  await db.query(
    `insert into dashboard_sessions (
       id_hash, subject, display_name, role, encrypted_access_token,
       csrf_secret_hash, mfa_level, created_at, last_seen_at,
       idle_expires_at, absolute_expires_at
     ) values ($1, $2, $3, $4, $5, $6, $7, $8, $8, $9, $10)`,
    [
      sha256Hex(sessionId),
      input.subject,
      input.displayName ?? null,
      input.role,
      encryptValue(secret, input.accessToken),
      sha256Hex(csrfToken),
      input.mfaLevel,
      now,
      idleExpiresAt,
      absoluteExpiresAt,
    ],
  );
  await recordAuthEvent(db, {
    subject: input.subject,
    action: "login",
    metadata: { role: input.role, mfaLevel: input.mfaLevel },
  });
  return { sessionId, csrfToken, idleExpiresAt, absoluteExpiresAt };
}

export type SessionLookup =
  | { valid: true; session: DashboardSessionRow; accessToken: string }
  | { valid: false; reason: "missing" | "revoked" | "expired" };

export async function getDashboardSession(
  db: Db,
  secret: string,
  sessionId: string,
  options: { touch?: boolean; now?: Date } = {},
): Promise<SessionLookup> {
  const now = options.now ?? new Date();
  const result = await db.query<DashboardSessionRow>(
    "select * from dashboard_sessions where id_hash = $1",
    [sha256Hex(sessionId)],
  );
  const session = result.rows[0];
  if (!session) return { valid: false, reason: "missing" };
  if (session.revoked_at) return { valid: false, reason: "revoked" };
  if (
    session.idle_expires_at.getTime() <= now.getTime() ||
    session.absolute_expires_at.getTime() <= now.getTime()
  ) {
    return { valid: false, reason: "expired" };
  }

  if (options.touch) {
    await db.query(
      `update dashboard_sessions
          set last_seen_at = $2,
              idle_expires_at = $3
        where id_hash = $1`,
      [
        session.id_hash,
        now,
        new Date(
          Math.min(
            now.getTime() + SESSION_IDLE_MS,
            session.absolute_expires_at.getTime(),
          ),
        ),
      ],
    );
  }

  return {
    valid: true,
    session,
    accessToken: decryptValue(secret, session.encrypted_access_token),
  };
}

/** Rotates the session id (login and privilege change): old id dies. */
export async function rotateDashboardSession(
  db: Db,
  secret: string,
  sessionId: string,
): Promise<CreatedSession | null> {
  const current = await getDashboardSession(db, secret, sessionId);
  if (!current.valid) return null;
  await revokeDashboardSession(db, sessionId, "rotated");
  const created = await createDashboardSession(db, secret, {
    subject: current.session.subject,
    displayName: current.session.display_name,
    role: current.session.role,
    accessToken: current.accessToken,
    mfaLevel: current.session.mfa_level,
  });
  if (current.session.step_up_deadline) {
    await db.query(
      `update dashboard_sessions
          set step_up_deadline = $2
        where id_hash = $1`,
      [sha256Hex(created.sessionId), current.session.step_up_deadline],
    );
  }
  return created;
}

export async function revokeDashboardSession(
  db: Db,
  sessionId: string,
  reason: string,
): Promise<boolean> {
  const result = await db.query<{ id_hash: string }>(
    `update dashboard_sessions
        set revoked_at = now(), revocation_reason = $2
      where id_hash = $1 and revoked_at is null
      returning id_hash`,
    [sha256Hex(sessionId), reason],
  );
  return result.rows.length > 0;
}

/** Revokes every session for a subject (role or password change). */
export async function revokeSessionsForSubject(
  db: Db,
  subject: string,
  reason: string,
): Promise<number> {
  const result = await db.query<{ id_hash: string }>(
    `update dashboard_sessions
        set revoked_at = now(), revocation_reason = $2
      where subject = $1 and revoked_at is null
      returning id_hash`,
    [subject, reason],
  );
  if (result.rows.length > 0) {
    await recordAuthEvent(db, {
      subject,
      action: "sessions_revoked",
      metadata: { reason, count: result.rows.length },
    });
  }
  return result.rows.length;
}

export function csrfMatches(session: DashboardSessionRow, csrfToken: string): boolean {
  const presented = Buffer.from(sha256Hex(csrfToken));
  const expected = Buffer.from(session.csrf_secret_hash);
  return presented.length === expected.length && timingSafeEqual(presented, expected);
}

export async function setStepUp(
  db: Db,
  sessionId: string,
  now: Date = new Date(),
): Promise<Date | null> {
  const deadline = new Date(now.getTime() + STEP_UP_MS);
  const result = await db.query<{ subject: string }>(
    `update dashboard_sessions
        set step_up_deadline = $2, mfa_level = 'totp'
      where id_hash = $1 and revoked_at is null
      returning subject`,
    [sha256Hex(sessionId), deadline],
  );
  const subject = result.rows[0]?.subject;
  if (!subject) return null;
  await recordAuthEvent(db, {
    subject,
    action: "step_up",
    metadata: { deadline: deadline.toISOString() },
  });
  return deadline;
}

/** Step-up deadline (epoch ms) for a session id, or null. Used by admin routes. */
export async function getSessionStepUpUntil(
  db: Queryable,
  sessionId: string,
): Promise<number | null> {
  const result = await db.query<{ step_up_deadline: Date | null }>(
    `select step_up_deadline from dashboard_sessions
      where id_hash = $1 and revoked_at is null`,
    [sha256Hex(sessionId)],
  );
  const deadline = result.rows[0]?.step_up_deadline;
  return deadline ? deadline.getTime() : null;
}

// ---------------------------------------------------------------------------
// MFA (TOTP + one-time recovery codes)
// ---------------------------------------------------------------------------

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Encode(buffer: Buffer): string {
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return output;
}

function base32Decode(encoded: string): Buffer {
  const clean = encoded.replace(/[\s=-]+/gi, "").toUpperCase();
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (const char of clean) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index === -1) throw new Error("Invalid base32 secret.");
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

export function totpCode(secretBase32: string, at: Date = new Date()): { code: string; step: number } {
  const step = Math.floor(at.getTime() / 30_000);
  const counter = Buffer.alloc(8);
  counter.writeBigInt64BE(BigInt(step));
  const digest = createHmac("sha1", base32Decode(secretBase32))
    .update(counter)
    .digest();
  const offset = digest[digest.length - 1]! & 0x0f;
  const binary =
    ((digest[offset]! & 0x7f) << 24) |
    ((digest[offset + 1]! & 0xff) << 16) |
    ((digest[offset + 2]! & 0xff) << 8) |
    (digest[offset + 3]! & 0xff);
  return { code: String(binary % 1_000_000).padStart(6, "0"), step };
}

/** Verifies a code within ±1 step; returns the matched step or null. */
export function verifyTotp(
  secretBase32: string,
  code: string,
  at: Date = new Date(),
): number | null {
  const normalized = code.replace(/\s+/g, "");
  if (!/^\d{6}$/.test(normalized)) return null;
  for (const delta of [-1, 0, 1]) {
    const candidate = totpCode(secretBase32, new Date(at.getTime() + delta * 30_000));
    const a = Buffer.from(candidate.code);
    const b = Buffer.from(normalized);
    if (a.length === b.length && timingSafeEqual(a, b)) return candidate.step;
  }
  return null;
}

export interface MfaRow {
  subject: string;
  encrypted_secret: string;
  recovery_code_hashes: string[];
  enabled: boolean;
  last_used_step: number | null;
  last_used_at: Date | null;
}

export async function getMfa(db: Queryable, subject: string): Promise<MfaRow | null> {
  const result = await db.query<MfaRow>(
    "select * from dashboard_mfa where subject = $1",
    [subject],
  );
  return result.rows[0] ?? null;
}

export async function enrollMfa(
  db: Db,
  secret: string,
  subject: string,
): Promise<{ secretBase32: string; otpauthUrl: string }> {
  const secretBase32 = base32Encode(randomBytes(20));
  await db.query(
    `insert into dashboard_mfa (subject, encrypted_secret, enabled)
     values ($1, $2, false)
     on conflict (subject) do update
        set encrypted_secret = excluded.encrypted_secret,
            enabled = false,
            recovery_code_hashes = '[]'::jsonb,
            last_used_step = null,
            updated_at = now()`,
    [subject, encryptValue(secret, secretBase32)],
  );
  const otpauthUrl =
    `otpauth://totp/Veripack:${encodeURIComponent(subject)}` +
    `?secret=${secretBase32}&issuer=Veripack&digits=6&period=30`;
  return { secretBase32, otpauthUrl };
}

export async function verifyMfaEnrollment(
  db: Db,
  secret: string,
  subject: string,
  code: string,
): Promise<string[] | null> {
  const row = await getMfa(db, subject);
  if (!row) return null;
  const step = verifyTotp(decryptValue(secret, row.encrypted_secret), code);
  if (step === null) {
    await recordAuthEvent(db, {
      subject,
      action: "mfa_verify_failed",
      success: false,
    });
    return null;
  }

  const recoveryCodes = Array.from({ length: 8 }, () =>
    randomBytes(5).toString("hex").toUpperCase(),
  ).map((hex) => `${hex.slice(0, 5)}-${hex.slice(5)}`);
  await db.query(
    `update dashboard_mfa
        set enabled = true,
            recovery_code_hashes = $2::jsonb,
            last_used_step = $3,
            last_used_at = now(),
            updated_at = now()
      where subject = $1`,
    [subject, JSON.stringify(recoveryCodes.map(sha256Hex)), step],
  );
  await recordAuthEvent(db, { subject, action: "mfa_enrolled" });
  return recoveryCodes;
}

/** Challenges an enabled MFA: accepts a TOTP code or a one-time recovery code. */
export async function challengeMfa(
  db: Db,
  secret: string,
  subject: string,
  input: { code?: string; recoveryCode?: string },
): Promise<boolean> {
  const row = await getMfa(db, subject);
  if (!row?.enabled) return false;

  if (input.recoveryCode) {
    const hash = sha256Hex(input.recoveryCode.replace(/[\s-]+/g, "").toUpperCase());
    const stored = row.recovery_code_hashes;
    // Stored hashes keep the display format; compare against both forms.
    const candidates = [
      hash,
      sha256Hex(input.recoveryCode.trim().toUpperCase()),
    ];
    const index = stored.findIndex((entry) => candidates.includes(entry));
    if (index === -1) {
      await recordAuthEvent(db, {
        subject,
        action: "mfa_challenge_failed",
        success: false,
      });
      return false;
    }
    const remaining = stored.filter((_, i) => i !== index);
    await db.query(
      `update dashboard_mfa
          set recovery_code_hashes = $2::jsonb, last_used_at = now(), updated_at = now()
        where subject = $1`,
      [subject, JSON.stringify(remaining)],
    );
    await recordAuthEvent(db, { subject, action: "mfa_recovery_used" });
    return true;
  }

  if (input.code) {
    const step = verifyTotp(decryptValue(secret, row.encrypted_secret), input.code);
    if (step === null || (row.last_used_step !== null && step <= row.last_used_step)) {
      await recordAuthEvent(db, {
        subject,
        action: "mfa_challenge_failed",
        success: false,
      });
      return false;
    }
    await db.query(
      `update dashboard_mfa
          set last_used_step = $2, last_used_at = now(), updated_at = now()
        where subject = $1`,
      [subject, step],
    );
    await recordAuthEvent(db, { subject, action: "mfa_challenge" });
    return true;
  }

  return false;
}

import type { Db } from "../db.js";
import { insertEvent } from "../releases.js";

export interface ExportResult {
  key: string;
  counts: { auditEvents: number; authEvents: number; installEvents: number };
  bytes: number;
}

interface ExportStore {
  putBuffer(key: string, value: Buffer, contentType: string): Promise<void>;
}

/**
 * V2 compliance export: audit, auth, and install events as JSON Lines for
 * S3/SIEM ingestion. The export itself is recorded as an audit event.
 */
export async function exportComplianceEvents(
  db: Db,
  store: ExportStore,
  input: {
    orgId: string;
    actor: string;
    from?: Date | null;
    to?: Date | null;
  },
): Promise<ExportResult> {
  const from = input.from ?? new Date(0);
  const to = input.to ?? new Date();

  const [auditEvents, authEvents, installEvents] = await Promise.all([
    db.query(
      `select * from audit_events
        where org_id = $1 and created_at >= $2 and created_at <= $3
        order by created_at asc`,
      [input.orgId, from, to],
    ),
    db.query(
      `select * from auth_events
        where created_at >= $1 and created_at <= $2
        order by created_at asc`,
      [from, to],
    ),
    db.query(
      `select * from install_events
        where org_id = $1 and created_at >= $2 and created_at <= $3
        order by created_at asc`,
      [input.orgId, from, to],
    ),
  ]);

  const lines: string[] = [];
  for (const row of auditEvents.rows) {
    lines.push(JSON.stringify({ kind: "audit_event", ...row }));
  }
  for (const row of authEvents.rows) {
    lines.push(JSON.stringify({ kind: "auth_event", ...row }));
  }
  for (const row of installEvents.rows) {
    lines.push(JSON.stringify({ kind: "install_event", ...row }));
  }

  const stamp = new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14);
  const key = `exports/${input.orgId}/${stamp}.jsonl`;
  const body = Buffer.from(lines.length ? `${lines.join("\n")}\n` : "");
  await store.putBuffer(key, body, "application/x-ndjson");

  const counts = {
    auditEvents: auditEvents.rows.length,
    authEvents: authEvents.rows.length,
    installEvents: installEvents.rows.length,
  };
  await insertEvent(db, {
    orgId: input.orgId,
    actor: input.actor,
    action: "compliance.exported",
    metadata: { key, counts },
  });

  return { key, counts, bytes: body.length };
}

import type { Db, Queryable } from "./db.js";

/**
 * V2 agent panel: specialized review agents post structured, append-only
 * advisory recommendations on releases. Agents never write approvals and
 * cannot move a release; human reviewers remain the decision makers. The
 * panel consensus is bounded by the release's risk tier (shown for
 * low/medium risk, advisory-only for high/critical).
 */

export type AgentRecommendation = "approve" | "reject" | "needs_info";

export interface AgentReviewRow {
  id: string;
  org_id: string;
  release_id: string;
  audit_id: string | null;
  agent_id: string;
  recommendation: AgentRecommendation;
  confidence: number | null;
  rationale: string;
  created_at: Date;
}

export async function createAgentReview(
  db: Db,
  input: {
    orgId: string;
    releaseId: string;
    auditId?: string | null;
    agentId: string;
    recommendation: AgentRecommendation;
    confidence?: number | null;
    rationale: string;
  },
): Promise<AgentReviewRow> {
  const result = await db.query<AgentReviewRow>(
    `insert into agent_reviews (
       org_id, release_id, audit_id, agent_id, recommendation, confidence,
       rationale
     ) values ($1, $2, $3, $4, $5, $6, $7)
     returning *`,
    [
      input.orgId,
      input.releaseId,
      input.auditId ?? null,
      input.agentId,
      input.recommendation,
      input.confidence ?? null,
      input.rationale,
    ],
  );
  return result.rows[0]!;
}

export async function listAgentReviews(
  db: Queryable,
  releaseId: string,
): Promise<AgentReviewRow[]> {
  const result = await db.query<AgentReviewRow>(
    `select * from agent_reviews
      where release_id = $1
      order by created_at desc`,
    [releaseId],
  );
  return result.rows;
}

export interface PanelConsensus {
  total: number;
  approve: number;
  reject: number;
  needsInfo: number;
  /** Unanimous panel recommendation, or null when split/empty. */
  consensus: AgentRecommendation | null;
}

/** Combined panel view: unanimous agents speak with one advisory voice. */
export function panelConsensus(reviews: AgentReviewRow[]): PanelConsensus {
  const approve = reviews.filter((r) => r.recommendation === "approve").length;
  const reject = reviews.filter((r) => r.recommendation === "reject").length;
  const needsInfo = reviews.filter(
    (r) => r.recommendation === "needs_info",
  ).length;
  const consensus: AgentRecommendation | null =
    reviews.length === 0
      ? null
      : approve === reviews.length
        ? "approve"
        : reject === reviews.length
          ? "reject"
          : needsInfo === reviews.length
            ? "needs_info"
            : null;
  return { total: reviews.length, approve, reject, needsInfo, consensus };
}

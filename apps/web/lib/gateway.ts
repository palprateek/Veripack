import type {
  AuditPolicy,
  ReleaseDetail,
  ReleaseDetailResponse,
  ReleaseListResponse,
  ReleaseSummary,
} from "@veripack/shared";
import { getDashboardSession } from "@/lib/auth";

const GATEWAY_URL = process.env.GATEWAY_URL ?? "http://localhost:4874";

export interface Result<T> {
  data?: T;
  error?: string;
}

export type PolicyConfig = AuditPolicy;

export interface PolicyVersion {
  id: string;
  version: string;
  policy: PolicyConfig;
  active: boolean;
  createdBy: string;
  createdAt: string;
}

export interface PolicyResponse {
  active: PolicyConfig & {
    id: string | null;
    source: "database" | "environment";
    createdBy: string | null;
    createdAt: string | null;
  };
  history: PolicyVersion[];
}

async function gatewayGet<T>(path: string): Promise<Result<T>> {
  const session = await getDashboardSession();
  if (!session) return { error: "Dashboard authentication is required." };

  try {
    const response = await fetch(`${GATEWAY_URL}${path}`, {
      headers: {
        authorization: `Bearer ${session.accessToken}`,
        accept: "application/json",
      },
      cache: "no-store",
    });

    if (!response.ok) {
      let message = `Gateway returned ${response.status}.`;
      try {
        const body = (await response.json()) as { error?: string };
        if (body.error) message = body.error;
      } catch {
        // Keep the status message.
      }
      return { error: message };
    }

    return { data: (await response.json()) as T };
  } catch (error) {
    return {
      error:
        error instanceof Error
          ? `Cannot reach the gateway at ${GATEWAY_URL}: ${error.message}`
          : `Cannot reach the gateway at ${GATEWAY_URL}.`,
    };
  }
}

export async function getReleases(): Promise<Result<ReleaseSummary[]>> {
  const result = await gatewayGet<ReleaseListResponse>("/admin/releases?limit=100");
  if (result.error) return { error: result.error };
  return { data: result.data?.releases ?? [] };
}

export async function getRelease(
  id: string,
): Promise<Result<ReleaseDetail>> {
  const result = await gatewayGet<ReleaseDetailResponse>(
    `/admin/releases/${encodeURIComponent(id)}`,
  );
  if (result.error) return { error: result.error };
  return { data: result.data?.release };
}

export async function getPolicy(): Promise<Result<PolicyResponse>> {
  return gatewayGet<PolicyResponse>("/admin/policy");
}

export interface BlocklistEntry {
  id: string;
  package_name: string;
  version: string | null;
  tarball_digest: string | null;
  reason: string;
  created_by: string;
  created_at: string;
  active: boolean;
  revoked_at: string | null;
}

export interface InstallEvent {
  id: string;
  actor: string;
  package_name: string;
  version: string | null;
  decision: "allowed" | "blocked";
  reason: string | null;
  source: "packument" | "tarball";
  created_at: string;
}

export async function getReviewQueue(): Promise<Result<ReleaseSummary[]>> {
  const result = await gatewayGet<{ releases: ReleaseSummary[] }>("/review/queue");
  if (result.error) return { error: result.error };
  return { data: result.data?.releases ?? [] };
}

export async function getBlocklist(): Promise<Result<BlocklistEntry[]>> {
  const result = await gatewayGet<{ entries: BlocklistEntry[] }>("/admin/blocklist");
  if (result.error) return { error: result.error };
  return { data: result.data?.entries ?? [] };
}

export async function getInstallEvents(): Promise<Result<InstallEvent[]>> {
  const result = await gatewayGet<{ events: InstallEvent[] }>(
    "/admin/install-events?limit=100",
  );
  if (result.error) return { error: result.error };
  return { data: result.data?.events ?? [] };
}

export interface PackageClaim {
  id: string;
  package_name: string;
  claimant: string;
  reason: string;
  status: "pending" | "approved" | "rejected";
  decided_by: string | null;
  created_at: string;
}

export interface AgentReview {
  id: string;
  release_id: string;
  agent_id: string;
  recommendation: "approve" | "reject" | "needs_info";
  confidence: number | null;
  rationale: string;
  created_at: string;
}

export async function getClaims(): Promise<Result<PackageClaim[]>> {
  const result = await gatewayGet<{ claims: PackageClaim[] }>("/admin/claims");
  if (result.error) return { error: result.error };
  return { data: result.data?.claims ?? [] };
}

export async function getAgentReviews(
  releaseId: string,
): Promise<Result<{ reviews: AgentReview[]; panel: { consensus: string | null; total: number } }>> {
  return gatewayGet(`/admin/releases/${encodeURIComponent(releaseId)}/agent-reviews`);
}

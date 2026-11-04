import type { Db } from "./db.js";

type Labels = Record<string, string | number>;

function labelText(labels: Labels): string {
  const entries = Object.entries(labels);
  if (entries.length === 0) return "";
  return `{${entries
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}="${String(value).replaceAll("\\", "\\\\").replaceAll('"', '\\"').replaceAll("\n", "\\n")}"`)
    .join(",")}}`;
}

export class MetricsRegistry {
  private readonly counters = new Map<string, number>();
  private readonly histograms = new Map<string, { count: number; sum: number }>();

  increment(name: string, labels: Labels = {}, value = 1): void {
    const key = `${name}${labelText(labels)}`;
    this.counters.set(key, (this.counters.get(key) ?? 0) + value);
  }

  observe(name: string, seconds: number, labels: Labels = {}): void {
    const key = `${name}${labelText(labels)}`;
    const current = this.histograms.get(key) ?? { count: 0, sum: 0 };
    current.count += 1;
    current.sum += seconds;
    this.histograms.set(key, current);
  }

  async render(db: Db): Promise<string> {
    const lines = [
      "# HELP veripack_gateway_process_info Gateway process information.",
      "# TYPE veripack_gateway_process_info gauge",
      "veripack_gateway_process_info{service=\"veripack-gateway\"} 1",
      "# HELP veripack_gateway_requests_total HTTP requests handled by the gateway.",
      "# TYPE veripack_gateway_requests_total counter",
    ];
    for (const [key, value] of this.counters) {
      lines.push(`${key} ${value}`);
    }
    lines.push(
      "# HELP veripack_gateway_request_duration_seconds HTTP request duration.",
      "# TYPE veripack_gateway_request_duration_seconds summary",
    );
    for (const [key, value] of this.histograms) {
      lines.push(`veripack_gateway_request_duration_seconds_count${key} ${value.count}`);
      lines.push(`veripack_gateway_request_duration_seconds_sum${key} ${value.sum}`);
    }

    try {
      const result = await db.query<{ status: string; count: string }>(
        "select status, count(*)::text as count from releases group by status",
      );
      lines.push(
        "# HELP veripack_registry_releases Number of releases by status.",
        "# TYPE veripack_registry_releases gauge",
      );
      for (const row of result.rows) {
        lines.push(
          `veripack_registry_releases{status="${row.status.replaceAll('"', '\\"')}"} ${Number(row.count)}`,
        );
      }
    } catch {
      lines.push("veripack_registry_database_query_errors_total 1");
    }

    try {
      const outbox = await db.query<{
        pending: string;
        attempts: string;
        oldest_age_seconds: string | null;
      }>(
        `select count(*) filter (where sent_at is null)::text as pending,
                coalesce(sum(attempts), 0)::text as attempts,
                coalesce(
                  extract(epoch from (
                    now() - min(next_attempt_at) filter (where sent_at is null)
                  )),
                  0
                )::text as oldest_age_seconds
           from audit_outbox`,
      );
      const row = outbox.rows[0];
      lines.push(
        "# HELP veripack_audit_outbox_pending Audit outbox entries waiting for queue dispatch.",
        "# TYPE veripack_audit_outbox_pending gauge",
        `veripack_audit_outbox_pending ${Number(row?.pending ?? 0)}`,
        "# HELP veripack_audit_outbox_attempts_total Audit outbox dispatch attempts.",
        "# TYPE veripack_audit_outbox_attempts_total counter",
        `veripack_audit_outbox_attempts_total ${Number(row?.attempts ?? 0)}`,
        "# HELP veripack_audit_outbox_oldest_age_seconds Age of the oldest unsent audit outbox entry.",
        "# TYPE veripack_audit_outbox_oldest_age_seconds gauge",
        `veripack_audit_outbox_oldest_age_seconds ${Number(row?.oldest_age_seconds ?? 0)}`,
      );
    } catch {
      lines.push("veripack_audit_outbox_query_errors_total 1");
    }

    try {
      const ages = await db.query<{
        pending_age: string | null;
        replay_age: string | null;
        blocked_hour: string;
      }>(
        `select
           (select coalesce(extract(epoch from (now() - min(created_at))), 0)::text
              from releases where status = 'pending') as pending_age,
           (select coalesce(extract(epoch from (now() - min(created_at))), 0)::text
              from replay_jobs where state = 'running') as replay_age,
           (select count(*)::text from install_events
             where decision = 'blocked'
               and created_at > now() - interval '1 hour') as blocked_hour`,
      );
      const row = ages.rows[0];
      lines.push(
        "# HELP veripack_pending_oldest_age_seconds Age of the oldest pending release.",
        "# TYPE veripack_pending_oldest_age_seconds gauge",
        `veripack_pending_oldest_age_seconds ${Number(row?.pending_age ?? 0)}`,
        "# HELP veripack_replay_running_oldest_age_seconds Age of the oldest running replay job.",
        "# TYPE veripack_replay_running_oldest_age_seconds gauge",
        `veripack_replay_running_oldest_age_seconds ${Number(row?.replay_age ?? 0)}`,
        "# HELP veripack_install_blocked_last_hour Blocked install attempts in the last hour.",
        "# TYPE veripack_install_blocked_last_hour gauge",
        `veripack_install_blocked_last_hour ${Number(row?.blocked_hour ?? 0)}`,
      );
    } catch {
      lines.push("veripack_serving_query_errors_total 1");
    }

    try {
      const replayJobs = await db.query<{ failed: string }>(
        "select count(*)::text as failed from replay_jobs where state = 'failed'",
      );
      lines.push(
        "# HELP veripack_replay_jobs_failed Replay jobs that exhausted their attempts.",
        "# TYPE veripack_replay_jobs_failed gauge",
        `veripack_replay_jobs_failed ${Number(replayJobs.rows[0]?.failed ?? 0)}`,
      );
    } catch {
      lines.push("veripack_replay_jobs_query_errors_total 1");
    }

    try {
      const workers = await db.query<{ age_seconds: string | null }>(
        `select coalesce(
                  extract(epoch from (now() - max(last_seen_at))),
                  0
                )::text as age_seconds
           from audit_worker_heartbeats`,
      );
      lines.push(
        "# HELP veripack_audit_worker_heartbeat_age_seconds Age of the newest audit worker heartbeat.",
        "# TYPE veripack_audit_worker_heartbeat_age_seconds gauge",
        `veripack_audit_worker_heartbeat_age_seconds ${Number(workers.rows[0]?.age_seconds ?? 0)}`,
      );
    } catch {
      lines.push("veripack_audit_worker_query_errors_total 1");
    }

    return `${lines.join("\n")}\n`;
  }
}

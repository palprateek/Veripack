# The LLM backend is pluggable because private code is sensitive

Status: accepted

Private packages contain sensitive code, so the audit cannot require sending code to a third-party model. We will make the LLM backend pluggable: deterministic checks always run; the LLM verdict can use a hosted no-retention provider, the team's own API key, a self-hosted model, or be disabled per repo. V1 ships SaaS + BYO key + deterministic-only fallback; self-hosted comes when a deal requires it. This is a sales requirement, not a nice-to-have.

## Consequences

- The audit report must distinguish deterministic signals from LLM-assisted ones.
- A deterministic-only policy is a valid configuration, not a degraded mode.
- Model, prompt hash, and sampling settings are pinned in the audit record for reproducibility.

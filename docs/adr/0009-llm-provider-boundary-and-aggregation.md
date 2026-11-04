# LLM review is advisory and evidence-cited

Status: accepted; amended 2026-11-04 by the V1 design contract

The first LLM integration uses an OpenAI-compatible HTTP boundary so the team
can choose a hosted no-retention provider, a BYO-key endpoint, or a compatible
self-hosted service without changing the audit worker. The backend receives the
release intent, deterministic signals, and structured change set only. It never
receives the tarball, and it receives no package source by default; selected
hunks require an explicit per-org opt-in with a separate privacy contract.

The response is accepted only when it contains bounded verdict fields and at
least one citation to a signal or change-set path. The audit records the
backend, model, prompt hash, sampling settings, confidence, token count, and
citations. Provider errors do not silently pass a release: they add a
review-required signal and preserve the deterministic result.

LLM output is advisory. It can add review signals and escalate risk, but it
cannot turn a deterministic critical finding into an approval or remove a
deterministic block. Deterministic-only mode remains the default and is a valid
configuration.

# Risk-proportional approval with bounded human review

Status: accepted; amended 2026-11-04 by the V1 design contract

Every private release requires a decision, but not every release deserves a human. We
auto-approve low-risk releases only when the safety floor permits. Medium and
high risk require a human reviewer within policy. Deterministic critical
findings always block; policy cannot disable them, and an admin may override a
specific release only with a recorded reason. Reviewers can approve or reject
medium/high releases within policy but cannot change policy, quarantine, or
override. The V2 agent panel is out of scope; LLM output is advisory only.

Self-approval is a per-org policy setting, disabled by default and admin-only to
enable. It requires a reason, emits `release.self_approved`, shows a dashboard
warning, and is allowed only up to medium risk. High-risk releases require an
independent reviewer or admin; critical risk requires an admin override with a
recorded reason. This keeps the gate usable without turning it into a rubber
stamp, and gives compliance buyers an accountability story.

## Consequences

- Low-risk releases still produce an audit trail and remain reversible by
  quarantine.
- A prompt-injected package cannot persuade an agent or LLM to override a
  deterministic block.
- Solo teams can enable self-approval per org, but the decision is visible,
  reason-bearing, and audited.
- No auto-approval is permitted when the previous artifact is unavailable, or
  when binary/WASM/native-addon content or obfuscation/minification is present.
- First-release review remains policy-configurable within the safety floor;
  `trust.intent` is required for private releases.
- A pending decision requires an audit produced under the currently active
  policy. Policy/engine changes do not retroactively change approved releases.
- Critical packages or scopes can require two reviewers.

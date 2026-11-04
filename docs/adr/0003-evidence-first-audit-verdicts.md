# Evidence-first audit verdicts, not a single score

Status: accepted

Most package security products reduce risk to a single score. We will expose two verdicts — safety (`clear`/`review`/`block`/`unknown`) and intent (`matches`/`mismatch`/`unknown`) — plus a risk tier and a separate policy result, all backed by deterministic and LLM-assisted signals with evidence. No numeric score. A single score is gameable, unauditable, and hides whether the problem is malicious behavior or a mismatch with the publisher's stated intent. The policy result is separate because the same audit can pass one team's policy and fail another's.

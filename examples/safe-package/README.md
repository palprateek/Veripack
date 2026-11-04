# @veripack/safe-package

A deliberately boring example package for the M1 publish gate.

- No install lifecycle scripts
- No runtime dependencies
- A release intent is declared in `package.json`

The first release requires review because first releases are not auto-approved.
After that baseline is approved, an unchanged-capability follow-up should
produce a low-risk audit and auto-approve.

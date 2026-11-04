# @veripack/risky-package

An M1 example that must be rejected automatically.

The `postinstall` script downloads a remote shell script and pipes it to `sh`.
The static audit emits a critical `install-script-download-exec` signal, which
the gate maps to a deterministic block. The release is never replayed to
Verdaccio and cannot be installed.

The script points at `example.invalid`, so even a mistake cannot fetch real
code.

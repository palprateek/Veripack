# @veripack/review-package

An M1 example that exercises the human approval path.

The package declares a benign `postinstall` script. The static audit records the
install command and classifies the release as high risk, so it stays `pending`
until an admin approves it in the dashboard or via the admin API.

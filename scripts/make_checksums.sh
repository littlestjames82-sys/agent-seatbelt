#!/bin/sh
# Build SHA256SUMS for the release assets of this tree.
# Usage: sh scripts/make_checksums.sh [output-file]
# Verify-then-run is the install story (README): a user downloads the
# plugin zip + SHA256SUMS, checks the hash, then installs.
set -eu
cd "$(dirname "$0")/.."
OUT="${1:-SHA256SUMS}"
TMP="$(mktemp)"
{
  find .claude-plugin hooks commands skills policies examples feed \
       bench experimental docs \
       -type f ! -name "*.pyc" 2>/dev/null
  echo "./pyproject.toml"
  echo "./install.py"
  echo "./README.md"
  echo "./CHANGELOG.md"
  echo "./LICENSE"
} | sort -u | while IFS= read -r f; do
  sha256sum "$f"
done > "$TMP"
mv "$TMP" "$OUT"
echo "wrote $OUT ($(wc -l < "$OUT") files)"

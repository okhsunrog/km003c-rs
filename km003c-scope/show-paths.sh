#!/usr/bin/env bash
# Print the public URL for the hosted scope, and the asset paths in dist/index.html.
set -euo pipefail
cd "$(dirname "$0")"

public_url="/tools/km003c-scope/"

echo "public URL: ${public_url}"
echo "page:       https://motionhyve.com${public_url}"
echo
echo "build:"
echo "  trunk build --release --public-url ${public_url}"
echo

index="dist/index.html"
if [[ ! -f "${index}" ]]; then
  echo "${index} is not built yet"
  exit 0
fi

echo "paths in ${index}:"
grep -oE '/tools/[^" ]+' "${index}" | sort -u

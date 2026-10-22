#!/usr/bin/env bash
set -euo pipefail
: "${DACS_SDK_ROOT:?Set DACS_SDK_ROOT to the trusted built SDK checkout}"
if [[ ! -d "$DACS_SDK_ROOT/src" || ! -d "$DACS_SDK_ROOT/dist" ]]; then
  echo 'SDK source and built dist are required' >&2
  exit 2
fi
export DACS_SDK_ROOT
example_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
for tool in passport-diff recipe-studio spend-simulator fault-theater rfq-restart-storyboard; do
  (cd "$example_root/$tool" && timeout 120s bun test ./test.mjs)
done
(cd "$example_root/quote-band-workbench" && timeout 45s node --test test.mjs)

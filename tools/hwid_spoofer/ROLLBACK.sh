#!/usr/bin/env bash
set -euo pipefail

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
target="${1:-$here/HWID_SPOOFER.py}"
baseline="$here/BASELINE.py"
expected_modified="66486b76ce45ce81ff901ddeb9df9ca31e2d64145b50ebe01cf5d65bf6838793"
expected_baseline="d90fec38940bdae1e62eb00f1d485452c9f9adfbbf02f71ccebfda0cdf271940"

actual_modified="$(sha256sum -- "$target" | awk '{print $1}')"
actual_baseline="$(sha256sum -- "$baseline" | awk '{print $1}')"
if [[ "$actual_modified" != "$expected_modified" ]]; then
  printf 'ROLLBACK_REJECTED target_sha256=%s\n' "$actual_modified" >&2
  exit 3
fi
if [[ "$actual_baseline" != "$expected_baseline" ]]; then
  printf 'ROLLBACK_REJECTED baseline_sha256=%s\n' "$actual_baseline" >&2
  exit 4
fi

cp -- "$baseline" "$target"
cmp -- "$baseline" "$target"
printf 'ROLLED_BACK baseline_sha256=%s\n' "$actual_baseline"

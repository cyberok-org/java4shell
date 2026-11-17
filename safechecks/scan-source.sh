#!/usr/bin/env bash
# Review candidates only. No target-code execution; no network probes.
set -u
if [[ $# -lt 1 ]]; then
  echo 'Usage: bash safechecks/scan-source.sh ROOT [additional rg options]' >&2
  exit 2
fi
if ! command -v rg >/dev/null 2>&1; then
  echo 'ripgrep (rg) is required' >&2
  exit 2
fi
root="$1"
shift
if [[ ! -d "$root" ]]; then
  echo 'ROOT must be an existing source directory' >&2
  exit 2
fi
echo 'Review candidates: verify decoder type, input provenance and destination lifetime.' >&2
exec rg --line-number --no-heading --multiline --glob '*.java' --glob '*.kt' \
  --regexp '(getDecoder|getUrlDecoder)\s*\(\s*\)\s*\.\s*decode\s*\(' \
  --regexp '\.decode\s*\([^(),]*,[^(),]*\)' "$@" -- "$root"

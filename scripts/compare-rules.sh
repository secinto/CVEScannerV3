#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# compare-rules.sh — compare the import rules of two database.py versions
#
# Builds two databases from the same NVD raw cache, one with database.py from
# BASE and one with the working tree, and prints the per-product difference
# (extra/compare_rules.py). Offline apart from the first cache download, and
# a few minutes instead of a CI rebuild.
#
# Usage (normally through `make compare-rules`):
#   scripts/compare-rules.sh [compare_rules.py options, e.g. --product exim]
#
# Environment:
#   BASE      git ref of the base importer (default: origin/master). It must
#             already have --from-raw.
#   RAW       NVD raw cache directory (default: ~/.cache/cvescannerv3/nvd-raw)
#   RAW_URL   where to download the cache when RAW has none (default: the
#             nvd-raw release of secinto/CVEScannerV3DB)
#   REFRESH   1 = download the cache again
#   KEEP      1 = keep the two databases and print where they are
#   PYTHON    interpreter with extra/requirements.txt installed (default: python3)
# -----------------------------------------------------------------------------
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE="${BASE:-origin/master}"
RAW="${RAW:-${XDG_CACHE_HOME:-$HOME/.cache}/cvescannerv3/nvd-raw}"
RAW_URL="${RAW_URL:-https://github.com/secinto/CVEScannerV3DB/releases/download/nvd-raw/nvd-raw.tar.zst}"
PYTHON="${PYTHON:-python3}"

log() { echo "[compare-rules] $*" >&2; }

OUT="$(mktemp -d "${TMPDIR:-/tmp}/compare-rules.XXXXXX")"
if [ "${KEEP:-0}" = 1 ]; then
    trap 'log "databases kept in $OUT"' EXIT
else
    trap 'rm -rf "$OUT"' EXIT
fi

if [ ! -f "$RAW/meta.json" ] || [ "${REFRESH:-0}" = 1 ]; then
    command -v zstd >/dev/null || { log "zstd is required to unpack the cache"; exit 1; }
    log "downloading the NVD raw cache to $RAW"
    mkdir -p "$RAW"
    curl -fL --retry 3 "$RAW_URL" | zstd -dc | tar -x -C "$RAW"
fi
log "raw cache: $(cat "$RAW/meta.json" | tr -d '\n')"

# The whole extra/ directory, so the base importer runs with its own helpers.
mkdir -p "$OUT/base"
git -C "$ROOT" archive "$BASE" extra | tar -x -C "$OUT/base"
if ! grep -q -- "--from-raw" "$OUT/base/extra/database.py"; then
    log "$BASE has no --from-raw yet; pick a newer BASE"
    exit 1
fi

log "building both databases from the cache ($BASE vs working tree)"
"$PYTHON" "$OUT/base/extra/database.py" -d "$OUT/base.db" --raw-dir "$RAW" \
    --from-raw --skip-exploits > "$OUT/base.log" 2>&1 &
base_pid=$!
"$PYTHON" "$ROOT/extra/database.py" -d "$OUT/new.db" --raw-dir "$RAW" \
    --from-raw --skip-exploits > "$OUT/new.log" 2>&1 &
new_pid=$!
status=0
wait "$base_pid" || { log "base build failed:"; tail -20 "$OUT/base.log" >&2; status=1; }
wait "$new_pid" || { log "working-tree build failed:"; tail -20 "$OUT/new.log" >&2; status=1; }
[ "$status" = 0 ] || exit 1

"$PYTHON" "$ROOT/extra/compare_rules.py" "$OUT/base.db" "$OUT/new.db" "$@"

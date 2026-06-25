#!/usr/bin/env bash

# SPDX-License-Identifier: GPL-3.0-or-later
#
# scan-host.sh — run nmap service detection against a target and report known
# CVEs via the standalone cvescan.py engine. No Lua/NSE dependency required.
#
# Pipeline:  nmap -sV -oX  →  nmap_to_services.py  →  cvescan.py scan
#
# Copyright (C) 2025 secinto GmbH. Part of CVEScannerV3, GPL-3.0-or-later.

set -euo pipefail

# --- resolve repo paths relative to this script (works from any cwd) --------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXTRA_DIR="$SCRIPT_DIR/extra"

# Prefer the project venv interpreter (it has the fixed httpx/httpcore + deps).
if [[ -x "$EXTRA_DIR/venv/bin/python3" ]]; then
    PY="$EXTRA_DIR/venv/bin/python3"
else
    PY="python3"
fi

# --- defaults ---------------------------------------------------------------
CVE_DB="${CVE_DB:-$SCRIPT_DIR/cve.db}"
PORTS=""
FORMAT="auto"
MAXCVE=""
OUTPUT=""
KEEP_XML=0
NMAP_EXTRA=()

usage() {
    cat <<'EOF'
Usage: scan-host.sh [options] <target> [-- <extra nmap args>]

Runs `nmap -sV` against <target>, then reports known CVEs for the detected
services using the standalone cvescan.py engine.

Options:
  -c, --cve PATH     CVE database path (default: <repo>/cve.db, or $CVE_DB)
  -p, --ports SPEC   nmap port spec, e.g. 80,443 or 1-1024 (default: nmap top ports)
  -f, --format FMT   output format: table | json | auto (default: auto —
                     table on a terminal, json when redirected to a file)
  -m, --maxcve N     max CVEs reported per service (0 = unlimited)
  -o, --output FILE  write CVE results to FILE instead of stdout
      --keep-xml     keep the intermediate nmap XML (path printed on stderr)
  -h, --help         show this help
  --                 pass all following arguments straight to nmap

Examples:
  ./scan-host.sh collaboration.xitrust.com
  ./scan-host.sh -p 443 -f json collaboration.xitrust.com
  ./scan-host.sh collaboration.xitrust.com -- -Pn --top-ports 200
EOF
}

# --- argument parsing -------------------------------------------------------
TARGET=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -c|--cve)     CVE_DB="$2"; shift 2 ;;
        -p|--ports)   PORTS="$2"; shift 2 ;;
        -f|--format)  FORMAT="$2"; shift 2 ;;
        -m|--maxcve)  MAXCVE="$2"; shift 2 ;;
        -o|--output)  OUTPUT="$2"; shift 2 ;;
        --keep-xml)   KEEP_XML=1; shift ;;
        -h|--help)    usage; exit 0 ;;
        --)           shift; NMAP_EXTRA+=("$@"); break ;;
        -*)           echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
        *)
            if [[ -z "$TARGET" ]]; then TARGET="$1"; shift
            else echo "Unexpected argument: $1" >&2; exit 2; fi
            ;;
    esac
done

if [[ -z "$TARGET" ]]; then
    echo "Error: no target specified." >&2
    usage >&2
    exit 2
fi

# --- preflight checks -------------------------------------------------------
command -v nmap >/dev/null 2>&1 || { echo "Error: nmap not found in PATH." >&2; exit 1; }
if [[ ! -f "$CVE_DB" ]]; then
    echo "Error: CVE database not found: $CVE_DB" >&2
    echo "Build it first, e.g.: $PY $EXTRA_DIR/cvescan.py update-db --api-key YOUR_NVD_KEY -c $CVE_DB" >&2
    exit 1
fi

# --- run nmap into a temp XML report ----------------------------------------
XML_FILE="$(mktemp -t cvescan-nmap.XXXXXX.xml)"
cleanup() { [[ "$KEEP_XML" -eq 0 ]] && rm -f "$XML_FILE"; }
trap cleanup EXIT

NMAP_CMD=(nmap -sV -oX "$XML_FILE")
[[ -n "$PORTS" ]] && NMAP_CMD+=(-p "$PORTS")
[[ ${#NMAP_EXTRA[@]} -gt 0 ]] && NMAP_CMD+=("${NMAP_EXTRA[@]}")
NMAP_CMD+=("$TARGET")

echo "[1/2] nmap service detection → $TARGET" >&2
echo "      $ ${NMAP_CMD[*]}" >&2
"${NMAP_CMD[@]}" >&2
[[ "$KEEP_XML" -eq 1 ]] && echo "[*] nmap XML kept at: $XML_FILE" >&2
echo "[2/2] matching detected services against CVE database…" >&2

# --- convert nmap XML → services JSON → cvescan.py scan ---------------------
SCAN_CMD=("$PY" "$EXTRA_DIR/cvescan.py" scan
          -i - -c "$CVE_DB"
          -a "$EXTRA_DIR/product-aliases.json"
          --cpe-to-pkg "$EXTRA_DIR/cpe-to-package.json"
          --format "$FORMAT")
[[ -n "$MAXCVE" ]] && SCAN_CMD+=(--maxcve "$MAXCVE")
[[ -n "$OUTPUT" ]] && SCAN_CMD+=(-o "$OUTPUT")

"$PY" "$EXTRA_DIR/nmap_to_services.py" "$XML_FILE" | "${SCAN_CMD[@]}"

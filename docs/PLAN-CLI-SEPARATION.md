# Plan: Separate CVE Detection/Analysis into Standalone CLI

## Goal

Extract the CVE lookup, version matching, and association logic out of the nmap NSE script into a standalone Python CLI tool (`cvescanner-cli`) that can be invoked independently with a JSON input describing services/products to analyze.

---

## Current Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    cvescannerv3.nse (Lua)                 │
│                                                          │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────┐ │
│  │ Input:       │  │ HTTP         │  │ CVE Lookup &    │ │
│  │ nmap service │→ │ Fingerprint  │→ │ Version Scoping │ │
│  │ detection    │  │ (optional)   │  │ + Output        │ │
│  └─────────────┘  └──────────────┘  └────────┬────────┘ │
│                                               │          │
│                                          ┌────▼────┐     │
│                                          │ cve.db  │     │
│                                          │ (SQLite)│     │
│                                          └─────────┘     │
└──────────────────────────────────────────────────────────┘

Supporting files (Python):
  extra/database.py  → builds/updates cve.db from NVD API
  extra/query.py     → simple single-product CLI query (limited)
```

## Target Architecture

```
┌─────────────────────────┐      ┌──────────────────────────────┐
│  cvescannerv3.nse (Lua) │      │  cvescanner-cli (Python)     │
│                         │      │                              │
│  nmap service detection │      │  Reads JSON input (stdin/    │
│  + HTTP fingerprinting  │      │  file) with services list    │
│          │              │      │          │                   │
│          ▼              │      │          ▼                   │
│  Collect CPEs/versions  │      │  ┌────────────────────────┐ │
│          │              │      │  │  Core Engine (Python)  │ │
│          ▼              │      │  │                        │ │
│  ┌──────────────────┐   │      │  │  • CPE parsing         │ │
│  │ CVE Lookup (Lua) │   │      │  │  • Product aliasing    │ │
│  │ (kept as-is for  │   │      │  │  • SQL queries         │ │
│  │  nmap compat)    │   │      │  │  • Version comparison  │ │
│  └────────┬─────────┘   │      │  │  • Scoped matching     │ │
│           │             │      │  │  • ExploitDB/MSF refs  │ │
│      ┌────▼────┐        │      │  └───────────┬────────────┘ │
│      │ cve.db  │        │      │              │              │
│      └─────────┘        │      │         ┌────▼────┐         │
└─────────────────────────┘      │         │ cve.db  │         │
                                 │         └─────────┘         │
                                 │              │              │
                                 │         JSON output         │
                                 └──────────────────────────────┘
```

---

## JSON Input Format

The CLI accepts a JSON document describing one or more services to analyze. Each service is identified by a product name and version, optionally with CPE, port context, and version-update metadata.

### Schema

```json
{
  "services": [
    {
      "product": "nginx",
      "version": "1.26.3",
      "cpe": "cpe:/a:nginx:nginx",
      "version_update": "*",
      "context": {
        "host": "192.168.1.10",
        "port": 443,
        "protocol": "tcp",
        "service_name": "https"
      }
    }
  ]
}
```

#### Field Definitions

| Field | Required | Description |
|---|---|---|
| `services` | **yes** | Array of service objects to analyze |
| `services[].product` | **yes** | Product name as used in the CVE database (e.g., `"nginx"`, `"apache_http_server"`, `"openssh"`) |
| `services[].version` | **yes** | Version string. Use `"*"` for "all versions". Supports ranges like `"3.x - 4.x"` |
| `services[].cpe` | no | Full CPE string (e.g., `"cpe:/a:nginx:nginx"`). If omitted, only the product name is used for lookup |
| `services[].version_update` | no | Version update/patch level (e.g., `"p1"`, `"sp2"`). Default: `"*"` |
| `services[].context` | no | Optional metadata about where this service was found. Passed through to output unchanged. Not used for CVE matching |

#### Minimal Example (single product)

```json
{
  "services": [
    {
      "product": "openssh",
      "version": "8.9"
    }
  ]
}
```

#### Nmap-Output Conversion Example

When the NSE script generates its matches, the equivalent CLI input would be:

```json
{
  "services": [
    {
      "product": "samba",
      "version": "3.X - 4.X",
      "cpe": "cpe:/a:samba:samba",
      "context": {
        "host": "192.168.69.129",
        "port": 445,
        "protocol": "tcp",
        "service_name": "netbios-ssn"
      }
    },
    {
      "product": "tomcat",
      "version": "5.5",
      "cpe": "cpe:/a:apache:tomcat",
      "context": {
        "host": "192.168.69.129",
        "port": 8180,
        "protocol": "tcp",
        "service_name": "http"
      }
    }
  ]
}
```

---

## JSON Output Format

```json
{
  "timestamp": "2026-02-27T10:30:00+00:00",
  "results": [
    {
      "product": "nginx",
      "version": "1.26.3",
      "version_update": "*",
      "cpe": "cpe:/a:nginx:nginx",
      "context": {
        "host": "192.168.1.10",
        "port": 443,
        "protocol": "tcp",
        "service_name": "https"
      },
      "vulnerabilities": {
        "total": 2,
        "cves": {
          "CVE-2025-23419": {
            "cvssv2": 5.0,
            "cvssv3": "7.5",
            "exploitdb": [],
            "metasploit": []
          },
          "CVE-2024-XXXXX": {
            "cvssv2": null,
            "cvssv3": "6.1",
            "exploitdb": [
              {
                "id": "51234",
                "name": "Nginx X.X.X - Buffer Overflow",
                "url": "https://www.exploit-db.com/exploits/51234"
              }
            ],
            "metasploit": [
              { "name": "exploit/linux/http/nginx_bof" }
            ]
          }
        }
      }
    }
  ]
}
```

---

## Implementation Plan

### Phase 1: Core Python Engine (`extra/cvecore.py`)

Port the following logic from `cvescannerv3.nse` (Lua) to a Python module:

| NSE Function | Python Equivalent | Lines in NSE |
|---|---|---|
| `version_parser()` | `parse_version(product, version)` → returns `VersionInfo` | 644–678 |
| `cpe_parser()` | `parse_cpe(cpe, version)` → extracts product, calls `parse_version` | 681–693 |
| `compare_version()` | `compare_version(v1, v2)` → returns -1/0/1 | 846–862 |
| `split_version()` | (inline in `compare_version`) | 831–837 |
| `remove_alpha()` | (inline in `compare_version`) | 840–843 |
| `scoped_multi_versions()` | `scope_multi_versions(rows, from_v, to_v)` → filters multiaffected | 874–916 |
| `scoped_versions()` | `scope_versions(rows, from_v, to_v, upd)` → filters affected | 919–961 |
| `vulnerabilities()` | `find_vulnerabilities(conn, product, version_info)` → main entry | 965–1048 |
| `dump_exploit()` | Merged into `find_vulnerabilities` using JOINs (eliminate N+1) | 756–813 |
| `query()` | SQL constants with parameterized queries (fix SEC-1) | 696–753 |

Key improvements over the Lua version:
- **Parameterized SQL queries** (fixes SEC-1: SQL injection)
- **Batch queries** for exploit/metasploit data using JOINs (fixes PERF-2: N+1 queries)
- **Product aliasing** integrated (reads `extra/product-aliases.json`)
- **0-CVE caching** (fixes BUG-5)

Note: `extra/query.py` already has `compare_version()` and the basic query logic in Python, but it lacks multiaffected version scoping. The new module unifies and extends this.

### Phase 2: CLI Wrapper (`extra/cvescanner_cli.py`)

```
usage: cvescanner_cli.py [-h] [-d DATABASE] [-a ALIASES]
                         [-i INPUT | -p PRODUCT] [-v VERSION]
                         [-u UPDATE] [--max-cve MAX_CVE]
                         [-o OUTPUT] [--format {json,table}]

options:
  -h, --help            show this help message and exit
  -d, --database PATH   Path to cve.db (default: ./cve.db)
  -a, --aliases PATH    Path to product-aliases.json
                        (default: ./extra/product-aliases.json)
  -i, --input PATH      JSON input file (use "-" for stdin)
  -p, --product NAME    Single product name (alternative to --input)
  -v, --version VER     Version string (with --product)
  -u, --update UPD      Version update (with --product, default: *)
  --max-cve N           Max CVEs to display in table mode (default: 10)
  -o, --output PATH     Write JSON output to file (default: stdout)
  --format {json,table} Output format (default: json)
```

#### Usage Examples

```bash
# Single product query (replaces extra/query.py)
python extra/cvescanner_cli.py -p nginx -v 1.26.3

# JSON input from file
python extra/cvescanner_cli.py -i scan_results.json

# Piped from another tool
cat services.json | python extra/cvescanner_cli.py -i -

# Custom database location + table output
python extra/cvescanner_cli.py -d /data/cve.db -p tomcat -v 5.5 --format table

# Output to file
python extra/cvescanner_cli.py -i services.json -o results.json
```

### Phase 3: Deprecate `extra/query.py`

`extra/query.py` becomes redundant since `cvescanner_cli.py -p PRODUCT -v VERSION --format table` provides the same functionality with correct multiaffected version scoping. Add a deprecation notice to `query.py` pointing to the new CLI.

---

## File Changes Summary

| File | Action | Description |
|---|---|---|
| `extra/cvecore.py` | **new** | Core CVE lookup engine (Python module) |
| `extra/cvescanner_cli.py` | **new** | CLI entry point |
| `extra/query.py` | **modify** | Add deprecation notice, keep working for backward compat |
| `extra/requirements.txt` | **modify** | Add `texttable` if not already present (it is, used by query.py) |
| `README.md` | **modify** | Document CLI usage and JSON input format |
| `cvescannerv3.nse` | **no change** | NSE script continues to work independently using its Lua implementation |

---

## Module Structure for `extra/cvecore.py`

```python
# Public API

@dataclass
class VersionInfo:
    version: str        # e.g. "1.26.3" or "*"
    update: str         # e.g. "p1" or "*"
    from_v: str | None  # range start (for "3.x - 4.x" style)
    to_v: str | None    # range end
    is_empty: bool      # True if version was "*" (unknown)
    is_range: bool      # True if version is a range

@dataclass
class CVEResult:
    cve_id: str
    cvssv2: float | None
    cvssv3: float | None
    exploitdb: list[dict]    # [{id, name, url}]
    metasploit: list[dict]   # [{name}]

def parse_version(product: str, version: str, update: str = "*") -> VersionInfo
def find_vulnerabilities(db_path: str, product: str, version_info: VersionInfo,
                         aliases: dict | None = None) -> list[CVEResult]
def compare_version(v1: str, v2: str) -> int  # -1, 0, 1
```

---

## Design Decisions

1. **Python, not Lua** — The CLI must work without nmap. Python is already used for `database.py` and `query.py`, and all dependencies are available.

2. **No change to the NSE script** — The Lua CVE lookup logic stays in `cvescannerv3.nse`. Re-implementing it in Python and calling Python from Lua would add complexity and a Python runtime dependency to nmap scans. The two implementations are functionally equivalent but independent.

3. **JSON as primary interface** — JSON input allows integration with any upstream tool (nmap XML parsers, asset inventories, CI/CD pipelines, other scanners). JSON output matches the existing `cvescannerv3.json` format where possible.

4. **Product name is the key** — The CVE database indexes on `products.product`. The CPE field is optional metadata; the product name is extracted from it if provided, but direct product names work too.

5. **`cvecore.py` as importable module** — Separating the engine from the CLI allows other Python tools to `from cvecore import find_vulnerabilities` directly, enabling programmatic integration without subprocess calls.

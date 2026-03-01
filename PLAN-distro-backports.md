# Plan: Distro Backport Detection in Standalone Mode

## Problem

Linux distributions (Debian, Ubuntu, RHEL, Alpine, SUSE) silently backport CVE
fixes without changing the upstream version number. CVEScannerV3's NVD-based
matching compares upstream versions, producing massive false positives on any
distro-managed system. OpenSSH 9.2p1 on Debian 12 may have 50+ CVEs patched via
`1:9.2p1-2+deb12u7`, but NVD still lists the upstream 9.2 as vulnerable.

## Scope

**Standalone mode only** (`extra/cvescan.py`). The NSE script is not modified.
This is the right boundary because:

- The standalone tool already has the Python ecosystem (stdlib `urllib`, `json`,
  `sqlite3`) needed for API calls and data processing
- NSE/Lua has limited library support and network call restrictions
- Standalone mode targets non-nmap workflows (SBOM, CI/CD, asset inventory)
  where distro context is more likely available as structured input
- The NSE script can later consume the standalone tool's output if desired

## Integration Design

### Where it fits in the current architecture

The existing `cvescan.py` pipeline is:

```
Input (JSON/CLI) → parse product/version → NVD lookup → rank CVEs → output
```

Distro backport detection adds a **post-filter stage** between NVD lookup and
output:

```
Input (JSON/CLI) → parse product/version → NVD lookup → BACKPORT FILTER → rank CVEs → output
```

This is the most efficient integration point because:

1. **Zero changes to the matching engine** — `find_vulnerabilities()`,
   `match_exact_versions()`, `match_range_versions()` remain untouched
2. **Zero changes to the database schema for NVD data** — `cve.db` keeps its
   existing tables
3. **Additive only** — new code filters/annotates the result dict that
   `find_vulnerabilities()` already returns
4. **Opt-in** — when no distro context is provided, behavior is identical to
   today

### Input format extension

Add optional `distro` fields to the service entry. Two ways to provide distro
context:

```json
{
  "services": [
    {
      "id": "ssh-22",
      "product": "openssh",
      "version": "9.2",
      "version_update": "p1",
      "distro": "debian",
      "distro_release": "12",
      "distro_package_version": "1:9.2p1-2+deb12u7"
    }
  ]
}
```

Or with a banner string for auto-detection:

```json
{
  "services": [
    {
      "id": "ssh-22",
      "cpe": "cpe:/a:openbsd:openssh:9.2p1",
      "banner": "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u7"
    }
  ]
}
```

Both are optional. When absent, current NVD-only behavior applies.

### CLI flags

```bash
# Enable online OSV.dev enrichment (off by default for airgap/stealth compat)
python extra/cvescan.py scan -i input.json --distro-check

# Use only the offline backport database (no network calls during scan)
python extra/cvescan.py scan -i input.json --distro-check --offline

# Populate/update the offline backport database
python extra/cvescan.py update-distro-db
```

---

## Implementation: 4 components, ordered by effort/value

### Component 1: Banner parsing for distro detection (small, high value)

**What:** Parse SSH and HTTP banners to extract distro family, release, and
package version. This is pure string processing — no network calls, no new
dependencies.

**Where:** New function `detect_distro(banner)` in `cvescan.py`, called from
`scan_service()` when a `banner` field is present.

**Patterns:**

| Distro | SSH Banner | Extractable |
|--------|-----------|-------------|
| Debian 12 | `SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u7` | family=debian, release=12, pkg_version=1:9.2p1-2+deb12u7 |
| Ubuntu 22.04 | `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10` | family=ubuntu, pkg_revision=3ubuntu0.10 |
| RHEL/Alpine | `SSH-2.0-OpenSSH_8.7` | Nothing — bare version |

**Implementation (~40 lines):**

```python
import re

_DEBIAN_RE = re.compile(
    r"Debian-(\d+)\+deb(\d+)u(\d+)"
)
_UBUNTU_RE = re.compile(
    r"Ubuntu-(\S+)"
)

def detect_distro(banner):
    """Extract distro info from a service banner string.

    Returns dict with keys: family, release, pkg_revision (or None).
    """
    if not banner:
        return None

    m = _DEBIAN_RE.search(banner)
    if m:
        deb_rev, deb_major, deb_patch = m.group(1), m.group(2), m.group(3)
        return {
            "family": "debian",
            "release": deb_major,
            "pkg_revision": m.group(0),
        }

    m = _UBUNTU_RE.search(banner)
    if m:
        return {
            "family": "ubuntu",
            "release": None,  # not reliably extractable from banner alone
            "pkg_revision": m.group(1),
        }

    return None
```

### Component 2: OSV.dev batch API integration (medium effort, highest accuracy)

**What:** Query OSV.dev's POST `/v1/querybatch` endpoint with distro-native
package names and versions. OSV aggregates Debian, Ubuntu, Alpine, RHEL, Rocky,
AlmaLinux, SUSE, and Chainguard advisories. One API, no key, no rate limits.

**Where:** New function `query_osv_batch()` in `cvescan.py`, called as a
post-filter after `find_vulnerabilities()` returns its NVD-based results.

**Why OSV.dev is the right choice:**
- Single endpoint covers all major distros
- No API key required
- Batch endpoint (up to 1000 queries per request)
- Returns distro-native affected ranges with `introduced`/`fixed` events
- Response directly answers "is package X at version Y vulnerable to CVE Z?"
- 100–500ms latency for a typical scan

**Request format:**

```json
POST https://api.osv.dev/v1/querybatch
{
  "queries": [
    {
      "package": {"name": "openssh", "ecosystem": "Debian:12"},
      "version": "1:9.2p1-2+deb12u7"
    }
  ]
}
```

**Integration with existing pipeline:**

```python
def filter_backported_cves(cve_results, distro_info, osv_response):
    """Remove CVEs that the distro has already patched.

    cve_results: dict from find_vulnerabilities() {cve_id: {cvss...}}
    distro_info: {family, release, pkg_version}
    osv_response: parsed OSV batch API response

    Returns filtered dict + annotation metadata.
    """
    # Build set of CVE IDs that OSV says affect this distro+version
    osv_vuln_ids = set()
    for result in osv_response.get("results", []):
        for vuln in result.get("vulns", []):
            for alias in vuln.get("aliases", []):
                if alias.startswith("CVE-"):
                    osv_vuln_ids.add(alias)

    filtered = {}
    patched = []
    for cve_id, info in cve_results.items():
        if cve_id in osv_vuln_ids:
            # OSV confirms this CVE still affects this distro+version
            filtered[cve_id] = info
            info["backport_status"] = "vulnerable"
        else:
            # CVE not in OSV results = likely patched by distro
            patched.append(cve_id)
            # Optionally still include with annotation:
            info["backport_status"] = "likely_patched"
            filtered[cve_id] = info

    return filtered, patched
```

**Network call (stdlib only — no new dependencies):**

```python
import json
import urllib.request

def query_osv_batch(queries):
    """Query OSV.dev batch API. Returns parsed response dict.

    queries: list of {"package": {"name": ..., "ecosystem": ...}, "version": ...}
    """
    body = json.dumps({"queries": queries}).encode()
    req = urllib.request.Request(
        "https://api.osv.dev/v1/querybatch",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())
```

### Component 3: CPE-to-distro-package-name mapping (small, critical)

**What:** A JSON mapping from NVD CPE vendor:product pairs to distro package
names. Without this, we can't query distro advisory databases because NVD says
`apache:http_server` while Debian says `apache2` and RHEL says `httpd`.

**Where:** New file `extra/cpe-distro-map.json`, loaded alongside
`product-aliases.json`.

**Format:**

```json
{
  "openbsd:openssh": {
    "debian": "openssh",
    "ubuntu": "openssh",
    "rhel": "openssh",
    "alpine": "openssh"
  },
  "apache:http_server": {
    "debian": "apache2",
    "ubuntu": "apache2",
    "rhel": "httpd",
    "alpine": "apache2"
  },
  "openssl:openssl": {
    "debian": "openssl",
    "ubuntu": "openssl",
    "rhel": "openssl",
    "alpine": "openssl"
  },
  "isc:bind": {
    "debian": "bind9",
    "ubuntu": "bind9",
    "rhel": "bind",
    "alpine": "bind"
  },
  "nginx:nginx": {
    "debian": "nginx",
    "ubuntu": "nginx",
    "rhel": "nginx",
    "alpine": "nginx"
  }
}
```

**Size:** Start with ~50 entries covering the most commonly scanned services.
Grow organically. For packages where NVD name == distro name (the majority),
no entry is needed — the code falls back to using the NVD product name as-is.

### Component 4: Offline backport database (medium effort, for airgapped use)

**What:** Pre-download distro advisory data into a local SQLite table so scans
can filter backports without network access.

**Where:** New `update-distro-db` subcommand in `cvescan.py` that fetches data
from:

1. **Debian Security Tracker** — bulk JSON dump (~29MB) from
   `https://security-tracker.debian.org/tracker/data/json`
2. **Red Hat Security API** — REST at
   `https://access.redhat.com/hydra/rest/securitydata/cve.json` (paginated)
3. **Alpine SecDB** — small JSON files per version from
   `https://secdb.alpinelinux.org/`

**New table in `cve.db`:**

```sql
CREATE TABLE IF NOT EXISTS distro_backports (
    cve_id TEXT NOT NULL,
    distro TEXT NOT NULL,        -- 'debian', 'ubuntu', 'rhel', 'alpine'
    release TEXT NOT NULL,       -- '12', '22.04', '9', '3.20'
    package TEXT NOT NULL,       -- distro package name
    fixed_version TEXT,          -- distro-native version string where fix landed
    status TEXT NOT NULL,        -- 'resolved', 'open', 'not-affected'
    PRIMARY KEY (cve_id, distro, release, package)
);

CREATE INDEX IF NOT EXISTS idx_backports_pkg
    ON distro_backports(package, distro, release);
```

**Why a separate table in the same DB (not a separate DB):**
- Single `cve.db` file to manage
- Can JOIN with existing `cves` table for enrichment
- `update-distro-db` can be run independently of NVD updates

---

## Output format extension

Each CVE entry gains an optional `backport_status` field:

```json
{
  "cve_id": "CVE-2024-6387",
  "cvss_v2": 7.5,
  "cvss_v3": 8.1,
  "backport_status": "likely_patched",
  "distro_fixed_version": "1:9.2p1-2+deb12u3"
}
```

Possible values:
- `"vulnerable"` — OSV/distro DB confirms this version is still affected
- `"likely_patched"` — NVD says vulnerable but distro advisory says fixed
- `null` / absent — no distro context available (NVD-only match)

The `total_cves` field continues to reflect all NVD matches. A new
`total_patched` field shows how many were filtered:

```json
{
  "product": "openssh",
  "version": "9.2",
  "total_cves": 52,
  "total_patched": 48,
  "distro": {"family": "debian", "release": "12"},
  "cves": [...]
}
```

Table format adds a column:

```
[ssh-22] openssh 9.2p1 (Debian 12 detected)
  Total CVEs: 52 (48 likely patched by distro)
  CVE ID               CVSSv2  CVSSv3 ExploitDB Metasploit  Status
  ---------------------------------------------------------------
  CVE-2024-6387           7.5    8.1       Yes         No  VULNERABLE
  CVE-2023-48795          5.0    5.9        No         No  PATCHED
```

---

## Version comparison for distro packages

Filtering backports requires comparing distro-native version strings, not
upstream versions.

**dpkg version comparison** (~50 lines of Python):
- Format: `[epoch:]upstream_version[-debian_revision]`
- `~` sorts before everything (pre-release: `1.0~rc1 < 1.0`)
- Numeric segments compared numerically, alpha segments by byte value
- Already well-specified: `man deb-version`

**RPM version comparison** (~40 lines of Python):
- Split into maximal runs of same-type chars (digits or letters)
- Numeric segments always beat alphabetic
- Separators ignored

These are only needed for Component 4 (offline DB comparison). Component 2
(OSV.dev) handles version comparison server-side.

---

## Integration into `scan_service()` flow

```python
def scan_service(cur, service, aliases, maxcve, cache=None,
                 distro_check=False, offline=False, osv_cache=None):
    # ... existing product/version resolution ...

    # NEW: Detect distro from banner or explicit fields
    distro_info = None
    if distro_check:
        if service.get("distro"):
            distro_info = {
                "family": service["distro"],
                "release": service.get("distro_release"),
                "pkg_version": service.get("distro_package_version"),
            }
        elif service.get("banner"):
            distro_info = detect_distro(service["banner"])

    # ... existing find_vulnerabilities() + rank_cves() ...

    # NEW: Post-filter with backport data
    if distro_info and all_vulns:
        if offline:
            all_vulns, patched = filter_from_local_db(
                cur, all_vulns, product, distro_info
            )
        else:
            all_vulns, patched = filter_from_osv(
                all_vulns, product, distro_info, osv_cache
            )
        result["total_patched"] = len(patched)
        result["distro"] = distro_info

    # ... existing output assembly ...
```

### Key design decisions

1. **`--distro-check` is opt-in** — no behavior change without the flag
2. **Patched CVEs are annotated, not removed** — users see the full picture
3. **OSV.dev is the default online source** — single API, all distros
4. **Offline mode available** — `--offline` uses only local `distro_backports` table
5. **Banner detection is best-effort** — works for Debian/Ubuntu, returns None for RHEL/Alpine
6. **Explicit `distro` fields override banner detection** — for SBOM/inventory
   workflows where the caller knows the target OS

---

## What is NOT done in the NSE script

None of this touches `cvescannerv3.nse`:
- No Lua banner parsing
- No OSV.dev calls from Lua
- No distro_backports table queries from Lua
- No new NSE script arguments
- No changes to NSE output format

The NSE script remains a pure NVD-based upstream version matcher. Users who need
distro-aware results use the standalone tool.

---

## Implementation order

| Step | Component | Effort | Value | Dependencies |
|------|-----------|--------|-------|-------------|
| 1 | Banner parsing (`detect_distro()`) | Small | High | None |
| 2 | CPE-to-distro-package map | Small | Critical | None |
| 3 | OSV.dev batch API integration | Medium | Highest | Steps 1-2 |
| 4 | Output format extension + `--distro-check` CLI flag | Small | High | Step 3 |
| 5 | Offline backport DB + `update-distro-db` + dpkg/rpm version compare | Medium | High | Steps 1-2 |
| 6 | Tests | Medium | High | Steps 1-5 |

Steps 1 and 2 can be done in parallel. Step 3 depends on both.
Step 5 is independent of Step 3 and can be done in parallel.

---

## File changes summary

| File | Action | Description |
|------|--------|-------------|
| `extra/cvescan.py` | **MODIFY** | Add `detect_distro()`, `query_osv_batch()`, `filter_backported_cves()`, `--distro-check`/`--offline` flags, `update-distro-db` subcommand, dpkg/rpm version comparison |
| `extra/cpe-distro-map.json` | **CREATE** | CPE vendor:product → distro package name mapping (~50 entries) |
| `extra/test_cvescan.py` | **MODIFY** | Tests for banner parsing, OSV integration, backport filtering, version comparison |
| `cvescannerv3.nse` | **NO CHANGE** | Not touched |
| `extra/database.py` | **NO CHANGE** | Not touched (distro data uses separate fetch logic) |

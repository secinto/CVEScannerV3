#!/usr/bin/env python3

# SPDX-License-Identifier: GPL-3.0-or-later

# cvescan - Standalone CVE detection/association engine.

# Copyright (C) 2021-2025 Sergio Chica Manjarrez @ pervasive.it.uc3m.es.
# Universidad Carlos III de Madrid.

# This file is part of CVEScannerV3.

# CVEScannerV3 is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# CVEScannerV3 is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import argparse
import json
import re
import sqlite3 as sql
import sys
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

VERSION = "3.4"


# ---------------------------------------------------------------------------
# Version parsing & comparison (ported from cvescannerv3.nse)
# ---------------------------------------------------------------------------

def remove_alpha(s):
    """Strip trailing alpha characters from a version component.
    Returns (numeric_str, alpha_str).
    Mirrors Lua remove_alpha().
    """
    m = re.match(r"([\d.]+)(\w*)", s)
    if m:
        return m.group(1), m.group(2)
    return s, ""


def compare_version(v1, v2):
    """Compare two version strings numerically.
    Returns -1, 0, or 1.
    Mirrors Lua compare_version().
    """
    v1_num, _ = remove_alpha(v1)
    v2_num, _ = remove_alpha(v2)
    parts1 = v1_num.split(".")
    parts2 = v2_num.split(".")
    max_len = max(len(parts1), len(parts2))
    for i in range(max_len):
        n1 = int(parts1[i]) if i < len(parts1) and parts1[i].isdigit() else 0
        n2 = int(parts2[i]) if i < len(parts2) and parts2[i].isdigit() else 0
        if n1 < n2:
            return -1
        elif n1 > n2:
            return 1
    return 0


def parse_version(version):
    """Parse a version string into a structured dict.
    Mirrors Lua version_parser().

    Returns dict with keys: ver, vup, from_, to_, empty, range_
    """
    if not version:
        return {"ver": "*", "vup": "*", "from_": None, "to_": None,
                "empty": True, "range_": False}

    # Strip nmap platform markers (mirrors Lua: version:gsub('for_windows_', ''))
    version = version.replace("for_windows_", "")

    # Range patterns: "3.x - 4.x" or "3.3.x - 3.4.x"
    m = re.match(r"([^-]*)\s+-\s+([^-]*)", version)
    if m:
        p1, p2 = m.group(1), m.group(2)
        if p1 and p2:
            m1 = re.match(r"([^a-zA-Z]*)(.*)", p1)
            m2 = re.match(r"([^a-zA-Z]*)(.*)", p2)
            from_v = m1.group(1) + m1.group(2)
            to_v = m2.group(1) + m2.group(2)
            return {"ver": None, "vup": None, "from_": from_v, "to_": to_v,
                    "empty": False, "range_": True}

    # Simple versions: "4.3" | "4.3p1" | "4.3.1sp1"
    m = re.match(r"([\d.]*)(.*)", version)
    if m and m.group(1):
        ver = m.group(1)
        vup = m.group(2) if m.group(2) else "*"
        return {"ver": ver, "vup": vup, "from_": None, "to_": None,
                "empty": False, "range_": False}

    return {"ver": "*", "vup": "*", "from_": None, "to_": None,
            "empty": True, "range_": False}


def parse_cpe(cpe_str):
    """Extract product, version from a CPE string.
    Handles both cpe:/a:vendor:product:version and cpe:/a:vendor:product formats.
    Mirrors Lua cpe_parser().

    Returns (product, version_info_dict).
    """
    parts = cpe_str.split(":")
    # parts: [cpe, /a, vendor, product, version?, ...]
    product = parts[3] if len(parts) > 3 else None
    version = parts[4] if len(parts) > 4 else None
    if product is None:
        return None, None
    info = parse_version(version)
    return product, info


# ---------------------------------------------------------------------------
# CVE matching logic (ported from cvescannerv3.nse)
# ---------------------------------------------------------------------------

def _default_version(version, default):
    """Mirrors Lua default_version()."""
    if version is None or version == "-":
        return default
    return version


def match_exact_versions(candidates, from_v, to_v, upd, result):
    """Filter exact-match CVE candidates against target version.
    Mirrors Lua scoped_versions().

    candidates: list of dicts with keys: id, cvss_v2, cvss_v3, version,
                version_update, exploitdb, metasploit
    from_v, to_v: version boundaries (equal for exact match)
    upd: version update string
    result: dict to populate {cve_id: {cvss_v2, cvss_v3, exploitdb, metasploit}}
    """
    for v in candidates:
        pr_v = _default_version(v["version"], "0")
        pr_vu = _default_version(v["version_update"], "*")
        if from_v != to_v:
            # Range mode
            if ((compare_version(pr_v, from_v) >= 0
                 or compare_version(pr_v + pr_vu, from_v) >= 0)
                and (compare_version(pr_v, to_v) <= 0
                     or compare_version(pr_v + pr_vu, to_v) <= 0)):
                if v["id"] not in result:
                    result[v["id"]] = {
                        "cvss_v2": v["cvss_v2"], "cvss_v3": v["cvss_v3"],
                        "exploitdb": v["exploitdb"],
                        "metasploit": v["metasploit"],
                    }
        else:
            # Exact match mode
            if ((compare_version(pr_v, from_v) == 0
                 and (pr_vu == upd or upd == "*"))
                or (compare_version(pr_v + pr_vu, from_v) == 0
                    and (pr_vu == "*" or upd == "*"))):
                if v["id"] not in result:
                    result[v["id"]] = {
                        "cvss_v2": v["cvss_v2"], "cvss_v3": v["cvss_v3"],
                        "exploitdb": v["exploitdb"],
                        "metasploit": v["metasploit"],
                    }


def match_range_versions(candidates, from_v, to_v, result):
    """Filter range-match CVE candidates against target version.
    Mirrors Lua scoped_multi_versions().

    candidates: list of dicts with keys: id, cvss_v2, cvss_v3,
                start_inc, start_exc, end_inc, end_exc, exploitdb, metasploit
    from_v, to_v: target version boundaries
    result: dict to populate
    """
    is_range_search = "." in from_v and ".9999999999" in to_v

    for v in candidates:
        st_in = _default_version(v["start_inc"], "0")
        st_ex = _default_version(v["start_exc"], "0")
        en_in = _default_version(v["end_inc"], "9999999999")
        en_ex = _default_version(v["end_exc"], "9999999999")

        if is_range_search:
            if ((compare_version(st_in, from_v) >= 0
                 or compare_version(st_ex, from_v) > 0)
                and (compare_version(en_in, to_v) <= 0
                     or compare_version(en_ex, to_v) < 0)):
                if v["id"] not in result:
                    result[v["id"]] = {
                        "cvss_v2": v["cvss_v2"], "cvss_v3": v["cvss_v3"],
                        "exploitdb": v["exploitdb"],
                        "metasploit": v["metasploit"],
                    }
        else:
            if (compare_version(from_v, st_in) >= 0
                and compare_version(from_v, st_ex) > 0
                and compare_version(to_v, en_in) <= 0
                    and compare_version(to_v, en_ex) < 0):
                if v["id"] not in result:
                    result[v["id"]] = {
                        "cvss_v2": v["cvss_v2"], "cvss_v3": v["cvss_v3"],
                        "exploitdb": v["exploitdb"],
                        "metasploit": v["metasploit"],
                    }


def rank_cves(cves):
    """Sort CVE result dict by CVSS score (v3 preferred, then v2).
    Returns sorted list of (cve_id, info_dict) tuples.
    Mirrors Lua cvss_comparator().
    """
    def sort_key(item):
        info = item[1]
        v3 = _to_float(info.get("cvss_v3"))
        v2 = _to_float(info.get("cvss_v2"))
        best = v3 if v3 is not None else v2
        return -(best if best is not None else -1)

    return sorted(cves.items(), key=sort_key)


def _to_float(val):
    if val is None or val == "-":
        return None
    try:
        return float(val)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Database queries
# ---------------------------------------------------------------------------

QUERY_MULTIAFFECTED = """
    SELECT multiaffected.cve_id, cves.cvss_v2, cves.cvss_v3,
           multiaffected.versionStartIncluding, multiaffected.versionStartExcluding,
           multiaffected.versionEndIncluding, multiaffected.versionEndExcluding,
           (SELECT EXISTS (SELECT 1 FROM referenced_exploit
            WHERE cve_id = multiaffected.cve_id)) as edb,
           (SELECT EXISTS (SELECT 1 FROM referenced_metasploit
            WHERE cve_id = multiaffected.cve_id)) as msf
    FROM multiaffected
    INNER JOIN cves ON multiaffected.cve_id = cves.cve_id
    WHERE product_id IN
          (SELECT product_id FROM products WHERE product = ? AND version = '*')
"""

QUERY_MULTIAFFECTED_EMPTY = """
    SELECT multiaffected.cve_id, cves.cvss_v2, cves.cvss_v3,
           (SELECT EXISTS (SELECT 1 FROM referenced_exploit
            WHERE cve_id = multiaffected.cve_id)) as edb,
           (SELECT EXISTS (SELECT 1 FROM referenced_metasploit
            WHERE cve_id = multiaffected.cve_id)) as msf
    FROM multiaffected
    INNER JOIN cves ON multiaffected.cve_id = cves.cve_id
    WHERE product_id IN
          (SELECT product_id FROM products
           WHERE product = ? AND version = '*' AND version_update = '*')
    AND versionStartIncluding IS NULL AND versionStartExcluding IS NULL
    AND versionEndIncluding IS NULL AND versionEndExcluding IS NULL
"""

QUERY_AFFECTED = """
    SELECT affected.cve_id, cves.cvss_v2, cves.cvss_v3,
           products.version, products.version_update,
           (SELECT EXISTS (SELECT 1 FROM referenced_exploit
            WHERE cve_id = affected.cve_id)) as edb,
           (SELECT EXISTS (SELECT 1 FROM referenced_metasploit
            WHERE cve_id = affected.cve_id)) as msf
    FROM products
    INNER JOIN affected ON products.product_id = affected.product_id
    INNER JOIN cves ON affected.cve_id = cves.cve_id
    WHERE products.product = ?
"""

QUERY_EXPLOIT_INFO = """
    SELECT exploits.exploit_id, exploits.name
    FROM referenced_exploit
    INNER JOIN exploits ON referenced_exploit.exploit_id = exploits.exploit_id
    WHERE referenced_exploit.cve_id = ?
"""

QUERY_METASPLOIT_INFO = """
    SELECT metasploits.name
    FROM referenced_metasploit
    INNER JOIN metasploits
        ON referenced_metasploit.metasploit_id = metasploits.metasploit_id
    WHERE referenced_metasploit.cve_id = ?
"""


def get_exploit_info(cur, cve_id):
    """Fetch ExploitDB and Metasploit references for a CVE."""
    exploits = []
    cur.execute(QUERY_EXPLOIT_INFO, [cve_id])
    for exploit_id, name in cur.fetchall():
        exploits.append({
            "id": int(exploit_id),
            "name": name,
            "url": f"https://www.exploit-db.com/exploits/{exploit_id}",
        })

    metasploits = []
    cur.execute(QUERY_METASPLOIT_INFO, [cve_id])
    for (name,) in cur.fetchall():
        metasploits.append({"name": name})

    return exploits, metasploits


def find_vulnerabilities(cur, product, version_info):
    """Main CVE lookup for a single product/version.
    Mirrors Lua vulnerabilities() — queries both affected and multiaffected tables.

    Returns dict {cve_id: {cvss_v2, cvss_v3, exploitdb, metasploit}}.
    """
    from_v = version_info["ver"]
    to_v = version_info["ver"]
    upd = version_info["vup"]

    if not version_info["empty"]:
        if version_info["range_"]:
            from_v = version_info["from_"].replace("x", "0").replace("X", "0")
            to_v = version_info["to_"].replace("x", "9999999999").replace("X", "9999999999")
    vulns = {}

    if version_info["empty"]:
        # When version is unknown, only match multiaffected entries
        # that have no version boundaries at all
        cur.execute(QUERY_MULTIAFFECTED_EMPTY, [product])
        for row in cur.fetchall():
            cve_id, cvss_v2, cvss_v3, edb, msf = row
            if cve_id not in vulns:
                vulns[cve_id] = {
                    "cvss_v2": cvss_v2, "cvss_v3": cvss_v3,
                    "exploitdb": edb, "metasploit": msf,
                }
    else:
        # Query multiaffected (version ranges)
        cur.execute(QUERY_MULTIAFFECTED, [product])
        multi_candidates = []
        for row in cur.fetchall():
            cve_id, cvss_v2, cvss_v3, st_in, st_ex, en_in, en_ex, edb, msf = row
            multi_candidates.append({
                "id": cve_id, "cvss_v2": cvss_v2, "cvss_v3": cvss_v3,
                "start_inc": st_in, "start_exc": st_ex,
                "end_inc": en_in, "end_exc": en_ex,
                "exploitdb": edb, "metasploit": msf,
            })
        match_range_versions(multi_candidates, from_v, to_v, vulns)

        # Query affected (exact versions)
        cur.execute(QUERY_AFFECTED, [product])
        exact_candidates = []
        for row in cur.fetchall():
            cve_id, cvss_v2, cvss_v3, ver, vupdate, edb, msf = row
            exact_candidates.append({
                "id": cve_id, "cvss_v2": cvss_v2, "cvss_v3": cvss_v3,
                "version": ver, "version_update": vupdate,
                "exploitdb": edb, "metasploit": msf,
            })
        match_exact_versions(exact_candidates, from_v, to_v, upd, vulns)

    return vulns


def resolve_aliases(product, aliases):
    """Return list of all product names to query (original + aliases).
    Mirrors Lua add_cpe_aliases().
    """
    names = [product]
    if aliases and product in aliases:
        names.extend(aliases[product])
    return names


# ---------------------------------------------------------------------------
# High-level scan orchestration
# ---------------------------------------------------------------------------

def scan_service(cur, service, aliases, maxcve, cache=None):
    """Scan a single service entry and return a result dict.

    cache: optional dict shared across services to avoid re-querying the same
           product|version|vupdate combination.  Mirrors Lua registry.cache.
    """
    if cache is None:
        cache = {}

    # Resolve product and version info
    if "cpe" in service and service["cpe"]:
        product, version_info = parse_cpe(service["cpe"])
        # Allow explicit overrides
        if "product" in service and service["product"]:
            product = service["product"]
        if "version" in service and service["version"] is not None:
            version_info = parse_version(service["version"])
            if "version_update" in service and service["version_update"]:
                version_info["vup"] = service["version_update"]
    elif "product" in service and service["product"]:
        product = service["product"]
        version_info = parse_version(service.get("version"))
        if "version_update" in service and service["version_update"]:
            version_info["vup"] = service["version_update"]
    else:
        return None

    # Determine version display strings
    if version_info["range_"]:
        ver_display = f"{version_info['from_']} - {version_info['to_']}"
        vup_display = "*"
    else:
        ver_display = version_info["ver"]
        vup_display = version_info["vup"]

    # Query for all product name variants (original + aliases)
    all_products = resolve_aliases(product, aliases)
    all_vulns = {}

    for prod_name in all_products:
        cache_key = f"{prod_name}|{ver_display}|{vup_display}"
        if cache_key in cache:
            all_vulns.update(cache[cache_key])
            continue
        prod_vulns = find_vulnerabilities(cur, prod_name, version_info)
        cache[cache_key] = prod_vulns
        all_vulns.update(prod_vulns)

    # Sort by CVSS score
    sorted_cves = rank_cves(all_vulns)

    # Apply maxcve limit
    if maxcve and maxcve > 0:
        sorted_cves = sorted_cves[:maxcve]

    # Build detailed CVE list with exploit info
    cve_list = []
    for cve_id, info in sorted_cves:
        exploits, metasploits = get_exploit_info(cur, cve_id)
        cve_entry = {
            "cve_id": cve_id,
            "cvss_v2": _to_float(info["cvss_v2"]),
            "cvss_v3": _to_float(info["cvss_v3"]),
        }
        if exploits:
            cve_entry["exploitdb"] = exploits
        if metasploits:
            cve_entry["metasploit"] = metasploits
        cve_list.append(cve_entry)

    result = {
        "product": product,
        "version": ver_display,
        "version_update": vup_display,
        "total_cves": len(all_vulns),
        "cves": cve_list,
    }
    if "id" in service:
        result["id"] = service["id"]
    if "cpe" in service:
        result["cpe"] = service["cpe"]
    return result


def run_scan(db_path, services, aliases=None, maxcve=0):
    """Run CVE scan for a list of service dicts.

    Returns the full output dict with metadata and results.
    """
    results = []
    cache = {}  # shared across all services (mirrors Lua registry.cache)
    with closing(sql.connect(db_path)) as conn:
        with closing(conn.cursor()) as cur:
            for service in services:
                result = scan_service(cur, service, aliases, maxcve, cache)
                if result is not None:
                    results.append(result)

    return {
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "database": str(db_path),
            "version": VERSION,
        },
        "results": results,
    }


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def format_table(output):
    """Format scan output as a human-readable table."""
    lines = []
    meta = output["metadata"]
    lines.append(f"Database: {meta['database']}")
    lines.append(f"Timestamp: {meta['timestamp']}")
    lines.append("")

    for result in output["results"]:
        header = result["product"]
        if result.get("id"):
            header = f"[{result['id']}] {header}"
        header += f" {result['version']}"
        if result["version_update"] != "*":
            header += result["version_update"]
        lines.append(header)
        lines.append(f"  Total CVEs: {result['total_cves']}")

        if result["cves"]:
            lines.append(
                f"  {'CVE ID':<20s} {'CVSSv2':>6s} {'CVSSv3':>6s}"
                f" {'ExploitDB':>9s} {'Metasploit':>10s}"
            )
            lines.append("  " + "-" * 55)
            for cve in result["cves"]:
                v2 = f"{cve['cvss_v2']:.1f}" if cve["cvss_v2"] is not None else "-"
                v3 = f"{cve['cvss_v3']:.1f}" if cve["cvss_v3"] is not None else "-"
                edb = "Yes" if cve.get("exploitdb") else "No"
                msf = "Yes" if cve.get("metasploit") else "No"
                lines.append(
                    f"  {cve['cve_id']:<20s} {v2:>6s} {v3:>6s}"
                    f" {edb:>9s} {msf:>10s}"
                )
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# db-info command
# ---------------------------------------------------------------------------

def cmd_db_info(args):
    """Show database metadata and statistics."""
    db_path = args.cve
    if not Path(db_path).is_file():
        print(f"Error: Database file not found: {db_path}", file=sys.stderr)
        sys.exit(1)

    with closing(sql.connect(db_path)) as conn:
        with closing(conn.cursor()) as cur:
            try:
                cur.execute("SELECT last_mod FROM metadata")
                row = cur.fetchone()
                last_mod = row[0] if row else "unknown"
            except sql.OperationalError:
                last_mod = "unknown"

            counts = {}
            for table in ("products", "cves", "exploits", "metasploits"):
                try:
                    cur.execute(f"SELECT COUNT(*) FROM {table}")  # noqa: S608
                    counts[table] = cur.fetchone()[0]
                except sql.OperationalError:
                    counts[table] = 0

            try:
                cur.execute(
                    "SELECT COUNT(*) FROM exploits WHERE name IS NOT NULL"
                )
                exploits_named = cur.fetchone()[0]
            except sql.OperationalError:
                exploits_named = 0

    print(f"Database:     {db_path}")
    print(f"Last updated: {last_mod}")
    print(f"Products:     {counts['products']:,}")
    print(f"CVEs:         {counts['cves']:,}")
    print(f"Exploits:     {counts['exploits']:,} (with names: {exploits_named:,})")
    print(f"Metasploit:   {counts['metasploits']:,}")


# ---------------------------------------------------------------------------
# update-db command
# ---------------------------------------------------------------------------

def _read_api_key_file():
    """Read NVD API key from .api file (same logic as database.py)."""
    api_file = Path(".api")
    if api_file.is_file():
        return api_file.read_text().strip()
    return None


def cmd_update_db(args):
    """Create or update the CVE database."""
    # Resolve API key: --api-key > .api file > NVD_KEY env var
    import os
    api_key = args.api_key or _read_api_key_file() or os.getenv("NVD_KEY")
    if not api_key:
        print(
            "Error: NVD API key required. Provide via --api-key, "
            ".api file, or NVD_KEY environment variable.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Import and delegate to database module
    try:
        from database import run_update
    except ImportError:
        # Handle running from project root vs extra/ directory
        sys.path.insert(0, str(Path(__file__).parent))
        from database import run_update

    try:
        run_update(
            database=Path(args.cve),
            api_key=api_key,
            noscrape=args.no_scrape,
            full=args.full,
        )
    except Exception as e:
        print(f"Error updating database: {e}", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# scan command
# ---------------------------------------------------------------------------

def cmd_scan(args):
    """Run CVE scan."""
    db_path = args.cve
    if not Path(db_path).is_file():
        print(f"Error: Database file not found: {db_path}", file=sys.stderr)
        sys.exit(1)

    # Load aliases
    aliases = None
    if args.aliases and Path(args.aliases).is_file():
        with open(args.aliases) as f:
            aliases = json.load(f)

    # Build services list from input
    services = None

    if args.input:
        # JSON file or stdin
        if args.input == "-":
            data = json.load(sys.stdin)
        else:
            with open(args.input) as f:
                data = json.load(f)
        services = data.get("services", [])
    elif args.cpe:
        services = [{"cpe": args.cpe}]
    elif args.product:
        svc = {"product": args.product}
        if args.version:
            svc["version"] = args.version
        if args.update:
            svc["version_update"] = args.update
        services = [svc]
    else:
        # Try reading from stdin if it's not a terminal
        if not sys.stdin.isatty():
            data = json.load(sys.stdin)
            services = data.get("services", [])
        else:
            print(
                "Error: Provide input via -i/--input, --cpe, -p/--product, "
                "or pipe JSON to stdin.",
                file=sys.stderr,
            )
            sys.exit(1)

    if not services:
        print("Error: No services to scan.", file=sys.stderr)
        sys.exit(1)

    # Run scan
    output = run_scan(db_path, services, aliases=aliases, maxcve=args.maxcve)

    # Format output
    if args.format == "table":
        text = format_table(output)
    else:
        text = json.dumps(output, indent=2)

    # Write output
    if args.output:
        with open(args.output, "w") as f:
            f.write(text)
            f.write("\n")
    else:
        print(text)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _add_db_arg(subparser):
    """Add the common -c/--cve database path argument to a subparser."""
    subparser.add_argument(
        "-c", "--cve", default="./cve.db",
        help="Path to CVE database (default: ./cve.db)",
    )


def main():
    parser = argparse.ArgumentParser(
        description="CVEScannerV3 — Standalone CVE detection and database management"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # -- scan subcommand --
    scan_parser = subparsers.add_parser(
        "scan", help="Scan services for known CVEs"
    )
    _add_db_arg(scan_parser)
    input_group = scan_parser.add_argument_group("input")
    input_group.add_argument(
        "-i", "--input",
        help="Path to input JSON file (or '-' for stdin)",
    )
    input_group.add_argument(
        "-p", "--product",
        help="Single product name (convenience mode)",
    )
    input_group.add_argument(
        "-v", "--version",
        help="Version string (with -p)",
    )
    input_group.add_argument(
        "-u", "--update",
        help="Version update suffix (with -p)",
    )
    input_group.add_argument(
        "--cpe",
        help="CPE string (convenience mode)",
    )
    scan_parser.add_argument(
        "-a", "--aliases",
        default="extra/product-aliases.json",
        help="Path to product-aliases JSON (default: extra/product-aliases.json)",
    )
    scan_parser.add_argument(
        "--maxcve", type=int, default=0,
        help="Max CVEs per service (0 = unlimited, default: 0)",
    )
    scan_parser.add_argument(
        "-o", "--output",
        help="Output file path (default: stdout)",
    )
    scan_parser.add_argument(
        "--format", choices=["json", "table"], default="json",
        help="Output format (default: json)",
    )

    # -- update-db subcommand --
    update_parser = subparsers.add_parser(
        "update-db", help="Create or update the CVE database"
    )
    _add_db_arg(update_parser)
    update_parser.add_argument(
        "--api-key",
        help="NVD API key (overrides .api file and NVD_KEY env var)",
    )
    update_parser.add_argument(
        "--no-scrape", action="store_true",
        help="Skip ExploitDB name scraping",
    )
    update_parser.add_argument(
        "--full", action="store_true",
        help="Force full database rebuild",
    )

    # -- db-info subcommand --
    dbinfo_parser = subparsers.add_parser(
        "db-info", help="Show database metadata and statistics"
    )
    _add_db_arg(dbinfo_parser)

    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "update-db":
        cmd_update_db(args)
    elif args.command == "db-info":
        cmd_db_info(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()

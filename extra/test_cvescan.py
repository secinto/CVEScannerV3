#!/usr/bin/env python3

"""Tests for cvescan.py — Standalone CVE detection/association engine."""

import json
import sqlite3 as sql
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

# Ensure extra/ is on the path
sys.path.insert(0, str(Path(__file__).parent))

from cvescan import (
    _detect_distro,
    _load_cpe_to_pkg,
    annotate_confidence,
    check_backports,
    compare_version,
    find_vulnerabilities,
    format_table,
    get_exploit_info,
    match_exact_versions,
    match_range_versions,
    parse_cpe,
    parse_version,
    rank_cves,
    resolve_aliases,
    run_scan,
    scan_service,
)
from distro import (
    detect_debian_release,
    detect_distro_from_banner,
    detect_ubuntu_release,
    get_osv_ecosystem,
    get_osv_ecosystem_parts,
)
from dpkg_version import compare_dpkg_versions, parse_dpkg_version


# ---------------------------------------------------------------------------
# Test database helpers
# ---------------------------------------------------------------------------

SCHEMA = """
    CREATE TABLE IF NOT EXISTS metadata (
        id INTEGER PRIMARY KEY,
        last_mod TEXT
    );

    CREATE TABLE IF NOT EXISTS exploits (
        exploit_id INTEGER PRIMARY KEY,
        name TEXT
    );

    CREATE TABLE IF NOT EXISTS metasploits (
        metasploit_id INTEGER PRIMARY KEY,
        name TEXT UNIQUE
    );

    CREATE TABLE IF NOT EXISTS cves (
        cve_id TEXT PRIMARY KEY,
        cvss_v2 TEXT,
        cvss_v3 TEXT,
        published INTEGER
    );

    CREATE TABLE IF NOT EXISTS products (
        product_id INTEGER PRIMARY KEY,
        vendor TEXT,
        product TEXT,
        version TEXT,
        version_update TEXT,
        UNIQUE (vendor, product, version, version_update)
    );

    CREATE TABLE IF NOT EXISTS affected (
        cve_id TEXT,
        product_id INT,
        FOREIGN KEY (cve_id) REFERENCES cves (cve_id),
        FOREIGN KEY (product_id) REFERENCES products (product_id),
        PRIMARY KEY (cve_id, product_id)
    );

    CREATE TABLE IF NOT EXISTS multiaffected (
        cve_id TEXT,
        product_id INT,
        versionStartIncluding TEXT,
        versionStartExcluding TEXT,
        versionEndIncluding TEXT,
        versionEndExcluding TEXT,
        FOREIGN KEY (cve_id) REFERENCES cves (cve_id),
        FOREIGN KEY (product_id) REFERENCES products (product_id),
        PRIMARY KEY (cve_id, product_id,
                     versionStartIncluding, versionStartExcluding,
                     versionEndIncluding, versionEndExcluding)
    );

    CREATE TABLE IF NOT EXISTS referenced_exploit (
        cve_id TEXT,
        exploit_id INTEGER,
        FOREIGN KEY (cve_id) REFERENCES cves (cve_id),
        FOREIGN KEY (exploit_id) REFERENCES exploits (exploit_id),
        PRIMARY KEY (cve_id, exploit_id)
    );

    CREATE TABLE IF NOT EXISTS referenced_metasploit (
        cve_id TEXT,
        metasploit_id INTEGER,
        FOREIGN KEY (cve_id) REFERENCES cves (cve_id),
        FOREIGN KEY (metasploit_id) REFERENCES metasploits (metasploit_id),
        PRIMARY KEY (cve_id, metasploit_id)
    );

    CREATE INDEX IF NOT EXISTS idx_products_product
        ON products(product);
    CREATE INDEX IF NOT EXISTS idx_products_product_version
        ON products(product, version);
    CREATE INDEX IF NOT EXISTS idx_referenced_exploit_cve
        ON referenced_exploit(cve_id);
    CREATE INDEX IF NOT EXISTS idx_referenced_metasploit_cve
        ON referenced_metasploit(cve_id);
    CREATE INDEX IF NOT EXISTS idx_affected_product
        ON affected(product_id);
    CREATE INDEX IF NOT EXISTS idx_multiaffected_product
        ON multiaffected(product_id);

    CREATE TABLE IF NOT EXISTS backports (
        cve_id TEXT NOT NULL,
        distro TEXT NOT NULL,
        release TEXT NOT NULL,
        package TEXT NOT NULL,
        fixed_version TEXT,
        status TEXT NOT NULL,
        UNIQUE (cve_id, distro, release, package)
    );

    CREATE TABLE IF NOT EXISTS backport_metadata (
        id INTEGER PRIMARY KEY,
        ecosystem TEXT NOT NULL UNIQUE,
        last_updated TEXT,
        record_count INTEGER
    );

    CREATE INDEX IF NOT EXISTS idx_backports_cve
        ON backports(cve_id);
    CREATE INDEX IF NOT EXISTS idx_backports_package_release
        ON backports(package, distro, release);
"""


def create_test_db(path=None):
    """Create a test database with sample data. Returns (conn, path)."""
    if path:
        conn = sql.connect(str(path))
    else:
        conn = sql.connect(":memory:")
    conn.executescript(SCHEMA)

    # Insert metadata
    conn.execute("INSERT INTO metadata VALUES (1, '2026-01-01T00:00:00+00:00')")

    # Insert products
    products = [
        # (vendor, product, version, version_update)
        ("openbsd", "openssh", "4.7", "p1"),
        ("openbsd", "openssh", "4.7", "*"),
        ("openbsd", "openssh", "8.0", "*"),
        ("openbsd", "openssh", "9.0", "*"),
        ("openbsd", "openssh", "*", "*"),  # wildcard product for multiaffected
        ("nginx", "nginx", "1.26.3", "*"),
        ("nginx", "nginx", "1.25.0", "*"),
        ("nginx", "nginx", "*", "*"),
        ("oracle", "mysql", "5.5.55", "*"),
        ("oracle", "mysql", "*", "*"),
    ]
    conn.executemany(
        "INSERT OR IGNORE INTO products (vendor, product, version, version_update) "
        "VALUES (?, ?, ?, ?)",
        products,
    )

    # Insert CVEs
    cves = [
        ("CVE-2016-1908", 7.5, 9.8, 2016),
        ("CVE-2018-15473", 5.0, 5.3, 2018),
        ("CVE-2020-1234", 6.0, 7.5, 2020),
        ("CVE-2021-5678", 4.0, None, 2021),
        ("CVE-2022-0001", None, 8.0, 2022),
        ("CVE-2023-1111", 5.0, 6.5, 2023),
        ("CVE-2023-2222", 3.0, 4.0, 2023),
        ("CVE-2024-0001", 7.0, 9.0, 2024),
    ]
    conn.executemany("INSERT OR REPLACE INTO cves VALUES (?, ?, ?, ?)", cves)

    # Insert affected (exact version matches)
    # openssh 4.7p1 affected by CVE-2016-1908
    conn.execute(
        "INSERT OR IGNORE INTO affected VALUES ('CVE-2016-1908', "
        "(SELECT product_id FROM products WHERE product='openssh' AND version='4.7' AND version_update='p1'))"
    )
    # openssh 4.7* affected by CVE-2018-15473
    conn.execute(
        "INSERT OR IGNORE INTO affected VALUES ('CVE-2018-15473', "
        "(SELECT product_id FROM products WHERE product='openssh' AND version='4.7' AND version_update='*'))"
    )
    # nginx 1.26.3 affected by CVE-2023-1111
    conn.execute(
        "INSERT OR IGNORE INTO affected VALUES ('CVE-2023-1111', "
        "(SELECT product_id FROM products WHERE product='nginx' AND version='1.26.3' AND version_update='*'))"
    )
    # mysql 5.5.55 affected by CVE-2021-5678
    conn.execute(
        "INSERT OR IGNORE INTO affected VALUES ('CVE-2021-5678', "
        "(SELECT product_id FROM products WHERE product='mysql' AND version='5.5.55' AND version_update='*'))"
    )

    # Insert multiaffected (version range matches)
    # openssh range: >=4.0 and <9.0 affected by CVE-2020-1234
    conn.execute(
        "INSERT OR IGNORE INTO multiaffected VALUES ('CVE-2020-1234', "
        "(SELECT product_id FROM products WHERE product='openssh' AND version='*'), "
        "'4.0', NULL, NULL, '9.0')"
    )
    # nginx range: >=1.25.0 and <=1.26.5 affected by CVE-2022-0001
    conn.execute(
        "INSERT OR IGNORE INTO multiaffected VALUES ('CVE-2022-0001', "
        "(SELECT product_id FROM products WHERE product='nginx' AND version='*'), "
        "'1.25.0', NULL, '1.26.5', NULL)"
    )
    # openssh: no version boundaries (empty version) affected by CVE-2023-2222
    conn.execute(
        "INSERT OR IGNORE INTO multiaffected VALUES ('CVE-2023-2222', "
        "(SELECT product_id FROM products WHERE product='openssh' AND version='*' AND version_update='*'), "
        "NULL, NULL, NULL, NULL)"
    )

    # Insert exploits
    conn.execute("INSERT OR IGNORE INTO exploits VALUES (40888, 'OpenSSH < 7.4 - Agent Protocol Arbitrary Library Loading')")
    conn.execute("INSERT OR IGNORE INTO referenced_exploit VALUES ('CVE-2016-1908', 40888)")

    # Insert metasploit
    conn.execute("INSERT OR IGNORE INTO metasploits VALUES (1, 'exploit/multi/ssh/sshexec')")
    conn.execute("INSERT OR IGNORE INTO referenced_metasploit VALUES ('CVE-2016-1908', 1)")

    # Insert backport data
    backports = [
        # CVE-2020-1234 fixed in Debian 12 openssh at version 1:4.7p1-2+deb12u3
        ("CVE-2020-1234", "Debian", "12", "openssh", "1:4.7p1-2+deb12u3", "fixed"),
        # CVE-2018-15473 fixed in Debian 12 openssh at version 1:4.7p1-2+deb12u1
        ("CVE-2018-15473", "Debian", "12", "openssh", "1:4.7p1-2+deb12u1", "fixed"),
        # CVE-2016-1908 still affected (no fix)
        ("CVE-2016-1908", "Debian", "12", "openssh", None, "affected"),
        # CVE-2023-1111 fixed in Debian 12 nginx
        ("CVE-2023-1111", "Debian", "12", "nginx", "1.22.1-9+deb12u1", "fixed"),
    ]
    conn.executemany(
        "INSERT OR REPLACE INTO backports "
        "(cve_id, distro, release, package, fixed_version, status) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        backports,
    )
    conn.execute(
        "INSERT OR REPLACE INTO backport_metadata VALUES (1, 'Debian:12', '2026-01-01T00:00:00', 4)"
    )

    conn.commit()
    return conn


# ---------------------------------------------------------------------------
# Tests: Version parsing and comparison
# ---------------------------------------------------------------------------

class TestCompareVersion(unittest.TestCase):
    def test_equal(self):
        self.assertEqual(compare_version("4.7", "4.7"), 0)

    def test_less(self):
        self.assertEqual(compare_version("4.6", "4.7"), -1)

    def test_greater(self):
        self.assertEqual(compare_version("4.8", "4.7"), 1)

    def test_different_lengths(self):
        self.assertEqual(compare_version("4.7.1", "4.7"), 1)
        self.assertEqual(compare_version("4.7", "4.7.1"), -1)

    def test_alpha_stripped(self):
        self.assertEqual(compare_version("4.7p1", "4.7"), 0)
        self.assertEqual(compare_version("4.7p1", "4.8"), -1)

    def test_multi_part(self):
        self.assertEqual(compare_version("1.25.0", "1.26.3"), -1)
        self.assertEqual(compare_version("1.26.5", "1.26.3"), 1)
        self.assertEqual(compare_version("1.26.3", "1.26.3"), 0)

    def test_zero_padding(self):
        self.assertEqual(compare_version("0", "0"), 0)
        self.assertEqual(compare_version("0", "1"), -1)
        self.assertEqual(compare_version("9999999999", "0"), 1)


class TestParseVersion(unittest.TestCase):
    def test_empty(self):
        info = parse_version(None)
        self.assertTrue(info["empty"])
        self.assertFalse(info["range_"])
        self.assertEqual(info["ver"], "*")

    def test_empty_string(self):
        info = parse_version("")
        self.assertTrue(info["empty"])

    def test_simple(self):
        info = parse_version("4.7")
        self.assertEqual(info["ver"], "4.7")
        self.assertEqual(info["vup"], "*")
        self.assertFalse(info["empty"])
        self.assertFalse(info["range_"])

    def test_with_update(self):
        info = parse_version("4.7p1")
        self.assertEqual(info["ver"], "4.7")
        self.assertEqual(info["vup"], "p1")

    def test_range(self):
        info = parse_version("3.x - 4.x")
        self.assertTrue(info["range_"])
        self.assertEqual(info["from_"], "3.x")
        self.assertEqual(info["to_"], "4.x")

    def test_range_detailed(self):
        info = parse_version("3.3.x - 3.4.x")
        self.assertTrue(info["range_"])
        self.assertEqual(info["from_"], "3.3.x")
        self.assertEqual(info["to_"], "3.4.x")

    def test_for_windows_stripped(self):
        info = parse_version("4.7for_windows_p1")
        self.assertEqual(info["ver"], "4.7")
        self.assertEqual(info["vup"], "p1")

    def test_for_windows_stripped_simple(self):
        info = parse_version("for_windows_4.7")
        self.assertEqual(info["ver"], "4.7")
        self.assertEqual(info["vup"], "*")


class TestParseCpe(unittest.TestCase):
    def test_full_cpe(self):
        product, info = parse_cpe("cpe:/a:openbsd:openssh:4.7p1")
        self.assertEqual(product, "openssh")
        self.assertEqual(info["ver"], "4.7")
        self.assertEqual(info["vup"], "p1")

    def test_cpe_no_version(self):
        product, info = parse_cpe("cpe:/a:openbsd:openssh")
        self.assertEqual(product, "openssh")
        self.assertTrue(info["empty"])

    def test_cpe_simple_version(self):
        product, info = parse_cpe("cpe:/a:nginx:nginx:1.26.3")
        self.assertEqual(product, "nginx")
        self.assertEqual(info["ver"], "1.26.3")
        self.assertEqual(info["vup"], "*")


# ---------------------------------------------------------------------------
# Tests: Version matching
# ---------------------------------------------------------------------------

class TestMatchExactVersions(unittest.TestCase):
    def setUp(self):
        self.candidates = [
            {"id": "CVE-A", "cvss_v2": 5.0, "cvss_v3": 7.0,
             "version": "4.7", "version_update": "p1",
             "exploitdb": 0, "metasploit": 0},
            {"id": "CVE-B", "cvss_v2": 3.0, "cvss_v3": 4.0,
             "version": "4.7", "version_update": "*",
             "exploitdb": 0, "metasploit": 0},
            {"id": "CVE-C", "cvss_v2": 6.0, "cvss_v3": 8.0,
             "version": "4.8", "version_update": "*",
             "exploitdb": 0, "metasploit": 0},
        ]

    def test_exact_match_with_update(self):
        result = {}
        match_exact_versions(self.candidates, "4.7", "4.7", "p1", result)
        self.assertIn("CVE-A", result)
        self.assertIn("CVE-B", result)  # wildcard update matches
        self.assertNotIn("CVE-C", result)

    def test_exact_match_wildcard_update(self):
        result = {}
        match_exact_versions(self.candidates, "4.7", "4.7", "*", result)
        self.assertIn("CVE-A", result)
        self.assertIn("CVE-B", result)
        self.assertNotIn("CVE-C", result)

    def test_no_match(self):
        result = {}
        match_exact_versions(self.candidates, "5.0", "5.0", "*", result)
        self.assertEqual(len(result), 0)

    def test_range_mode(self):
        result = {}
        match_exact_versions(self.candidates, "4.6", "4.9", "*", result)
        self.assertIn("CVE-A", result)
        self.assertIn("CVE-B", result)
        self.assertIn("CVE-C", result)


class TestMatchRangeVersions(unittest.TestCase):
    def setUp(self):
        self.candidates = [
            # CVE for range >=4.0 and <9.0
            {"id": "CVE-R1", "cvss_v2": 6.0, "cvss_v3": 7.5,
             "start_inc": "4.0", "start_exc": None,
             "end_inc": None, "end_exc": "9.0",
             "exploitdb": 0, "metasploit": 0},
            # CVE for range >=1.25.0 and <=1.26.5
            {"id": "CVE-R2", "cvss_v2": None, "cvss_v3": 8.0,
             "start_inc": "1.25.0", "start_exc": None,
             "end_inc": "1.26.5", "end_exc": None,
             "exploitdb": 0, "metasploit": 0},
        ]

    def test_within_range(self):
        result = {}
        match_range_versions(self.candidates, "4.7", "4.7", result)
        self.assertIn("CVE-R1", result)
        self.assertNotIn("CVE-R2", result)

    def test_at_start_boundary_inclusive(self):
        result = {}
        match_range_versions(self.candidates, "4.0", "4.0", result)
        self.assertIn("CVE-R1", result)

    def test_below_range(self):
        result = {}
        match_range_versions(self.candidates, "3.9", "3.9", result)
        self.assertNotIn("CVE-R1", result)

    def test_at_end_boundary_exclusive(self):
        result = {}
        match_range_versions(self.candidates, "9.0", "9.0", result)
        self.assertNotIn("CVE-R1", result)

    def test_nginx_range(self):
        result = {}
        match_range_versions(self.candidates, "1.26.3", "1.26.3", result)
        self.assertIn("CVE-R2", result)

    def test_nginx_outside_range(self):
        result = {}
        match_range_versions(self.candidates, "1.27.0", "1.27.0", result)
        self.assertNotIn("CVE-R2", result)


# ---------------------------------------------------------------------------
# Tests: CVE ranking
# ---------------------------------------------------------------------------

class TestRankCves(unittest.TestCase):
    def test_sort_by_cvss(self):
        cves = {
            "CVE-LOW": {"cvss_v2": 3.0, "cvss_v3": 4.0},
            "CVE-HIGH": {"cvss_v2": 7.0, "cvss_v3": 9.8},
            "CVE-MED": {"cvss_v2": 5.0, "cvss_v3": 6.5},
        }
        ranked = rank_cves(cves)
        ids = [r[0] for r in ranked]
        self.assertEqual(ids, ["CVE-HIGH", "CVE-MED", "CVE-LOW"])

    def test_v3_none_fallback_to_v2(self):
        cves = {
            "CVE-V3": {"cvss_v2": 3.0, "cvss_v3": 8.0},
            "CVE-V2": {"cvss_v2": 9.0, "cvss_v3": None},
        }
        ranked = rank_cves(cves)
        ids = [r[0] for r in ranked]
        self.assertEqual(ids, ["CVE-V2", "CVE-V3"])


# ---------------------------------------------------------------------------
# Tests: Alias resolution
# ---------------------------------------------------------------------------

class TestResolveAliases(unittest.TestCase):
    def test_no_aliases(self):
        result = resolve_aliases("openssh", None)
        self.assertEqual(result, ["openssh"])

    def test_with_aliases(self):
        aliases = {"nginx": ["nginx_plus"]}
        result = resolve_aliases("nginx", aliases)
        self.assertEqual(result, ["nginx", "nginx_plus"])

    def test_no_match(self):
        aliases = {"nginx": ["nginx_plus"]}
        result = resolve_aliases("openssh", aliases)
        self.assertEqual(result, ["openssh"])


# ---------------------------------------------------------------------------
# Tests: Database integration
# ---------------------------------------------------------------------------

class TestFindVulnerabilities(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.conn = create_test_db()
        cls.cur = cls.conn.cursor()

    @classmethod
    def tearDownClass(cls):
        cls.cur.close()
        cls.conn.close()

    def test_exact_version_match(self):
        info = parse_version("4.7p1")
        vulns = find_vulnerabilities(self.cur, "openssh", info)
        self.assertIn("CVE-2016-1908", vulns)
        self.assertIn("CVE-2018-15473", vulns)

    def test_range_match(self):
        info = parse_version("4.7")
        vulns = find_vulnerabilities(self.cur, "openssh", info)
        # Should match multiaffected >=4.0 <9.0
        self.assertIn("CVE-2020-1234", vulns)

    def test_empty_version(self):
        info = parse_version(None)
        vulns = find_vulnerabilities(self.cur, "openssh", info)
        # Should match multiaffected with no version boundaries
        self.assertIn("CVE-2023-2222", vulns)

    def test_nginx_match(self):
        info = parse_version("1.26.3")
        vulns = find_vulnerabilities(self.cur, "nginx", info)
        self.assertIn("CVE-2023-1111", vulns)  # exact
        self.assertIn("CVE-2022-0001", vulns)  # range

    def test_outside_range(self):
        info = parse_version("10.0")
        vulns = find_vulnerabilities(self.cur, "openssh", info)
        # Should NOT match >=4.0 <9.0
        self.assertNotIn("CVE-2020-1234", vulns)


class TestGetExploitInfo(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.conn = create_test_db()
        cls.cur = cls.conn.cursor()

    @classmethod
    def tearDownClass(cls):
        cls.cur.close()
        cls.conn.close()

    def test_exploit_info(self):
        exploits, metasploits = get_exploit_info(self.cur, "CVE-2016-1908")
        self.assertEqual(len(exploits), 1)
        self.assertEqual(exploits[0]["id"], 40888)
        self.assertIn("exploit-db.com", exploits[0]["url"])
        self.assertEqual(len(metasploits), 1)
        self.assertEqual(metasploits[0]["name"], "exploit/multi/ssh/sshexec")

    def test_no_exploits(self):
        exploits, metasploits = get_exploit_info(self.cur, "CVE-2023-1111")
        self.assertEqual(len(exploits), 0)
        self.assertEqual(len(metasploits), 0)


# ---------------------------------------------------------------------------
# Tests: High-level scan
# ---------------------------------------------------------------------------

class TestScanService(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.conn = create_test_db()
        cls.cur = cls.conn.cursor()

    @classmethod
    def tearDownClass(cls):
        cls.cur.close()
        cls.conn.close()

    def test_scan_by_product(self):
        result = scan_service(
            self.cur,
            {"product": "openssh", "version": "4.7", "version_update": "p1"},
            aliases=None, maxcve=0,
        )
        self.assertEqual(result["product"], "openssh")
        self.assertGreater(result["total_cves"], 0)
        cve_ids = [c["cve_id"] for c in result["cves"]]
        self.assertIn("CVE-2016-1908", cve_ids)

    def test_scan_by_cpe(self):
        result = scan_service(
            self.cur,
            {"cpe": "cpe:/a:openbsd:openssh:4.7p1"},
            aliases=None, maxcve=0,
        )
        self.assertEqual(result["product"], "openssh")
        self.assertIn("cpe", result)

    def test_scan_maxcve(self):
        result = scan_service(
            self.cur,
            {"product": "openssh", "version": "4.7", "version_update": "p1"},
            aliases=None, maxcve=1,
        )
        self.assertEqual(len(result["cves"]), 1)
        # total_cves should reflect all found, not limited
        self.assertGreater(result["total_cves"], 1)

    def test_scan_with_id(self):
        result = scan_service(
            self.cur,
            {"id": "test-1", "product": "nginx", "version": "1.26.3"},
            aliases=None, maxcve=0,
        )
        self.assertEqual(result["id"], "test-1")

    def test_scan_cpe_with_capitalized_product(self):
        # Regression: nmap emits "OpenSSH" as product label alongside a lowercase
        # CPE. The CPE must win; otherwise case-sensitive SQL lookups return 0.
        result = scan_service(
            self.cur,
            {"cpe": "cpe:/a:openbsd:openssh:4.7p1", "product": "OpenSSH"},
            aliases=None, maxcve=0,
        )
        self.assertEqual(result["product"], "openssh")
        self.assertGreater(result["total_cves"], 0)

    def test_scan_product_capitalized(self):
        # Regression: callers passing only a capitalised product (no CPE) must
        # still match — defence-in-depth lowercase normalisation.
        result = scan_service(
            self.cur,
            {"product": "OpenSSH", "version": "4.7", "version_update": "p1"},
            aliases=None, maxcve=0,
        )
        self.assertEqual(result["product"], "openssh")
        self.assertGreater(result["total_cves"], 0)


class TestRunScan(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = Path(self.tmpdir) / "test.db"
        self.conn = create_test_db(self.db_path)
        self.conn.close()

    def test_full_scan(self):
        services = [
            {"id": "ssh", "product": "openssh", "version": "4.7", "version_update": "p1"},
            {"id": "web", "product": "nginx", "version": "1.26.3"},
        ]
        output = run_scan(str(self.db_path), services)
        self.assertIn("metadata", output)
        self.assertIn("results", output)
        self.assertEqual(len(output["results"]), 2)
        self.assertEqual(output["metadata"]["version"], "3.4")

    def test_cache_shared_across_services(self):
        """Same product/version appearing twice should produce identical results
        and benefit from the shared cache."""
        services = [
            {"id": "ssh1", "product": "openssh", "version": "4.7"},
            {"id": "ssh2", "product": "openssh", "version": "4.7"},
        ]
        output = run_scan(str(self.db_path), services)
        r1 = output["results"][0]
        r2 = output["results"][1]
        self.assertEqual(r1["total_cves"], r2["total_cves"])
        cves1 = {c["cve_id"] for c in r1["cves"]}
        cves2 = {c["cve_id"] for c in r2["cves"]}
        self.assertEqual(cves1, cves2)


# ---------------------------------------------------------------------------
# Tests: Output formatting
# ---------------------------------------------------------------------------

class TestFormatTable(unittest.TestCase):
    def test_table_output(self):
        output = {
            "metadata": {
                "timestamp": "2026-01-01T00:00:00+00:00",
                "database": "test.db",
                "version": "3.4",
            },
            "results": [
                {
                    "product": "openssh",
                    "version": "4.7",
                    "version_update": "p1",
                    "total_cves": 1,
                    "cves": [
                        {
                            "cve_id": "CVE-2016-1908",
                            "cvss_v2": 7.5,
                            "cvss_v3": 9.8,
                        }
                    ],
                }
            ],
        }
        text = format_table(output)
        self.assertIn("openssh", text)
        self.assertIn("CVE-2016-1908", text)
        self.assertIn("9.8", text)


# ---------------------------------------------------------------------------
# Tests: CLI
# ---------------------------------------------------------------------------

class TestCLI(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = Path(self.tmpdir) / "test.db"
        self.conn = create_test_db(self.db_path)
        self.conn.close()
        self.cvescan = str(Path(__file__).parent / "cvescan.py")

    def test_scan_product_args(self):
        result = subprocess.run(
            [sys.executable, self.cvescan, "scan",
             "-c", str(self.db_path),
             "-p", "openssh", "-v", "4.7", "-u", "p1",
             "-a", "/nonexistent"],  # no aliases file
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        self.assertEqual(len(output["results"]), 1)
        self.assertGreater(output["results"][0]["total_cves"], 0)

    def test_scan_cpe_arg(self):
        result = subprocess.run(
            [sys.executable, self.cvescan, "scan",
             "-c", str(self.db_path),
             "--cpe", "cpe:/a:nginx:nginx:1.26.3",
             "-a", "/nonexistent"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        self.assertEqual(output["results"][0]["product"], "nginx")

    def test_scan_json_stdin(self):
        input_data = json.dumps({
            "services": [
                {"product": "mysql", "version": "5.5.55"}
            ]
        })
        result = subprocess.run(
            [sys.executable, self.cvescan, "scan",
             "-c", str(self.db_path),
             "-i", "-",
             "-a", "/nonexistent"],
            input=input_data,
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        self.assertGreater(output["results"][0]["total_cves"], 0)

    def test_scan_json_file(self):
        input_file = Path(self.tmpdir) / "input.json"
        input_file.write_text(json.dumps({
            "services": [
                {"id": "s1", "product": "openssh", "version": "4.7", "version_update": "p1"}
            ]
        }))
        result = subprocess.run(
            [sys.executable, self.cvescan, "scan",
             "-c", str(self.db_path),
             "-i", str(input_file),
             "-a", "/nonexistent"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        self.assertEqual(output["results"][0]["id"], "s1")

    def test_scan_table_format(self):
        result = subprocess.run(
            [sys.executable, self.cvescan, "scan",
             "-c", str(self.db_path),
             "-p", "openssh", "-v", "4.7",
             "--format", "table",
             "-a", "/nonexistent"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("openssh", result.stdout)
        self.assertIn("CVE-", result.stdout)

    def test_scan_output_file(self):
        out_file = Path(self.tmpdir) / "output.json"
        result = subprocess.run(
            [sys.executable, self.cvescan, "scan",
             "-c", str(self.db_path),
             "-p", "nginx", "-v", "1.26.3",
             "-o", str(out_file),
             "-a", "/nonexistent"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(out_file.exists())
        output = json.loads(out_file.read_text())
        self.assertEqual(len(output["results"]), 1)

    def test_db_info(self):
        result = subprocess.run(
            [sys.executable, self.cvescan, "db-info",
             "-c", str(self.db_path)],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Last updated:", result.stdout)
        self.assertIn("CVEs:", result.stdout)

    def test_missing_db(self):
        result = subprocess.run(
            [sys.executable, self.cvescan, "scan",
             "-c", "/nonexistent/cve.db",
             "-p", "openssh"],
            capture_output=True, text=True,
        )
        self.assertNotEqual(result.returncode, 0)

    def test_no_command(self):
        result = subprocess.run(
            [sys.executable, self.cvescan],
            capture_output=True, text=True,
        )
        self.assertNotEqual(result.returncode, 0)


# ---------------------------------------------------------------------------
# Tests: Distro detection
# ---------------------------------------------------------------------------

class TestDistroDetection(unittest.TestCase):
    def test_debian_ssh_banner(self):
        banner = "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u7"
        info = detect_distro_from_banner(banner)
        self.assertIsNotNone(info)
        self.assertEqual(info["distro"], "debian")
        self.assertEqual(info["distro_release"], "bookworm")
        self.assertEqual(info["package_revision"], "2+deb12u7")

    def test_ubuntu_ssh_banner(self):
        banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"
        info = detect_distro_from_banner(banner)
        self.assertIsNotNone(info)
        self.assertEqual(info["distro"], "ubuntu")

    def test_rhel_http_banner(self):
        banner = "Apache/2.4.37 (Red Hat Enterprise Linux)"
        info = detect_distro_from_banner(banner)
        self.assertIsNotNone(info)
        self.assertEqual(info["distro"], "rhel")

    def test_debian_http_banner(self):
        banner = "Apache/2.4.57 (Debian)"
        info = detect_distro_from_banner(banner)
        self.assertIsNotNone(info)
        self.assertEqual(info["distro"], "debian")

    def test_ubuntu_http_banner(self):
        banner = "Apache/2.4.52 (Ubuntu)"
        info = detect_distro_from_banner(banner)
        self.assertIsNotNone(info)
        self.assertEqual(info["distro"], "ubuntu")

    def test_bare_banner(self):
        info = detect_distro_from_banner("OpenSSH_9.2p1")
        self.assertIsNone(info)

    def test_empty_banner(self):
        self.assertIsNone(detect_distro_from_banner(""))
        self.assertIsNone(detect_distro_from_banner(None))


class TestDebianRelease(unittest.TestCase):
    def test_deb12(self):
        self.assertEqual(detect_debian_release("2+deb12u7"), "bookworm")

    def test_deb11(self):
        self.assertEqual(detect_debian_release("1+deb11u3"), "bullseye")

    def test_deb10(self):
        self.assertEqual(detect_debian_release("1+deb10u1"), "buster")

    def test_unknown(self):
        self.assertIsNone(detect_debian_release("3ubuntu0.10"))


class TestOsvEcosystem(unittest.TestCase):
    def test_debian_bookworm(self):
        self.assertEqual(get_osv_ecosystem("debian", "bookworm"), "Debian:12")

    def test_ubuntu_jammy(self):
        self.assertEqual(get_osv_ecosystem("ubuntu", "jammy"), "Ubuntu:22.04")

    def test_unknown(self):
        self.assertIsNone(get_osv_ecosystem("debian", "unknown"))
        self.assertIsNone(get_osv_ecosystem(None, None))

    def test_parts(self):
        prefix, release = get_osv_ecosystem_parts("debian", "bookworm")
        self.assertEqual(prefix, "Debian")
        self.assertEqual(release, "12")


class TestDetectDistroService(unittest.TestCase):
    def test_explicit_override(self):
        svc = {"product": "openssh", "distro": "debian", "distro_release": "bookworm"}
        d, r = _detect_distro(svc)
        self.assertEqual(d, "debian")
        self.assertEqual(r, "bookworm")

    def test_from_banner(self):
        svc = {"product": "openssh", "banner": "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u7"}
        d, r = _detect_distro(svc)
        self.assertEqual(d, "debian")
        self.assertEqual(r, "bookworm")

    def test_no_distro(self):
        svc = {"product": "openssh"}
        d, r = _detect_distro(svc)
        self.assertIsNone(d)
        self.assertIsNone(r)


# ---------------------------------------------------------------------------
# Tests: dpkg version comparison
# ---------------------------------------------------------------------------

class TestDpkgVersionParse(unittest.TestCase):
    def test_simple(self):
        self.assertEqual(parse_dpkg_version("1.0"), (0, "1.0", "0"))

    def test_with_epoch(self):
        self.assertEqual(parse_dpkg_version("1:9.2p1-2+deb12u7"),
                         (1, "9.2p1", "2+deb12u7"))

    def test_no_revision(self):
        self.assertEqual(parse_dpkg_version("2:1.0"), (2, "1.0", "0"))

    def test_multiple_hyphens(self):
        self.assertEqual(parse_dpkg_version("1.0-beta-2"),
                         (0, "1.0-beta", "2"))

    def test_empty(self):
        self.assertEqual(parse_dpkg_version(""), (0, "0", "0"))
        self.assertEqual(parse_dpkg_version(None), (0, "0", "0"))


class TestDpkgVersionCompare(unittest.TestCase):
    def test_equal(self):
        self.assertEqual(compare_dpkg_versions("1.0", "1.0"), 0)

    def test_epoch_wins(self):
        self.assertEqual(compare_dpkg_versions("2:1.0", "1:2.0"), 1)
        self.assertEqual(compare_dpkg_versions("1:1.0", "2:1.0"), -1)

    def test_upstream_compare(self):
        self.assertEqual(compare_dpkg_versions("1.1", "1.0"), 1)
        self.assertEqual(compare_dpkg_versions("1.0", "1.1"), -1)

    def test_revision_compare(self):
        self.assertEqual(compare_dpkg_versions("1.0-2", "1.0-1"), 1)
        self.assertEqual(compare_dpkg_versions("1.0-1", "1.0-2"), -1)

    def test_tilde_sorts_before_empty(self):
        self.assertEqual(compare_dpkg_versions("1.0~rc1", "1.0"), -1)
        self.assertEqual(compare_dpkg_versions("1.0", "1.0~rc1"), 1)

    def test_tilde_ordering(self):
        self.assertEqual(compare_dpkg_versions("1.0~alpha", "1.0~beta"), -1)

    def test_deb_versions(self):
        # Real Debian version comparison
        self.assertEqual(
            compare_dpkg_versions("1:9.2p1-2+deb12u3", "1:9.2p1-2+deb12u7"),
            -1
        )
        self.assertEqual(
            compare_dpkg_versions("1:9.2p1-2+deb12u7", "1:9.2p1-2+deb12u3"),
            1
        )

    def test_same_version(self):
        self.assertEqual(
            compare_dpkg_versions("1:9.2p1-2+deb12u7", "1:9.2p1-2+deb12u7"),
            0
        )


# ---------------------------------------------------------------------------
# Tests: Backport checking
# ---------------------------------------------------------------------------

class TestCheckBackports(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.conn = create_test_db()
        cls.cur = cls.conn.cursor()
        cls.cpe_to_pkg = {"openbsd:openssh": {"debian": "openssh"}}

    @classmethod
    def tearDownClass(cls):
        cls.cur.close()
        cls.conn.close()

    def test_patched_cve(self):
        """CVE with a fixed version where installed >= fixed should be patched."""
        result = check_backports(
            self.cur,
            ["CVE-2020-1234"],
            "debian", "bookworm",
            "openbsd", "openssh",
            self.cpe_to_pkg,
            installed_version="1:4.7p1-2+deb12u7",
        )
        self.assertEqual(result["CVE-2020-1234"]["status"], "patched")
        self.assertEqual(result["CVE-2020-1234"]["fixed_version"], "1:4.7p1-2+deb12u3")

    def test_affected_cve(self):
        """CVE marked as affected (no fix) should be affected."""
        result = check_backports(
            self.cur,
            ["CVE-2016-1908"],
            "debian", "bookworm",
            "openbsd", "openssh",
            self.cpe_to_pkg,
        )
        self.assertEqual(result["CVE-2016-1908"]["status"], "affected")

    def test_unknown_cve(self):
        """CVE not in backport DB should be unknown."""
        result = check_backports(
            self.cur,
            ["CVE-9999-0001"],
            "debian", "bookworm",
            "openbsd", "openssh",
            self.cpe_to_pkg,
        )
        self.assertEqual(result["CVE-9999-0001"]["status"], "unknown")

    def test_no_distro(self):
        """Without distro ecosystem mapping, all should be unknown."""
        result = check_backports(
            self.cur,
            ["CVE-2020-1234"],
            "debian", "unknown_release",
            "openbsd", "openssh",
            self.cpe_to_pkg,
        )
        self.assertEqual(result["CVE-2020-1234"]["status"], "unknown")

    def test_no_package_mapping(self):
        """Without package mapping, all should be unknown."""
        result = check_backports(
            self.cur,
            ["CVE-2020-1234"],
            "debian", "bookworm",
            "unknown", "unknown_product",
            self.cpe_to_pkg,
        )
        self.assertEqual(result["CVE-2020-1234"]["status"], "unknown")


# ---------------------------------------------------------------------------
# Tests: Confidence annotation
# ---------------------------------------------------------------------------

class TestAnnotateConfidence(unittest.TestCase):
    def test_no_distro_no_annotation(self):
        """Without distro, all CVEs stay in active list without confidence key."""
        cves = [{"cve_id": "CVE-1", "cvss_v3": 8.0, "cvss_v2": None}]
        active, patched = annotate_confidence(cves, None, None, {})
        self.assertEqual(len(active), 1)
        self.assertEqual(len(patched), 0)
        # No confidence key added when no distro
        self.assertNotIn("confidence", active[0])

    def test_patched_split(self):
        """Patched CVEs should move to patched list."""
        cves = [
            {"cve_id": "CVE-1", "cvss_v3": 8.0, "cvss_v2": None},
            {"cve_id": "CVE-2", "cvss_v3": 5.0, "cvss_v2": None},
        ]
        bp = {
            "CVE-1": {"status": "patched", "fixed_version": "1.0-1"},
            "CVE-2": {"status": "affected", "fixed_version": None},
        }
        active, patched = annotate_confidence(cves, "debian", "bookworm", bp)
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0]["cve_id"], "CVE-2")
        self.assertEqual(active[0]["confidence"], "UPSTREAM_MATCH")
        self.assertEqual(len(patched), 1)
        self.assertEqual(patched[0]["cve_id"], "CVE-1")
        self.assertEqual(patched[0]["confidence"], "LIKELY_PATCHED")
        self.assertEqual(patched[0]["fixed_version"], "1.0-1")

    def test_uncertain(self):
        """Unknown backport status should result in UNCERTAIN."""
        cves = [{"cve_id": "CVE-1", "cvss_v3": 8.0, "cvss_v2": None}]
        bp = {"CVE-1": {"status": "unknown", "fixed_version": None}}
        active, patched = annotate_confidence(cves, "debian", "bookworm", bp)
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0]["confidence"], "UNCERTAIN")
        self.assertEqual(len(patched), 0)


# ---------------------------------------------------------------------------
# Tests: Scan with distro (integration)
# ---------------------------------------------------------------------------

class TestScanServiceWithDistro(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.conn = create_test_db()
        cls.cur = cls.conn.cursor()
        cls.cpe_to_pkg = {"openbsd:openssh": {"debian": "openssh"}}

    @classmethod
    def tearDownClass(cls):
        cls.cur.close()
        cls.conn.close()

    def test_scan_without_distro_unchanged(self):
        """Without distro fields, output should be identical to original format."""
        result = scan_service(
            self.cur,
            {"product": "openssh", "version": "4.7", "version_update": "p1"},
            aliases=None, maxcve=0,
        )
        self.assertNotIn("distro", result)
        self.assertNotIn("likely_patched", result)
        self.assertNotIn("confidence", result["cves"][0])

    def test_scan_with_distro(self):
        """With distro fields, output should have distro info and confidence."""
        result = scan_service(
            self.cur,
            {
                "product": "openssh", "version": "4.7", "version_update": "p1",
                "distro": "debian", "distro_release": "bookworm",
                "installed_version": "1:4.7p1-2+deb12u7",
            },
            aliases=None, maxcve=0,
            cpe_to_pkg=self.cpe_to_pkg,
        )
        self.assertEqual(result["distro"], "debian")
        self.assertEqual(result["distro_release"], "bookworm")
        # Should have some CVEs split
        all_cve_ids = {c["cve_id"] for c in result["cves"]}
        patched_ids = {c["cve_id"] for c in result.get("likely_patched", [])}
        # CVE-2020-1234 should be patched (fixed_version exists, installed >= fixed)
        self.assertIn("CVE-2020-1234", patched_ids)
        # CVE-2016-1908 is marked affected in backport DB, should stay active
        self.assertIn("CVE-2016-1908", all_cve_ids)

    def test_scan_with_banner(self):
        """Banner should trigger distro detection."""
        result = scan_service(
            self.cur,
            {
                "product": "openssh", "version": "4.7",
                "banner": "SSH-2.0-OpenSSH_4.7p1 Debian-2+deb12u7",
            },
            aliases=None, maxcve=0,
            cpe_to_pkg=self.cpe_to_pkg,
        )
        self.assertEqual(result.get("distro"), "debian")
        self.assertEqual(result.get("distro_release"), "bookworm")


class TestRunScanWithDistro(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = Path(self.tmpdir) / "test.db"
        self.conn = create_test_db(self.db_path)
        self.conn.close()

    def test_full_scan_with_distro(self):
        cpe_to_pkg = {"openbsd:openssh": {"debian": "openssh"}}
        services = [
            {
                "id": "ssh",
                "product": "openssh", "version": "4.7",
                "distro": "debian", "distro_release": "bookworm",
            },
        ]
        output = run_scan(
            str(self.db_path), services,
            cpe_to_pkg=cpe_to_pkg,
        )
        result = output["results"][0]
        self.assertEqual(result["distro"], "debian")

    def test_full_scan_backward_compat(self):
        """Without distro, output should be unchanged."""
        services = [
            {"id": "ssh", "product": "openssh", "version": "4.7"},
        ]
        output = run_scan(str(self.db_path), services)
        result = output["results"][0]
        self.assertNotIn("distro", result)
        self.assertNotIn("likely_patched", result)


# ---------------------------------------------------------------------------
# Tests: Format table with distro
# ---------------------------------------------------------------------------

class TestFormatTableWithDistro(unittest.TestCase):
    def test_table_with_patched(self):
        output = {
            "metadata": {
                "timestamp": "2026-01-01T00:00:00+00:00",
                "database": "test.db",
                "version": "3.4",
            },
            "results": [
                {
                    "product": "openssh",
                    "version": "9.2",
                    "version_update": "*",
                    "distro": "debian",
                    "distro_release": "bookworm",
                    "total_cves": 2,
                    "cves": [
                        {"cve_id": "CVE-2024-6387", "cvss_v2": None, "cvss_v3": 8.1,
                         "confidence": "UPSTREAM_MATCH"},
                    ],
                    "likely_patched": [
                        {"cve_id": "CVE-2023-48795", "cvss_v2": None, "cvss_v3": 5.9,
                         "confidence": "LIKELY_PATCHED",
                         "fixed_version": "1:9.2p1-2+deb12u3"},
                    ],
                }
            ],
        }
        text = format_table(output)
        self.assertIn("Distro: debian (bookworm)", text)
        self.assertIn("Likely Patched:", text)
        self.assertIn("CVE-2024-6387", text)
        self.assertIn("CVE-2023-48795", text)
        self.assertIn("fixed: 1:9.2p1-2+deb12u3", text)


# ---------------------------------------------------------------------------
# Tests: CLI with distro args
# ---------------------------------------------------------------------------

class TestCLIDistro(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = Path(self.tmpdir) / "test.db"
        self.conn = create_test_db(self.db_path)
        self.conn.close()
        self.cvescan = str(Path(__file__).parent / "cvescan.py")

    def test_scan_with_distro_args(self):
        result = subprocess.run(
            [sys.executable, self.cvescan, "scan",
             "-c", str(self.db_path),
             "-p", "openssh", "-v", "4.7",
             "--distro", "debian", "--distro-release", "bookworm",
             "-a", "/nonexistent"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        r = output["results"][0]
        self.assertEqual(r["distro"], "debian")
        self.assertEqual(r["distro_release"], "bookworm")

    def test_scan_without_distro_backward_compat(self):
        """Without --distro, output should match original format."""
        result = subprocess.run(
            [sys.executable, self.cvescan, "scan",
             "-c", str(self.db_path),
             "-p", "openssh", "-v", "4.7",
             "-a", "/nonexistent"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        r = output["results"][0]
        self.assertNotIn("distro", r)
        self.assertNotIn("likely_patched", r)

    def test_db_info_with_backports(self):
        result = subprocess.run(
            [sys.executable, self.cvescan, "db-info",
             "-c", str(self.db_path)],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Backports:", result.stdout)
        self.assertIn("Debian:12", result.stdout)


if __name__ == "__main__":
    unittest.main()

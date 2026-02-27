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


if __name__ == "__main__":
    unittest.main()

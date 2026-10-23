#!/usr/bin/env python3

"""Tests for database.py — CVE database build tooling."""

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
# The NVD rate limiter is built at import; the raw-cache tests fake NVD, so
# let their page fetches through without waiting.
os.environ.setdefault("NVD_RATE_PER_30S", "100000")

from database import applicable_cpes, classify_cpes, summarize_ubuntu_rows  # noqa: E402

RELEASES = ("24.04", "22.04", "20.04")


def _row(release, cve="CVE-2024-0001", package="mariadb"):
    """A backports row as update_backports_ubuntu builds it."""
    return (cve, "Ubuntu", release, package, "1:1.0-0ubuntu1", "fixed",
            None, "ubuntu-security", None)


class TestSummarizeUbuntuRows(unittest.TestCase):
    def test_no_rows_at_all_flags_the_package_name(self):
        lines = summarize_ubuntu_rows("exim", RELEASES, [], [], 0)
        self.assertEqual(len(lines), 1)
        self.assertIn("no rows", lines[0])
        self.assertIn("check the source", lines[0])

    def test_every_release_covered_reports_only_success(self):
        definitive = [_row(rel) for rel in RELEASES]
        lines = summarize_ubuntu_rows("openssh", RELEASES, definitive, [], 3)
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith("[+]"))

    def test_success_line_carries_the_per_release_breakdown(self):
        definitive = [_row("24.04"), _row("24.04"), _row("22.04"), _row("20.04")]
        lines = summarize_ubuntu_rows("openssh", RELEASES, definitive, [], 4)
        self.assertIn("24.04=2", lines[0])
        self.assertIn("22.04=1", lines[0])
        self.assertIn("20.04=1", lines[0])

    def test_partial_coverage_warns_naming_the_empty_releases(self):
        """The MariaDB case: valid name for 24.04, renamed on the others."""
        definitive = [_row("24.04") for _ in range(280)]
        lines = summarize_ubuntu_rows("mariadb", RELEASES, definitive, [], 1355)
        self.assertEqual(len(lines), 2)
        self.assertTrue(lines[0].startswith("[+]"))
        self.assertTrue(lines[1].startswith("[!]"))
        self.assertIn("22.04", lines[1])
        self.assertIn("20.04", lines[1])
        self.assertNotIn("24.04", lines[1].split("though")[0])

    def test_warning_points_at_both_halves_of_the_fix(self):
        """Adding the name is only half of it; the rows must also be readable."""
        lines = summarize_ubuntu_rows("mariadb", RELEASES, [_row("24.04")], [], 1)
        self.assertIn("package list", lines[1])
        self.assertIn("cpe-to-package.json", lines[1])

    def test_soft_rows_count_toward_coverage(self):
        """A release with only affected/wont_fix rows is still covered."""
        definitive = [_row("24.04")]
        soft = [_row("22.04"), _row("20.04")]
        lines = summarize_ubuntu_rows("nginx", RELEASES, definitive, soft, 3)
        self.assertEqual(len(lines), 1)

    def test_single_release_request_is_not_warned_about(self):
        """Asking for one release and getting it is complete, not partial."""
        lines = summarize_ubuntu_rows("mariadb", ("24.04",), [_row("24.04")], [], 1)
        self.assertEqual(len(lines), 1)


def _match(criteria, vulnerable=True, **versions):
    return {"vulnerable": vulnerable, "criteria": criteria, **versions}


def _kept(configurations):
    """(vendor, product, version) of every CPE applicable_cpes keeps."""
    return [cpe[:3] for cpe, _ in applicable_cpes(configurations)]


class TestApplicableCpes(unittest.TestCase):
    """Configuration shapes copied from NVD (API 2.0, 2026-10-14)."""

    def test_platform_marked_not_vulnerable_is_skipped(self):
        """CVE-2011-2688: the flaw is in an add-on, httpd is only where it runs."""
        configs = [{"operator": "AND", "nodes": [
            {"operator": "OR", "negate": False, "cpeMatch": [_match(
                "cpe:2.3:a:mod_authnz_external_project:mod_authnz_external:*:*:*:*:*:*:*:*",
                versionEndIncluding="3.2.5")]},
            {"operator": "OR", "negate": False, "cpeMatch": [_match(
                "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", vulnerable=False)]},
        ]}]
        self.assertEqual(_kept(configs), [
            ("mod_authnz_external_project", "mod_authnz_external", "*")])

    def test_open_ended_cpe_in_and_config_is_skipped(self):
        """CVE-2008-3844: OpenSSH only in the trojaned RHEL 4/5 packages."""
        configs = [{"operator": "AND", "nodes": [
            {"operator": "OR", "negate": False, "cpeMatch": [_match(
                "cpe:2.3:o:redhat:enterprise_linux:5.0:*:*:*:*:*:*:*", vulnerable=False)]},
            {"operator": "OR", "negate": False, "cpeMatch": [_match(
                "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*")]},
        ]}]
        self.assertEqual(_kept(configs), [])

    def test_bounded_cpe_in_and_config_is_kept(self):
        """A range still limits the match; "on Windows" findings stay."""
        configs = [{"operator": "AND", "nodes": [
            {"operator": "OR", "negate": False, "cpeMatch": [_match(
                "cpe:2.3:a:vendor:server:*:*:*:*:*:*:*:*", versionEndExcluding="2.0")]},
            {"operator": "OR", "negate": False, "cpeMatch": [_match(
                "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*", vulnerable=False)]},
        ]}]
        kept = list(applicable_cpes(configs))
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0][0][:3], ("vendor", "server", "*"))
        self.assertEqual(kept[0][1], [None, None, None, "2.0"])

    def test_wildcard_next_to_concrete_version_is_skipped(self):
        """CVE-2004-0399: exim:* beside exim:3.35 matched every Exim."""
        configs = [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [
            _match("cpe:2.3:a:university_of_cambridge:exim:*:*:*:*:*:*:*:*"),
            _match("cpe:2.3:a:university_of_cambridge:exim:3.35:*:*:*:*:*:*:*"),
        ]}]}]
        self.assertEqual(_kept(configs), [
            ("university_of_cambridge", "exim", "3.35")])

    def test_wildcard_alone_is_kept(self):
        """CVE-2023-51767 really affects every OpenSSH release."""
        configs = [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [
            _match("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*")]}]}]
        self.assertEqual(_kept(configs), [("openbsd", "openssh", "*")])

    def test_wildcard_beside_another_products_version_is_kept(self):
        """Only a concrete version of the same product makes the wildcard noise."""
        configs = [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [
            _match("cpe:2.3:a:vendor:alpha:*:*:*:*:*:*:*:*"),
            _match("cpe:2.3:a:vendor:beta:1.0:*:*:*:*:*:*:*"),
        ]}]}]
        self.assertEqual(_kept(configs), [
            ("vendor", "alpha", "*"), ("vendor", "beta", "1.0")])

    def test_negated_node_is_skipped(self):
        configs = [{"operator": "AND", "nodes": [
            {"operator": "OR", "negate": False, "cpeMatch": [_match(
                "cpe:2.3:a:vendor:server:1.0:*:*:*:*:*:*:*")]},
            {"operator": "OR", "negate": True, "cpeMatch": [_match(
                "cpe:2.3:a:vendor:plugin:2.0:*:*:*:*:*:*:*")]},
        ]}]
        self.assertEqual(_kept(configs), [("vendor", "server", "1.0")])

    def test_operating_systems_are_never_findings(self):
        configs = [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [
            _match("cpe:2.3:o:debian:debian_linux:12.0:*:*:*:*:*:*:*")]}]}]
        self.assertEqual(_kept(configs), [])



class TestClassifyCpesReasons(unittest.TestCase):
    """Every left-out CPE carries the reason it was left out, for the log."""

    def _reasons(self, configurations):
        return [(cpe[1], skip) for cpe, _, skip in classify_cpes(configurations)]

    def test_each_skip_names_its_reason(self):
        configs = [
            {"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [
                _match("cpe:2.3:a:university_of_cambridge:exim:*:*:*:*:*:*:*:*"),
                _match("cpe:2.3:a:university_of_cambridge:exim:3.35:*:*:*:*:*:*:*")]}]},
            {"operator": "AND", "nodes": [
                {"operator": "OR", "negate": False, "cpeMatch": [_match(
                    "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*")]},
                {"operator": "OR", "negate": False, "cpeMatch": [_match(
                    "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", vulnerable=False)]},
                {"operator": "OR", "negate": True, "cpeMatch": [_match(
                    "cpe:2.3:a:vendor:plugin:2.0:*:*:*:*:*:*:*")]},
            ]},
        ]
        self.assertEqual(self._reasons(configs), [
            ("exim", "wildcard_beside_concrete_version"),
            ("exim", None),
            ("openssh", "open_range_in_and_config"),
            ("http_server", "not_vulnerable"),
            ("plugin", "negated"),
        ])

if __name__ == "__main__":
    unittest.main()


# ── NVD raw cache, offline import and build stamp ──────────────────────────

import json  # noqa: E402
import sqlite3  # noqa: E402
import tempfile  # noqa: E402
from concurrent.futures import ThreadPoolExecutor  # noqa: E402
from datetime import datetime, timedelta, timezone  # noqa: E402
from unittest import mock  # noqa: E402
from urllib.parse import parse_qs, urlparse  # noqa: E402

import database  # noqa: E402


def _cve(cve_id, criteria, modified="2026-01-01T00:00:00.000", status="Analyzed",
         **match):
    return {
        "id": cve_id, "vulnStatus": status, "published": "2020-05-01T00:00:00.000",
        "lastModified": modified, "metrics": {},
        "configurations": [{"nodes": [{"operator": "OR", "negate": False,
                                       "cpeMatch": [dict(vulnerable=True, criteria=criteria, **match)]}]}],
        "references": [],
    }


def _write_lines(path, items):
    with open(path, "w") as f:
        for item in items:
            f.write((item if isinstance(item, str) else json.dumps(item, separators=(",", ":"))) + "\n")


class TestRawDeltaWindow(unittest.TestCase):
    NOW = datetime(2026, 10, 15, tzinfo=timezone.utc)

    def test_no_cache_means_full_fetch(self):
        self.assertEqual(database.raw_delta_window(None, self.NOW), "")

    def test_full_flag_wins_over_a_recent_cache(self):
        meta = {"last_mod": (self.NOW - timedelta(days=1)).isoformat()}
        self.assertEqual(database.raw_delta_window(meta, self.NOW, full=True), "")

    def test_recent_cache_asks_for_the_changes_since_last_mod(self):
        meta = {"last_mod": (self.NOW - timedelta(days=3)).isoformat()}
        window = database.raw_delta_window(meta, self.NOW)
        self.assertIn("lastModStartDate=2026-10-12", window)
        self.assertIn("lastModEndDate=2026-10-15", window)

    def test_cache_older_than_nvds_window_is_fetched_in_full(self):
        meta = {"last_mod": (self.NOW - timedelta(days=database.RAW_MAX_DELTA_DAYS + 1)).isoformat()}
        self.assertEqual(database.raw_delta_window(meta, self.NOW), "")


class TestMergeRaw(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.raw = Path(self.tmp.name)
        self.delta = self.raw / "delta"
        self.delta.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def _cves(self):
        with (self.raw / "cves.jsonl").open() as f:
            return {c["id"]: c for c in map(json.loads, f)}

    def test_delta_replaces_changed_cves_and_keeps_the_rest(self):
        _write_lines(self.raw / "cves.jsonl", [
            _cve("CVE-2020-0001", "cpe:2.3:a:v:p:1.0:*:*:*:*:*:*:*"),
            _cve("CVE-2020-0002", "cpe:2.3:a:v:p:2.0:*:*:*:*:*:*:*"),
        ])
        _write_lines(self.delta / "cves_000000000", [
            _cve("CVE-2020-0002", "cpe:2.3:a:v:p:2.1:*:*:*:*:*:*:*", modified="2026-02-01T00:00:00.000"),
            _cve("CVE-2020-0003", "cpe:2.3:a:v:p:3.0:*:*:*:*:*:*:*"),
        ])
        counts = database.merge_raw(self.raw, self.delta)
        cves = self._cves()
        self.assertEqual(counts["cves"], 3)
        self.assertEqual(set(cves), {"CVE-2020-0001", "CVE-2020-0002", "CVE-2020-0003"})
        self.assertIn(":2.1:", cves["CVE-2020-0002"]["configurations"][0]["nodes"][0]["cpeMatch"][0]["criteria"])

    def test_the_newest_copy_wins_when_a_cve_appears_on_two_pages(self):
        """NVD paging over changing data can return one CVE twice."""
        _write_lines(self.delta / "cves_000000000", [
            _cve("CVE-2020-0001", "cpe:2.3:a:v:p:new:*:*:*:*:*:*:*", modified="2026-03-01T00:00:00.000")])
        _write_lines(self.delta / "cves_000002000", [
            _cve("CVE-2020-0001", "cpe:2.3:a:v:p:old:*:*:*:*:*:*:*", modified="2026-01-01T00:00:00.000")])
        database.merge_raw(self.raw, self.delta, full=True)
        crit = self._cves()["CVE-2020-0001"]["configurations"][0]["nodes"][0]["cpeMatch"][0]["criteria"]
        self.assertIn(":new:", crit)

    def test_full_merge_drops_the_old_cache(self):
        _write_lines(self.raw / "cves.jsonl", [_cve("CVE-2019-0001", "cpe:2.3:a:v:p:1:*:*:*:*:*:*:*")])
        _write_lines(self.raw / "cpes.txt", ["cpe:2.3:a:old:old:1:*:*:*:*:*:*:*"])
        _write_lines(self.delta / "cves_000000000", [_cve("CVE-2020-0001", "cpe:2.3:a:v:p:1:*:*:*:*:*:*:*")])
        _write_lines(self.delta / "cpes_000000000", ["cpe:2.3:a:new:new:1:*:*:*:*:*:*:*"])
        counts = database.merge_raw(self.raw, self.delta, full=True)
        self.assertEqual(set(self._cves()), {"CVE-2020-0001"})
        self.assertEqual((self.raw / "cpes.txt").read_text().split(), ["cpe:2.3:a:new:new:1:*:*:*:*:*:*:*"])
        self.assertEqual(counts, {"cves": 1, "cpes": 1})

    def test_cpes_are_merged_sorted_and_unique(self):
        _write_lines(self.raw / "cpes.txt", ["cpe:2.3:a:b:b:1:*:*:*:*:*:*:*"])
        _write_lines(self.delta / "cpes_000000000",
                     ["cpe:2.3:a:a:a:1:*:*:*:*:*:*:*", "cpe:2.3:a:b:b:1:*:*:*:*:*:*:*"])
        database.merge_raw(self.raw, self.delta)
        self.assertEqual((self.raw / "cpes.txt").read_text().split(),
                         ["cpe:2.3:a:a:a:1:*:*:*:*:*:*:*", "cpe:2.3:a:b:b:1:*:*:*:*:*:*:*"])


class _FakeNvd:
    """Serves NVD pages by offset from lists a test may change mid-fetch."""

    def __init__(self, cves):
        self.data = {"cves": list(cves), "cpes": []}
        self.fail = set()  # (kind, startIndex) pages that always fail
        self.after_page = None  # called with (kind, start) after a page is served

    def __call__(self, url, headers=None, **_):
        kind = "cves" if "/cves/" in url else "cpes"
        query = parse_qs(urlparse(url).query)
        start = int(query["startIndex"][0])
        size = int(query.get("resultsPerPage", [database.CONST[kind[:-1]]])[0])
        if (kind, start) in self.fail:
            raise database.DatabaseUpdateError(f"NVD down for {kind} {start}")
        items = self.data[kind][start:start + size]
        page = {"totalResults": len(self.data[kind]),
                "vulnerabilities": [{"cve": cve} for cve in items],
                "products": [{"cpe": {"cpeName": cpe}} for cpe in items]}
        if size > 1 and self.after_page:
            self.after_page(kind, start)
        return page


class TestRefreshRaw(unittest.TestCase):
    """refresh_raw over a fake NVD with 4 CVEs per page."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.raw = Path(self.tmp.name)
        self.nvd = _FakeNvd(_cve(f"CVE-2026-{i:04d}", "cpe:2.3:a:v:p:1:*:*:*:*:*:*:*")
                            for i in range(12))
        for patcher in (
            mock.patch.object(database, "nvd_get_json", self.nvd),
            mock.patch.dict(database.CONST, {"cve": 4}),
            # One page at a time, in order, so a test can change NVD between pages.
            mock.patch.object(database, "ThreadPoolExecutor",
                              lambda: ThreadPoolExecutor(max_workers=1)),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def tearDown(self):
        self.tmp.cleanup()

    def _cached_ids(self):
        with (self.raw / "cves.jsonl").open() as f:
            return {json.loads(line)["id"] for line in f}

    def _start_from_a_recent_cache(self):
        _write_lines(self.raw / "cves.jsonl", [])
        _write_lines(self.raw / "cpes.txt", [])
        last_mod = datetime.now(timezone.utc) - timedelta(days=1)
        (self.raw / "meta.json").write_text(json.dumps({"last_mod": last_mod.isoformat()}))

    def test_a_failed_fetch_resumes_with_the_pages_it_has(self):
        self.nvd.fail.add(("cves", 4))
        with self.assertRaises(database.DatabaseUpdateError):
            database.refresh_raw(self.raw)
        self.nvd.fail.clear()
        served = []
        self.nvd.after_page = lambda kind, start: served.append(start)
        database.refresh_raw(self.raw)
        self.assertEqual(served, [4])
        self.assertEqual(len(self._cached_ids()), 12)
        self.assertFalse((self.raw / "delta").exists())

    def test_the_resumed_fetch_keeps_the_first_attempts_window(self):
        self.nvd.fail.add(("cves", 8))
        with self.assertRaises(database.DatabaseUpdateError):
            database.refresh_raw(self.raw)
        until = json.loads((self.raw / "delta" / "plan.json").read_text())["until"]
        self.nvd.fail.clear()
        meta = database.refresh_raw(self.raw)
        self.assertEqual(meta["last_mod"], until)

    def test_a_half_written_page_is_dropped_on_resume(self):
        self.nvd.fail.add(("cves", 4))
        with self.assertRaises(database.DatabaseUpdateError):
            database.refresh_raw(self.raw)
        (self.raw / "delta" / "cves_000000004.tmp").write_text('{"id":"CVE-2026-')
        self.nvd.fail.clear()
        database.refresh_raw(self.raw)
        self.assertEqual(len(self._cached_ids()), 12)

    def test_pages_of_a_fetch_with_another_start_are_discarded(self):
        delta = self.raw / "delta"
        delta.mkdir()
        (delta / "plan.json").write_text(json.dumps(
            {"since": "2026-01-01T00:00:00+00:00", "until": "2026-01-02T00:00:00+00:00",
             "totals": {"cpes": 0, "cves": 4}}))
        _write_lines(delta / "cves_000000000", [_cve("CVE-1999-9999", "cpe:2.3:a:v:p:1:*:*:*:*:*:*:*")])
        database.refresh_raw(self.raw)
        self.assertNotIn("CVE-1999-9999", self._cached_ids())
        self.assertEqual(len(self._cached_ids()), 12)

    def test_a_record_that_moved_onto_a_fetched_page_is_still_fetched(self):
        """CVE-2026-0001 changes again after page 4 and leaves the window, so
        CVE-2026-0008 moves onto page 4; page 8 then starts at CVE-2026-0009."""
        self._start_from_a_recent_cache()

        def leave_the_window(kind, start):
            if kind == "cves" and start == 4:
                del self.nvd.data["cves"][1]
                self.nvd.after_page = None
        self.nvd.after_page = leave_the_window
        database.refresh_raw(self.raw)
        self.assertIn("CVE-2026-0008", self._cached_ids())
        self.assertEqual(len(self._cached_ids()), 12)

    def test_a_full_fetch_ignores_records_added_at_the_end(self):
        added = _cve("CVE-2026-0012", "cpe:2.3:a:v:p:1:*:*:*:*:*:*:*")

        def publish(kind, start):
            if kind == "cves" and start == 4:
                self.nvd.data["cves"].append(added)
                self.nvd.after_page = None
        self.nvd.after_page = publish
        database.refresh_raw(self.raw)
        # Page 8 was planned for 12 records, so it holds 4 of the 5; the
        # new one waits for the next delta, and no page is fetched twice.
        self.assertEqual(len(self._cached_ids()), 12)

    def test_a_delta_window_that_changed_too_much_is_fetched_again(self):
        self._start_from_a_recent_cache()

        def leave_the_window(kind, start):
            if kind == "cves" and start == 0:
                del self.nvd.data["cves"][0:3]  # 2 * 3 > 4 records per page
                self.nvd.after_page = None
        self.nvd.after_page = leave_the_window
        database.refresh_raw(self.raw)
        # The three that left changed again after the window; the next delta
        # fetches them. Every record still in the window is here.
        self.assertEqual(self._cached_ids(),
                         {f"CVE-2026-{i:04d}" for i in range(3, 12)})


class TestPopulateFromRaw(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.raw = Path(self.tmp.name) / "raw"
        self.raw.mkdir()
        self.db = Path(self.tmp.name) / "cve.db"
        _write_lines(self.raw / "cpes.txt", ["cpe:2.3:a:exim:exim:4.100:*:*:*:*:*:*:*",
                                             "cpe:2.3:o:linux:linux_kernel:6.1:*:*:*:*:*:*:*"])
        _write_lines(self.raw / "cves.jsonl", [
            _cve("CVE-2020-0001", "cpe:2.3:a:exim:exim:4.92:*:*:*:*:*:*:*"),
            _cve("CVE-2020-0002", "cpe:2.3:a:exim:exim:*:*:*:*:*:*:*:*", versionEndExcluding="4.94"),
            _cve("CVE-2020-0003", "cpe:2.3:a:exim:exim:4.92:*:*:*:*:*:*:*", status="Rejected"),
        ])
        (self.raw / "meta.json").write_text(json.dumps(
            {"last_mod": "2026-10-14T03:00:00+00:00", "cves": 3, "cpes": 2}))

    def tearDown(self):
        self.tmp.cleanup()

    def _query(self, sql_text):
        con = sqlite3.connect(self.db)
        try:
            return con.execute(sql_text).fetchall()
        finally:
            con.close()

    def test_builds_the_same_rows_as_the_api_path(self):
        database.populate_from_raw(self.db, self.raw)
        self.assertEqual(self._query("SELECT cve_id FROM cves ORDER BY cve_id"),
                         [("CVE-2020-0001",), ("CVE-2020-0002",)])
        self.assertEqual(self._query("SELECT cve_id FROM affected"), [("CVE-2020-0001",)])
        self.assertEqual(self._query("SELECT cve_id, versionEndExcluding FROM multiaffected"),
                         [("CVE-2020-0002", "4.94")])

    def test_small_batches_still_link_rows_to_their_products(self):
        """A full affected batch must not be written before its products."""
        with (self.raw / "cves.jsonl").open("a") as f:
            f.write(json.dumps(_cve("CVE-2020-0004", "cpe:2.3:a:exim:exim:4.93:*:*:*:*:*:*:*")) + "\n")
        # Size 2: the second affected row fills its batch while its product
        # still waits in the products batch.
        original = database._BatchSink.__init__.__defaults__
        database._BatchSink.__init__.__defaults__ = (2,)
        try:
            database.populate_from_raw(self.db, self.raw)
        finally:
            database._BatchSink.__init__.__defaults__ = original
        self.assertEqual(self._query("SELECT COUNT(*) FROM affected WHERE product_id IS NULL"), [(0,)])
        self.assertEqual(self._query("SELECT COUNT(*) FROM affected"), [(2,)])

    def test_only_application_cpes_become_products(self):
        database.populate_from_raw(self.db, self.raw)
        products = {r[0] for r in self._query("SELECT product FROM products")}
        self.assertIn("exim", products)
        self.assertNotIn("linux_kernel", products)

    def test_last_mod_comes_from_the_cache_not_the_clock(self):
        """A later incremental API update must continue from the cache's time."""
        database.populate_from_raw(self.db, self.raw)
        self.assertEqual(self._query("SELECT last_mod FROM metadata"),
                         [("2026-10-14T03:00:00+00:00",)])

    def test_an_existing_database_is_replaced(self):
        self.db.write_bytes(b"not a database")
        database.populate_from_raw(self.db, self.raw)
        self.assertEqual(len(self._query("SELECT cve_id FROM cves")), 2)

    def test_missing_cache_is_an_error(self):
        with self.assertRaises(database.DatabaseUpdateError):
            database.populate_from_raw(self.db, Path(self.tmp.name) / "nothing")


class TestBuildStamp(unittest.TestCase):
    def test_backports_key_is_order_independent(self):
        a = database.backports_config_key(["Debian:12", "AlmaLinux:9"], True, ["openssh", "bind"],
                                          ["9", "8"], False)
        b = database.backports_config_key(["AlmaLinux:9", "Debian:12"], True, ["bind", "openssh"],
                                          ["8", "9"], False)
        self.assertEqual(a, b)
        self.assertEqual(a, "osv=AlmaLinux:9,Debian:12|redhat=bind,openssh@8,9|ubuntu=-")

    def test_curated_overlay_stamps_its_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "cve.db"
            curated = Path(tmp) / "curated.json"
            curated.write_text(json.dumps({"dispositions": []}))
            database.load_curated_dispositions(db_path, curated)
            with database.Database(db_path) as db:
                info = db.build_info()
            self.assertEqual(info["curated_sha256"], database.file_sha256(curated))

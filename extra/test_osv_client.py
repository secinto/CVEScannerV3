#!/usr/bin/env python3

"""Tests for osv_client.py — the online OSV fallback for uncertain CVEs."""

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent))

import httpx

import osv_client
from osv_client import enrich_from_osv, query_osv_batch


def _vulns(*ids):
    return {"vulns": [{"id": i, "modified": "2026-10-21T00:00:00Z"} for i in ids]}


def _enrich(affecting, known, cves=("CVE-2023-51767",)):
    """enrich_from_osv on an Ubuntu 24.04 openssh with canned OSV answers."""
    with mock.patch.object(osv_client, "query_osv_batch",
                           return_value=[affecting, known]) as q:
        out = enrich_from_osv(list(cves), "ubuntu", "noble", "openssh",
                              "1:9.6p1-3ubuntu13.18")
    return out, q


class TestEnrichFromOsv(unittest.TestCase):
    def test_reads_the_cve_from_distro_record_ids(self):
        # querybatch returns no aliases; Ubuntu's ids are UBUNTU-CVE-…
        out, q = _enrich(_vulns("UBUNTU-CVE-2026-106552"),
                         _vulns("UBUNTU-CVE-2026-106552", "UBUNTU-CVE-2026-60000"),
                         cves=("CVE-2026-106552", "CVE-2026-60000"))
        self.assertEqual(out["CVE-2026-106552"],
                         {"status": "affected", "ecosystem": "Ubuntu:24.04",
                          "osv_id": "UBUNTU-CVE-2026-106552"})
        self.assertEqual(out["CVE-2026-60000"]["status"], "not_affected")
        self.assertEqual(out["CVE-2026-60000"]["osv_id"], "UBUNTU-CVE-2026-60000")
        # One query with the installed version, one without.
        queries = q.call_args.args[0]
        self.assertEqual(queries[0]["version"], "1:9.6p1-3ubuntu13.18")
        self.assertNotIn("version", queries[1])

    def test_no_record_in_the_ecosystem_is_unknown(self):
        # timetac.com: OSV has no Ubuntu 24.04 statement on CVE-2023-51767 or
        # CVE-2007-2768. That used to suppress both, with no reason.
        out, _ = _enrich(_vulns("UBUNTU-CVE-2026-106552"),
                         _vulns("UBUNTU-CVE-2026-106552"),
                         cves=("CVE-2023-51767", "CVE-2007-2768"))
        for cve in ("CVE-2023-51767", "CVE-2007-2768"):
            self.assertEqual(out[cve]["status"], "unknown")
            self.assertIsNone(out[cve]["osv_id"])

    def test_failed_request_is_unknown_not_unaffected(self):
        with mock.patch.object(osv_client, "query_osv_batch", return_value=None):
            out = enrich_from_osv(["CVE-2026-60000"], "ubuntu", "noble",
                                  "openssh", "1:9.6p1-3ubuntu13.18")
        self.assertEqual(out["CVE-2026-60000"]["status"], "unknown")

    def test_paged_answer_is_unknown(self):
        paged = dict(_vulns("UBUNTU-CVE-2026-1"), next_page_token="t")
        out, _ = _enrich(_vulns(), paged, cves=("CVE-2026-60000",))
        self.assertEqual(out["CVE-2026-60000"]["status"], "unknown")

    def test_without_installed_version_or_ecosystem_is_unknown(self):
        with mock.patch.object(osv_client, "query_osv_batch") as q:
            out = enrich_from_osv(["CVE-1"], "ubuntu", "noble", "openssh", None)
            self.assertEqual(out["CVE-1"]["status"], "unknown")
            out = enrich_from_osv(["CVE-1"], "nosuchdistro", "x", "openssh", "1.0")
            self.assertEqual(out["CVE-1"]["status"], "unknown")
            q.assert_not_called()


class TestQueryOsvBatch(unittest.TestCase):
    def test_http_error_is_none(self):
        with mock.patch.object(osv_client.httpx, "post",
                               side_effect=httpx.ConnectError("down")):
            self.assertIsNone(query_osv_batch([{"package": {}}]))

    def test_short_answer_is_none(self):
        resp = mock.Mock()
        resp.json.return_value = {"results": [_vulns()]}
        with mock.patch.object(osv_client.httpx, "post", return_value=resp):
            self.assertIsNone(query_osv_batch([{"package": {}}, {"package": {}}]))


if __name__ == "__main__":
    unittest.main()

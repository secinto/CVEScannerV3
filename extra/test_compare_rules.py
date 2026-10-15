#!/usr/bin/env python3

"""Tests for compare_rules.py — per-product diff of two cve.db files."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import compare_rules  # noqa: E402
import database  # noqa: E402


def _cve(cve_id, criteria, **match):
    return {"id": cve_id, "vulnStatus": "Analyzed", "published": "2020-01-01T00:00:00.000",
            "lastModified": "", "metrics": {}, "references": [],
            "configurations": [{"nodes": [{"operator": "OR", "negate": False,
                                           "cpeMatch": [dict(vulnerable=True, criteria=criteria, **match)]}]}]}


def _build(tmp, name, cves):
    raw = Path(tmp) / f"raw-{name}"
    raw.mkdir()
    (raw / "cpes.txt").write_text("")
    (raw / "cves.jsonl").write_text("".join(json.dumps(c) + "\n" for c in cves))
    (raw / "meta.json").write_text(json.dumps({"last_mod": "2026-10-15T00:00:00+00:00"}))
    db = Path(tmp) / f"{name}.db"
    database.populate_from_raw(db, raw)
    return db


class TestCompareRules(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        common = _cve("CVE-2020-0001", "cpe:2.3:a:openbsd:openssh:8.0:*:*:*:*:*:*:*")
        self.base = _build(self.tmp.name, "base", [
            common,
            _cve("CVE-2004-0399", "cpe:2.3:a:exim:exim:*:*:*:*:*:*:*:*"),
        ])
        self.new = _build(self.tmp.name, "new", [
            common,
            _cve("CVE-2021-0002", "cpe:2.3:a:exim:exim:*:*:*:*:*:*:*:*", versionEndExcluding="4.94"),
        ])

    def tearDown(self):
        self.tmp.cleanup()

    def test_totals_and_open_ended_rows(self):
        totals, _ = compare_rules.compare(compare_rules.load_rows(self.base),
                                          compare_rules.load_rows(self.new))
        self.assertEqual(totals["affected"], {"base": 1, "new": 1})
        self.assertEqual(totals["multiaffected"], {"base": 1, "new": 1})
        self.assertEqual(totals["open_ended"], {"base": 1, "new": 0})

    def test_only_changed_products_are_listed(self):
        _, changes = compare_rules.compare(compare_rules.load_rows(self.base),
                                           compare_rules.load_rows(self.new))
        self.assertEqual([(c["product"], c["removed"], c["added"]) for c in changes],
                         [("exim", 1, 1)])

    def test_product_listing_names_the_cves(self):
        from io import StringIO
        from contextlib import redirect_stdout
        out = StringIO()
        with redirect_stdout(out):
            compare_rules.main([str(self.base), str(self.new), "--product", "exim"])
        text = out.getvalue()
        self.assertIn("- CVE-2004-0399 exim:exim multiaffected */*/*/*", text)
        self.assertIn("+ CVE-2021-0002 exim:exim multiaffected */*/*/4.94", text)

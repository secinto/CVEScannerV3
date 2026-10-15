#!/usr/bin/env python3

"""Tests for database.py — CVE database build tooling."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

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

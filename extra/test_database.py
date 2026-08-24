#!/usr/bin/env python3

"""Tests for database.py — CVE database build tooling."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from database import summarize_ubuntu_rows  # noqa: E402

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


if __name__ == "__main__":
    unittest.main()

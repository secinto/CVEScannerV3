#!/usr/bin/env python3

# SPDX-License-Identifier: GPL-3.0-or-later

"""Pure-Python dpkg version comparison (Debian Policy 5.6.12).

Implements the full dpkg version comparison algorithm including:
- Epoch, upstream version, and Debian revision splitting
- Tilde (~) sorting before empty string
- Alternating character/digit segment comparison
"""

import re


def parse_dpkg_version(s):
    """Parse a dpkg version string into (epoch, upstream, revision).

    Format: [epoch:]upstream_version[-debian_revision]
    - epoch defaults to 0 if absent
    - revision defaults to "0" if absent
    """
    if not s:
        return (0, "0", "0")

    epoch = 0
    rest = s

    # Extract epoch (everything before first colon)
    if ":" in rest:
        epoch_str, rest = rest.split(":", 1)
        try:
            epoch = int(epoch_str)
        except ValueError:
            epoch = 0

    # Extract revision (everything after last hyphen)
    if "-" in rest:
        idx = rest.rfind("-")
        upstream = rest[:idx]
        revision = rest[idx + 1:]
    else:
        upstream = rest
        revision = "0"

    return (epoch, upstream, revision)


def _order(c):
    """Return sort order for a single character per dpkg rules.

    - '~' sorts before everything (returns -1)
    - letters sort before non-letters (but after ~)
    - non-letters (digits handled separately) sort after letters
    - empty/end-of-segment sorts after ~ but before letters
    """
    if c == "~":
        return -1
    if c == "":
        return 0
    if c.isalpha():
        return ord(c)
    # Non-alpha, non-digit, non-tilde (e.g. '.', '+')
    return ord(c) + 256


def _compare_fragment(a, b):
    """Compare two version fragments using dpkg's algorithm.

    Alternates between comparing non-digit and digit segments.
    """
    i = 0
    j = 0
    la = len(a)
    lb = len(b)

    while i < la or j < lb:
        # Compare non-digit characters
        while (i < la and not a[i].isdigit()) or (j < lb and not b[j].isdigit()):
            ac = _order(a[i]) if i < la and not a[i].isdigit() else _order("")
            bc = _order(b[j]) if j < lb and not b[j].isdigit() else _order("")
            if ac != bc:
                return -1 if ac < bc else 1
            if i < la and not a[i].isdigit():
                i += 1
            if j < lb and not b[j].isdigit():
                j += 1
            if (i >= la or a[i].isdigit()) and (j >= lb or b[j].isdigit()):
                break

        # Extract digit segments and compare numerically
        num_a = ""
        while i < la and a[i].isdigit():
            num_a += a[i]
            i += 1

        num_b = ""
        while j < lb and b[j].isdigit():
            num_b += b[j]
            j += 1

        na = int(num_a) if num_a else 0
        nb = int(num_b) if num_b else 0
        if na != nb:
            return -1 if na < nb else 1

    return 0


def compare_dpkg_versions(v1, v2):
    """Compare two dpkg version strings.

    Returns:
        -1 if v1 < v2
         0 if v1 == v2
         1 if v1 > v2
    """
    e1, u1, r1 = parse_dpkg_version(v1)
    e2, u2, r2 = parse_dpkg_version(v2)

    # Compare epochs first
    if e1 != e2:
        return -1 if e1 < e2 else 1

    # Compare upstream versions
    result = _compare_fragment(u1, u2)
    if result != 0:
        return result

    # Compare revisions
    return _compare_fragment(r1, r2)

#!/usr/bin/env python3

# SPDX-License-Identifier: GPL-3.0-or-later

"""Ubuntu Security tracker parse helpers — primary Ubuntu backport source.

OSV's Ubuntu ecosystem is derived from Ubuntu Security *Notices*: it only
carries CVEs that got a published USN. CVEs Canonical assessed as not-affected,
fixed silently in an SRU, or still pending never appear. That is why the OSV
bucket is large overall (81k rows for 24.04) yet holds only 5 openssh rows,
against 82 for Debian 12 — whose OSV feed is built from the full security
tracker.

Canonical's own tracker has the complete per-release picture, free and
unauthenticated, and its list endpoint carries the statuses inline, so one
paginated call per package is enough (no per-CVE detail fetch, unlike Red Hat).

These are pure parse helpers; the network fetch lives in database.py.
"""

import re

UBUNTU_SECURITY_API = "https://ubuntu.com/security"

# Ubuntu release codename → the release string used in the backports table.
# Must match the OSV bucket's release ("Ubuntu:24.04:LTS" is stored as 24.04)
# so Canonical rows land alongside, not beside, the OSV ones.
UBUNTU_CODENAME_RELEASE = {
    "trusty": "14.04",
    "xenial": "16.04",
    "bionic": "18.04",
    "focal": "20.04",
    "jammy": "22.04",
    "kinetic": "22.10",
    "lunar": "23.04",
    "mantic": "23.10",
    "noble": "24.04",
    "oracular": "24.10",
    "plucky": "25.04",
}

# Ubuntu per-release status → our disposition enum (the backports.status
# vocabulary). Deliberately absent:
#   DNE          the package does not exist in that release, so a host running
#                it cannot have got it from there — asserting "not affected"
#                off a contradiction would be worse than staying silent
#   needs-triage Canonical has not assessed it yet; unknown is not a verdict
STATUS_DISPOSITION = {
    "released": "fixed",            # suppressed once installed >= fixed
    "not-affected": "not_affected",  # suppressed — provably not vulnerable
    "ignored": "wont_fix",          # surfaced + badged — e.g. end of support
    "deferred": "fix_deferred",     # surfaced + badged — fix pending
    "needed": "affected",           # active — confirmed, no fix yet
    "pending": "affected",          # active — fix built, not yet published
}

# Dispositions Canonical can state definitively. Only these overwrite an
# existing row: the tracker is upstream of OSV's Ubuntu data, so it wins on a
# conflict. The softer verdicts insert-or-ignore, so a row already recorded as
# fixed can never be downgraded to affected by a slower-moving field.
DEFINITIVE_DISPOSITIONS = {"fixed", "not_affected"}

# A released status carries the fixed version in `description`, e.g.
# "1:9.6p1-3ubuntu13.3". Free text shows up there too ("introduced in v8.5p1"
# on not-affected rows), so validate rather than trust the field.
_RE_DEB_VERSION = re.compile(r"^(?:\d+:)?\d[A-Za-z0-9.+~:-]*$")


def ubuntu_disposition(status):
    """Map an Ubuntu per-release status to our disposition enum, or None."""
    return STATUS_DISPOSITION.get((status or "").strip().lower())


def ubuntu_release(codename):
    """Map an Ubuntu codename to the backports-table release, or None."""
    return UBUNTU_CODENAME_RELEASE.get((codename or "").strip().lower())


def ubuntu_fixed_version(status, description):
    """Fixed version for a `released` status, or None.

    Only returns a value for `released`, and only when the description is
    actually a Debian version — Canonical uses the same field for prose.
    """
    if (status or "").strip().lower() != "released":
        return None
    ver = (description or "").strip()
    return ver if ver and _RE_DEB_VERSION.match(ver) else None


def ubuntu_cve_url(cve_id):
    """Canonical's public page for a CVE — used as the row's citation."""
    return f"{UBUNTU_SECURITY_API}/{cve_id}"


def ubuntu_rows_for_cve(entry, package, releases):
    """Backport rows for one CVE from the list endpoint's JSON entry.

    Yields (cve_id, release, fixed_version, disposition, reason, citation) for
    each requested release the entry has a usable status for. `releases` are
    backports-table release strings ("24.04"), not codenames.
    """
    cve_id = (entry.get("id") or "").strip()
    if not cve_id.startswith("CVE-"):
        return
    wanted = set(releases)
    for pkg in entry.get("packages") or []:
        # Match the source package exactly: openssh-ssh1 is a separate source
        # package Canonical explicitly does not support, and folding its
        # statuses into openssh would import verdicts for software the host
        # is not running.
        if (pkg.get("name") or "").strip() != package:
            continue
        for st in pkg.get("statuses") or []:
            release = ubuntu_release(st.get("release_codename"))
            if not release or release not in wanted:
                continue
            status = st.get("status")
            disposition = ubuntu_disposition(status)
            if not disposition:
                continue
            description = st.get("description")
            fixed = ubuntu_fixed_version(status, description)
            # A released status with an unparseable version cannot be compared
            # against the installed one, so it is not a usable fix record.
            if disposition == "fixed" and not fixed:
                continue
            reason = f"Ubuntu: {status} ({release})"
            if fixed:
                reason = f"Ubuntu: fixed in {fixed} ({release})"
            elif description:
                reason = f"Ubuntu: {status} ({release}) — {description.strip()}"
            yield (cve_id, release, fixed, disposition, reason,
                   ubuntu_cve_url(cve_id))

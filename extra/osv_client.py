#!/usr/bin/env python3

# SPDX-License-Identifier: GPL-3.0-or-later

"""OSV.dev REST API client for online CVE enrichment."""

import re

import httpx

OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://osv.dev/vulnerability/{}"


def build_osv_ecosystem(distro, release):
    """Map distro/release to OSV ecosystem string.

    E.g. ("debian", "bookworm") → "Debian:12"
    """
    # Import here to avoid circular dependency
    from distro import get_osv_ecosystem
    return get_osv_ecosystem(distro, release)


def query_osv_batch(queries, timeout=30):
    """POST batch queries to OSV.dev /v1/querybatch.

    Args:
        queries: list of query dicts, each with keys like:
            {"package": {"name": "openssh", "ecosystem": "Debian:12"},
             "version": "1:9.2p1-2+deb12u7"}
            OR
            {"commit": "..."}
        timeout: request timeout in seconds

    Returns:
        list of result dicts (one per query), or None when any request failed.
        Each result has a "vulns" key with the matching vulnerabilities (id and
        modified only) and, when OSV paged the answer, a "next_page_token".
        A failed request is not an empty answer: the caller must not read
        "no vulnerability listed" into it.
    """
    if not queries:
        return []

    # OSV querybatch supports up to 1000 queries per request
    all_results = []
    for i in range(0, len(queries), 1000):
        batch = queries[i:i + 1000]
        try:
            resp = httpx.post(
                OSV_QUERYBATCH_URL,
                json={"queries": batch},
                timeout=timeout,
            )
            resp.raise_for_status()
            results = resp.json().get("results", [])
        except (httpx.HTTPError, httpx.TimeoutException, ValueError):
            return None
        if len(results) != len(batch):
            return None
        all_results.extend(results)

    return all_results


# OSV names a distro record after the CVE it tracks: "UBUNTU-CVE-2023-51767",
# "DEBIAN-CVE-2024-6387". querybatch returns no aliases, so the CVE id is read
# from the record id itself.
_CVE_IN_OSV_ID = re.compile(r"(?:^|-)(CVE-\d{4}-\d+)$")


def _cve_ids_by_osv_id(result):
    """Map CVE id → OSV record id for one querybatch result, or None when
    OSV paged the answer (the list is then incomplete)."""
    if result.get("next_page_token"):
        return None
    out = {}
    for vuln in result.get("vulns") or []:
        m = _CVE_IN_OSV_ID.search(vuln.get("id", ""))
        if m:
            out.setdefault(m.group(1), vuln["id"])
    return out


def enrich_from_osv(uncertain_cves, distro, distro_release, pkg_name,
                    installed_version):
    """Ask OSV whether uncertain CVEs affect the installed package version.

    Two queries for the package in the release's ecosystem: one with the
    installed version (the records that affect it) and one without (every
    record OSV has for the package). A CVE is "not_affected" only when OSV has
    a record for it here and that record does not list the installed version.
    A CVE OSV has no record for stays "unknown": the absence of a record is
    not a verdict. So is every CVE when a request fails or OSV pages the answer.

    Args:
        uncertain_cves: list of CVE ID strings to check
        distro: distro name (e.g. "debian")
        distro_release: release codename (e.g. "bookworm")
        pkg_name: distro source package name (e.g. "openssh")
        installed_version: distro-native version string

    Returns:
        dict mapping cve_id → {"status": "affected" | "not_affected" |
        "unknown", "ecosystem": str, "osv_id": str or None}
    """
    ecosystem = build_osv_ecosystem(distro, distro_release)

    def unknown():
        return {cve_id: {"status": "unknown", "ecosystem": ecosystem,
                         "osv_id": None}
                for cve_id in uncertain_cves}

    if not ecosystem or not pkg_name or not installed_version:
        return unknown()

    package = {"name": pkg_name, "ecosystem": ecosystem}
    results = query_osv_batch([
        {"package": package, "version": installed_version},
        {"package": package},
    ])
    if not results:
        return unknown()
    affecting = _cve_ids_by_osv_id(results[0])
    known = _cve_ids_by_osv_id(results[1])
    if affecting is None or known is None:
        return unknown()

    result = {}
    for cve_id in uncertain_cves:
        if cve_id in affecting:
            status, osv_id = "affected", affecting[cve_id]
        elif cve_id in known:
            status, osv_id = "not_affected", known[cve_id]
        else:
            status, osv_id = "unknown", None
        result[cve_id] = {"status": status, "ecosystem": ecosystem,
                          "osv_id": osv_id}
    return result

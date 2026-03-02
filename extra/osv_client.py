#!/usr/bin/env python3

# SPDX-License-Identifier: GPL-3.0-or-later

"""OSV.dev REST API client for online CVE enrichment."""

import httpx

OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"


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
        list of result dicts (one per query), or empty list on error.
        Each result has a "vulns" key with list of matching vulnerabilities.
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
            data = resp.json()
            all_results.extend(data.get("results", []))
        except (httpx.HTTPError, httpx.TimeoutException, ValueError):
            # Graceful degradation: return empty results for this batch
            all_results.extend([{"vulns": []} for _ in batch])

    return all_results


def enrich_from_osv(uncertain_cves, distro, distro_release, pkg_name,
                    installed_version):
    """Query OSV for uncertain CVEs and determine if they affect the installed version.

    Args:
        uncertain_cves: list of CVE ID strings to check
        distro: distro name (e.g. "debian")
        distro_release: release codename (e.g. "bookworm")
        pkg_name: distro source package name (e.g. "openssh")
        installed_version: distro-native version string

    Returns:
        dict mapping cve_id → "affected" | "not_affected" | "unknown"
    """
    ecosystem = build_osv_ecosystem(distro, distro_release)
    if not ecosystem or not pkg_name:
        return {cve_id: "unknown" for cve_id in uncertain_cves}

    # Build a single query: package + version → get all vulns affecting it
    queries = [
        {
            "package": {"name": pkg_name, "ecosystem": ecosystem},
            "version": installed_version,
        }
    ]

    results = query_osv_batch(queries)
    if not results:
        return {cve_id: "unknown" for cve_id in uncertain_cves}

    # Collect all CVE aliases from the OSV response
    affected_cves = set()
    vulns = results[0].get("vulns", [])
    for vuln in vulns:
        # The vuln ID itself might be a CVE
        vid = vuln.get("id", "")
        if vid.startswith("CVE-"):
            affected_cves.add(vid)
        # Check aliases
        for alias in vuln.get("aliases", []):
            if alias.startswith("CVE-"):
                affected_cves.add(alias)

    result = {}
    for cve_id in uncertain_cves:
        if cve_id in affected_cves:
            result[cve_id] = "affected"
        else:
            result[cve_id] = "not_affected"

    return result

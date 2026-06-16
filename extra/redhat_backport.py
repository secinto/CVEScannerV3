#!/usr/bin/env python3

# SPDX-License-Identifier: GPL-3.0-or-later

"""Red Hat securitydata parse helpers — secondary el8/el9 backport source.

AlmaLinux's OSV (ALSA) feed misses some fixes Red Hat shipped (e.g.
CVE-2020-14145, fixed in openssh-8.0p1-10.el8 via RHSA-2021:4368) and carries no
"Not affected" dispositions. Red Hat's securitydata API has both. These pure
helpers parse its responses; the network fetch lives in database.py.
"""

import re

RH_SECURITYDATA = "https://access.redhat.com/hydra/rest/securitydata"

# "<name>-<epoch>:<version>-<release>", e.g. "openssh-0:8.0p1-10.el8"
_RE_RPM_EVR = re.compile(
    r"^(?P<name>.+)-(?P<epoch>\d+):(?P<ver>[^-\s]+)-(?P<rel>.+)$"
)

# fix_state values that mean "this release is provably not vulnerable" → suppress.
NOT_AFFECTED_STATES = {"not affected"}


def rh_fixed_version(affected_packages, package, release):
    """el<release> fixed version (epoch-stripped, OSV-shaped) for `package`.

    Reads the list endpoint's ``affected_packages`` (RHSA-fixed builds), e.g.
    ['openssh-0:8.0p1-10.el8'] → '8.0p1-10.el8'. Returns None if no el<release>
    build is listed. Accepts subpackages (openssh-server) since they share the
    source RPM's EVR.
    """
    elpat = re.compile(rf"\.el{release}(\D|$)")
    for ap in affected_packages or []:
        m = _RE_RPM_EVR.match((ap or "").strip())
        if not m:
            continue
        name = m.group("name")
        if name != package and not name.startswith(package + "-"):
            continue
        rel = m.group("rel")
        if elpat.search(rel):
            return f"{m.group('ver')}-{rel}"
    return None


def rh_fix_state(package_state, package, release):
    """Red Hat fix_state for `package` on el<release>, or None.

    Reads per-CVE detail ``package_state`` (e.g. 'Not affected', 'Will not fix',
    'Fix deferred', 'Affected').
    """
    cpe_key = f"enterprise_linux:{release}"
    for ps in package_state or []:
        if ps.get("package_name") != package:
            continue
        if cpe_key not in ps.get("cpe", ""):
            continue
        return ps.get("fix_state")
    return None


def is_not_affected(fix_state):
    """True if a fix_state string means the release is not vulnerable."""
    return (fix_state or "").strip().lower() in NOT_AFFECTED_STATES

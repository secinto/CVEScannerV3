#!/usr/bin/env python3

# SPDX-License-Identifier: GPL-3.0-or-later

"""Distro detection from service banners and release mapping."""

import re

# Debian codename → (OSV ecosystem prefix, release number)
DEBIAN_RELEASES = {
    "deb13": ("trixie", "13"),
    "deb12": ("bookworm", "12"),
    "deb11": ("bullseye", "11"),
    "deb10": ("buster", "10"),
    "deb9": ("stretch", "9"),
}

# Ubuntu revision patterns → (codename, version)
UBUNTU_RELEASES = {
    "noble": ("noble", "24.04"),
    "jammy": ("jammy", "22.04"),
    "focal": ("focal", "20.04"),
    "bionic": ("bionic", "18.04"),
    "mantic": ("mantic", "23.10"),
    "lunar": ("lunar", "23.04"),
    "kinetic": ("kinetic", "22.10"),
}

# RHEL family freezes exactly one OpenSSH version per major release and never
# bumps the version string — fixes are backported as RPM release bumps
# (openssh-8.0p1-19.el8 → -29.el8_10). So the bare upstream version in the SSH
# banner deterministically identifies the el major. Banner has no portable
# "pN" suffix and no Debian-/Ubuntu- tag, e.g. "SSH-2.0-OpenSSH_8.0".
#   el7 → 7.4,  el8 → 8.0,  el9 → 8.7,  el10 → 9.9
RHEL_OPENSSH_RELEASES = {
    "7.4": "7",
    "8.0": "8",
    "8.7": "9",
    "9.9": "10",
}

# Map (distro, codename) → OSV ecosystem string
RELEASE_TO_OSV = {
    # RHEL family: AlmaLinux is the OSV proxy bucket. CloudLinux/Rocky/CentOS
    # and RHEL itself are el-ABI-identical and ship the same openssh-*.elN RPMs;
    # AlmaLinux's OSV feed (ALSA) carries the el fixed-version data and, unlike
    # the "Red Hat" OSV bucket, matches plain "openssh" version queries.
    # el7 has no AlmaLinux OSV feed (AlmaLinux starts at 8) — the "AlmaLinux:7"
    # bucket is a lookup key only, populated solely by the Red Hat securitydata
    # backfill (which writes distro="AlmaLinux", release="7"). Do NOT add it to
    # the OSV download ecosystems. el10 does have an AlmaLinux feed.
    ("rhel", "7"): "AlmaLinux:7",
    ("rhel", "8"): "AlmaLinux:8",
    ("rhel", "9"): "AlmaLinux:9",
    ("rhel", "10"): "AlmaLinux:10",
    ("debian", "trixie"): "Debian:13",
    ("debian", "bookworm"): "Debian:12",
    ("debian", "bullseye"): "Debian:11",
    ("debian", "buster"): "Debian:10",
    ("debian", "stretch"): "Debian:9",
    ("ubuntu", "noble"): "Ubuntu:24.04",
    ("ubuntu", "jammy"): "Ubuntu:22.04",
    ("ubuntu", "focal"): "Ubuntu:20.04",
    ("ubuntu", "bionic"): "Ubuntu:18.04",
    ("ubuntu", "mantic"): "Ubuntu:23.10",
    ("ubuntu", "lunar"): "Ubuntu:23.04",
    ("ubuntu", "kinetic"): "Ubuntu:22.10",
    ("alpine", "3.20"): "Alpine:3.20",
    ("alpine", "3.19"): "Alpine:3.19",
    ("alpine", "3.18"): "Alpine:3.18",
}

# SSH banner patterns
_RE_DEBIAN_SSH = re.compile(
    r"OpenSSH_[\d.]+p\d+\s+Debian-(\S+)", re.IGNORECASE
)
_RE_UBUNTU_SSH = re.compile(
    r"OpenSSH_[\d.]+p\d+\s+Ubuntu-(\S+)", re.IGNORECASE
)
# RHEL-family SSH banner: bare "OpenSSH_<maj>.<min>" with NO portable "pN"
# suffix and NO distro tag. The absence of "pN" is itself the RHEL tell —
# upstream portable always carries it, Debian/Ubuntu carry it plus a tag.
_RE_BARE_SSH = re.compile(
    r"OpenSSH_(\d+\.\d+)(p\d+)?(.*)$", re.IGNORECASE
)
# HTTP Server header patterns
_RE_RHEL_HTTP = re.compile(
    r"\(Red\s+Hat(?:\s+Enterprise\s+Linux)?\)", re.IGNORECASE
)
_RE_DEBIAN_HTTP = re.compile(r"\(Debian\)", re.IGNORECASE)
_RE_UBUNTU_HTTP = re.compile(r"\(Ubuntu\)", re.IGNORECASE)


def detect_debian_release(revision):
    """Map Debian package revision to codename.

    E.g. '2+deb12u7' → 'bookworm'
    """
    for tag, (codename, _) in DEBIAN_RELEASES.items():
        if tag in revision:
            return codename
    return None


def detect_ubuntu_release(revision):
    """Map Ubuntu package revision to codename.

    E.g. '3ubuntu0.10' → try matching known codename hints.
    Ubuntu revisions don't always embed the codename, so this is best-effort.
    """
    rev_lower = revision.lower()
    for codename in UBUNTU_RELEASES:
        if codename in rev_lower:
            return codename
    return None


def detect_rhel_release(openssh_version):
    """Map a bare OpenSSH version to a RHEL/el major release.

    E.g. '8.0' → '8'. Returns None for versions RHEL never shipped (which
    therefore are not a backported-el build).
    """
    return RHEL_OPENSSH_RELEASES.get(openssh_version)


def detect_distro_from_banner(banner):
    """Parse a service banner to detect distro information.

    Returns a dict with keys: distro, distro_release, package_revision
    or None if no distro detected.
    """
    if not banner:
        return None

    # Debian SSH banner: OpenSSH_9.2p1 Debian-2+deb12u7
    m = _RE_DEBIAN_SSH.search(banner)
    if m:
        revision = m.group(1)
        codename = detect_debian_release(revision)
        return {
            "distro": "debian",
            "distro_release": codename,
            "package_revision": revision,
        }

    # Ubuntu SSH banner: OpenSSH_8.9p1 Ubuntu-3ubuntu0.10
    m = _RE_UBUNTU_SSH.search(banner)
    if m:
        revision = m.group(1)
        codename = detect_ubuntu_release(revision)
        return {
            "distro": "ubuntu",
            "distro_release": codename,
            "package_revision": revision,
        }

    # RHEL-family SSH banner: bare "OpenSSH_8.0" — no portable "pN", no distro
    # tag, and the version is one RHEL actually froze for an el major. The
    # Debian/Ubuntu SSH checks above already consumed any tagged banner, so a
    # match here is a strong el-family signal. distro_release is the el major;
    # callers may corroborate with the SSH crypto fingerprint (Tier 2).
    m = _RE_BARE_SSH.search(banner)
    if m and not m.group(2):  # group(2) is the "pN" suffix — must be absent
        tail = m.group(3) or ""
        if not re.search(r"Debian-|Ubuntu-", tail, re.IGNORECASE):
            el_major = detect_rhel_release(m.group(1))
            if el_major:
                return {
                    "distro": "rhel",
                    "distro_release": el_major,
                    "package_revision": None,
                }

    # RHEL HTTP banner: Apache/2.4.37 (Red Hat Enterprise Linux)
    if _RE_RHEL_HTTP.search(banner):
        return {
            "distro": "rhel",
            "distro_release": None,
            "package_revision": None,
        }

    # Debian HTTP banner: Apache/2.4.57 (Debian)
    if _RE_DEBIAN_HTTP.search(banner):
        return {
            "distro": "debian",
            "distro_release": None,
            "package_revision": None,
        }

    # Ubuntu HTTP banner: Apache/2.4.52 (Ubuntu)
    if _RE_UBUNTU_HTTP.search(banner):
        return {
            "distro": "ubuntu",
            "distro_release": None,
            "package_revision": None,
        }

    return None


def get_osv_ecosystem(distro, distro_release):
    """Map distro + release codename to OSV ecosystem string.

    Returns e.g. 'Debian:12' or None if unmapped.
    """
    if not distro or not distro_release:
        return None
    return RELEASE_TO_OSV.get((distro, distro_release))


def get_osv_ecosystem_parts(distro, distro_release):
    """Map distro + release codename to (osv_prefix, osv_release).

    Returns e.g. ('Debian', '12') or (None, None) if unmapped.
    """
    eco = get_osv_ecosystem(distro, distro_release)
    if eco and ":" in eco:
        parts = eco.split(":", 1)
        return parts[0], parts[1]
    return None, None

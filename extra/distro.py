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

# Map (distro, codename) → OSV ecosystem string
RELEASE_TO_OSV = {
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

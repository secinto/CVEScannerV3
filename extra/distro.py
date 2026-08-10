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

# Stock OpenSSH upstream version per Debian/Ubuntu release. Unlike Debian's
# "+deb12u7", an Ubuntu package revision ("3ubuntu13.16") does not embed the
# codename, so the revision alone cannot resolve a release. Each release does
# pin exactly one upstream OpenSSH version for its lifetime, so the version
# resolves it instead. Only unambiguous versions are mapped: 9.0p1 shipped in
# both kinetic and lunar and so is deliberately absent.
#
# These maps are consulted ONLY when a distro tag is present in the banner.
# A bare banner (DebianBanner no) must stay unresolved — matching a stock
# version there would assert a patch level the banner does not carry.
UBUNTU_OPENSSH_RELEASES = {
    "7.6p1": "bionic",
    "8.2p1": "focal",
    "8.9p1": "jammy",
    "9.3p1": "mantic",
    "9.6p1": "noble",
}
DEBIAN_OPENSSH_RELEASES = {
    "7.4p1": "stretch",
    "7.9p1": "buster",
    "8.4p1": "bullseye",
    "9.2p1": "bookworm",
    "10.0p2": "trixie",
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

# RHEL family also freezes the Apache httpd version per major and backports
# fixes as RPM release bumps. BUT, unlike OpenSSH, httpd is periodically
# *rebased* within el9/el10 (el9 has shipped 2.4.51 … 2.4.62; el10 is 2.4.63),
# and some versions (e.g. 2.4.62) appear in more than one major — so the banner
# version is NOT a collision-free el discriminator there. Only el7 (2.4.6) and
# el8 (2.4.37) are frozen-for-life with a unique version, so only those are
# mapped. el9/el10 httpd hosts resolve to distro=rhel with release=None (no
# false suppression); their release is meant to be pinned later via
# cross-service host-level OS propagation, not the httpd banner alone.
# Unlike OpenSSH there is no "pN"-style RHEL tell in an Apache banner, so this
# map is only consulted when an el-family Server-tag is present (see
# _RE_RHEL_HTTP) — never on a bare "Apache/x.y.z".
RHEL_HTTPD_RELEASES = {
    "2.4.6": "7",
    "2.4.37": "8",
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
#
# The separator is [-\s], not just "-": sshd sends "OpenSSH_9.6p1
# Ubuntu-3ubuntu13.16", but nmap normalizes that hyphen to a space in its
# `version` attribute ("9.6p1 Ubuntu 3ubuntu13.16"), and banners are
# synthesized from that attribute. Matching only the hyphen silently missed
# every nmap-derived banner, so Debian/Ubuntu backport suppression never ran.
#
# The revision must start with a digit. Synthesized banners append nmap's
# `extrainfo`, which reads "Ubuntu Linux; protocol 2.0" — without that anchor
# a tagless banner would capture "Linux;" as its package revision.
_RE_DEBIAN_SSH = re.compile(
    r"OpenSSH_([\d.]+p\d+)\s+Debian[-\s](\d\S*)", re.IGNORECASE
)
_RE_UBUNTU_SSH = re.compile(
    r"OpenSSH_([\d.]+p\d+)\s+Ubuntu[-\s](\d\S*)", re.IGNORECASE
)
# RHEL-family SSH banner: bare "OpenSSH_<maj>.<min>" with NO portable "pN"
# suffix and NO distro tag. The absence of "pN" is itself the RHEL tell —
# upstream portable always carries it, Debian/Ubuntu carry it plus a tag.
_RE_BARE_SSH = re.compile(
    r"OpenSSH_(\d+\.\d+)(p\d+)?(.*)$", re.IGNORECASE
)
# HTTP Server header patterns
# el-family Server tag: Red Hat itself plus the el-ABI-identical rebuilds
# (CentOS, CloudLinux, AlmaLinux, Rocky, Oracle Linux) that ship the same
# httpd-*.elN RPMs and so share the AlmaLinux:N backport bucket.
_RE_RHEL_HTTP = re.compile(
    r"\((?:Red\s+Hat(?:\s+Enterprise\s+Linux)?"
    r"|CentOS|CloudLinux|AlmaLinux|Rocky(?:\s+Linux)?|Oracle(?:\s+Linux)?)\)",
    re.IGNORECASE,
)
_RE_DEBIAN_HTTP = re.compile(r"\(Debian\)", re.IGNORECASE)
_RE_UBUNTU_HTTP = re.compile(r"\(Ubuntu\)", re.IGNORECASE)
# Apache version inside a Server header or synthesized banner. Tolerates both
# the HTTP Server-header shape "Apache/2.4.37 ..." and nmap's product-based
# synthesis "Apache httpd/2.4.37 ..." (nmap reports product="Apache httpd").
_RE_APACHE_VER = re.compile(r"Apache(?:\s+httpd)?/(\d+\.\d+\.\d+)", re.IGNORECASE)


def detect_debian_release(revision, version=None):
    """Map Debian package revision to codename.

    E.g. '2+deb12u7' → 'bookworm'

    `version` is the upstream OpenSSH version from the same tagged banner. It
    is a fallback for revisions nmap truncated to a bare number ("Debian 7"),
    where the "+debN" marker is gone.
    """
    for tag, (codename, _) in DEBIAN_RELEASES.items():
        if tag in revision:
            return codename
    return DEBIAN_OPENSSH_RELEASES.get(version or "")


def detect_ubuntu_release(revision, version=None):
    """Map Ubuntu package revision to codename.

    E.g. '3ubuntu0.10' → try matching known codename hints.
    Ubuntu revisions don't always embed the codename, so this is best-effort.

    `version` is the upstream OpenSSH version from the same tagged banner.
    Ubuntu revisions normally carry no codename at all ('3ubuntu13.16'), so
    the stock-version map is the primary resolver here, not a rare fallback.
    """
    rev_lower = revision.lower()
    for codename in UBUNTU_RELEASES:
        if codename in rev_lower:
            return codename
    return UBUNTU_OPENSSH_RELEASES.get(version or "")


def detect_rhel_release(openssh_version):
    """Map a bare OpenSSH version to a RHEL/el major release.

    E.g. '8.0' → '8'. Returns None for versions RHEL never shipped (which
    therefore are not a backported-el build).
    """
    return RHEL_OPENSSH_RELEASES.get(openssh_version)


def detect_rhel_httpd_release(httpd_version):
    """Map a frozen Apache httpd version to a RHEL/el major release.

    E.g. '2.4.37' → '8'. Returns None for versions that are not a unique,
    frozen-for-life el identifier (el9/el10 rebase httpd and are intentionally
    not mapped — see RHEL_HTTPD_RELEASES). Only meaningful when the banner
    already carries an el-family Server tag.
    """
    return RHEL_HTTPD_RELEASES.get(httpd_version)


def detect_distro_from_banner(banner):
    """Parse a service banner to detect distro information.

    Returns a dict with keys: distro, distro_release, package_revision
    or None if no distro detected.
    """
    if not banner:
        return None

    # Debian SSH banner: OpenSSH_9.2p1 Debian-2+deb12u7
    # (nmap-normalized: OpenSSH_9.2p1 Debian 2+deb12u10)
    m = _RE_DEBIAN_SSH.search(banner)
    if m:
        version, revision = m.group(1), m.group(2)
        codename = detect_debian_release(revision, version)
        return {
            "distro": "debian",
            "distro_release": codename,
            "package_revision": revision,
        }

    # Ubuntu SSH banner: OpenSSH_8.9p1 Ubuntu-3ubuntu0.10
    # (nmap-normalized: OpenSSH_9.6p1 Ubuntu 3ubuntu13.16)
    m = _RE_UBUNTU_SSH.search(banner)
    if m:
        version, revision = m.group(1), m.group(2)
        codename = detect_ubuntu_release(revision, version)
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
        if not re.search(r"Debian[-\s]|Ubuntu[-\s]", tail, re.IGNORECASE):
            el_major = detect_rhel_release(m.group(1))
            if el_major:
                return {
                    "distro": "rhel",
                    "distro_release": el_major,
                    "package_revision": None,
                }

    # RHEL-family HTTP banner: Apache/2.4.37 (Red Hat Enterprise Linux),
    # ... (CentOS) / (CloudLinux) / (AlmaLinux) / (Rocky Linux) / (Oracle Linux).
    # The el-family Server tag fixes the distro; a frozen-for-life httpd version
    # (el7 2.4.6 / el8 2.4.37) additionally pins the el major. el9/el10 httpd is
    # rebased so its version is left unmapped → release stays None (no
    # suppression) until cross-service OS propagation supplies it.
    if _RE_RHEL_HTTP.search(banner):
        el_major = None
        vm = _RE_APACHE_VER.search(banner)
        if vm:
            el_major = detect_rhel_httpd_release(vm.group(1))
        return {
            "distro": "rhel",
            "distro_release": el_major,
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


# Patch-confidence states. External scanning can read a version string but not
# a patch level, and those are different things: a distro backports security
# fixes without moving the upstream version, so "OpenSSH 9.2p1" alone says
# nothing about whether a given CVE is fixed. These three states record how
# much the observed banner actually supports.
#
#   CONFIRMED  a package revision was observed (Debian/Ubuntu tag) or the
#              el-family frozen-version path resolved a release. Backport
#              evaluation applies and its verdict can be trusted.
#   UNKNOWN    the host is evidently distro-managed but disclosed no patch
#              level -- a stripped banner (DebianBanner no), or an OS tag with
#              no revision. Version-range matching still produces CVEs, but
#              they are POTENTIAL: undecidable from outside.
#   UPSTREAM   the version is not attributable to any distro's stock package,
#              so upstream range matching means what it says.
PATCH_CONFIRMED = "confirmed"
PATCH_LEVEL_UNKNOWN = "patch-level-unknown"
PATCH_UPSTREAM = "upstream"


def matches_distro_stock_version(version):
    """Distro releases whose stock OpenSSH is exactly `version`.

    Returns a list of (distro, codename); empty when the version belongs to no
    known stock package. A bare "9.2p1" is Bookworm's stock OpenSSH, which
    makes the host *probably* distro-managed -- evidence for lowering
    confidence, never for asserting a patch level.
    """
    if not version:
        return []
    out = [("debian", c) for v, c in DEBIAN_OPENSSH_RELEASES.items() if v == version]
    out += [("ubuntu", c) for v, c in UBUNTU_OPENSSH_RELEASES.items() if v == version]
    return out


def classify_patch_confidence(hint, version=None):
    """Classify how far a service's patch level is externally knowable.

    `hint` is a detect_distro_from_banner() result (or None); `version` is the
    upstream version string. Returns one of the PATCH_* constants.
    """
    if hint:
        # A package revision is the only direct evidence of a patch level.
        if hint.get("package_revision"):
            return PATCH_CONFIRMED
        # el-family: the version is frozen per major and fixes ship as RPM
        # release bumps, so a resolved release IS the patch context. This is
        # the established Tier-1 path and is deliberately left confident.
        if hint.get("distro") == "rhel" and hint.get("distro_release"):
            return PATCH_CONFIRMED
        # Distro-tagged but no revision, e.g. "Apache/2.4.57 (Debian)".
        return PATCH_LEVEL_UNKNOWN

    if matches_distro_stock_version(version):
        return PATCH_LEVEL_UNKNOWN

    return PATCH_UPSTREAM


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

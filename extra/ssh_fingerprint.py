#!/usr/bin/env python3

# SPDX-License-Identifier: GPL-3.0-or-later

"""SSH crypto-fingerprint analysis (Tier 2 backport corroboration).

The SSH version banner alone cannot prove whether an OpenSSH that reports an
old version (e.g. RHEL/el8's frozen "OpenSSH_8.0") has been security-patched,
because the distro never bumps the version string. The set of algorithms the
server offers during key exchange *can*, because some algorithms did not exist
in the upstream release the banner claims:

  * ``kex-strict-s-v00@openssh.com`` — the "strict KEX" countermeasure for the
    Terrapin attack (CVE-2023-48795). Introduced upstream in OpenSSH 9.6
    (Dec 2023). A server advertising it cannot be an unpatched upstream release
    older than 9.6, so on a banner claiming e.g. 8.0 its presence is direct
    proof the binary was patched/backported beyond its upstream baseline.

This module turns the algorithm lists (as produced by
``nmap --script ssh2-enum-algos`` or ``ssh-audit``) into a small evidence dict
the CVE pipeline uses to (a) raise confidence on banner-only backport
suppressions and (b) directly decide the Terrapin CVE.
"""

# Server-side strict-KEX marker (Terrapin / CVE-2023-48795 mitigation, OpenSSH 9.6+).
STRICT_KEX_MARKER = "kex-strict-s-v00@openssh.com"

# The Terrapin prefix-truncation attack requires a vulnerable cipher/MAC
# combination to be negotiable: ChaCha20-Poly1305, or any CBC cipher paired
# with an Encrypt-then-MAC algorithm.
_CHACHA = "chacha20-poly1305@openssh.com"

# CVE that the crypto fingerprint can decide directly rather than just corroborate.
TERRAPIN_CVE = "CVE-2023-48795"


def _norm(algos):
    """Normalise an algorithm list to a lowercase set, tolerating None/str."""
    if not algos:
        return set()
    if isinstance(algos, str):
        algos = algos.replace(",", " ").split()
    return {a.strip().lower() for a in algos if a and a.strip()}


def analyze_ssh_crypto(kex_algorithms=None, encryption_algorithms=None,
                       mac_algorithms=None):
    """Analyse offered SSH algorithms into a backport-evidence dict.

    Returns keys:
      has_crypto_evidence  -- any algorithm data was supplied
      strict_kex           -- server offers the strict-KEX marker (>= 9.6 code)
      backport_corroborated-- strict_kex (proves binary patched beyond upstream
                              version it advertises)
      terrapin_vulnerable  -- Terrapin-capable cipher/MAC negotiable AND no
                              strict KEX → CVE-2023-48795 is actually present
    """
    kex = _norm(kex_algorithms)
    enc = _norm(encryption_algorithms)
    mac = _norm(mac_algorithms)
    have = bool(kex or enc or mac)

    strict_kex = STRICT_KEX_MARKER in kex

    cbc = any(c.endswith("-cbc") for c in enc)
    etm = any(m.endswith("-etm@openssh.com") for m in mac)
    terrapin_capable = (_CHACHA in enc) or (cbc and etm)

    return {
        "has_crypto_evidence": have,
        "strict_kex": strict_kex,
        "backport_corroborated": strict_kex,
        "terrapin_vulnerable": bool(have and terrapin_capable and not strict_kex),
    }


def crypto_from_service(service):
    """Build the evidence dict from a service dict's SSH algorithm fields.

    Producer (checkfix_test) populates ssh_kex_algorithms /
    ssh_encryption_algorithms / ssh_mac_algorithms from ssh2-enum-algos.
    Returns None when no SSH crypto fields are present at all.
    """
    if not any(k in service for k in (
        "ssh_kex_algorithms",
        "ssh_encryption_algorithms",
        "ssh_mac_algorithms",
    )):
        return None
    return analyze_ssh_crypto(
        kex_algorithms=service.get("ssh_kex_algorithms"),
        encryption_algorithms=service.get("ssh_encryption_algorithms"),
        mac_algorithms=service.get("ssh_mac_algorithms"),
    )

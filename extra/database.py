#!/usr/bin/env python3

# SPDX-License-Identifier: GPL-3.0-or-later

# database - Database generator/updater.

# Copyright (C) 2025 secinto GmbH.

# This file is part of CVEScannerV3.

# CVEScannerV3 is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# CVEScannerV3 is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import argparse
import html
import os
import random
import re
import sqlite3 as sql
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from queue import Empty, Queue
from threading import Event, Thread
from urllib.parse import quote as _urlquote

import httpx
from fake_useragent import UserAgent

from pyrate_limiter import Duration, Limiter, Rate
from tqdm import tqdm


# NVD allows 50 requests per rolling 30s window with an API key. Setting the
# rate this close to the ceiling can momentarily burst over it (and thus draw
# 429s), so default a little below and let it be tuned via the environment.
NVD_RATE_PER_30S = int(os.getenv("NVD_RATE_PER_30S", "40"))
# pyrate-limiter Duration is millisecond-based, so a 30s window is
# Duration.SECOND * 30. The sync decorator blocks until a slot frees (the v4
# equivalent of the old v2 `delay=True`).
LIMITER = Limiter(Rate(NVD_RATE_PER_30S, Duration.SECOND * 30))
# NVD's edge (Cloudflare) intermittently answers with HTTP 429 or an HTML 503
# "No server is available" page instead of JSON. Retry transient failures with
# exponential backoff so a blip doesn't silently drop a whole batch of records.
NVD_MAX_RETRIES = int(os.getenv("NVD_MAX_RETRIES", "6"))
NVD_BACKOFF_BASE = float(os.getenv("NVD_BACKOFF_BASE", "2.0"))
NVD_BACKOFF_CAP = float(os.getenv("NVD_BACKOFF_CAP", "120.0"))
# Status codes worth retrying (transient): rate-limit + the 5xx family.
NVD_RETRY_STATUS = (429, 500, 502, 503, 504)
UA = UserAgent()
KEY = ""
RE = {
    "tit": re.compile(
        r"""<meta property=(?P<quote>['"])og:title(?P=quote) """
        r"""content=(?P<quotex>['"])(.*?)(?P=quotex)""",
        re.IGNORECASE | re.DOTALL,
    ),
    "msf": re.compile(
        r"""['"]Name['"]\s+=>\s+(?P<quote>['"])((\\.|.)*?)(?P=quote)""",
        re.IGNORECASE | re.DOTALL,
    ),
    "cpe": re.compile(
        r"cpe:2.3:"
        r"(.*?)(?<!:):(?!:)"
        r"(.*?)(?<!:):(?!:)"
        r"(.*?)(?<!:):(?!:)"
        r"(.*?)(?<!:):(?!:)"
        r"(.*?)(?<!:):(?!:)"
        r".*"
    ),
    "v3": re.compile(r"(cvssMetricV3.+)"),
    "exp": re.compile(r"https?://www.exploit-db.com/exploits/(\d+)"),
    "cve": re.compile(r"CVE-\d+-\d+"),
}
VTAGS = (
    "versionStartIncluding",
    "versionStartExcluding",
    "versionEndIncluding",
    "versionEndExcluding",
)
URL = {
    "nvd": "https://services.nvd.nist.gov/rest/json/{}/2.0?startIndex={}",
    "expdb": "https://www.exploit-db.com/exploits",
    "msfdb": "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
}
CONST = {
    "cpe": 10000,  # max results per page
    "cve": 2000,
    "bat": 25,
}


class DatabaseUpdateError(Exception):
    """Raised when the database update process fails."""
    pass


COPYRIGHT = """
CVEScannerV3  Copyright (C) 2025 secinto GmbH.
This program comes with ABSOLUTELY NO WARRANTY; for details check below.
This is free software, and you are welcome to redistribute it
under certain conditions; check below for details.
"""  # noqa


class Database:
    def __init__(self, database):
        self.path = database

    def __enter__(self):
        self.conn = sql.connect(self.path)
        self.cursor = self.conn.cursor()
        return self

    def __exit__(self, exc_class, exc, traceback):
        self.conn.commit()
        self.conn.close()

    def setup(self):
        self.cursor.executescript(
            """
            CREATE TABLE IF NOT EXISTS metadata (
                id INTEGER PRIMARY KEY,
                last_mod TEXT
            );

            CREATE TABLE IF NOT EXISTS exploits (
                exploit_id INTEGER PRIMARY KEY,
                name TEXT
            );

            CREATE TABLE IF NOT EXISTS metasploits (
                metasploit_id INTEGER PRIMARY KEY,
                name TEXT UNIQUE
            );

            CREATE TABLE IF NOT EXISTS cves (
                cve_id TEXT PRIMARY KEY,
                cvss_v2 TEXT,
                cvss_v3 TEXT,
                published INTEGER
            );

            CREATE TABLE IF NOT EXISTS products (
                product_id INTEGER PRIMARY KEY,
                vendor TEXT,
                product TEXT,
                version TEXT,
                version_update TEXT,
                UNIQUE (vendor, product, version, version_update)
            );

            CREATE TABLE IF NOT EXISTS affected (
                cve_id TEXT,
                product_id INT,
                FOREIGN KEY (cve_id)
                    REFERENCES cves (cve_id),
                FOREIGN KEY (product_id)
                    REFERENCES products (product_id),
                PRIMARY KEY (cve_id, product_id)
            );

            CREATE TABLE IF NOT EXISTS multiaffected (
                cve_id TEXT,
                product_id INT,
                versionStartIncluding TEXT,
                versionStartExcluding TEXT,
                versionEndIncluding TEXT,
                versionEndExcluding TEXT,
                FOREIGN KEY (cve_id)
                    REFERENCES cves (cve_id),
                FOREIGN KEY (product_id)
                    REFERENCES products (product_id),
                PRIMARY KEY (cve_id, product_id,
                             versionStartIncluding, versionStartExcluding,
                             versionEndIncluding, versionEndExcluding)
            );

            CREATE TABLE IF NOT EXISTS referenced_exploit (
                cve_id TEXT,
                exploit_id INTEGER,
                FOREIGN KEY (cve_id)
                    REFERENCES cves (cve_id),
                FOREIGN KEY (exploit_id)
                    REFERENCES exploits (exploit_id),
                PRIMARY KEY (cve_id, exploit_id)
            );

            CREATE TABLE IF NOT EXISTS referenced_metasploit (
                cve_id TEXT,
                metasploit_id INTEGER,
                FOREIGN KEY (cve_id)
                    REFERENCES cves (cve_id),
                FOREIGN KEY (metasploit_id)
                    REFERENCES metasploits (metasploit_id),
                PRIMARY KEY (cve_id, metasploit_id)
            );

            CREATE TABLE IF NOT EXISTS backports (
                cve_id TEXT NOT NULL,
                distro TEXT NOT NULL,
                release TEXT NOT NULL,
                package TEXT NOT NULL,
                fixed_version TEXT,
                status TEXT NOT NULL,
                reason TEXT,
                source TEXT,
                citation TEXT,
                UNIQUE (cve_id, distro, release, package)
            );

            CREATE TABLE IF NOT EXISTS backport_metadata (
                id INTEGER PRIMARY KEY,
                ecosystem TEXT NOT NULL UNIQUE,
                last_updated TEXT,
                record_count INTEGER
            );

            PRAGMA foreign_keys = ON;

            CREATE INDEX IF NOT EXISTS idx_products_product
                ON products(product);
            CREATE INDEX IF NOT EXISTS idx_products_product_version
                ON products(product, version);
            CREATE INDEX IF NOT EXISTS idx_referenced_exploit_cve
                ON referenced_exploit(cve_id);
            CREATE INDEX IF NOT EXISTS idx_referenced_metasploit_cve
                ON referenced_metasploit(cve_id);
            CREATE INDEX IF NOT EXISTS idx_affected_product
                ON affected(product_id);
            CREATE INDEX IF NOT EXISTS idx_multiaffected_product
                ON multiaffected(product_id);
            CREATE INDEX IF NOT EXISTS idx_backports_cve
                ON backports(cve_id);
            CREATE INDEX IF NOT EXISTS idx_backports_package_release
                ON backports(package, distro, release);
            """
        )
        self._migrate_backports_columns()

    def _migrate_backports_columns(self):
        """Idempotently add disposition columns to a pre-existing backports table.

        CREATE TABLE IF NOT EXISTS won't add columns to a DB built before these
        existed; add them in place so older cve.db files upgrade without a full
        rebuild (the weekly rebuild self-heals too).
        """
        existing = {row[1] for row in self.cursor.execute(
            "PRAGMA table_info(backports)").fetchall()}
        for col in ("reason", "source", "citation"):
            if col not in existing:
                self.cursor.execute(
                    f"ALTER TABLE backports ADD COLUMN {col} TEXT")

    def cached_metadata(self):
        self.cursor.execute("SELECT last_mod FROM metadata")
        return self.cursor.fetchone()[0]

    def cached_cve(self, cve):
        self.cursor.execute(
            "SELECT EXISTS "
            "("
            "SELECT 1 "
            "FROM cves "
            "WHERE cve_id = ?"
            ")",
            [cve],
        )
        return self.cursor.fetchone()[0]

    def cached_exploits(self):
        self.cursor.execute(
            "SELECT exploit_id FROM exploits WHERE name IS NULL"
        )
        return [expl[0] for expl in self.cursor.fetchall()]

    def insert_products(self, products):
        self.cursor.executemany(
            "INSERT or IGNORE INTO products "
            "(vendor, product, version, version_update) "
            "VALUES (?, ?, ?, ?)",
            products,
        )
        self.conn.commit()

    def insert_cves(self, cves):
        self.cursor.executemany(
            "INSERT or REPLACE INTO cves VALUES (?, ?, ?, ?)",
            cves,
        )
        self.conn.commit()

    def insert_exploits(self, exploits):
        self.cursor.executemany(
            "INSERT or IGNORE INTO exploits (exploit_id) VALUES (?)",
            exploits,
        )
        self.conn.commit()

    def insert_metasploits(self, metasploits):
        self.cursor.executemany(
            "INSERT or IGNORE INTO metasploits (name) VALUES (?)",
            metasploits,
        )
        self.conn.commit()

    def insert_affected(self, cves_products):
        self.cursor.executemany(
            "INSERT or IGNORE INTO affected "
            "VALUES "
            "(?, "
            "("
            "SELECT product_id FROM products "
            "WHERE vendor = ? AND product = ? "
            "AND version = ? AND version_update = ?"
            ")"
            ")",
            cves_products,
        )
        self.conn.commit()

    def insert_multiaffected(self, cves_products_versions):
        self.cursor.executemany(
            "INSERT or IGNORE INTO multiaffected "
            "VALUES "
            "(?, "
            "("
            "SELECT product_id FROM products "
            "WHERE vendor = ? AND product = ? "
            "AND version = '*'"
            "), "
            "?, ?, ?, ?)",
            cves_products_versions,
        )
        self.conn.commit()

    def insert_referenced(self, cves_exploits):
        self.cursor.executemany(
            "INSERT or IGNORE INTO referenced_exploit VALUES (?, ?)",
            cves_exploits,
        )
        self.conn.commit()

    def insert_referencedm(self, cves_exploits):
        self.cursor.executemany(
            "INSERT or IGNORE INTO referenced_metasploit "
            "VALUES "
            "(?, "
            "("
            "SELECT metasploit_id "
            "FROM metasploits "
            "WHERE name = ?"
            ")"
            ")",
            cves_exploits,
        )
        self.conn.commit()

    def update_metadata(self):
        self.cursor.execute(
            "INSERT or REPLACE INTO metadata VALUES (1, ?)", [now()]
        )
        self.conn.commit()

    def update_exploits(self, exploits):
        self.cursor.executemany(
            "UPDATE exploits SET name = ? WHERE exploit_id = ?",
            exploits,
        )
        self.conn.commit()

    def remove_cves(self, cves):
        self.cursor.executemany(
            "DELETE FROM referenced_exploit WHERE cve_id = ?", cves
        )
        self.cursor.executemany(
            "DELETE FROM referenced_metasploit WHERE cve_id = ?", cves
        )
        self.cursor.executemany("DELETE FROM affected WHERE cve_id = ?", cves)
        self.cursor.executemany(
            "DELETE FROM multiaffected WHERE cve_id = ?", cves
        )
        self.cursor.executemany("DELETE FROM cves WHERE cve_id = ?", cves)
        self.conn.commit()

    def clean(self):
        self.cursor.execute(
            "DELETE FROM referenced_exploit "
            "WHERE exploit_id IN "
            "("
            "SELECT exploit_id "
            "FROM exploits "
            "WHERE name LIKE '404 Page %'"
            ")"
        )
        self.cursor.execute(
            "DELETE FROM exploits WHERE name LIKE '404 Page %'"
        )
        self.conn.commit()


DEFAULT_ECOSYSTEMS = [
    "Debian:12",
    "Debian:11",
    "Ubuntu:24.04:LTS",
    "Ubuntu:22.04:LTS",
    "Ubuntu:20.04:LTS",
]

OSV_BULK_URL = (
    "https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"
)

# OSV publishes Debian/Ubuntu bulk exports keyed per release (the bucket name
# includes the release, e.g. "Debian:12"). RHEL-family distros instead publish
# ONE bulk export per distro covering all releases — the bucket name is the
# bare distro ("AlmaLinux", "Rocky Linux", "Red Hat") and the release lives only
# in each record's package.ecosystem ("AlmaLinux:8"). So the download bucket and
# the per-record ecosystem filter differ for these distros.
_COMBINED_BULK_DISTROS = {"AlmaLinux", "Rocky Linux", "Red Hat"}


def _bulk_bucket(distro, ecosystem):
    """OSV bulk-export bucket name for an ecosystem (see _COMBINED_BULK_DISTROS)."""
    return distro if distro in _COMBINED_BULK_DISTROS else ecosystem


def parse_ecosystem(ecosystem):
    """Split an OSV ecosystem string into (distro, release) for the backports table.

    OSV bucket keys use distro-specific shapes:
      - Debian uses ``Debian:<N>`` (e.g. ``Debian:12``)
      - Ubuntu uses ``Ubuntu:<X.Y>[:LTS]`` (e.g. ``Ubuntu:22.04:LTS``)

    The downstream lookup in ``cvescan.check_backports`` queries the table with
    the canonical release form (``"22.04"``, not ``"22.04:LTS"``), so the
    trailing ``:LTS`` segment is stripped here when storing rows. The original
    ecosystem string is still used as the bucket key and as the per-record
    ``package.ecosystem`` filter.
    """
    if ":" not in ecosystem:
        return None, None
    distro, _, release = ecosystem.partition(":")
    if release.endswith(":LTS"):
        release = release[: -len(":LTS")]
    return distro, release


def now():
    return datetime.now(timezone.utc).isoformat()


def update_backports_osv(db_path, ecosystems=None):
    """Download OSV.dev bulk exports and populate the backports table.

    Args:
        db_path: Path to the SQLite database.
        ecosystems: list of ecosystem strings like ["Debian:12", "Ubuntu:22.04"].
                    Defaults to DEFAULT_ECOSYSTEMS.
    """
    import io
    import json as _json
    import zipfile

    if ecosystems is None:
        ecosystems = DEFAULT_ECOSYSTEMS

    # Cache downloaded bulk zips: RHEL-family releases (AlmaLinux:8, AlmaLinux:9)
    # share one per-distro bucket, so we fetch it once and filter per release.
    bulk_cache = {}

    with Database(db_path) as db:
        db.setup()
        for ecosystem in ecosystems:
            distro, release = parse_ecosystem(ecosystem)
            if not distro or not release:
                print(f"[!] Invalid ecosystem format: {ecosystem}")
                continue

            bulk_name = _bulk_bucket(distro, ecosystem)
            zf = bulk_cache.get(bulk_name)
            if zf is None:
                # Preserve ":" (a literal segment in OSV bucket keys), encode
                # spaces ("Rocky Linux" → "Rocky%20Linux").
                url = OSV_BULK_URL.format(ecosystem=_urlquote(bulk_name, safe=":"))
                print(f"[*] Downloading OSV data for {bulk_name}...")
                try:
                    resp = httpx.get(url, timeout=300, follow_redirects=True)
                    resp.raise_for_status()
                except (httpx.HTTPError, httpx.TimeoutException) as e:
                    print(f"[!] Failed to download {bulk_name}: {e}")
                    continue
                try:
                    zf = zipfile.ZipFile(io.BytesIO(resp.content))
                except zipfile.BadZipFile:
                    print(f"[!] Invalid zip file for {bulk_name}")
                    continue
                bulk_cache[bulk_name] = zf

            # Clear existing data for this ecosystem
            db.cursor.execute(
                "DELETE FROM backports WHERE distro = ? AND release = ?",
                [distro, release],
            )

            record_count = 0
            batch = []
            json_files = [n for n in zf.namelist() if n.endswith(".json")]

            print(f"[+] Processing {len(json_files)} entries for {ecosystem}...")

            for name in json_files:
                try:
                    entry = _json.loads(zf.read(name))
                except (ValueError, KeyError):
                    continue

                # Collect CVE IDs from id, aliases, and related. Ubuntu OSV
                # records use IDs like "UBUNTU-CVE-YYYY-NNNN" or "USN-…" and
                # carry the canonical CVE only in `related`, so the alias-only
                # path silently drops every Ubuntu entry.
                cve_ids = set()
                candidates = [entry.get("id", "")]
                candidates.extend(entry.get("aliases") or [])
                candidates.extend(entry.get("related") or [])
                for cand in candidates:
                    if not cand:
                        continue
                    if cand.startswith("CVE-"):
                        cve_ids.add(cand)
                    elif cand.startswith("UBUNTU-CVE-"):
                        cve_ids.add(cand[len("UBUNTU-"):])

                if not cve_ids:
                    continue

                # Process affected packages
                for affected in entry.get("affected", []):
                    pkg = affected.get("package", {})
                    pkg_ecosystem = pkg.get("ecosystem", "")
                    pkg_name = pkg.get("name", "")
                    if not pkg_name or pkg_ecosystem != ecosystem:
                        continue

                    # Extract fixed versions from ranges
                    fixed_version = None
                    status = "affected"
                    for rng in affected.get("ranges", []):
                        if rng.get("type") != "ECOSYSTEM":
                            continue
                        for event in rng.get("events", []):
                            if "fixed" in event:
                                fixed_version = event["fixed"]
                                status = "fixed"

                    advisory = entry.get("id", "")
                    source = f"osv-{distro.lower().replace(' ', '')}"
                    if status == "fixed":
                        reason = f"{distro} {release}: fixed in {fixed_version}"
                    else:
                        reason = f"{distro} {release}: affected"
                    for cve_id in cve_ids:
                        batch.append((
                            cve_id, distro, release, pkg_name,
                            fixed_version, status, reason, source, advisory,
                        ))
                        record_count += 1

                # Flush in batches of 5000
                if len(batch) >= 5000:
                    db.cursor.executemany(
                        "INSERT OR REPLACE INTO backports (cve_id, distro, "
                        "release, package, fixed_version, status, reason, "
                        "source, citation) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        batch,
                    )
                    db.conn.commit()
                    batch = []

            # Flush remaining
            if batch:
                db.cursor.executemany(
                    "INSERT OR REPLACE INTO backports (cve_id, distro, "
                    "release, package, fixed_version, status, reason, "
                    "source, citation) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    batch,
                )
                db.conn.commit()

            # Update metadata
            db.cursor.execute(
                "INSERT OR REPLACE INTO backport_metadata "
                "(id, ecosystem, last_updated, record_count) "
                "VALUES ("
                "(SELECT id FROM backport_metadata WHERE ecosystem = ?), "
                "?, ?, ?)",
                [ecosystem, ecosystem, now(), record_count],
            )
            db.conn.commit()

            print(f"[+] {ecosystem}: {record_count} backport records loaded")

    print("[+] Backport data update complete")


# ---------------------------------------------------------------------------
# Red Hat securitydata — secondary backport source for the el8/el9 family.
#
# AlmaLinux's OSV (ALSA) feed misses some fixes Red Hat shipped (e.g.
# CVE-2020-14145, fixed in openssh-8.0p1-10.el8 via RHSA-2021:4368) and carries
# NO "Not affected" dispositions. Red Hat's securitydata API has both. Rows are
# merged into the AlmaLinux:N proxy bucket with INSERT OR IGNORE so the primary
# ALSA data wins and Red Hat only backfills gaps.
# ---------------------------------------------------------------------------

from redhat_backport import (  # noqa: E402
    RH_SECURITYDATA,
    rh_disposition,
    rh_fixed_version,
    rh_fix_state,
)
from ubuntu_backport import (  # noqa: E402
    DEFINITIVE_DISPOSITIONS,
    UBUNTU_SECURITY_API,
    ubuntu_rows_for_cve,
)


# The Ubuntu security API rejects limit > 20 with HTTP 422, so this is a hard
# ceiling rather than a tuning knob.
UBUNTU_PAGE_SIZE = 20
# It also rate-limits (HTTP 429) a burst of page requests. These bound the
# retry/backoff so a rebuild degrades into "slow" rather than "empty".
UBUNTU_MAX_RETRIES = 5
UBUNTU_BACKOFF_BASE = 3.0
UBUNTU_PAGE_PAUSE = 0.5


def update_backports_ubuntu(db_path, releases=("24.04", "22.04", "20.04"),
                            packages=("openssh",), page_size=UBUNTU_PAGE_SIZE):
    """Backfill the backports table from Canonical's security tracker.

    OSV's Ubuntu ecosystem only carries CVEs that got a published USN, so it
    misses not-affected determinations and silent SRU fixes entirely — 5
    openssh rows for 24.04 against Debian 12's 82. Canonical's tracker has the
    full per-release picture and its list endpoint embeds the statuses, so one
    paginated call per package suffices (no per-CVE detail fetch).

    Rows land in the same Ubuntu:<release> bucket as the OSV data. Canonical is
    upstream of that data, so its definitive verdicts (fixed / not_affected)
    replace an existing row, while softer ones (affected / wont_fix /
    fix_deferred) insert-or-ignore — a row already known to be fixed must never
    be downgraded to affected.
    """
    page_size = min(page_size, UBUNTU_PAGE_SIZE)

    def _get(url):
        """GET with backoff on rate-limiting. Canonical answers a burst of page
        requests with 429, so a naive loop silently yields zero rows."""
        for attempt in range(UBUNTU_MAX_RETRIES):
            resp = httpx.get(url, timeout=60, follow_redirects=True,
                             headers={"User-Agent": "checkfix-cvescanner",
                                      "Accept": "application/json"})
            if resp.status_code not in (429, 500, 502, 503, 504):
                resp.raise_for_status()
                return resp.json()
            if attempt == UBUNTU_MAX_RETRIES - 1:
                resp.raise_for_status()
            # Honour Retry-After when present, else exponential backoff.
            try:
                wait = float(resp.headers.get("Retry-After", ""))
            except ValueError:
                wait = 0.0
            time.sleep(max(wait, UBUNTU_BACKOFF_BASE * (2 ** attempt)))
        return None

    with Database(db_path) as db:
        db.setup()
        total = 0
        for package in packages:
            entries, offset = [], 0
            while True:
                url = (f"{UBUNTU_SECURITY_API}/cves.json?package={package}"
                       f"&limit={page_size}&offset={offset}")
                try:
                    page = _get(url)
                except (httpx.HTTPError, httpx.TimeoutException, ValueError) as e:
                    # Partial data is worse than none here: a missing page
                    # would look like "Canonical has no verdict", which reads
                    # as unfixed. Drop the package rather than half-record it.
                    print(f"[!] Ubuntu fetch failed for {package} "
                          f"(offset {offset}): {e} — skipping package")
                    entries = []
                    break
                if page is None:
                    entries = []
                    break
                batch = page.get("cves") or []
                entries.extend(batch)
                offset += len(batch)
                # Stop on a short page or once the reported total is reached;
                # both guard against an endpoint that ignores the offset.
                if not batch or offset >= (page.get("total_results") or 0):
                    break
                time.sleep(UBUNTU_PAGE_PAUSE)

            definitive, soft = [], []
            for entry in entries:
                for (cve_id, release, fixed, disposition, reason,
                     citation) in ubuntu_rows_for_cve(entry, package, releases):
                    row = (cve_id, "Ubuntu", release, package, fixed,
                           disposition, reason, "ubuntu-security", citation)
                    if disposition in DEFINITIVE_DISPOSITIONS:
                        definitive.append(row)
                    else:
                        soft.append(row)

            cols = ("INSERT OR {} INTO backports (cve_id, distro, release, "
                    "package, fixed_version, status, reason, source, citation) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
            db.cursor.executemany(cols.format("REPLACE"), definitive)
            db.cursor.executemany(cols.format("IGNORE"), soft)
            db.conn.commit()
            total += len(definitive) + len(soft)
            if not definitive and not soft:
                # A misspelled or wrongly-versioned source package name returns
                # an empty result set, not an error — Ubuntu's source names are
                # not the CPE product names (exim -> exim4, mysql -> mysql-8.0).
                # Left quiet, that reads as "nothing to suppress", which is
                # indistinguishable from "this package is clean".
                print(f"[!] Ubuntu {package}: no rows — check the source "
                      f"package name ({len(entries)} CVEs returned)")
            else:
                print(f"[+] Ubuntu {package}: {len(definitive)} definitive + "
                      f"{len(soft)} other rows ({len(entries)} CVEs scanned)")

        for rel in releases:
            db.cursor.execute(
                "INSERT OR REPLACE INTO backport_metadata "
                "(id, ecosystem, last_updated, record_count) VALUES ("
                "(SELECT id FROM backport_metadata WHERE ecosystem = ?), "
                "?, ?, ?)",
                [f"UbuntuSecurity:{rel}", f"UbuntuSecurity:{rel}", now(), total],
            )
        db.conn.commit()
    print(f"[+] Ubuntu security tracker backfill complete ({total} rows)")


def _rh_cve_url(cve_id):
    return f"https://access.redhat.com/security/cve/{cve_id}"


def update_backports_redhat(db_path, releases=("8", "9"),
                            packages=("openssh",), max_workers=8):
    """Backfill the backports table from Red Hat securitydata for the el family.

    For each package: one list call yields all CVEs + RHSA-fixed builds; the
    unfixed remainder is detail-fetched concurrently to read package_state.
    Records every disposition — fixed / not_affected (suppressed),
    wont_fix / fix_deferred (surfaced + badged), affected (active) — with a
    human reason + source + citation. Rows land in the AlmaLinux:<release>
    bucket (INSERT OR IGNORE so the primary ALSA data wins).
    """
    from concurrent.futures import ThreadPoolExecutor

    def _get(url):
        resp = httpx.get(url, timeout=60, follow_redirects=True,
                         headers={"User-Agent": "checkfix-cvescanner"})
        resp.raise_for_status()
        return resp.json()

    with Database(db_path) as db:
        db.setup()
        total = 0
        for package in packages:
            try:
                listing = _get(f"{RH_SECURITYDATA}/cve.json"
                               f"?package={package}&per_page=5000")
            except (httpx.HTTPError, httpx.TimeoutException, ValueError) as e:
                print(f"[!] Red Hat list fetch failed for {package}: {e}")
                continue

            rows = []
            need_detail = []  # (cve_id, [releases without a fixed build])
            for entry in listing:
                cve_id = entry.get("CVE", "")
                if not cve_id.startswith("CVE-"):
                    continue
                affected = entry.get("affected_packages") or []
                missing = []
                for rel in releases:
                    fixed = rh_fixed_version(affected, package, rel)
                    if fixed:
                        rows.append((
                            cve_id, "AlmaLinux", rel, package, fixed, "fixed",
                            f"Red Hat: fixed in {fixed}",
                            "redhat-securitydata", _rh_cve_url(cve_id)))
                        total += 1
                    else:
                        missing.append(rel)
                if missing:
                    need_detail.append((cve_id, missing))

            # Detail-fetch the unfixed remainder for package_state dispositions.
            def _fetch(item):
                cve_id, miss = item
                try:
                    d = _get(f"{RH_SECURITYDATA}/cve/{cve_id}.json")
                except (httpx.HTTPError, httpx.TimeoutException, ValueError):
                    return []
                pstate = d.get("package_state")
                out = []
                for rel in miss:
                    state = rh_fix_state(pstate, package, rel)
                    disp = rh_disposition(state)
                    if disp:
                        out.append((
                            cve_id, "AlmaLinux", rel, package, None, disp,
                            f"Red Hat: {state} (el{rel})",
                            "redhat-securitydata", _rh_cve_url(cve_id)))
                return out

            if need_detail:
                with ThreadPoolExecutor(max_workers=max_workers) as ex:
                    for res in ex.map(_fetch, need_detail):
                        rows.extend(res)
                        total += len(res)

            db.cursor.executemany(
                "INSERT OR IGNORE INTO backports (cve_id, distro, release, "
                "package, fixed_version, status, reason, source, citation) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                rows,
            )
            db.conn.commit()
            print(f"[+] Red Hat {package}: {len(rows)} rows "
                  f"({len(listing)} CVEs scanned)")

        for rel in releases:
            db.cursor.execute(
                "INSERT OR REPLACE INTO backport_metadata "
                "(id, ecosystem, last_updated, record_count) VALUES ("
                "(SELECT id FROM backport_metadata WHERE ecosystem = ?), "
                "?, ?, ?)",
                [f"RedHat:{rel}", f"RedHat:{rel}", now(), total],
            )
        db.conn.commit()
    print(f"[+] Red Hat securitydata backfill complete ({total} rows)")


# Disposition values accepted in the curated overlay (same vocabulary as the
# backports.status column). "false_positive" is stored as not_affected so it
# suppresses; product-scoped false positives stay in checkfix_test's enricher.
_CURATED_STATUSES = {
    "fixed", "not_affected", "wont_fix", "fix_deferred", "affected",
    "false_positive",
}


def load_curated_dispositions(db_path, path):
    """Merge a curated, version-controlled disposition overlay into backports.

    Highest precedence: loaded LAST with INSERT OR REPLACE so analyst-verified
    entries win over the auto-sourced OSV/Red Hat data. This is the
    "improve over time" store — add entries as triage decisions are made.

    JSON shape (see extra/curated_dispositions.json):
        {"dispositions": [
            {"cve": "...", "distro": "AlmaLinux", "release": "8",
             "package": "openssh", "disposition": "not_affected",
             "fixed_version": null, "reason": "...", "citation": "...",
             "added_by": "...", "date": "..."}, ...]}
    """
    import json as _json

    if not path or not Path(path).is_file():
        print(f"[*] No curated disposition overlay at {path} — skipping")
        return
    with open(path) as f:
        data = _json.load(f)

    rows = []
    for e in data.get("dispositions", []):
        cve = (e.get("cve") or "").strip()
        distro = (e.get("distro") or "").strip()
        release = str(e.get("release") or "").strip()
        package = (e.get("package") or "").strip()
        disp = (e.get("disposition") or "").strip()
        if not (cve and distro and release and package) or disp not in _CURATED_STATUSES:
            print(f"[!] Skipping invalid curated entry: {e}")
            continue
        status = "not_affected" if disp == "false_positive" else disp
        rows.append((
            cve, distro, release, package, e.get("fixed_version"), status,
            e.get("reason") or f"Curated: {disp}", "curated",
            e.get("citation"),
        ))

    if not rows:
        print("[*] Curated disposition overlay is empty")
        return
    with Database(db_path) as db:
        db.setup()
        db.cursor.executemany(
            "INSERT OR REPLACE INTO backports (cve_id, distro, release, "
            "package, fixed_version, status, reason, source, citation) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        db.conn.commit()
    print(f"[+] Curated disposition overlay: {len(rows)} entries applied")


def _norm(string):
    return string.replace("\\", "")


def split(cpe_uri):
    return RE["cpe"].match(_norm(cpe_uri)).groups()


def parse_node(node):
    return [
        (
            split(cpe["criteria"]),
            [_norm(cpe[vt]) if vt in cpe else None for vt in VTAGS],
        )
        for cpe in node["cpeMatch"]
    ]


class PopulateDBThread(Thread):
    def __init__(self, path, finished, insert, queue):
        Thread.__init__(self)
        self.path = path
        self.finished = finished
        self.insert = insert
        self.queue = queue

    def setup_execm(self, db):
        self.execmany = {
            0: db.insert_products,
            1: db.insert_cves,
            2: db.remove_cves,
            3: db.insert_exploits,
            4: db.insert_metasploits,
            5: db.insert_affected,
            6: db.insert_multiaffected,
            7: db.insert_referenced,
            8: db.insert_referencedm,
        }
        self.datalist = {k: [] for k in self.execmany}

    def run(self):
        with Database(self.path) as db:
            db.setup()
            self.setup_execm(db)
            try:
                while True:
                    try:
                        dtype, data = self.queue.get(timeout=1)
                        self.datalist[dtype].append(data)
                    except Empty:
                        if self.insert.is_set():
                            self.insert.clear()
                            for dt in range(len(self.execmany)):
                                self.execmany[dt](self.datalist[dt])
                                self.datalist[dt] = []
                        elif self.finished.is_set():
                            break
            except Exception as exc:
                print(traceback.format_exc())
                raise DatabaseUpdateError(
                    "Database population thread failed"
                ) from exc


def _nvd_backoff_sleep(seconds):
    """Sleep `seconds` (capped) plus jitter to desynchronise retrying threads."""
    delay = min(max(seconds, 0.0), NVD_BACKOFF_CAP)
    time.sleep(delay + random.uniform(0, min(delay, 5.0)))


def nvd_get_json(url, headers=None, timeout=120, max_retries=NVD_MAX_RETRIES):
    """GET `url` and return parsed JSON, retrying transient NVD failures.

    Retries on connection/timeout errors, 429/5xx responses, and non-JSON
    bodies (NVD serves an HTML 503 page under load), honouring a numeric
    Retry-After header when present. Raises DatabaseUpdateError once the final
    attempt fails so callers can decide whether to drop the batch or abort.

    This exists because NVD's edge intermittently rejects a large fraction of
    requests; without per-request retries those batches were silently dropped,
    producing a half-populated database that still "succeeded".
    """
    if headers is None:
        headers = {"apiKey": KEY}
    last_err = "unknown error"
    for attempt in range(max_retries):
        try:
            resp = httpx.get(url, timeout=timeout, headers=headers)
        except httpx.HTTPError as exc:
            last_err = f"transport error: {exc}"
        else:
            if resp.status_code == 200:
                try:
                    return resp.json()
                except ValueError as exc:
                    # 200 with an unparseable body — treat as transient.
                    last_err = f"non-JSON 200 body: {exc}"
            elif resp.status_code in NVD_RETRY_STATUS:
                last_err = f"HTTP {resp.status_code}"
                retry_after = resp.headers.get("Retry-After", "")
                if retry_after.isdigit():
                    _nvd_backoff_sleep(float(retry_after))
                    continue
            else:
                # Non-transient (e.g. 403/404) — no point retrying.
                raise DatabaseUpdateError(
                    f"NVD API returned HTTP {resp.status_code} for {url}: "
                    f"{resp.text[:200]}"
                )
        if attempt < max_retries - 1:
            _nvd_backoff_sleep(NVD_BACKOFF_BASE * (2 ** attempt))
    raise DatabaseUpdateError(
        f"NVD request failed after {max_retries} attempts ({last_err}): {url}"
    )


@LIMITER.as_decorator(name="identity")
def query_api(args):
    try:
        url, bar, thread_objs, batch, populate = args
        _, ev_ins, queue = thread_objs
        data = nvd_get_json(url, {"apiKey": KEY})
        if "cpes" in url:
            idy = 0
            for prod in data["products"]:
                ptype, ven, pro, ver, vup = split(prod["cpe"]["cpeName"])
                idy += 1
                if ptype == "a":
                    queue.put((0, (ven, pro, ver, vup)))
        else:
            for vuln in data["vulnerabilities"]:
                cve_id = vuln["cve"]["id"]
                if vuln["cve"]["vulnStatus"].lower() in (
                    "deferred",
                    "rejected",
                ):
                    if not populate:
                        #print(f"sending {cve_id} to remove")
                        queue.put((2, (cve_id,)))
                    continue
                cvssv2 = (
                    None
                    if "cvssMetricV2" not in vuln["cve"]["metrics"]
                    else vuln["cve"]["metrics"]["cvssMetricV2"][0]["cvssData"][
                        "baseScore"
                    ]
                )
                cvssv3keys = [
                    key
                    for key in vuln["cve"]["metrics"].keys()
                    if RE["v3"].match(key) is not None
                ]
                cvssv3 = (
                    None
                    if not cvssv3keys
                    else vuln["cve"]["metrics"][cvssv3keys[0]][0]["cvssData"][
                        "baseScore"
                    ]
                )
                year = int(vuln["cve"]["published"][:4])
                queue.put((1, (cve_id, cvssv2, cvssv3, year)))
                if "configurations" in vuln["cve"]:
                    for config in vuln["cve"]["configurations"]:
                        for node in config["nodes"]:
                            products = parse_node(node)
                            for (
                                ptype,
                                ven,
                                pro,
                                ver,
                                vup,
                            ), tags in products:
                                if ptype == "a":
                                    queue.put((0, (ven, pro, ver, vup)))
                                    if (
                                        all(t is None for t in tags)
                                        and ver != "*"
                                    ):
                                        queue.put(
                                            (
                                                5,
                                                (
                                                    cve_id,
                                                    ven,
                                                    pro,
                                                    ver,
                                                    vup,
                                                ),
                                            )
                                        )
                                    else:
                                        queue.put(
                                            (6, (cve_id, ven, pro, *tags))
                                        )
                if "references" in vuln["cve"]:
                    for reference in vuln["cve"]["references"]:
                        if "exploit-db" in reference["url"] and (
                            "tags" not in reference
                            or (
                                "tags" in reference
                                and "Broken Link" not in reference["tags"]
                            )
                        ):
                            match = RE["exp"].match(reference["url"])
                            if match is not None:
                                exp_id = match.group(1)
                                queue.put((3, (exp_id,)))
                                queue.put((7, (cve_id, exp_id)))
    except Exception:
        # Retries inside nvd_get_json are exhausted: drop this batch rather than
        # abort the whole run. The caller's completeness check (ingested vs
        # reported totals) is the backstop that rejects a partial rebuild.
        print(f"[!] Dropping batch after retries: {url}")
        print(traceback.format_exc())
    ev_ins.set()
    bar.update(batch)


def update_db(args, thread_objs, populate=False):
    extra = ""
    if not populate:
        print("[*] Updating database...")
        with Database(args.database) as db:
            try:
                last = db.cached_metadata()
                extra = (f"&lastModStartDate={_urlquote(last)}"
                         f"&lastModEndDate={_urlquote(now())}")
            except TypeError:
                pass
    else:
        print("[+] Creating database...")

    api_headers = {"apiKey": KEY}
    print("[*] Retrieving CVEs/CPEs metadata...")
    # Resilient: the preflight previously aborted the whole run on a single
    # transient 503/429. nvd_get_json retries before giving up.
    cpes = nvd_get_json(
        f"{URL['nvd'].format('cpes', 0)}&resultsPerPage=1{extra}", api_headers
    )["totalResults"]
    cves = nvd_get_json(
        f"{URL['nvd'].format('cves', 0)}&resultsPerPage=1{extra}", api_headers
    )["totalResults"]
    print(f"[+] Metadata: {cpes} CPEs | {cves} CVEs")
    cve_q, cpe_q = -(-cves // CONST["cve"]), -(-cpes // CONST["cpe"])
    cve_l = cves % CONST["cve"] or CONST["cve"]
    cpe_l = cpes % CONST["cpe"] or CONST["cpe"]
    time.sleep(5)

    if cpes:
        with tqdm(
            total=cpes, ascii=" =", desc="[+] Retrieving CPEs"
        ) as bar:
            q_args = []
            idx = 0
            with ThreadPoolExecutor() as tpe:
                for _ in range(cpe_q):
                    q_args.append(
                        [
                            f"{URL['nvd'].format('cpes', idx)}{extra}",
                            bar,
                            thread_objs,
                            CONST["cpe"],
                            populate,
                        ]
                    )
                    idx += CONST["cpe"]
                q_args[-1][-2] = cpe_l  # last batch
                tpe.map(query_api, q_args)

    if cves:
        with tqdm(
            total=cves, ascii=" =", desc="[+] Retrieving CVEs"
        ) as bar:
            q_args = []
            idx = 0
            with ThreadPoolExecutor() as tpe:
                for _ in range(cve_q):
                    q_args.append(
                        [
                            f"{URL['nvd'].format('cves', idx)}{extra}",
                            bar,
                            thread_objs,
                            CONST["cve"],
                            populate,
                        ]
                    )
                    idx += CONST["cve"]
                q_args[-1][-2] = cve_l  # last batch
                tpe.map(query_api, q_args)


def update_metasploit(args, thread_objs):
    try:
        page = httpx.get(URL["msfdb"], timeout=120)
    except httpx.HTTPError as e:
        raise DatabaseUpdateError(
            f"HTTP error retrieving Metasploit data: {e}"
        ) from e
    try:
        cache = page.json()
    except Exception as e:
        raise DatabaseUpdateError(
            f"Failed to parse Metasploit response: {e}"
        ) from e
    with Database(args.database) as db:
        for vuln in tqdm(
            cache, ascii=" =", desc="[+] Retrieving metasploit data"
        ):
            name = cache[vuln]["fullname"]
            thread_objs[2].put((4, (name,)))
            for ref in cache[vuln]["references"]:
                match = RE["cve"].match(ref)
                if match is not None:
                    max_retries = 10
                    for attempt in range(max_retries):
                        try:
                            if db.cached_cve(ref):
                                thread_objs[2].put((8, (ref, name)))
                        except sql.OperationalError:
                            if attempt == max_retries - 1:
                                print(f"[!] Failed to query CVE {ref} after {max_retries} retries")
                                break
                            time.sleep(2)
                        else:
                            break
    thread_objs[1].set()


def scrape_title(exploit):
    title = None
    delay = 5
    try:
        page = httpx.get(
            f"{URL['expdb']}/{exploit}",
            headers={"User-Agent": UA.random},
            timeout=120,
        )
        decoded = html.unescape(page.text)
        match = RE["tit"].search(decoded)
        if match:
            title = match.group(3)  # group 1 and 2 are quotes
    except httpx.HTTPError as e:
        raise DatabaseUpdateError(
            f"HTTP error scraping ExploitDB {exploit}: {e}"
        ) from e
    finally:
        time.sleep(delay)
    return title, exploit


def exploit_batch(exploits):
    for i in range(0, len(exploits), CONST["bat"]):
        yield exploits[i : i + CONST["bat"]]


def update_exploitdb(args):
    with Database(args.database) as db:
        db.clean()
        if not args.noscrape:
            exps = db.cached_exploits()
            # low requests per minute, but we need this to bypass WAF
            threads = 3
            if len(exps) > 0:
                exp_gen = exploit_batch(exps)
                with ThreadPoolExecutor(max_workers=threads) as tpe:
                    with tqdm(
                        total=len(exps) // CONST["bat"] + 1,
                        ascii=" =",
                        desc="[+] Retrieving exploit-db names",
                    ) as bar:
                        for batch in exp_gen:
                            res = list(tpe.map(scrape_title, batch))
                            db.update_exploits(list(res))
                            bar.update()


def run_update(database, api_key, noscrape=False, full=False,
               backports=False, backports_only=False, ecosystems=None,
               redhat=False, redhat_packages=("openssh",),
               redhat_releases=("8", "9"), curated_path=None,
               ubuntu=False, ubuntu_packages=("openssh",),
               ubuntu_releases=("24.04", "22.04", "20.04")):
    """Run the database create/update process.

    Args:
        database: Path to the database file.
        api_key: NVD API key string.
        noscrape: If True, skip ExploitDB name scraping.
        full: If True, force full rebuild (delete existing DB first).
        backports: If True, also fetch OSV backport data after NVD update.
        backports_only: If True, skip NVD update, only fetch backport data.
        ecosystems: List of OSV ecosystem strings to fetch (e.g. ["Debian:12"]).

    Raises:
        DatabaseUpdateError: On any failure during the update process.
    """
    global KEY
    KEY = api_key

    database = Path(database)

    if backports_only:
        # Only update backport data, skip NVD
        print(COPYRIGHT)
        # Ensure tables exist
        with Database(database) as db:
            db.setup()
        update_backports_osv(database, ecosystems=ecosystems)
        if redhat:
            update_backports_redhat(database, releases=redhat_releases,
                                    packages=redhat_packages)
        if ubuntu:
            update_backports_ubuntu(database, releases=ubuntu_releases,
                                    packages=ubuntu_packages)
        if curated_path:
            load_curated_dispositions(database, curated_path)
        return

    if full and database.is_file():
        database.unlink()

    # Create an args-like object for backward compatibility with
    # update_db/update_metasploit/update_exploitdb functions
    class _Args:
        pass
    args = _Args()
    args.database = database
    args.noscrape = noscrape

    print(COPYRIGHT)

    thread_objs = (Event(), Event(), Queue())
    thread = PopulateDBThread(database, *thread_objs)
    thread.start()

    try:
        update_db(args, thread_objs, populate=not database.is_file())

        with Database(database) as db:
            db.update_metadata()

        update_metasploit(args, thread_objs)
        update_exploitdb(args)
    finally:
        with tqdm(total=1, ascii=" =", desc="[*] Awaiting database thread") as bar:
            thread_objs[0].set()
            thread.join()
            bar.update()

    if backports:
        update_backports_osv(database, ecosystems=ecosystems)
        if redhat:
            update_backports_redhat(database, releases=redhat_releases,
                                    packages=redhat_packages)
        if ubuntu:
            update_backports_ubuntu(database, releases=ubuntu_releases,
                                    packages=ubuntu_packages)
        if curated_path:
            load_curated_dispositions(database, curated_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Tool to generate/update CVEScannerV3 database"
    )
    parser.add_argument(
        "-d", "--database", default="cve.db", type=Path, help="Database file path"
    )
    parser.add_argument(
        "-ns",
        "--noscrape",
        action="store_true",
        help="Disable exploit-db name scraping",
    )
    parser.add_argument(
        "--backports",
        action="store_true",
        help="Also fetch OSV backport data after NVD update",
    )
    parser.add_argument(
        "--backports-only",
        action="store_true",
        help="Skip NVD update, only fetch OSV backport data",
    )
    parser.add_argument(
        "--ecosystems",
        help="Comma-separated OSV ecosystems (default: Debian:12,Debian:11,Ubuntu:22.04,Ubuntu:24.04)",
    )
    parser.add_argument(
        "--redhat",
        action="store_true",
        help="Also backfill el8/el9 backports from Red Hat securitydata "
             "(fixed versions ALSA misses + 'Not affected' dispositions)",
    )
    parser.add_argument(
        "--redhat-packages",
        default="openssh",
        help="Comma-separated source packages for the Red Hat backfill "
             "(default: openssh)",
    )
    parser.add_argument(
        "--redhat-releases",
        default="8,9",
        help="Comma-separated el releases for the Red Hat backfill (default: 8,9)",
    )
    parser.add_argument(
        "--ubuntu",
        action="store_true",
        help="Also backfill Ubuntu backports from Canonical's security tracker "
             "(OSV's Ubuntu feed is USN-only: no not-affected verdicts, no "
             "silent SRU fixes)",
    )
    parser.add_argument(
        "--ubuntu-packages",
        default="openssh",
        help="Comma-separated source packages for the Ubuntu backfill "
             "(default: openssh)",
    )
    parser.add_argument(
        "--ubuntu-releases",
        default="24.04,22.04,20.04",
        help="Comma-separated Ubuntu releases for the backfill "
             "(default: 24.04,22.04,20.04)",
    )
    parser.add_argument(
        "--curated",
        help="Path to a curated disposition overlay JSON (highest precedence)",
    )
    args = parser.parse_args()

    ecosystems = None
    if args.ecosystems:
        ecosystems = [e.strip() for e in args.ecosystems.split(",")]

    redhat_packages = tuple(p.strip() for p in args.redhat_packages.split(",") if p.strip())
    redhat_releases = tuple(r.strip() for r in args.redhat_releases.split(",") if r.strip())
    ubuntu_packages = tuple(p.strip() for p in args.ubuntu_packages.split(",") if p.strip())
    ubuntu_releases = tuple(r.strip() for r in args.ubuntu_releases.split(",") if r.strip())

    api = Path(".api")
    if api.is_file():
        with api.open() as f:
            api_key = f.read().strip()
    else:
        api_key = os.getenv("NVD_KEY")
        if api_key is None and not args.backports_only:
            print(
                "[!] NVD API key required in order to retrieve data. "
                "Check README.md for more information"
            )
            sys.exit(1)
        if api_key is None:
            api_key = ""

    try:
        run_update(
            database=args.database,
            api_key=api_key,
            noscrape=args.noscrape,
            backports=args.backports,
            backports_only=args.backports_only,
            ecosystems=ecosystems,
            redhat=args.redhat,
            redhat_packages=redhat_packages,
            redhat_releases=redhat_releases,
            ubuntu=args.ubuntu,
            ubuntu_packages=ubuntu_packages,
            ubuntu_releases=ubuntu_releases,
            curated_path=args.curated,
        )
    except DatabaseUpdateError as e:
        print(f"[!] {e}")
        sys.exit(1)

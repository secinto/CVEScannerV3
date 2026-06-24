#!/usr/bin/env python3

# SPDX-License-Identifier: GPL-3.0-or-later

# nmap_to_services - Convert an nmap -oX (XML) scan into the cvescan.py
# `{"services": [...]}` input format.
#
# Copyright (C) 2025 secinto GmbH.
#
# This file is part of CVEScannerV3 and is distributed under the terms of the
# GNU General Public License v3 or later; see <https://www.gnu.org/licenses/>.

"""Read an nmap XML report (file argument or stdin) and emit the JSON service
list consumed by `cvescan.py scan`.

For each open port that nmap fingerprinted, we prefer the application CPE
(``cpe:/a:vendor:product:version``) it emitted, because that is already in the
NVD vendor:product form that cvescan matches against. When no application CPE is
present we fall back to the banner ``product``/``version`` strings.
"""

import json
import sys
import xml.etree.ElementTree as ET


def _host_label(host):
    """Best human-readable identifier for a host element (hostname or IP)."""
    hostname = host.find("./hostnames/hostname")
    if hostname is not None and hostname.get("name"):
        return hostname.get("name")
    addr = host.find("./address")
    return addr.get("addr") if addr is not None else "unknown"


def _service_to_entry(port, host_name):
    """Build one cvescan service dict from a <port> element, or None to skip."""
    state = port.find("./state")
    if state is None or state.get("state") != "open":
        return None

    service = port.find("./service")
    if service is None:
        return None

    portid = port.get("portid", "?")
    protocol = port.get("protocol", "tcp")
    entry = {"id": f"{host_name} {portid}/{protocol}"}

    # Prefer the application CPE (cpe:/a:...) — canonical NVD identifier.
    app_cpe = next(
        (c.text for c in service.findall("./cpe")
         if c.text and c.text.startswith("cpe:/a:")),
        None,
    )
    product = service.get("product")
    version = service.get("version")

    if app_cpe:
        entry["cpe"] = app_cpe
        # Carry the banner version too: cvescan re-parses it over the CPE
        # version, which keeps update/patch suffixes nmap split off.
        if version:
            entry["version"] = version
    elif product:
        entry["product"] = product
        if version:
            entry["version"] = version
    else:
        # No CPE and no product name — nothing to match on.
        return None

    return entry


def nmap_xml_to_services(xml_source):
    """Parse nmap XML (path or file-like) into a list of service dicts."""
    tree = ET.parse(xml_source)
    root = tree.getroot()

    services = []
    for host in root.findall("./host"):
        host_name = _host_label(host)
        for port in host.findall("./ports/port"):
            entry = _service_to_entry(port, host_name)
            if entry is not None:
                services.append(entry)
    return services


def main():
    source = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] != "-" else sys.stdin
    try:
        services = nmap_xml_to_services(source)
    except ET.ParseError as e:
        print(f"Error: failed to parse nmap XML: {e}", file=sys.stderr)
        sys.exit(1)

    json.dump({"services": services}, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()

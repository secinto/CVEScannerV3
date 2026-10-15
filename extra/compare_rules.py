#!/usr/bin/env python3

# SPDX-License-Identifier: GPL-3.0-or-later

# compare_rules - Compare the findings of two CVE databases per product.

# Copyright (C) 2025 secinto GmbH.

# This file is part of CVEScannerV3.

"""Compare two cve.db files built from the same NVD data by two importers.

Run through `make compare-rules`, which builds both databases from the NVD
raw cache. Prints the row totals, then the products whose rows changed,
largest change first. --product lists the CVEs that differ for one product.

Usage:
    compare_rules.py BASE.db NEW.db [--top N] [--product NAME] [--json]
"""

import argparse
import json
import sqlite3
import sys

# A row's identity in each table. NULL bounds are compared as "".
ROW_SQL = {
    "affected": (
        "SELECT a.cve_id, p.vendor, p.product, p.version, p.version_update, "
        "'', '', '', '' FROM affected a JOIN products p ON p.product_id = a.product_id"
    ),
    "multiaffected": (
        "SELECT m.cve_id, p.vendor, p.product, '', '', "
        "IFNULL(m.versionStartIncluding, ''), IFNULL(m.versionStartExcluding, ''), "
        "IFNULL(m.versionEndIncluding, ''), IFNULL(m.versionEndExcluding, '') "
        "FROM multiaffected m JOIN products p ON p.product_id = m.product_id"
    ),
}
OPEN_SQL = (
    "SELECT COUNT(*) FROM multiaffected WHERE versionStartIncluding IS NULL "
    "AND versionStartExcluding IS NULL AND versionEndIncluding IS NULL "
    "AND versionEndExcluding IS NULL"
)


def load_rows(path):
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        rows = {table: set(con.execute(query)) for table, query in ROW_SQL.items()}
        rows["open_ended"] = con.execute(OPEN_SQL).fetchone()[0]
    finally:
        con.close()
    return rows


def compare(base, new):
    """Totals per table and the per-product changes, largest first."""
    totals = {
        table: {"base": len(base[table]), "new": len(new[table])} for table in ROW_SQL
    }
    totals["open_ended"] = {"base": base["open_ended"], "new": new["open_ended"]}
    products = {}
    for table in ROW_SQL:
        for side, rows in (("removed", base[table] - new[table]),
                           ("added", new[table] - base[table])):
            for row in rows:
                entry = products.setdefault(
                    (row[1], row[2]), {"removed": set(), "added": set()})
                entry[side].add((table,) + row)
    changes = sorted(
        ({"vendor": ven, "product": pro, "removed": len(e["removed"]),
          "added": len(e["added"]), "rows": e} for (ven, pro), e in products.items()),
        key=lambda c: (-(c["removed"] + c["added"]), c["vendor"], c["product"]),
    )
    return totals, changes


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("base", help="Database built by the base importer")
    parser.add_argument("new", help="Database built by the changed importer")
    parser.add_argument("--top", type=int, default=30,
                        help="Products to list (default 30, 0 = all)")
    parser.add_argument("--product", help="List the differing rows for this product")
    parser.add_argument("--json", action="store_true", help="Machine-readable output")
    args = parser.parse_args(argv)

    totals, changes = compare(load_rows(args.base), load_rows(args.new))
    shown = changes if args.top == 0 else changes[: args.top]

    if args.json:
        json.dump({
            "totals": totals,
            "products": [{k: v for k, v in c.items() if k != "rows"} for c in changes],
        }, sys.stdout, indent=1)
        print()
        return 0

    print(f"{'rows':<15}{'base':>12}{'new':>12}{'change':>10}")
    for name, t in totals.items():
        print(f"{name:<15}{t['base']:>12,}{t['new']:>12,}{t['new'] - t['base']:>+10,}")
    print(f"\n{len(changes)} products changed"
          + (f", the {len(shown)} largest:" if shown else "."))
    for c in shown:
        name = f"{c['vendor']}:{c['product']}"
        print(f"  {name:<50} -{c['removed']:<6} +{c['added']}")

    if args.product:
        print(f"\nRows that differ for {args.product}:")
        for c in changes:
            if c["product"] != args.product:
                continue
            for side, sign in (("removed", "-"), ("added", "+")):
                for row in sorted(c["rows"][side]):
                    table, cve_id, ven, pro, ver, vup, *bounds = row
                    detail = ver if table == "affected" else "/".join(b or "*" for b in bounds)
                    print(f"  {sign} {cve_id} {ven}:{pro} {table} {detail}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

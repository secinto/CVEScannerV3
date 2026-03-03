# CVEScannerV3

Nmap script and standalone Python CLI that provides information about probable
vulnerabilities based on discovered services.

**Contents:**
  - [Features](#features)
  - [Requirements](#requirements)
      - [Optional](#optional)
  - [Nmap scanner](#nmap-scanner)
      - [Script arguments](#script-arguments)
      - [Output](#output)
  - [Standalone scanner](#standalone-scanner)
      - [Scanning for CVEs](#scanning-for-cves)
      - [Database management](#database-management)
      - [Database info](#database-info)
  - [Backport detection](#backport-detection)
  - [Docker container](#docker-container)
  - [Errors and fixes](#errors-and-fixes)
    - [Blocked IP](#blocked-ip)
    - [Missing luasql](#missing-luasql)
  - [Acknowledgements](#acknowledgements)
  - [License](#license)


# Features

- **Nmap NSE integration** — runs as `nmap --script cvescannerv3` to scan
  discovered services against a local CVE database.
- **Standalone Python CLI** (`extra/cvescan.py`) — scan products for CVEs
  without Nmap, manage the database, and view statistics.
- **Smart HTTP fingerprinting** — 3-phase detection using headers, cookies,
  meta-generator tags, and JS library analysis (5-15 requests per port instead
  of 190+).
- **Distro-aware backport detection** — automatically detects Debian/Ubuntu
  from SSH/HTTP banners and filters out CVEs that have been patched by the
  distribution, reducing false positives.
- **Batch SQL queries** — optimized database lookups (2 queries per product
  instead of 3*N per CVE).
- **ExploitDB and Metasploit** cross-referencing for every CVE found.

# Requirements

**For the Nmap scanner**, you need:
- `lua-sql-sqlite3` (Ubuntu/Debian) or `lua5.4-sql-sqlite3` (Alpine)
- CVE database: `cve.db`
- Data files in `extra/`:
  - `http-paths-vulnerscom.json` — HTTP probe paths
  - `http-regex-vulnerscom.json` — HTTP fingerprint regexes
  - `product-aliases.json` — CPE product alias mappings

**For the standalone scanner** (`extra/cvescan.py`), you need:
- Python 3.8+
- Dependencies from `extra/requirements.txt`

```bash
pip install -r extra/requirements.txt
```

## Optional

If you don't have the database `cve.db`, you can build it using the standalone
CLI, using `extra/database.py` directly, or download a (semi-updated) copy from
[CVEScannerV3DB](https://github.com/secinto/CVEScannerV3DB) using `.sql`
files or under Actions->Latest->Summary->Artifacts.

> This repository is updated every two weeks.

```bash
# Using the standalone CLI
pip install -r extra/requirements.txt
python extra/cvescan.py update-db --api-key YOUR_NVD_KEY
```

```bash
# Using database.py directly
pip install -r extra/requirements.txt
python extra/database.py
```

```bash
# Using pre-built database
git clone https://github.com/secinto/CVEScannerV3DB
cd CVEScannerV3DB && sh build.sh
```

> **Note:** Building from NVD requires an
> [API key](https://nvd.nist.gov/developers/request-an-api-key).
> Save it to a file named `.api` in your working directory, set the `NVD_KEY`
> environment variable, or pass `--api-key` to the CLI.


# Nmap scanner

The NSE script detects vulnerabilities for each open port based on:

- **CPE + version**: CVEs affecting the exact version and version ranges
  that include it.
- **CPE + version range**: CVEs affecting versions within the range.
- **CPE, no version**: all CVEs for the product.
- **No CPE / no results**: falls back to HTTP fingerprinting (for
  HTTP/SSL/UPnP ports).

HTTP fingerprinting uses a 3-phase approach:
1. **Phase 1** — GET `/`: scans response headers, cookies, body regexes,
   `<meta name="generator">` tags, and inline JS library references.
2. **Phase 2** (fallback) — probes a short list of common paths
   (`/index.html`, `/index.php`, `/index.jsp`, `/default.aspx`, `/admin`).
3. **Phase 3** (targeted) — for detected products, probes known version
   endpoints (e.g., Jenkins `/api/json`, WordPress `/feed/`,
   Grafana `/api/health`, Tomcat root page).

```
nmap -sV --script cvescannerv3 <TARGET>
nmap -sV --script cvescannerv3 --script-args log=logfile.log,json=logfile.json <TARGET>
```

## Script arguments

| Argument | Default | Description |
|---|---|---|
| `db` | `cve.db` | CVE database file path |
| `maxcve` | `10` | Max CVEs printed on screen |
| `http` | `1` | Enable/disable HTTP detection (`0` or `1`) |
| `maxredirect` | `1` | Max HTTP redirects to follow |
| `log` | `cvescannerv3.log` | Log file path |
| `json` | `cvescannerv3.json` | JSON output file path |
| `path` | `extra/http-paths-vulnerscom.json` | HTTP probe paths file |
| `regex` | `extra/http-regex-vulnerscom.json` | HTTP fingerprint regex file |
| `aliases` | `extra/product-aliases.json` | Product alias mappings |
| `service` | `all` | Filter to a specific service name |
| `version` | `all` | Filter to a specific version |

<details>
    <summary><b>script-args examples</b></summary>

    nmap -sV --script cvescannerv3 --script-args db=cve.db <TARGET>
    nmap -sV --script cvescannerv3 --script-args maxcve=5 <TARGET>

    # Change reports path
    nmap -sV --script cvescannerv3 --script-args log=scan2023.log,json=scan2023.json <TARGET>

    # Only scan certain service/version
    nmap -sV --script cvescannerv3 --script-args service=http_server,version=2.4.57 <TARGET>

    # Disable HTTP detection
    nmap -sV --script cvescannerv3 --script-args http=0 <TARGET>
</details>

> **Note**: `cvescannerv3.nse` can be placed in Nmap default script directory
> for global execution.
>
> - Linux and OSX default script locations:
>   - /usr/local/share/nmap/scripts/
>   - /usr/share/nmap/scripts/
>   - /opt/local/share/nmap/scripts/
>   - /usr/local/Cellar/nmap/<i>&lt;version&gt;</i>/share/nmap/scripts/
>
> - Windows default script locations:
>   - C:\Program Files\Nmap\Scripts
>   - %APPDATA%\nmap
>
> It's recommended to create a **symbolic link**, so changes in repository are reflected
> in the script.

## Output
CVEScannerV3 will show CVEs related to every `service-version` discovered.
> **Note**: This script depends on heuristics implemented in Nmap, so if it doesn't
> detect a service or is detected incorrectly, CVEScannerV3 will show an incorrect output.

<details>
    <summary><b>Nmap output</b></summary>

    PORT      STATE    SERVICE        VERSION
    22/tcp    open  ssh                  OpenSSH 7.1 (protocol 2.0)
    | cvescannerv3:
    |   product: openssh
    |   version: 4.7
    |   vupdate: p1
    |   cves: 38
    |   	CVE ID              	CVSSv2	CVSSv3	ExploitDB 	Metasploit
    |   	CVE-2016-1908       	7.5  	9.8  	No        	No
    |   	CVE-2023-38408      	nil  	9.8  	No        	No
    |       ...
    |   	CVE-2016-6515       	7.8  	7.5  	Yes       	No
    |_
    ...
    ...
    3306/tcp  open  mysql                MySQL 5.5.20-log
    | cvescannerv3:
    |   product: mysql
    |   version: 5.0.51
    |   vupdate: a
    |   cves: 212
    |   	CVE ID              	CVSSv2	CVSSv3	ExploitDB 	Metasploit
    |   	CVE-2009-2446       	8.5  	-    	No        	No
    |       ...
    |   	CVE-2009-4484       	7.5  	-    	No        	Yes
    |   	CVE-2008-0226       	7.5  	-    	No        	Yes
    |_
    ...
    ...
</details>

Log file **\*.log** contains every _exploit/metasploit_ found.

<details>
    <summary><b>cvescannerv3.log</b></summary>

    ## 2023-08-26T14:38:30+00:00

    [*] host: 192.168.69.129
    [*] port: 22
    [+] protocol: tcp
    [+] service: ssh
    [+] cpe: cpe:/a:openbsd:openssh:4.7p1
    [+] product: openssh
    [+] version: 4.7
    [+] vupdate: p1
    [+] cves: 38
    [-] 	id: CVE-2016-1908     	cvss_v2: 7.5  	cvss_v3: 9.8
    [-] 	id: CVE-2023-38408    	cvss_v2: nil  	cvss_v3: 9.8
    ...
    [-] 	id: CVE-2016-6515     	cvss_v2: 7.8  	cvss_v3: 7.5
    [!] 		ExploitDB:
    [#] 			name: nil
    [#] 			id: 40888
    [#] 			url: https://www.exploit-db.com/exploits/40888
    [-] 	id: CVE-2010-4478     	cvss_v2: 7.5  	cvss_v3: -
    ...
    -------------------------------------------------
    [*] host: 192.168.69.129
    [*] port: 3306
    [+] protocol: tcp
    [+] service: mysql
    [+] cpe: cpe:/a:mysql:mysql:5.0.51a-3ubuntu5
    [+] product: mysql
    [+] version: 5.0.51
    [+] vupdate: a
    [+] cves: 212
    [-] 	id: CVE-2009-2446     	cvss_v2: 8.5  	cvss_v3: -
    ...
    [-] 	id: CVE-2009-4484     	cvss_v2: 7.5  	cvss_v3: -
    [!] 		Metasploit:
    [#] 			name: exploit/linux/mysql/mysql_yassl_getname
    [-] 	id: CVE-2008-0226     	cvss_v2: 7.5  	cvss_v3: -
    [!] 		Metasploit:
    [#] 			name: exploit/linux/mysql/mysql_yassl_hello
    [#] 			name: exploit/windows/mysql/mysql_yassl_hello
    ...
</details>

Log file **\*.json** contains the same information but formatted as **json**

<details>
    <summary><b>cvescannerv3.json</b></summary>

    {
      "192.168.69.129": {
        "ports": {
          "22/tcp": {
            "services": [
              {
                "vupdate": "p1",
                "vulnerabilities": {
                  "total": 38,
                  "info": "scan",
                  "cves": {
                    "CVE-2014-1692": {
                      "cvssv2": 7.5,
                      "cvssv3": "-"
                    },
                    ...
                    "CVE-2016-6210": {
                      "cvssv3": 5.9,
                      "exploitdb": [
                        {
                          "id": 40113,
                          "url": "https://www.exploit-db.com/exploits/40113"
                        },
                        {
                          "id": 40136,
                          "url": "https://www.exploit-db.com/exploits/40136"
                        }
                      ],
                      "metasploit": [
                        {
                          "name": "auxiliary/scanner/ssh/ssh_enumusers"
                        }
                      ],
                      "cvssv2": 4.3
                    },
                  }
                  ...
                },
                "cpe": "cpe:/a:openbsd:openssh:4.7p1",
                "name": "ssh",
                "version": "4.7",
                "product": "openssh"
              }
            ]
          },
          ...
        "timestamp": "2023-08-26T14:38:30+00:00"
      }
    }
</details>

> You can find the full output of **metasploitable2/3** in `example_data`.


# Standalone scanner

The standalone Python CLI (`extra/cvescan.py`) provides CVE scanning, database
management, and statistics without requiring Nmap.

```bash
python extra/cvescan.py --help
```

## Scanning for CVEs

Three input modes are supported:

```bash
# Single product
python extra/cvescan.py scan -p openssh -v 4.7 -u p1

# CPE string
python extra/cvescan.py scan --cpe cpe:/a:openbsd:openssh:4.7p1

# JSON file with multiple services
python extra/cvescan.py scan -i services.json

# Pipe from stdin
cat services.json | python extra/cvescan.py scan -i -
```

<details>
    <summary><b>Input JSON format</b></summary>

```json
{
  "services": [
    {"id": "ssh-22", "cpe": "cpe:/a:openbsd:openssh:4.7p1"},
    {"id": "http-80", "product": "nginx", "version": "1.26.3"},
    {"id": "db-3306", "product": "mysql", "version": "5.5.55"},
    {"id": "smb-445", "product": "samba", "version": "3.x - 4.x"}
  ]
}
```
</details>

Output options:

```bash
# JSON output (default)
python extra/cvescan.py scan -p openssh -v 4.7

# Table output
python extra/cvescan.py scan -p openssh -v 4.7 --format table

# Write to file
python extra/cvescan.py scan -p openssh -v 4.7 -o results.json

# Limit CVEs per service
python extra/cvescan.py scan -p openssh -v 4.7 --maxcve 5
```

## Database management

Build or update the CVE database:

```bash
# Full build (requires NVD API key)
python extra/cvescan.py update-db --api-key YOUR_KEY

# Incremental update
python extra/cvescan.py update-db

# Skip ExploitDB title scraping
python extra/cvescan.py update-db --no-scrape

# Force full rebuild
python extra/cvescan.py update-db --full

# Include backport data from OSV.dev
python extra/cvescan.py update-db --backports

# Only update backport data (skip NVD)
python extra/cvescan.py update-db --backports-only

# Specify target ecosystems
python extra/cvescan.py update-db --backports-only --ecosystems "Debian:12,Ubuntu:24.04"
```

The NVD API key can be provided via:
1. `--api-key` flag
2. `NVD_KEY` environment variable
3. `.api` file in the working directory

## Database info

View database statistics:

```bash
python extra/cvescan.py db-info
```

Shows last update time, product count, CVE count, exploit/metasploit counts,
and backport data per ecosystem.


# Backport detection

On Debian and Ubuntu systems, distribution maintainers backport security fixes
into older upstream versions. Without backport awareness, the scanner reports
false positives for CVEs that have already been patched.

CVEScannerV3 addresses this with distro-aware scanning:

**Automatic detection** — distro and release are detected from service banners:
- SSH: `OpenSSH_9.2p1 Debian-2+deb12u7` -> Debian 12 (bookworm)
- SSH: `OpenSSH_8.9p1 Ubuntu-3ubuntu0.10` -> Ubuntu 22.04
- HTTP: Server headers containing `(Debian)`, `(Ubuntu)`, etc.

**Manual override**:
```bash
python extra/cvescan.py scan -i services.json --distro debian --distro-release bookworm
```

**Offline backport database** — uses OSV.dev bulk exports:
```bash
# Fetch backport data for default ecosystems (Debian 11/12, Ubuntu 22.04/24.04)
python extra/cvescan.py update-db --backports-only
```

**Online enrichment** — for CVEs with unknown backport status, query OSV.dev
API at scan time:
```bash
python extra/cvescan.py scan -p openssh -v 8.4 --distro debian --distro-release bookworm --online
```

When backport detection is active, CVEs are split into `cves` (active) and
`likely_patched` in the JSON output.

**Supported data files:**
- `extra/cpe-to-package.json` — maps CPE vendor:product to distro package names


# Docker container
We have prepared two containers configured and ready to be used, you can download them
from DockerHub
- Database embedded version: `secinto/cvescanner:db` or `secinto/cvescanner:latest`
- No database: `secinto/cvescannerv3:nodb`

```bash
docker run -v /tmp/cvslogs:/tmp/cvslogs secinto/cvescanner --script-args log=/tmp/cvslogs/scan.log,json=/tmp/cvslogs/scan.json <TARGET>

docker run -v ./cve.db:/CVEScannerV3/cve.db -v /tmp/cvslogs:/tmp/cvslogs secinto/cvescanner:nodb --script-args log=/tmp/cvslogs/cvescannerv3.log,json=/tmp/cvslogs/cvescannerv3.json <TARGET>
```

> **Note**: You can find your logs in `/tmp/cvslogs` directory


# Query database
There is a helper script, `extra/query.py` to retrieve information directly from the
sqlite database. For most use cases, `extra/cvescan.py scan` is preferred.

```bash
python extra/query.py -h
usage: query.py [-h] [-c CVE] -p PRODUCT [-v VERSION] [-u UPDATE] [-r] [-d]

Command line utility to query related CVEs

options:
  -h, --help            show this help message and exit
  -c CVE, --cve CVE     Path to CVE db
  -p PRODUCT, --product PRODUCT
                        Product name to query
  -v VERSION, --version VERSION
                        Version of the product
  -u UPDATE, --update UPDATE
                        Version update of the product
  -r, --raw             Output raw data (no filters applied)
  -d, --debug           Debug messages
```

<details>
    <summary><b>query.py example</b></summary>

```bash
python extra/query.py -p "gibbon" -v "25.0.0"

Exact match:
+----------------+--------+--------+-----------+---------+---------+----------+-----+-----+
|      CVE       | CVSSv2 | CVSSv3 |  Vendor   | Product | Version | V.Update | EDB | MSF |
+================+========+========+===========+=========+=========+==========+=====+=====+
| CVE-2023-34599 |        |  6.1   | gibbonedu | gibbon  | 25.0.00 |    *     | No  | No  |
+----------------+--------+--------+-----------+---------+---------+----------+-----+-----+
| CVE-2023-34598 |        |  9.8   | gibbonedu | gibbon  | 25.0.00 |    *     | No  | No  |
+----------------+--------+--------+-----------+---------+---------+----------+-----+-----+

Multi match:
+----------------+--------+--------+-----------+---------+--------------+--------------+------------+------------+-----+-----+
|      CVE       | CVSSv2 | CVSSv3 |  Vendor   | Product | StartInclude | StartExclude | EndInclude | EndExclude | EDB | MSF |
+================+========+========+===========+=========+==============+==============+============+============+=====+=====+
| CVE-2023-45881 |        |  6.1   | gibbonedu | gibbon  |              |              |  25.0.00   |            | No  | No  |
+----------------+--------+--------+-----------+---------+--------------+--------------+------------+------------+-----+-----+
| CVE-2023-45878 |        |  9.8   | gibbonedu | gibbon  |              |              |  25.0.01   |            | No  | No  |
+----------------+--------+--------+-----------+---------+--------------+--------------+------------+------------+-----+-----+
| CVE-2023-45879 |        |  5.4   | gibbonedu | gibbon  |              |              |  25.0.00   |            | No  | No  |
+----------------+--------+--------+-----------+---------+--------------+--------------+------------+------------+-----+-----+
| CVE-2023-45880 |        |  7.2   | gibbonedu | gibbon  |              |              |  25.0.00   |            | No  | No  |
+----------------+--------+--------+-----------+---------+--------------+--------------+------------+------------+-----+-----+
```
</details>


# Errors and fixes
## Blocked IP
> Connection timeout/error during CRAWL phase (`database.py`)

**Fix:** Wait 15 minutes before re-running `database.py`.

## Missing luasql
> cvescannerv3.nse:54: module 'luasql.sqlite3' not found:<br>
> NSE failed to find nselib/luasql/sqlite3.lua in search paths.<br>
> ...

**Fix:** Install the library based on your OS (check [Requirements](#requirements))
and create a symlink to Nmap search path.
```bash
apt install lua-sql-sqlite3
ln -s /usr/lib/x86_64-linux-gnu/lua /usr/local/lib/lua
```

```bash
apk add --no-cache lua5.4-sql-sqlite3
ln -s /usr/lib/lua /usr/local/lib/lua
```
> Above commands may require super user permissions.


# Acknowledgements
- Originally developed by [scmanjarrez/CVEScannerV3](https://github.com/scmanjarrez/CVEScannerV3).

- Based on [alegr3/CVEscanner](https://github.com/alegr3/CVEscanner) script.

- Common server regexes and paths from [vulnersCom/nmap-vulners](https://github.com/vulnersCom/nmap-vulners).

- Modules cache generated from [rapid7/metasploit-framework](https://github.com/rapid7/metasploit-framework).
  > Can be found in **~/.msf4/store/modules_metadata.json** after running **msfconsole**

- CVE information gathered from [nvd.nist.gov](https://nvd.nist.gov).

- Backport data from [OSV.dev](https://osv.dev).

# License
    CVEScannerV3  Copyright (C) 2021-2025 Sergio Chica Manjarrez @ pervasive.it.uc3m.es.
    Universidad Carlos III de Madrid.
    This program comes with ABSOLUTELY NO WARRANTY; for details check below.
    This is free software, and you are welcome to redistribute it
    under certain conditions; check below for details.

[LICENSE](LICENSE)

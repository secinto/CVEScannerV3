# CVEScannerV3 Codebase Analysis

Comprehensive analysis of security issues, bugs, and performance improvements.

---

## Security Issues

### SEC-1: SQL Injection via String Formatting in NSE Script (CRITICAL)

**File:** `cvescannerv3.nse:442-498, 506-542`

The `query()` function builds SQL templates with `'${p}'` placeholders for product names, and `'%s'` for CVE IDs. These are substituted via `fmtn()` and `fmt()` with no sanitization or parameterized queries.

```lua
-- Line 496: product name injected directly into SQL
WHERE products.product = '${p}'

-- Line 507: CVE ID injected directly into SQL via string format
fmt(query('cve_score'), vuln)
```

Product names come from CPE strings (parsed from Nmap service detection and HTTP response analysis). A maliciously crafted service banner or HTTP header could contain SQL injection payloads (e.g., a product name like `test'; DROP TABLE cves; --`).

**Impact:** An attacker controlling a scanned service's banner could manipulate the scanner's local SQLite database or extract data.

**Recommended Fix:** Use parameterized queries via the LuaSQL API instead of string interpolation. LuaSQL's `conn:prepare()` or escaping functions should be used.

---

### SEC-2: File Handle Leak / Nil Dereference in `valid_json()` (HIGH)

**File:** `cvescannerv3.nse:181-195`

```lua
local function valid_json (arg, ftype)
   local f = io.open(arg, 'r')
   local status, data = json.parse(f:read('*all'))  -- crashes if f is nil
   ...
end
```

Although `exists()` is called before `valid_json()` in `required_files()`, there is a TOCTOU (Time-of-Check to Time-of-Use) race condition. If the file is deleted or becomes unreadable between the `exists()` check and the `io.open()` call, `f` will be nil and `f:read()` will cause a nil dereference crash.

**Recommended Fix:** Check `f` for nil before calling `f:read()` and handle the error gracefully.

---

### SEC-3: httpx.Client Shared Across Threads (MEDIUM)

**File:** `extra/database.py:530, 566-602`

An `httpx.Client` instance is created in `update_db()` and passed into `ThreadPoolExecutor` workers via the `query_api()` function arguments. The [httpx documentation](https://www.python-httpx.org/advanced/#calling-into-python-web-apps) states that `Client` instances are not thread-safe for concurrent access.

```python
with httpx.Client(timeout=120, headers={"apiKey": KEY}) as cl:
    ...
    with ThreadPoolExecutor() as tpe:
        # cl is shared across all threads
        q_args.append([..., cl, ...])
        tpe.map(query_api, q_args)
```

**Impact:** Potential race conditions leading to corrupted HTTP state, request mixing, or crashes under high concurrency.

**Recommended Fix:** Create a separate `httpx.Client` per thread, or use `httpx.AsyncClient` with an async architecture.

---

### SEC-4: `return` in `finally` Block Swallows Exceptions (MEDIUM)

**File:** `extra/database.py:636-652`

```python
def scrape_title(exploit):
    title = None
    try:
        page = httpx.get(...)
        title = RE["tit"].search(decoded).group(3)
    except httpx.HTTPError as e:
        print(e)
        os._exit(1)
    finally:
        time.sleep(delay)
        return title, exploit  # swallows any unhandled exception
```

If `RE["tit"].search(decoded)` returns `None`, calling `.group(3)` raises `AttributeError`. This exception is not caught by the `except httpx.HTTPError` handler, but the `return` in `finally` silently swallows it, returning `(None, exploit)` without any indication of the error.

**Recommended Fix:** Move the `return` outside the `try/finally` block. Handle `AttributeError` explicitly.

---

### SEC-5: GitHub Actions Workflow Uses Outdated Action Versions (LOW)

**File:** `.github/workflows/docker.yaml:15-24`

```yaml
- uses: docker/setup-qemu-action@v2
- uses: docker/setup-buildx-action@v2
- uses: docker/login-action@v2
- uses: docker/build-push-action@v4
```

These action versions are outdated. Current versions are v3 for most docker actions and v5+ for build-push-action. Outdated actions may contain unpatched vulnerabilities.

**File:** `.github/workflows/copyright.yaml:13`
```yaml
- uses: actions/checkout@v3  # v4 is current
```

**Recommended Fix:** Update all GitHub Actions to their latest major versions.

---

### SEC-6: Deprecated `datetime.utcnow()` Usage (LOW)

**File:** `extra/database.py:342`

```python
def now():
    return datetime.isoformat(datetime.utcnow())
```

`datetime.utcnow()` is deprecated since Python 3.12 because it creates a naive datetime that can be ambiguous.

**Recommended Fix:** Use `datetime.now(datetime.timezone.utc)` instead.

---

### SEC-7: GitLab Sync Workflow Writes Credentials to Disk (LOW)

**File:** `.github/workflows/gitlab.yaml:18-27`

The workflow creates a credential helper script at `/usr/local/bin/credential-helper` and writes the GitLab token to `/tmp/gitlab`. While this runs in an ephemeral CI environment, it's a pattern that could leak credentials if the runner is shared or persistent.

---

## Bugs

### BUG-1: Column Mismatch in `multiaffected_empty` Query Unpacking (HIGH)

**File:** `cvescannerv3.nse:475-486, 725-740`

The `multiaffected_empty` query returns **5 columns**: `cve_id, cvss_v2, cvss_v3, edb, msf`. However, the code unpacks **9 variables**:

```lua
-- Query returns 5 columns:
-- cve_id, cvss_v2, cvss_v3, edb, msf

-- But code unpacks 9:
vuln, cvssv2, cvssv3, st_in, st_ex, en_in, en_ex, exploitdb, metasploit = cur:fetch()
```

This causes:
- `st_in` gets the `edb` value (0 or 1)
- `st_ex` gets the `msf` value (0 or 1)
- `en_in`, `en_ex`, `exploitdb`, `metasploit` are all `nil`

**Impact:**
1. ExploitDB and Metasploit flags are always reported as "No" when version is empty (since `exploitdb` and `metasploit` are nil, not 0/1).
2. `scoped_multi_versions()` receives integer version bounds (0 or 1) instead of nil, leading to incorrect version range comparisons.
3. Calling `compare_version('*', 0)` triggers a crash in `remove_alpha()` because `'*'` doesn't match the numeric pattern, returning nil, which then crashes `split_version(nil)`.

**Recommended Fix:** Use separate unpacking for `multiaffected_empty`:
```lua
vuln, cvssv2, cvssv3, exploitdb, metasploit = cur:fetch()
```

---

### BUG-2: Unescaped Dot in `gsub` Pattern (MEDIUM)

**File:** `cvescannerv3.nse:375`

```lua
local k_stripped = (k:gsub('.js', '')):lower()
```

In Lua patterns, `.` matches **any character**, not a literal dot. This means `"xjs"`, `"1js"`, etc. would all be stripped. The correct pattern should escape the dot:

```lua
local k_stripped = (k:gsub('%.js', '')):lower()
```

---

### BUG-3: `scoped_versions()` Called with Multiaffected Data When `info.empty` (MEDIUM)

**File:** `cvescannerv3.nse:745-765`

When `info.empty` is true, the code skips re-initializing `tmp_vulns` for the affected query (lines 745-763), so `tmp_vulns` still contains data from the multiaffected query. Then `scoped_versions(tmp_vulns, from, to, upd, vulns)` is called on line 765 with `from = '*'` and `to = '*'`.

Inside `scoped_versions`, `compare_version()` is called with `'*'` as an argument. Since `remove_alpha('*')` returns `nil`, this causes `split_version(nil)` to crash with a nil dereference.

**Recommended Fix:** Re-initialize `tmp_vulns = {}` before line 765 regardless of `info.empty`, or skip `scoped_versions()` when `info.empty` is true.

---

### BUG-4: `portaction` Returns Empty Table Instead of `nil` for 0-CVE Products (HIGH)

**File:** `cvescannerv3.nse:908, 980-984`

**Observed on:** Host 195.201.149.167, nginx 1.26.3 on ports 80, 443, and 2100.

When a product is detected and matched (e.g., nginx 1.26.3) but has genuinely 0 CVEs in the database (all version ranges exclude it), the following flow occurs:

1. `portaction` matches CPEs for nginx 1.26.3 → `matches['size'] > 0`
2. Calls `analysis()` which queries the CVE database
3. nginx 1.26.3 has 0 CVEs — all version ranges in the DB exclude it (e.g., CVE-2023-44487 ends at 1.25.2, CVE-2025-23419 excludes exactly 1.26.3)
4. `analysis()` returns `{}` (empty table) at line 908
5. `portaction` returns this `{}` at line 984
6. Nmap's NSE engine sees a non-nil return that produces no string output → **"Bug in cvescannerv2: no string output"**

```lua
-- Line 908: analysis returns {} when no CVEs found
return vulns  -- vulns = {} (empty table, which is non-nil in Lua)

-- Line 980-984: portaction passes it through unchanged
local vulns
if matches['size'] ~= 0 then
   vulns = analysis(host, port, matches)
end
return vulns  -- returns {} instead of nil
```

Nmap's NSE engine expects portrule action functions to return either `nil` (no output) or a table/string that produces visible output. An empty table `{}` is non-nil but generates no string, triggering the "no string output" warning.

**Recommended Fix:** `portaction` should return `nil` when vulns is empty:

```lua
if matches['size'] ~= 0 then
   vulns = analysis(host, port, matches)
end
if vulns and #vulns == 0 then
   return nil
end
return vulns
```

---

### BUG-5: Zero-CVE Results Not Cached, Causing Redundant Queries (MEDIUM)

**File:** `cvescannerv3.nse:846-866`

**Observed on:** Host 195.201.149.167, nginx 1.26.3 on ports 80, 443, and 2100.

When a product/version lookup yields 0 CVEs, the result is **not cached**. The cache write on line 865 is gated by `if nvulns > 0` (line 849):

```lua
if not registry.cache[fmt('%s|%s|%s', product, v, vu)] then
   tmp_vulns = vulnerabilities(host, port, cpe, product, info)
   local nvulns = table.remove(tmp_vulns, 1)
   if nvulns > 0 then
      -- ... cache write only happens here (line 865)
      registry.cache[fmt('%s|%s|%s', product, v, vu)] = { nvulns, tmp_vulns }
   end
   -- nvulns == 0 falls through with no cache write
```

Because the cache is never populated for 0-CVE products, every subsequent port with the same product/version bypasses the cache (`registry.cache[key]` is still nil) and re-enters the `vulnerabilities()` function, re-executing all the expensive SQL queries against the database.

**Impact:** When scanning nginx 1.26.3 across ports 80, 443, and 2100, the same database queries for `nginx|1.26.3|*` run **3 times** instead of being cached after the first lookup. For scans with many ports sharing the same service, this multiplies query cost linearly.

**Recommended Fix:** Cache 0-CVE results as well:

```lua
if nvulns > 0 then
   -- ... existing formatting and cache write
   registry.cache[fmt('%s|%s|%s', product, v, vu)] = { nvulns, tmp_vulns }
else
   registry.cache[fmt('%s|%s|%s', product, v, vu)] = { 0, {} }
end
```

---

### BUG-6: Last Batch Progress Bar Update is Zero When Total is Exact Multiple (LOW)

**File:** `extra/database.py:556-579`

```python
cve_q, cpe_q = -(-cves // CONST["cve"]), -(-cpes // CONST["cpe"])
cve_l, cpe_l = cves % CONST["cve"], cpes % CONST["cpe"]
...
q_args[-1][-2] = cpe_l  # last batch size for progress bar
```

When `cpes` is an exact multiple of `CONST["cpe"]` (10000), `cpe_l = 0`. This sets the last batch's progress bar increment to 0, so the progress bar never reaches 100%.

**Recommended Fix:**
```python
cpe_l = cpes % CONST["cpe"] or CONST["cpe"]
cve_l = cves % CONST["cve"] or CONST["cve"]
```

---

### BUG-7: Infinite Retry Loop in `update_metasploit()` (LOW)

**File:** `extra/database.py:625-632`

```python
while True:
    try:
        if db.cached_cve(ref):
            thread_objs[2].put((8, (ref, name)))
    except sql.OperationalError:
        time.sleep(2)
    else:
        break
```

If `sql.OperationalError` occurs persistently (e.g., corrupted database), this loop retries infinitely with 2-second sleeps. There is no maximum retry limit.

**Recommended Fix:** Add a maximum retry count (e.g., 10 attempts) and raise the error after exhausting retries.

---

### BUG-8: Database Cursors Not Closed on Error (LOW)

**File:** `cvescannerv3.nse:506-553`

In `dump_exploit()`, three cursors are opened (lines 506, 518, 542) but none have error handling. If any operation between cursor creation and the function end throws an error, the cursors leak. Only the last cursor opened in `vulnerabilities()` is explicitly closed on line 822.

---

### BUG-9: Typo in database.py tqdm description (COSMETIC)

**File:** `extra/database.py:619`

```python
desc="[+] Retrieving metastploit data"
#                     ^ typo: "metastploit" should be "metasploit"
```

---

## Performance Improvements

### PERF-1: HTTP Path Brute-Force is O(paths x extensions) Sequential Requests (HIGH)

**File:** `cvescannerv3.nse:298-387`

The `http_match()` function iterates over all combinations of paths (12) and extensions (17) = **204 HTTP requests per port**, all made sequentially. Each request has a 90-second timeout.

**Worst case:** 204 × 90s = **~5 hours per port** if all requests timeout.

**Recommended Fix:**
1. Use Nmap's `stdnse.new_thread()` for parallel HTTP requests
2. Reduce timeout from 90s to a more reasonable 10-15s
3. Implement early termination if the server is clearly unresponsive
4. Skip extensions that clearly don't match the detected service

---

### PERF-2: Individual SQL Queries Per CVE in `dump_exploit()` (HIGH)

**File:** `cvescannerv3.nse:502-553`

For every CVE found, `dump_exploit()` executes **3 separate SQL queries** (score, exploit-db, metasploit). For a product with 500 CVEs, that's 1,500 individual queries.

**Recommended Fix:** Batch these into single queries that return all CVEs' scores, exploit-db references, and metasploit references at once, using `IN (...)` clauses or joins in the main vulnerability query.

---

### PERF-3: Missing Database Indexes (HIGH)

**File:** `extra/database.py:110-192`

The SQLite schema creates tables with primary keys but no additional indexes. The NSE script queries filter heavily on `products.product` and `products.version`, but these columns have no index.

Key queries that would benefit from indexes:
```sql
-- Used in every scan
SELECT product_id FROM products WHERE product = '...' AND version = '*'
SELECT product_id FROM products WHERE product = '...'

-- Used for every CVE found
SELECT 1 FROM referenced_exploit WHERE cve_id = '...'
SELECT 1 FROM referenced_metasploit WHERE cve_id = '...'
```

**Recommended Fix:** Add indexes:
```sql
CREATE INDEX IF NOT EXISTS idx_products_product ON products(product);
CREATE INDEX IF NOT EXISTS idx_products_product_version ON products(product, version);
CREATE INDEX IF NOT EXISTS idx_referenced_exploit_cve ON referenced_exploit(cve_id);
CREATE INDEX IF NOT EXISTS idx_referenced_metasploit_cve ON referenced_metasploit(cve_id);
CREATE INDEX IF NOT EXISTS idx_affected_product ON affected(product_id);
CREATE INDEX IF NOT EXISTS idx_multiaffected_product ON multiaffected(product_id);
```

---

### PERF-4: Queue Polling with `time.sleep(1)` (MEDIUM)

**File:** `extra/database.py:390-406`

The `PopulateDBThread.run()` method polls the queue with a 1-second sleep when idle:

```python
while True:
    if not self.queue.empty():
        dtype, data = self.queue.get()
        ...
    else:
        ...
        time.sleep(1)  # wasteful polling
```

**Recommended Fix:** Use `self.queue.get(timeout=1)` with `queue.Empty` exception handling for blocking wait instead of busy polling.

---

### PERF-5: CPE String Re-Parsed Multiple Times (MEDIUM)

**File:** `cvescannerv3.nse:238-250, 427-438`

`add_cpe_aliases()` re-parses the CPE string using `string.gmatch()` on every call, even though the same CPE was already parsed (or will be parsed) in `cpe_parser()`.

**Recommended Fix:** Parse the CPE once and pass the parsed components to both functions.

---

### PERF-6: Redundant String Format Operations in Hot Loops (LOW)

**File:** `cvescannerv3.nse:846, 865, 869, 896`

The cache key `fmt('%s|%s|%s', product, v, vu)` is computed 4+ times in `analysis()` for the same product/version/vupdate combination.

**Recommended Fix:** Compute it once and store in a local variable.

---

### PERF-7: `set()` Conversion on Every Batch Flush (LOW)

**File:** `extra/database.py:398`

```python
self.execmany[dt](set(self.datalist[dt]))
```

Converting lists to sets on every flush is O(n) and loses insertion order. For large batches with few duplicates, this is wasteful. The database already handles duplicates via `INSERT OR IGNORE`.

**Recommended Fix:** Remove the `set()` conversion and rely on the database's `INSERT OR IGNORE` for deduplication.

---

## Summary

| Category    | Critical | High | Medium | Low | Cosmetic |
|-------------|----------|------|--------|-----|----------|
| Security    | 1        | 1    | 2      | 3   | 0        |
| Bugs        | 0        | 2    | 3      | 3   | 1        |
| Performance | 0        | 3    | 2      | 2   | 0        |
| **Total**   | **1**    | **6**| **7**  | **8**| **1**   |

### Top Priority Items
1. **SEC-1:** SQL injection in NSE script (Critical)
2. **BUG-1:** Column mismatch causing crashes when version is empty (High)
3. **BUG-4:** `portaction` returns empty table triggering Nmap "no string output" warning (High)
4. **SEC-2:** Nil dereference in `valid_json()` (High)
5. **BUG-5:** Zero-CVE results not cached, causing redundant queries on multi-port hosts (Medium)
6. **PERF-1:** 204 sequential HTTP requests per port (High)
7. **PERF-2:** N+1 query pattern in `dump_exploit()` (High)
8. **PERF-3:** Missing database indexes (High)

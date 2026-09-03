#!/usr/bin/env python3
"""
Lightweight program status check for SCAN workflows (triday-scan, extended-scan).

Unlike check_program_status.py (used by vet), this does NOT check:
  - bug bounty vs VDP, public/private, safe harbor
  - scope fetch
  - automation ban / rate limit / ID verification policy text

It only checks: is the program OPEN or BLOCKED/SUSPENDED right now.
Domains belonging to a blocked/suspended program are excluded.
Everything else is assumed already vetted (see check_program_status.py / vet workflow)
and re-scoped at the subdomain level in recon.
"""
import os, csv, json, re, sys
import urllib.request, urllib.error

HOME = os.path.expanduser("~")
MAPPING_PATH = os.environ.get("MAPPING_CSV_PATH") or os.path.join(HOME, "bug-bounty-hunter", "domain_program_map.csv")
EXCLUDE_OUTPUT_PATH = os.environ.get("EXCLUDED_OUTPUT_PATH") or os.path.join(HOME, "bug-bounty-hunter", "excluded_domains.txt")


def get_token(env_name, file_path):
    val = os.environ.get(env_name)
    if val:
        return val.strip()
    with open(file_path) as f:
        return f.read().strip()


def fetch_hackerone_programs(token):
    import base64, time
    auth = base64.b64encode(f"oxidizer:{token}".encode()).decode()
    last_err = None
    for attempt in range(3):
        try:
            programs = []
            url = "https://api.hackerone.com/v1/hackers/programs?page[size]=100"
            while url:
                req = urllib.request.Request(url, headers={"Authorization": f"Basic {auth}", "Accept": "application/json"})
                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = json.loads(resp.read().decode())
                for p in data.get("data", []):
                    a = p["attributes"]
                    programs.append({"handle": a["handle"], "name": a["name"], "status": a["submission_state"]})
                url = data.get("links", {}).get("next")
            return programs
        except Exception as e:
            last_err = e
            if attempt < 2:
                print(f"  -> HackerOne fetch attempt {attempt+1} failed ({e}), retrying...")
                time.sleep(5 * (attempt + 1))
    raise last_err


def fetch_intigriti_programs(token):
    import time
    last_err = None
    for attempt in range(3):
        try:
            url = "https://api.intigriti.com/external/researcher/v1/programs?limit=500"
            req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())
            programs = []
            for p in data.get("records", []):
                programs.append({"handle": p["handle"], "name": p["name"], "status": p["status"]["value"], "id": p["id"]})
            return programs
        except Exception as e:
            last_err = e
            if attempt < 2:
                print(f"  -> Intigriti fetch attempt {attempt+1} failed ({e}), retrying...")
                time.sleep(5 * (attempt + 1))
    raise last_err


def wildcard_to_regex(pattern):
    # Same glob convention used in filter_to_scope.py: "*" -> ".*"
    escaped = re.escape(pattern)
    escaped = escaped.replace(r"\*", ".*")
    return re.compile(f"^{escaped}$", re.IGNORECASE)


def bare_host(host):
    # Same normalization as filter_to_scope.py's bare_host() - combined_full.txt
    # entries carry a scheme (http://...), domain_program_map.csv entries don't.
    h = host.replace("https://", "").replace("http://", "")
    return h.split("/")[0].split(":")[0]


def is_mapped(host, exact_domains, wildcard_regexes):
    h = bare_host(host)
    if h in exact_domains:
        return True
    return any(rx.match(h) for rx in wildcard_regexes)


def find_match(programs, keyword, platform=None):
    if platform == "intigriti":
        by_id = [p for p in programs if p.get("id", "").lower() == keyword.lower()]
        if by_id:
            return by_id
    exact = [p for p in programs if p["handle"].lower() == keyword.lower()]
    if exact:
        return exact
    return [p for p in programs if keyword.lower() in p["name"].lower()]


def check_yeswehack(slug):
    url = f"https://api.yeswehack.com/programs/{slug}"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        disabled = data.get("disabled", False)
        return ("blocked" if disabled else "open", data.get("title", slug))
    except urllib.error.HTTPError as e:
        return ("error", f"HTTP {e.code}")
    except Exception as e:
        return ("error", str(e))


def check_bugcrowd(slug):
    # Uses the same JSON listing endpoint (bugcrowd.com/engagements?page=N)
    # that discover_all_programs.py's discover_bugcrowd() already relies on
    # successfully, instead of scraping the HTML page for a "state" field -
    # no verified single-program JSON endpoint by slug exists, so this
    # paginates the listing and matches by slug via briefUrl, same as
    # vet_bugcrowd_program() does.
    page = 1
    total_pages = None
    while total_pages is None or page <= total_pages:
        url = f"https://bugcrowd.com/engagements?page={page}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            return ("error", f"HTTP {e.code}")
        except Exception as e:
            return ("error", str(e))
        for p in data.get("engagements", []):
            p_slug = p.get("briefUrl", "").rstrip("/").split("/")[-1]
            if p_slug == slug:
                status = p.get("accessStatus")
                return ("open" if status == "open" else "blocked", status)
        if total_pages is None:
            meta = data.get("paginationMeta") or {}
            limit = meta.get("limit")
            total_count = meta.get("totalCount")
            if limit and total_count is not None:
                total_pages = -(-total_count // limit)
            else:
                break
        page += 1
    return ("error", "slug not found in engagements listing")


def check_hackenproof(slug):
    auth_cookie = os.environ.get("HACKENPROOF_AUTH", "")
    if not auth_cookie:
        return ("error", "no HACKENPROOF_AUTH set")
    url = f"https://dashboard.hackenproof.com/api/internal/user/opportunities/{slug}"
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
        "Accept": "application/json, text/plain, */*",
        "Referer": "https://dashboard.hackenproof.com/user/programs?tab=bounties",
        "Cookie": auth_cookie,
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        if data.get("state") != "published":
            return ("blocked", f"state={data.get('state')}")
        if (data.get("status") or {}).get("name") != "Active":
            return ("blocked", f"status={(data.get('status') or {}).get('name')}")
        if data.get("private") is True:
            return ("blocked", "private")
        return ("open", "published/active/public")
    except urllib.error.HTTPError as e:
        return ("error", f"HTTP {e.code}")
    except Exception as e:
        return ("error", str(e))


def main():
    try:
        h1_token = get_token("HACKERONE_TOKEN", os.path.join(HOME, ".hackerone_token"))
        intigriti_token = get_token("INTIGRITI_TOKEN", os.path.join(HOME, ".intigriti_token"))
    except FileNotFoundError as e:
        print(f"ERROR: missing token (no env var set, no local file found) - {e}")
        sys.exit(1)

    print("Fetching HackerOne programs...")
    try:
        h1_programs = fetch_hackerone_programs(h1_token)
        print(f"  -> {len(h1_programs)} programs retrieved\n")
    except Exception as e:
        print(f"  -> ERROR fetching HackerOne programs: {e} - all H1 domains will be excluded this run\n")
        h1_programs = []

    print("Fetching Intigriti programs...")
    try:
        intigriti_programs = fetch_intigriti_programs(intigriti_token)
        print(f"  -> {len(intigriti_programs)} programs retrieved\n")
    except Exception as e:
        print(f"  -> ERROR fetching Intigriti programs: {e} - all Intigriti domains will be excluded this run\n")
        intigriti_programs = []

    rows = []
    with open(MAPPING_PATH) as f:
        for row in csv.DictReader(f):
            rows.append(row)

    groups = {}
    for row in rows:
        groups.setdefault((row["platform"], row["keyword"]), []).append(row["domain"])

    print(f"Checking {len(groups)} unique program groups across {len(rows)} domains (open/blocked only)...\n")
    print("=" * 70)

    excluded_domains = []
    no_match = []

    mapped_domains = {row["domain"] for row in rows if "*" not in row["domain"]}
    wildcard_regexes = [wildcard_to_regex(row["domain"]) for row in rows if "*" in row["domain"]]
    combined_path = os.environ.get("COMBINED_HOSTS_PATH", "combined.txt")
    if os.path.exists(combined_path):
        with open(combined_path) as f:
            unmapped = [line.strip() for line in f if line.strip() and not is_mapped(line.strip(), mapped_domains, wildcard_regexes)]
        if unmapped:
            print(f"[UNMAPPED] {len(unmapped)} domain(s) not in domain_program_map.csv - EXCLUDING (no program status known)")
            for d in unmapped:
                print(f"    - {d}")
            excluded_domains.extend(unmapped)

    for (platform, keyword), domains in sorted(groups.items()):
        if platform == "yeswehack":
            status, detail = check_yeswehack(keyword)
        elif platform == "bugcrowd":
            status, detail = check_bugcrowd(keyword)
        elif platform == "hackenproof":
            status, detail = check_hackenproof(keyword)
        else:
            programs = h1_programs if platform == "hackerone" else intigriti_programs
            matches = find_match(programs, keyword, platform)
            if len(matches) != 1:
                print(f"[NO MATCH]  {platform}/{keyword} -> {len(matches)} programs matched ({len(domains)} domain(s)) - EXCLUDING")
                no_match.append((platform, keyword, domains))
                excluded_domains.extend(domains)
                continue
            m = matches[0]
            status = "open" if m["status"].lower() == "open" else "blocked"
            detail = m["status"]

        if status == "error":
            print(f"[ERROR]   {platform}/{keyword} -> {detail} ({len(domains)} domain(s)) - EXCLUDING (can't confirm open)")
            no_match.append((platform, keyword, domains))
            excluded_domains.extend(domains)
            continue

        tag = "OPEN  " if status == "open" else "BLOCKED"
        print(f"[{tag}]  {platform}/{keyword} -> {detail} ({len(domains)} domain(s))")
        if status == "blocked":
            excluded_domains.extend(domains)

    print("=" * 70)
    print(f"\nSUMMARY: {len(excluded_domains)} domains would be EXCLUDED (blocked/suspended/unconfirmed)")
    for d in excluded_domains:
        print(f"    - {d}")
    print(f"\n  No/ambiguous API match or error: {len(no_match)} group(s)")

    # Downstream (exclude_grep.txt in the scanner workflows) does suffix-match
    # exclusion, not wildcard-glob matching. Strip a literal "*." prefix here
    # so a blocked wildcard-scoped entry (e.g. "*.etoro.com") actually excludes
    # its real subdomains (api.etoro.com, etc.) instead of only the literal
    # "*.etoro.com" string, which never appears in a live host list.
    normalized_excluded = []
    for d in excluded_domains:
        if d.startswith("*."):
            d = d[2:]
        normalized_excluded.append(d)

    exclude_tmp_path = f"{EXCLUDE_OUTPUT_PATH}.tmp"
    with open(exclude_tmp_path, "w") as f:
        for d in normalized_excluded:
            f.write(d + "\n")
    os.replace(exclude_tmp_path, EXCLUDE_OUTPUT_PATH)
    print(f"\nWrote {len(excluded_domains)} domains to {EXCLUDE_OUTPUT_PATH}")


if __name__ == "__main__":
    main()

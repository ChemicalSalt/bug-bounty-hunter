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
import os, csv, json, sys
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
    import base64
    auth = base64.b64encode(f"oxidizer:{token}".encode()).decode()
    programs = []
    url = "https://api.hackerone.com/v1/hackers/programs?page[size]=100"
    while url:
        req = urllib.request.Request(url, headers={"Authorization": f"Basic {auth}", "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        for p in data.get("data", []):
            a = p["attributes"]
            programs.append({"handle": a["handle"], "name": a["name"], "status": a["submission_state"]})
        url = data.get("links", {}).get("next")
    return programs


def fetch_intigriti_programs(token):
    url = "https://api.intigriti.com/external/researcher/v1/programs?limit=500"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read().decode())
    programs = []
    for p in data.get("records", []):
        programs.append({"handle": p["handle"], "name": p["name"], "status": p["status"]["value"], "id": p["id"]})
    return programs


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
    import re
    url = f"https://bugcrowd.com/engagements/{slug}"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            html = resp.read().decode()
        match = re.search(r"&quot;state&quot;:&quot;([^&]+)&quot;", html) or re.search(r'"state":"([^"]+)"', html)
        if not match:
            return ("error", "state field not found")
        state = match.group(1)
        return ("open" if state == "in_progress" else "blocked", state)
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
    h1_programs = fetch_hackerone_programs(h1_token)
    print(f"  -> {len(h1_programs)} programs retrieved\n")

    print("Fetching Intigriti programs...")
    intigriti_programs = fetch_intigriti_programs(intigriti_token)
    print(f"  -> {len(intigriti_programs)} programs retrieved\n")

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

    for (platform, keyword), domains in sorted(groups.items()):
        if platform == "yeswehack":
            status, detail = check_yeswehack(keyword)
        elif platform == "bugcrowd":
            status, detail = check_bugcrowd(keyword)
        else:
            programs = h1_programs if platform == "hackerone" else intigriti_programs
            matches = find_match(programs, keyword, platform)
            if len(matches) != 1:
                print(f"[NO MATCH]  {platform}/{keyword} -> {len(matches)} programs matched ({len(domains)} domain(s)) - EXCLUDING, needs manual review")
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

    exclude_tmp_path = f"{EXCLUDE_OUTPUT_PATH}.tmp"
    with open(exclude_tmp_path, "w") as f:
        for d in excluded_domains:
            f.write(d + "\n")
    os.replace(exclude_tmp_path, EXCLUDE_OUTPUT_PATH)
    print(f"\nWrote {len(excluded_domains)} domains to {EXCLUDE_OUTPUT_PATH}")


if __name__ == "__main__":
    main()

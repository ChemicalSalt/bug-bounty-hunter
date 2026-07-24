#!/usr/bin/env python3
import csv, json, urllib.request, urllib.error, re, os, sys, base64
from discover_all_programs import extract_ywh_domains

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
    auth = base64.b64encode(f"oxidizer:{token}".encode()).decode()
    programs = []
    url = "https://api.hackerone.com/v1/hackers/programs?page[size]=100"
    while url:
        req = urllib.request.Request(url, headers={"Authorization": f"Basic {auth}", "Accept": "application/json"})
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
        for p in data.get("data", []):
            a = p["attributes"]
            programs.append({"handle": a["handle"], "name": a["name"], "status": a["submission_state"], "offers_bounties": a.get("offers_bounties")})
        url = data.get("links", {}).get("next")
    return programs

def fetch_hackerone_scope(handle, token):
    auth = base64.b64encode(f"oxidizer:{token}".encode()).decode()
    url = f"https://api.hackerone.com/v1/hackers/programs/{handle}"
    req = urllib.request.Request(url, headers={"Authorization": f"Basic {auth}", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
    except Exception as e:
        return {"scope": [], "safe_harbor": None, "error": str(e)}

    scopes = data.get("relationships", {}).get("structured_scopes", {}).get("data", [])
    in_scope_domains = []
    out_scope_domains = []
    for s in scopes:
        a = s.get("attributes", {})
        if a.get("asset_type") not in ("URL", "WILDCARD"):
            continue
        if a.get("eligible_for_submission") is True:
            in_scope_domains.append(a.get("asset_identifier"))
        elif a.get("eligible_for_submission") is False:
            out_scope_domains.append(a.get("asset_identifier"))

    safe_harbor = data.get("attributes", {}).get("gold_standard_safe_harbor")
    return {"scope": in_scope_domains, "out_scope": out_scope_domains, "safe_harbor": safe_harbor, "error": None}

def fetch_intigriti_programs(token):
    url = "https://api.intigriti.com/external/researcher/v1/programs?limit=500"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read().decode())
    programs = []
    for p in data.get("records", []):
        programs.append({"handle": p["handle"], "name": p["name"], "status": p["status"]["value"], "id": p["id"], "type": p.get("type", {}).get("value")})
    return programs

import itertools


def fetch_intigriti_scope(program_id, token):
    url = f"https://api.intigriti.com/external/researcher/v1/programs/{program_id}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
    except Exception as e:
        return {"scope": [], "safe_harbor": None, "rate_limit": None, "error": str(e)}

    domains = data.get("domains", {}).get("content", [])
    in_scope = []
    out_scope = []
    for d in domains:
        asset_type = d.get("type", {}).get("value", "")
        tier = d.get("tier", {}).get("value", "")
        endpoint = d.get("endpoint")
        if asset_type not in ("Wildcard", "Url") or not endpoint:
            continue
        if tier == "Out Of Scope":
            out_scope.append(endpoint)
        elif tier != "No Bounty":
            in_scope.append(endpoint)

    roe = data.get("rulesOfEngagement", {}).get("content", {})
    safe_harbor = roe.get("safeHarbour")
    rate_limit = roe.get("testingRequirements", {}).get("automatedTooling")

    return {"scope": in_scope, "out_scope": out_scope, "safe_harbor": safe_harbor, "rate_limit": rate_limit, "error": None}

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
        title = data.get("title", slug)
        return ("blocked" if disabled else "open", title)
    except urllib.error.HTTPError as e:
        return ("error", f"HTTP {e.code}")
    except Exception as e:
        return ("error", str(e))

def check_bugcrowd(slug):
    url = f"https://bugcrowd.com/engagements/{slug}"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            html = resp.read().decode()
        match = re.search(r"&quot;state&quot;:&quot;([^&]+)&quot;", html)
        if not match:
            match = re.search(r'"state":"([^"]+)"', html)
        if not match:
            return ("error", "state field not found")
        state = match.group(1)
        return ("open" if state == "in_progress" else "blocked", state)
    except urllib.error.HTTPError as e:
        return ("error", f"HTTP {e.code}")
    except Exception as e:
        return ("error", str(e))

def fetch_bugcrowd_scope(slug):
    headers = {"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
    try:
        req = urllib.request.Request(f"https://bugcrowd.com/engagements/{slug}/changelog.json", headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            cl_data = json.loads(resp.read().decode())
        changelogs = cl_data.get("changelogs", [])
        if not changelogs:
            return {"scope": [], "error": "no changelog entries"}
        latest = next((c for c in changelogs if c.get("changelogState") == "Latest"), changelogs[0])
        req2 = urllib.request.Request(f"https://bugcrowd.com/engagements/{slug}/changelog/{latest['id']}.json", headers=headers)
        with urllib.request.urlopen(req2, timeout=15) as resp:
            full = json.loads(resp.read().decode())
    except Exception as e:
        return {"scope": [], "error": str(e)}
    domains = []
    out_domains = []
    for grp in full.get("data", {}).get("scope", []):
        target_domains = []
        for t in grp.get("targets", []):
            uri = t.get("uri")
            name = t.get("name", "") or ""
            if uri:
                target_domains.append(re.sub(r"^https?://", "", uri).split("/")[0])
            elif re.match(r"^[a-zA-Z0-9*][a-zA-Z0-9\-.*]*\.[a-zA-Z]{2,}$", name.strip()):
                target_domains.append(name.strip())
        if grp.get("inScope"):
            domains.extend(target_domains)
        else:
            out_domains.extend(target_domains)
    return {"scope": sorted(set(domains)), "out_scope": sorted(set(out_domains)), "error": None}
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
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)

    groups = {}
    for row in rows:
        key = (row["platform"], row["keyword"])
        groups.setdefault(key, []).append(row["domain"])

    print(f"Checking {len(groups)} unique program groups across {len(rows)} domains...\n")
    print("=" * 70)

    excluded_domains = []
    no_match = []
    ambiguous = []
    hackerone_scope_lines = []
    hackerone_out_lines = []
    intigriti_scope_lines = []
    intigriti_out_lines = []
    yeswehack_scope_lines = []
    bugcrowd_scope_lines = []
    bugcrowd_out_lines = []

    for (platform, keyword), domains in sorted(groups.items()):
        if platform == "yeswehack":
            status, detail = check_yeswehack(keyword)
            if status == "error":
                print(f"[ERROR]   {platform}/{keyword} -> {detail} ({len(domains)} domain(s))")
                no_match.append((platform, keyword, domains))
            else:
                tag = "OPEN  " if status == "open" else "BLOCKED"
                print(f"[{tag}]  {platform}/{keyword} -> {detail} ({len(domains)} domain(s))")
                if status == "blocked":
                    excluded_domains.extend(domains)
                elif status == "open":
                    ywh_url = f"https://api.yeswehack.com/programs/{keyword}"
                    ywh_req = urllib.request.Request(ywh_url, headers={"Accept": "application/json"})
                    try:
                        with urllib.request.urlopen(ywh_req, timeout=15) as resp:
                            ywh_data = json.loads(resp.read().decode())
                        ywh_domains = extract_ywh_domains(ywh_data.get("scopes", []))
                        for d in ywh_domains:
                            yeswehack_scope_lines.append(d)
                        print(f"    [SCOPE] {len(ywh_domains)} in-scope asset(s) found")
                    except Exception as e:
                        print(f"    [SCOPE ERROR] {e}")
            continue
        if platform == "bugcrowd":
            status, detail = check_bugcrowd(keyword)
            if status == "error":
                print(f"[ERROR]   {platform}/{keyword} -> {detail} ({len(domains)} domain(s))")
                no_match.append((platform, keyword, domains))
            else:
                tag = "OPEN  " if status == "open" else "BLOCKED"
                print(f"[{tag}]  {platform}/{keyword} -> state={detail} ({len(domains)} domain(s))")
                if status == "blocked":
                    excluded_domains.extend(domains)
                elif status == "open":
                    scope_result = fetch_bugcrowd_scope(keyword)
                    if scope_result["error"]:
                        print(f"    [SCOPE ERROR] {scope_result['error']}")
                    else:
                        for d in scope_result["scope"]:
                            bugcrowd_scope_lines.append(d)
                        for d in scope_result.get("out_scope", []):
                            bugcrowd_out_lines.append(d)
                        print(f"    [SCOPE] {len(scope_result['scope'])} in-scope, {len(scope_result.get('out_scope', []))} out-of-scope asset(s) found")
            continue
        programs = h1_programs if platform == "hackerone" else intigriti_programs
        matches = find_match(programs, keyword, platform)

        if len(matches) == 0:
            print(f"[NO MATCH]  {platform}/{keyword} -> 0 programs found for {len(domains)} domain(s) - EXCLUDING (program may be removed/renamed, needs manual review)")
            no_match.append((platform, keyword, domains))
            excluded_domains.extend(domains)
            continue

        if len(matches) > 1:
            names = [m["name"] for m in matches]
            print(f"[AMBIGUOUS] {platform}/{keyword} -> {len(matches)} programs matched: {names} - EXCLUDING (needs manual review)")
            ambiguous.append((platform, keyword, matches, domains))
            excluded_domains.extend(domains)
            continue

        m = matches[0]
        is_open = (m["status"].lower() == "open")
        is_bbp = True
        intigriti_scope_result = None
        if platform == "hackerone":
            is_bbp = m.get("offers_bounties") is True
        elif platform == "intigriti" and is_open:
            intigriti_scope_result = fetch_intigriti_scope(m["id"], intigriti_token)
            if intigriti_scope_result["error"]:
                is_bbp = False
            else:
                is_bbp = len(intigriti_scope_result["scope"]) > 0
        tag = "OPEN  " if is_open else "BLOCKED"
        print(f"[{tag}]  {platform}/{keyword} -> '{m['name']}' (handle={m['handle']}) status={m['status']} bbp={is_bbp} ({len(domains)} domain(s))")
        if not is_open or not is_bbp:
            excluded_domains.extend(domains)

        if platform == "hackerone" and is_open and is_bbp:
            scope_result = fetch_hackerone_scope(m["handle"], h1_token)
            if scope_result["error"]:
                print(f"    [SCOPE ERROR] {scope_result['error']}")
            else:
                for asset in scope_result["scope"]:
                    hackerone_scope_lines.append(asset)
                for asset in scope_result.get("out_scope", []):
                    hackerone_out_lines.append(asset)
                print(f"    [SCOPE] {len(scope_result['scope'])} in-scope, {len(scope_result.get('out_scope', []))} out-of-scope asset(s) found")

        if platform == "intigriti" and is_open and intigriti_scope_result is not None:
            scope_result = intigriti_scope_result
            if scope_result["error"]:
                print(f"    [SCOPE ERROR] {scope_result['error']}")
            else:
                for asset in scope_result["scope"]:
                    intigriti_scope_lines.append(asset)
                for asset in scope_result.get("out_scope", []):
                    intigriti_out_lines.append(asset)
                print(f"    [SCOPE] {len(scope_result['scope'])} in-scope, {len(scope_result.get('out_scope', []))} out-of-scope asset(s) found | safe_harbor={scope_result['safe_harbor']} | rate_limit={scope_result['rate_limit']}")

    print("=" * 70)
    print(f"\nSUMMARY: {len(excluded_domains)} domains would be EXCLUDED")
    for d in excluded_domains:
        print(f"    - {d}")
    print(f"\n  No API match found: {len(no_match)} groups")
    print(f"  Ambiguous matches: {len(ambiguous)} groups")

    with open(EXCLUDE_OUTPUT_PATH, "w") as f:
        for d in excluded_domains:
            f.write(d + "\n")
    print(f"\nWrote {len(excluded_domains)} domains to {EXCLUDE_OUTPUT_PATH}")

    hackerone_scope_lines = sorted(set(hackerone_scope_lines))
    hackerone_out_lines = sorted(set(hackerone_out_lines))
    scope_output_path = os.environ.get("HACKERONE_SCOPE_OUTPUT_PATH") or os.path.join(HOME, "bug-bounty-hunter", "hackerone_scope.txt")
    with open(scope_output_path, "w") as f:
        for asset in hackerone_scope_lines:
            f.write(f"IN:{asset}\n")
        for asset in hackerone_out_lines:
            f.write(f"OUT:{asset}\n")
    print(f"Wrote {len(hackerone_scope_lines)} in-scope + {len(hackerone_out_lines)} out-of-scope HackerOne assets to {scope_output_path}")

    intigriti_scope_lines = sorted(set(intigriti_scope_lines))
    intigriti_out_lines = sorted(set(intigriti_out_lines))
    intigriti_scope_output_path = os.environ.get("INTIGRITI_SCOPE_OUTPUT_PATH") or os.path.join(HOME, "bug-bounty-hunter", "intigriti_scope.txt")
    with open(intigriti_scope_output_path, "w") as f:
        for asset in intigriti_scope_lines:
            f.write(f"IN:{asset}\n")
        for asset in intigriti_out_lines:
            f.write(f"OUT:{asset}\n")
    print(f"Wrote {len(intigriti_scope_lines)} in-scope + {len(intigriti_out_lines)} out-of-scope Intigriti assets to {intigriti_scope_output_path}")

    yeswehack_scope_lines = sorted(set(yeswehack_scope_lines))
    yeswehack_scope_output_path = os.environ.get("YESWEHACK_SCOPE_OUTPUT_PATH") or os.path.join(HOME, "bug-bounty-hunter", "yeswehack_scope.txt")
    with open(yeswehack_scope_output_path, "w") as f:
        for asset in yeswehack_scope_lines:
            f.write(f"IN:{asset}\n")
    print(f"Wrote {len(yeswehack_scope_lines)} YesWeHack in-scope assets to {yeswehack_scope_output_path}")

    bugcrowd_scope_lines = sorted(set(bugcrowd_scope_lines))
    bugcrowd_out_lines = sorted(set(bugcrowd_out_lines))
    bugcrowd_scope_output_path = os.environ.get("BUGCROWD_SCOPE_OUTPUT_PATH") or os.path.join(HOME, "bug-bounty-hunter", "bugcrowd_scope.txt")
    with open(bugcrowd_scope_output_path, "w") as f:
        for asset in bugcrowd_scope_lines:
            f.write(f"IN:{asset}\n")
        for asset in bugcrowd_out_lines:
            f.write(f"OUT:{asset}\n")
    print(f"Wrote {len(bugcrowd_scope_lines)} in-scope + {len(bugcrowd_out_lines)} out-of-scope Bugcrowd assets to {bugcrowd_scope_output_path}")

if __name__ == "__main__":
    main()


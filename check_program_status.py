import os
#!/usr/bin/env python3
import csv, json, urllib.request, urllib.error, re, os, sys, base64, time
from discover_all_programs import extract_ywh_domains, extract_ywh_out_of_scope_domains, check_automation_ban_two_layer, check_rate_limit_two_layer, check_safe_harbor_two_layer, check_id_verification_two_layer, MISTRAL_API_KEY

HOME = os.path.expanduser("~")
MAPPING_PATH = os.environ.get("MAPPING_CSV_PATH") or os.path.join(HOME, "bug-bounty-hunter", "domain_program_map.csv")
EXCLUDE_OUTPUT_PATH = os.environ.get("EXCLUDED_OUTPUT_PATH") or os.path.join(HOME, "bug-bounty-hunter", "excluded_domains.txt")
FLAT_RATE_LIMIT = 5  # our scanner rate (req/s) - program must allow at least this

HTML_TAG_RE = re.compile(r"<[^>]+>")
def strip_html(text):
    if not text:
        return ""
    return HTML_TAG_RE.sub(" ", text)

def automation_ban_check(text, program_name):
    """Returns "allowed" (confirmed ok), or "banned"/"silent"/"review"/"no_key"
    (all treated as not-ok here - this file fails closed on anything short of
    confirmed explicit permission, same as the vet-time check)."""
    if not MISTRAL_API_KEY:
        return "no_key"
    result, reason = check_automation_ban_two_layer(text, program_name)
    return result

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
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        for p in data.get("data", []):
            a = p["attributes"]
            programs.append({
                "handle": a["handle"],
                "name": a["name"],
                "status": a["submission_state"],
                "offers_bounties": a.get("offers_bounties"),
                "state": a.get("state"),  # "public_mode" = public program
                "gold_standard_safe_harbor": a.get("gold_standard_safe_harbor"),
                "policy": a.get("policy"),
            })
        url = data.get("links", {}).get("next")
    return programs

def urlopen_with_retry(req, timeout=15, max_retries=3):
    """Retry on transient network errors (timeouts, connection resets, 5xx, 429).
    Does NOT retry on definitive client errors (404, 401, 403) - those are final answers.
    Returns decoded response body string. Raises the last exception if all retries fail."""
    last_err = None
    for attempt in range(max_retries):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode()
        except urllib.error.HTTPError as e:
            last_err = e
            if e.code in (429, 500, 502, 503, 504):
                if attempt < max_retries - 1:
                    time.sleep(3 * (attempt + 1))
                    continue
            raise
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            last_err = e
            if attempt < max_retries - 1:
                time.sleep(3 * (attempt + 1))
                continue
            raise
    raise last_err


def fetch_hackerone_scope(handle, token):
    auth = base64.b64encode(f"oxidizer:{token}".encode()).decode()
    url = f"https://api.hackerone.com/v1/hackers/programs/{handle}"
    req = urllib.request.Request(url, headers={"Authorization": f"Basic {auth}", "Accept": "application/json"})
    try:
        body = urlopen_with_retry(req, timeout=15, max_retries=3)
        data = json.loads(body)
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
    policy_text = data.get("attributes", {}).get("policy")
    return {"scope": in_scope_domains, "out_scope": out_scope_domains, "safe_harbor": safe_harbor, "policy": policy_text, "error": None}

def fetch_intigriti_programs(token):
    url = "https://api.intigriti.com/external/researcher/v1/programs?limit=500"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read().decode())
    programs = []
    for p in data.get("records", []):
        programs.append({
            "handle": p["handle"],
            "name": p["name"],
            "status": p["status"]["value"],
            "id": p["id"],
            "type": p.get("type", {}).get("value"),  # raw value logged below for confirmation
        })
    return programs

def fetch_intigriti_scope(program_id, token):
    url = f"https://api.intigriti.com/external/researcher/v1/programs/{program_id}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        body = urlopen_with_retry(req, timeout=15, max_retries=3)
        data = json.loads(body)
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
    automated_tooling = roe.get("testingRequirements", {}).get("automatedTooling")
    policy_text = roe.get("description")
    roe_text = json.dumps(roe) if roe else policy_text
    confidentiality = data.get("confidentialityLevel", {}).get("value")

    return {"scope": in_scope, "out_scope": out_scope, "safe_harbor": safe_harbor, "rate_limit": automated_tooling, "policy": policy_text, "roe_text": roe_text, "confidentiality": confidentiality, "error": None}

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
        body = urlopen_with_retry(req, timeout=15, max_retries=3)
        data = json.loads(body)
        disabled = data.get("disabled", False)
        title = data.get("title", slug)
        status = "blocked" if disabled else "open"
        return (status, title, data)
    except urllib.error.HTTPError as e:
        return ("error", f"HTTP {e.code}", None)
    except Exception as e:
        return ("error", str(e), None)

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
            return ("error", "state field not found", None)
        state = match.group(1)
        # productLabel (e.g. "Bug Bounty" vs "Vulnerability Disclosure") is
        # embedded in this same HTML - condition #2 (BBP not VDP) needs this,
        # and discover_all_programs.py already excludes non-BBP engagements,
        # so this recheck must match it instead of only checking open/blocked.
        type_match = re.search(r"&quot;productLabel&quot;:&quot;([^&]+)&quot;", html)
        if not type_match:
            type_match = re.search(r'"productLabel":"([^"]+)"', html)
        engagement_type = type_match.group(1) if type_match else None
        return ("open" if state == "in_progress" else "blocked", state, engagement_type)
    except urllib.error.HTTPError as e:
        return ("error", f"HTTP {e.code}", None)
    except Exception as e:
        return ("error", str(e), None)

def fetch_bugcrowd_scope(slug):
    headers = {"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
    try:
        req = urllib.request.Request(f"https://bugcrowd.com/engagements/{slug}/changelog.json", headers=headers)
        cl_body = urlopen_with_retry(req, timeout=15, max_retries=3)
        cl_data = json.loads(cl_body)
        changelogs = cl_data.get("changelogs", [])
        if not changelogs:
            return {"scope": [], "error": "no changelog entries"}
        latest = next((c for c in changelogs if c.get("changelogState") == "Latest"), changelogs[0])
        req2 = urllib.request.Request(f"https://bugcrowd.com/engagements/{slug}/changelog/{latest['id']}.json", headers=headers)
        full_body = urlopen_with_retry(req2, timeout=15, max_retries=3)
        full = json.loads(full_body)
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
    brief = full.get("data", {}).get("brief", {}) or {}
    policy_text = strip_html(" ".join(filter(None, [brief.get("description"), brief.get("targetsOverview")])))
    engagement_config = full.get("data", {}).get("engagementConfiguration", {}) or {}
    participation = engagement_config.get("participation")
    return {"scope": sorted(set(domains)), "out_scope": sorted(set(out_domains)), "policy": policy_text, "participation": participation, "error": None}

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
    print("  Raw Intigriti 'type' values seen (VERIFY these before trusting BBP/VDP filter):")
    print(f"    {sorted(set(p.get('type') for p in intigriti_programs))}\n")

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
    yeswehack_out_lines = []
    bugcrowd_scope_lines = []
    bugcrowd_out_lines = []

    for (platform, keyword), domains in sorted(groups.items()):
        if platform == "yeswehack":
            status, detail, ywh_data = check_yeswehack(keyword)
            if status == "error":
                print(f"[ERROR]   {platform}/{keyword} -> {detail} ({len(domains)} domain(s))")
                no_match.append((platform, keyword, domains))
            else:
                tag = "OPEN  " if status == "open" else "BLOCKED"
                print(f"[{tag}]  {platform}/{keyword} -> {detail} ({len(domains)} domain(s))")
                if status == "blocked":
                    excluded_domains.extend(domains)
                elif status == "open":
                    is_public = ywh_data.get("public") is True
                    is_demo = ywh_data.get("demo") is True
                    is_vdp = ywh_data.get("vdp") is True
                    ywh_domains = extract_ywh_domains(ywh_data.get("scopes", []))
                    ywh_out_domains = extract_ywh_out_of_scope_domains(ywh_data.get("out_of_scope", []))
                    if ywh_out_domains:
                        ywh_domains = sorted(set(ywh_domains) - set(ywh_out_domains))
                        yeswehack_out_lines.extend(ywh_out_domains)
                    has_scope = len(ywh_domains) > 0
                    policy_text = strip_html(ywh_data.get("rules") or ywh_data.get("rules_html") or "")
                    ban_result = check_automation_ban_two_layer(policy_text, f"yeswehack/{keyword}")
                    rate_result, _ = check_rate_limit_two_layer(policy_text, f"yeswehack/{keyword}")
                    sh_result = check_safe_harbor_two_layer(policy_text, f"yeswehack/{keyword}")
                    id_result = check_id_verification_two_layer(policy_text, f"yeswehack/{keyword}")
                    ban_ok = ban_result[0] == "allowed"
                    rate_ok = rate_result is None or rate_result >= FLAT_RATE_LIMIT
                    sh_ok = sh_result[0] is True
                    id_ok = id_result[0] is not True
                    eligible = has_scope and is_public and not is_demo and not is_vdp and ban_ok and rate_ok and sh_ok and id_ok
                    print(f"    [SCOPE] {len(ywh_domains)} in-scope | public={is_public} demo={is_demo} vdp={is_vdp} | ban={ban_result[0]} | rate={rate_result} | safe_harbor={sh_result[0]} | id_verification={id_result[0]} | eligible={eligible}")
                    if id_result[0] is True:
                        print(f"    [EXCLUDED] ID verification requirement detected - {id_result[1]}")
                    elif id_result[0] == "review":
                        print(f"    [KEPT-IF-ELSE-OK] ID verification unclear, no answer - not excluding on this alone - {id_result[1]}")
                    if not eligible:
                        excluded_domains.extend(domains)
                    else:
                        for d in ywh_domains:
                            yeswehack_scope_lines.append(d)
            continue
        if platform == "bugcrowd":
            status, detail, engagement_type = check_bugcrowd(keyword)
            if status == "error":
                print(f"[ERROR]   {platform}/{keyword} -> {detail} ({len(domains)} domain(s))")
                no_match.append((platform, keyword, domains))
            else:
                tag = "OPEN  " if status == "open" else "BLOCKED"
                print(f"[{tag}]  {platform}/{keyword} -> state={detail} engagement_type={engagement_type} ({len(domains)} domain(s))")
                is_bbp = engagement_type == "Bug Bounty"
                if status == "blocked":
                    excluded_domains.extend(domains)
                elif status == "open" and not is_bbp:
                    print(f"    [EXCLUDED] not a Bug Bounty engagement (productLabel={engagement_type})")
                    excluded_domains.extend(domains)
                elif status == "open":
                    scope_result = fetch_bugcrowd_scope(keyword)
                    if scope_result["error"]:
                        print(f"    [SCOPE ERROR] {scope_result['error']}")
                        excluded_domains.extend(domains)
                    else:
                        has_scope = len(scope_result["scope"]) > 0
                        is_public = scope_result.get("participation") == "open"
                        policy_text = scope_result.get("policy") or ""
                        ban_result = check_automation_ban_two_layer(policy_text, f"bugcrowd/{keyword}")
                        rate_result, _ = check_rate_limit_two_layer(policy_text, f"bugcrowd/{keyword}")
                        sh_result = check_safe_harbor_two_layer(policy_text, f"bugcrowd/{keyword}")
                        id_result = check_id_verification_two_layer(policy_text, f"bugcrowd/{keyword}")
                        ban_ok = ban_result[0] == "allowed"
                        rate_ok = rate_result is None or rate_result >= FLAT_RATE_LIMIT
                        sh_ok = sh_result[0] is True
                        id_flag = id_result[0]
                        id_ok = id_flag is not True
                        eligible = has_scope and is_public and ban_ok and rate_ok and sh_ok and id_ok
                        print(f"    [SCOPE] {len(scope_result['scope'])} in-scope, {len(scope_result.get('out_scope', []))} out-of-scope | participation={scope_result.get('participation')} | ban={ban_result[0]} | rate={rate_result} | safe_harbor={sh_result[0]} | id_verification={id_flag} | eligible={eligible}")
                        if id_flag is True:
                            print(f"    [EXCLUDED] ID verification requirement detected - {id_result[1]}")
                        elif id_flag == "review":
                            print(f"    [KEPT] ID verification unclear, no answer - keeping program, verify manually if you want")
                        if not eligible:
                            excluded_domains.extend(domains)
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
            print(f"[NO MATCH]  {platform}/{keyword} -> 0 programs found for {len(domains)} domain(s) - EXCLUDING (program may be removed/renamed)")
            no_match.append((platform, keyword, domains))
            excluded_domains.extend(domains)
            continue

        if len(matches) > 1:
            names = [m["name"] for m in matches]
            print(f"[AMBIGUOUS] {platform}/{keyword} -> {len(matches)} programs matched: {names} - EXCLUDING")
            ambiguous.append((platform, keyword, matches, domains))
            excluded_domains.extend(domains)
            continue

        m = matches[0]
        is_open = (m["status"].lower() == "open")

        if platform == "hackerone":
            is_bbp = m.get("offers_bounties") is True
            is_public = m.get("state") == "public_mode"
            if m.get("gold_standard_safe_harbor") is True:
                sh_ok = True
            else:
                sh_text = strip_html(m.get("policy") or "")
                sh_result = check_safe_harbor_two_layer(sh_text, f"hackerone/{keyword}")
                sh_ok = sh_result[0] is True
            eligible = is_open and is_bbp and is_public and sh_ok
            print(f"[{'OPEN  ' if is_open else 'BLOCKED'}]  {platform}/{keyword} -> '{m['name']}' status={m['status']} bbp={is_bbp} public={is_public} safe_harbor={sh_ok} eligible={eligible} ({len(domains)} domain(s))")
            print(f"    [NOTE] HackerOne API does not expose automated-tooling-allowed - covered by text-based check below")
            if not eligible:
                excluded_domains.extend(domains)
            else:
                scope_result = fetch_hackerone_scope(m["handle"], h1_token)
                if scope_result["error"]:
                    print(f"    [SCOPE ERROR] {scope_result['error']}")
                    excluded_domains.extend(domains)
                else:
                    ban_text = strip_html(scope_result.get("policy"))
                    ban_result = automation_ban_check(ban_text, f"hackerone/{keyword}")
                    rate_result, _ = check_rate_limit_two_layer(ban_text, f"hackerone/{keyword}")
                    id_result = check_id_verification_two_layer(ban_text, f"hackerone/{keyword}")
                    ban_ok = ban_result == "allowed"
                    rate_ok = rate_result is None or rate_result >= FLAT_RATE_LIMIT
                    id_ok = id_result[0] is not True
                    text_eligible = ban_ok and rate_ok and id_ok
                    print(f"    [BAN CHECK] automation_ban={ban_result} | rate={rate_result} | id_verification={id_result[0]} | text_eligible={text_eligible}")
                    if id_result[0] is True:
                        print(f"    [EXCLUDED] ID verification requirement detected - {id_result[1]}")
                    elif id_result[0] == "review":
                        print(f"    [KEPT-IF-ELSE-OK] ID verification unclear, no answer - not excluding on this alone")
                    if not text_eligible:
                        print(f"    [EXCLUDED] did not pass ban/rate/id text checks")
                        excluded_domains.extend(domains)
                    else:
                        for asset in scope_result["scope"]:
                            hackerone_scope_lines.append(asset)
                        for asset in scope_result.get("out_scope", []):
                            hackerone_out_lines.append(asset)
                    print(f"    [SCOPE] {len(scope_result['scope'])} in-scope, {len(scope_result.get('out_scope', []))} out-of-scope asset(s) found")

        elif platform == "intigriti":
            raw_type = (m.get("type") or "").lower()
            is_bbp = "bounty" in raw_type  # heuristic - VERIFY against printed raw values above
            print(f"[{'OPEN  ' if is_open else 'BLOCKED'}]  {platform}/{keyword} -> '{m['name']}' status={m['status']} raw_type='{m.get('type')}' bbp_guess={is_bbp} ({len(domains)} domain(s))")
            if not is_open or not is_bbp:
                excluded_domains.extend(domains)
                continue
            scope_result = fetch_intigriti_scope(m["id"], intigriti_token)
            if scope_result["error"]:
                print(f"    [SCOPE ERROR] {scope_result['error']}")
                excluded_domains.extend(domains)
                continue
            has_scope = len(scope_result["scope"]) > 0
            safe_harbor_ok = scope_result["safe_harbor"] is True
            rate_limit_val = scope_result["rate_limit"]
            if rate_limit_val is not None and not isinstance(rate_limit_val, (int, float)):
                fallback_text = strip_html(scope_result.get("roe_text") or scope_result.get("policy"))
                rate_limit_val, _ = check_rate_limit_two_layer(fallback_text, f"intigriti/{keyword}")
            automated_ok = rate_limit_val is None or rate_limit_val >= FLAT_RATE_LIMIT
            eligible = has_scope and safe_harbor_ok and automated_ok
            print(f"    [SCOPE] {len(scope_result['scope'])} in-scope, {len(scope_result.get('out_scope', []))} out-of-scope | safe_harbor={scope_result['safe_harbor']} | automated_tooling_rate={rate_limit_val} | eligible={eligible}")
            if rate_limit_val is None:
                print(f"    [KEPT-ON-RATE] No automatedTooling rate limit specified - not a blocker, we self-limit to {FLAT_RATE_LIMIT}rps regardless")
            elif rate_limit_val < FLAT_RATE_LIMIT:
                print(f"    [EXCLUDED] Program's automatedTooling rate ({rate_limit_val}) is stricter than our flat {FLAT_RATE_LIMIT} rps")
            print(f"    [NOTE] Intigriti API does not expose ID-verification-required - covered by text-based check below")
            if not eligible:
                excluded_domains.extend(domains)
            else:
                ban_text = strip_html(scope_result.get("roe_text") or scope_result.get("policy"))
                ban_result = automation_ban_check(ban_text, f"intigriti/{keyword}")
                id_result = check_id_verification_two_layer(ban_text, f"intigriti/{keyword}")
                ban_ok = ban_result == "allowed"
                id_ok = id_result[0] is not True
                text_eligible = ban_ok and id_ok
                print(f"    [BAN CHECK] automation_ban={ban_result} | id_verification={id_result[0]} | text_eligible={text_eligible}")
                if id_result[0] is True:
                    print(f"    [EXCLUDED] ID verification requirement detected - {id_result[1]}")
                elif id_result[0] == "review":
                    print(f"    [KEPT-IF-ELSE-OK] ID verification unclear, no answer - not excluding on this alone")
                if not text_eligible:
                    print(f"    [EXCLUDED] did not pass ban/id text checks")
                    excluded_domains.extend(domains)
                else:
                    for asset in scope_result["scope"]:
                        intigriti_scope_lines.append(asset)
                    for asset in scope_result.get("out_scope", []):
                        intigriti_out_lines.append(asset)

    print("=" * 70)
    print(f"\nSUMMARY: {len(excluded_domains)} domains would be EXCLUDED")
    for d in excluded_domains:
        print(f"    - {d}")
    print(f"\n  No API match found: {len(no_match)} groups")
    print(f"  Ambiguous matches: {len(ambiguous)} groups")

    # weekend-recon.yml builds exclude_grep.txt from this file as a suffix-match
    # regex (\.domain$|^domain$), not a wildcard-glob match. Strip a literal
    # "*." prefix here so a blocked/ineligible wildcard-scoped entry (e.g.
    # "*.etoro.com") actually excludes its real subdomains (api.etoro.com,
    # etc.) instead of only the literal "*.etoro.com" string, which never
    # appears in a live host list. Same fix as check_program_open.py.
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

    hackerone_scope_lines = sorted(set(hackerone_scope_lines))
    hackerone_out_lines = sorted(set(hackerone_out_lines))
    scope_output_path = os.environ.get("HACKERONE_SCOPE_OUTPUT_PATH") or os.path.join(HOME, "bug-bounty-hunter", "hackerone_scope.txt")
    scope_tmp_path = f"{scope_output_path}.tmp"
    with open(scope_tmp_path, "w") as f:
        for asset in hackerone_scope_lines:
            f.write(f"IN:{asset}\n")
        for asset in hackerone_out_lines:
            f.write(f"OUT:{asset}\n")
    os.replace(scope_tmp_path, scope_output_path)
    print(f"Wrote {len(hackerone_scope_lines)} in-scope + {len(hackerone_out_lines)} out-of-scope HackerOne assets to {scope_output_path}")

    intigriti_scope_lines = sorted(set(intigriti_scope_lines))
    intigriti_out_lines = sorted(set(intigriti_out_lines))
    intigriti_scope_output_path = os.environ.get("INTIGRITI_SCOPE_OUTPUT_PATH") or os.path.join(HOME, "bug-bounty-hunter", "intigriti_scope.txt")
    intigriti_tmp_path = f"{intigriti_scope_output_path}.tmp"
    with open(intigriti_tmp_path, "w") as f:
        for asset in intigriti_scope_lines:
            f.write(f"IN:{asset}\n")
        for asset in intigriti_out_lines:
            f.write(f"OUT:{asset}\n")
    os.replace(intigriti_tmp_path, intigriti_scope_output_path)
    print(f"Wrote {len(intigriti_scope_lines)} in-scope + {len(intigriti_out_lines)} out-of-scope Intigriti assets to {intigriti_scope_output_path}")

    yeswehack_scope_lines = sorted(set(yeswehack_scope_lines))
    yeswehack_out_lines = sorted(set(yeswehack_out_lines))
    yeswehack_scope_output_path = os.environ.get("YESWEHACK_SCOPE_OUTPUT_PATH") or os.path.join(HOME, "bug-bounty-hunter", "yeswehack_scope.txt")
    yeswehack_tmp_path = f"{yeswehack_scope_output_path}.tmp"
    with open(yeswehack_tmp_path, "w") as f:
        for asset in yeswehack_scope_lines:
            f.write(f"IN:{asset}\n")
        for asset in yeswehack_out_lines:
            f.write(f"OUT:{asset}\n")
    os.replace(yeswehack_tmp_path, yeswehack_scope_output_path)
    print(f"Wrote {len(yeswehack_scope_lines)} in-scope + {len(yeswehack_out_lines)} out-of-scope YesWeHack assets to {yeswehack_scope_output_path}")

    bugcrowd_scope_lines = sorted(set(bugcrowd_scope_lines))
    bugcrowd_out_lines = sorted(set(bugcrowd_out_lines))
    bugcrowd_scope_output_path = os.environ.get("BUGCROWD_SCOPE_OUTPUT_PATH") or os.path.join(HOME, "bug-bounty-hunter", "bugcrowd_scope.txt")
    bugcrowd_tmp_path = f"{bugcrowd_scope_output_path}.tmp"
    with open(bugcrowd_tmp_path, "w") as f:
        for asset in bugcrowd_scope_lines:
            f.write(f"IN:{asset}\n")
        for asset in bugcrowd_out_lines:
            f.write(f"OUT:{asset}\n")
    os.replace(bugcrowd_tmp_path, bugcrowd_scope_output_path)
    print(f"Wrote {len(bugcrowd_scope_lines)} in-scope + {len(bugcrowd_out_lines)} out-of-scope Bugcrowd assets to {bugcrowd_scope_output_path}")

if __name__ == "__main__":
    main()

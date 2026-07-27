#!/usr/bin/env python3
"""
validate_pipeline.py

Post-run sanity checks for the bug-bounty-hunter pipeline's domain/scope files.
Run this after discover_all_programs.py and before committing results.
Exits non-zero (fails the CI job) if any check fails.
"""
import os
import sys
import subprocess

try:
    import tldextract
except ImportError:
    print("ERROR: tldextract not installed. Run: pip install tldextract --break-system-packages")
    sys.exit(2)

MAX_REMOVAL_PCT = float(os.environ.get("VALIDATE_MAX_REMOVAL_PCT", "15"))
MAX_SKIP_RATE_PCT = float(os.environ.get("VALIDATE_MAX_SKIP_RATE_PCT", "15"))
MAX_EXCLUDED_RATE_PCT = float(os.environ.get("VALIDATE_MAX_EXCLUDED_RATE_PCT", "95"))

ROOT_DOMAIN_FILES = [
    os.environ.get("DOMAINS_TXT_PATH", "domains.txt"),
]

RAW_SCOPE_FILES = [
    "hackerone_scope.txt",
    "intigriti_scope.txt",
    "yeswehack_scope.txt",
    "bugcrowd_scope.txt",
]

BAD_CHARS = ("*", "[", "]")


def get_git_previous_version(path):
    directory = os.path.dirname(path) or "."
    filename = os.path.basename(path)
    try:
        result = subprocess.run(
            ["git", "-C", directory, "show", f"HEAD:{filename}"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return None
        return result.stdout
    except Exception:
        return None


def check_file(path, is_root_domain_file):
    problems = []

    if not os.path.exists(path):
        return False, ["file does not exist"]

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        raw_lines = f.read().splitlines()

    empty_count = sum(1 for l in raw_lines if l.strip() == "")
    if empty_count:
        problems.append(f"{empty_count} empty line(s) found")

    non_empty = [l for l in raw_lines if l.strip() != ""]

    seen = set()
    dupes = set()
    for l in non_empty:
        if l in seen:
            dupes.add(l)
        seen.add(l)
    if dupes:
        problems.append(f"{len(dupes)} duplicate line(s): {sorted(dupes)[:10]}")

    if is_root_domain_file:
        malformed = [l for l in non_empty if any(c in l for c in BAD_CHARS)]
        if malformed:
            problems.append(f"{len(malformed)} malformed entr(y/ies) with '*'/'['/']': {malformed[:10]}")

        bad_domains = []
        for l in non_empty:
            if any(c in l for c in BAD_CHARS):
                continue
            candidate = l.strip().lower()
            candidate = candidate.replace("https://", "").replace("http://", "")
            candidate = candidate.split("/")[0].split(":")[0]
            ext = tldextract.extract(candidate)
            if not ext.domain or not ext.suffix:
                bad_domains.append(l)
        if bad_domains:
            problems.append(f"{len(bad_domains)} entr(y/ies) failing tldextract sanity check: {bad_domains[:10]}")

    prev_content = get_git_previous_version(path)
    if prev_content is not None:
        prev_lines = set(l for l in prev_content.splitlines() if l.strip() != "")
        curr_lines = set(non_empty)
        if prev_lines:
            removed = prev_lines - curr_lines
            removal_pct = (len(removed) / len(prev_lines)) * 100
            if removal_pct > MAX_REMOVAL_PCT:
                problems.append(
                    f"removal guard tripped: {len(removed)}/{len(prev_lines)} "
                    f"({removal_pct:.1f}%) lines removed vs last commit, "
                    f"exceeds MAX_REMOVAL_PCT={MAX_REMOVAL_PCT}%"
                )

    return (len(problems) == 0), problems


def check_skip_rate(csv_path="discovery_stats.csv"):
    problems = []
    if not os.path.exists(csv_path):
        return False, [f"{csv_path} does not exist - cannot verify run health, failing closed"]
    import csv
    latest = {}
    with open(csv_path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            latest[row["platform"]] = row
    if not latest:
        return False, [f"{csv_path} has no data rows - cannot verify run health, failing closed"]
    ok = True
    for platform, row in latest.items():
        try:
            total = int(row["total_discovered"])
            skipped = int(row["skipped"])
            included = int(row["included"])
            excluded = int(row["excluded"])
        except (KeyError, ValueError):
            problems.append(f"{platform}: missing/non-numeric total_discovered, included, excluded, or skipped column")
            ok = False
            continue
        if total == 0:
            problems.append(f"{platform}: total_discovered is 0 - discovery may have failed silently")
            ok = False
            continue
        skip_pct = (skipped / total) * 100
        if skip_pct > MAX_SKIP_RATE_PCT:
            problems.append(f"{platform}: skip rate {skip_pct:.1f}% ({skipped}/{total}) exceeds {MAX_SKIP_RATE_PCT}% threshold")
            ok = False
        excluded_pct = (excluded / total) * 100
        if excluded_pct > MAX_EXCLUDED_RATE_PCT:
            problems.append(f"{platform}: excluded rate {excluded_pct:.1f}% ({excluded}/{total}) exceeds {MAX_EXCLUDED_RATE_PCT}% threshold - possible systemic failure (auth, quota, broken check)")
            ok = False
        if included == 0:
            problems.append(f"{platform}: included count is 0 out of {total} discovered - possible systemic failure")
            ok = False
    return ok, problems


def main():
    overall_ok = True
    print("=== Pipeline validation ===")
    for path in ROOT_DOMAIN_FILES:
        ok, problems = check_file(path, is_root_domain_file=True)
        status = "OK" if ok else "FAIL"
        print(f"[{status}] {path}")
        for p in problems:
            print(f"    - {p}")
        if not ok:
            overall_ok = False
    for path in RAW_SCOPE_FILES:
        ok, problems = check_file(path, is_root_domain_file=False)
        status = "OK" if ok else "FAIL"
        print(f"[{status}] {path}")
        for p in problems:
            print(f"    - {p}")
        if not ok:
            overall_ok = False
    ok, problems = check_skip_rate()
    status = "OK" if ok else "FAIL"
    print(f"[{status}] discovery_stats.csv skip-rate check")
    for p in problems:
        print(f"    - {p}")
    if not ok:
        overall_ok = False
    print("===========================")
    if not overall_ok:
        print("VALIDATION FAILED — see problems above. Nothing should be committed.")
        sys.exit(1)
    print("VALIDATION PASSED")
    sys.exit(0)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
filter_to_scope.py
Filters a host list down to only hosts that match at least one declared
in-scope asset pattern from the 4 platform scope files (hackerone_scope.txt,
intigriti_scope.txt, yeswehack_scope.txt, bugcrowd_scope.txt).

This prevents scanning subdomains that recon discovered but that aren't
actually declared in-scope by the program - a real gap: exclusion filtering
(paused/banned programs) already existed, but positive scope-matching did not.
"""
import os
import re
import sys

INPUT_PATH = os.environ.get("SCOPE_FILTER_INPUT", "input.txt")
OUTPUT_PATH = os.environ.get("SCOPE_FILTER_OUTPUT", "input.txt")
SCOPE_FILES = [
    os.environ.get("HACKERONE_SCOPE_OUTPUT_PATH", "hackerone_scope.txt"),
    os.environ.get("INTIGRITI_SCOPE_OUTPUT_PATH", "intigriti_scope.txt"),
    os.environ.get("YESWEHACK_SCOPE_OUTPUT_PATH", "yeswehack_scope.txt"),
    os.environ.get("BUGCROWD_SCOPE_OUTPUT_PATH", "bugcrowd_scope.txt"),
    os.environ.get("HACKENPROOF_SCOPE_OUTPUT_PATH", "hackenproof_scope.txt"),
]


def pattern_to_regex(pattern):
    # Strip a scheme prefix from the raw scope entry itself, matching what
    # bare_host() does to the host being tested - otherwise IN: entries
    # like "https://portal.3cx.com" can never match anything.
    pattern = re.sub(r"^https?://", "", pattern, flags=re.IGNORECASE)
    escaped = re.escape(pattern)
    escaped = escaped.replace(r"\*", ".*")
    return re.compile(f"^{escaped}$", re.IGNORECASE)


def load_patterns():
    in_patterns = []
    out_patterns = []
    for path in SCOPE_FILES:
        if not os.path.exists(path):
            continue
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if line.startswith("IN:"):
                    rest = line[3:]
                    if rest:
                        in_patterns.append(pattern_to_regex(rest))
                elif line.startswith("OUT:"):
                    rest = line[4:]
                    if rest:
                        out_patterns.append(pattern_to_regex(rest))
    return in_patterns, out_patterns


def bare_host(host):
    h = host.replace("https://", "").replace("http://", "")
    return h.split("/")[0].split(":")[0]


def main():
    if not os.path.exists(INPUT_PATH):
        print(f"[SCOPE FILTER] {INPUT_PATH} not found, nothing to filter")
        return

    in_patterns, out_patterns = load_patterns()
    if not in_patterns:
        print("[SCOPE FILTER] ERROR: No IN scope patterns loaded (scope files missing/empty) - refusing to filter. Aborting without writing.")
        sys.exit(1)

    with open(INPUT_PATH) as f:
        hosts = [h.strip() for h in f if h.strip()]

    kept = []
    dropped_not_in_scope = 0
    dropped_out_scope = 0
    for host in hosts:
        h = bare_host(host)
        if not any(p.match(h) for p in in_patterns):
            dropped_not_in_scope += 1
            continue
        if any(p.match(h) for p in out_patterns):
            dropped_out_scope += 1
            continue
        kept.append(host)

    tmp_path = f"{OUTPUT_PATH}.tmp"
    with open(tmp_path, "w") as f:
        for h in kept:
            f.write(h + "\n")
    os.replace(tmp_path, OUTPUT_PATH)

    print(f"[SCOPE FILTER] {len(hosts)} hosts checked, {len(kept)} kept, "
          f"{dropped_not_in_scope} dropped (not in declared scope), "
          f"{dropped_out_scope} dropped (explicit OUT-of-scope match)")


if __name__ == "__main__":
    main()

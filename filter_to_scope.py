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

INPUT_PATH = os.environ.get("SCOPE_FILTER_INPUT", "input.txt")
OUTPUT_PATH = os.environ.get("SCOPE_FILTER_OUTPUT", "input.txt")
SCOPE_FILES = [
    os.environ.get("HACKERONE_SCOPE_OUTPUT_PATH", "hackerone_scope.txt"),
    os.environ.get("INTIGRITI_SCOPE_OUTPUT_PATH", "intigriti_scope.txt"),
    os.environ.get("YESWEHACK_SCOPE_OUTPUT_PATH", "yeswehack_scope.txt"),
    os.environ.get("BUGCROWD_SCOPE_OUTPUT_PATH", "bugcrowd_scope.txt"),
]


def pattern_to_regex(pattern):
    escaped = re.escape(pattern)
    escaped = escaped.replace(r"\*", ".*")
    return re.compile(f"^{escaped}$", re.IGNORECASE)


def load_patterns():
    patterns = []
    for path in SCOPE_FILES:
        if not os.path.exists(path):
            continue
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if line.startswith("IN:"):
                    line = line[3:]
                if not line:
                    continue
                patterns.append(pattern_to_regex(line))
    return patterns


def bare_host(host):
    h = host.replace("https://", "").replace("http://", "")
    return h.split("/")[0].split(":")[0]


def main():
    if not os.path.exists(INPUT_PATH):
        print(f"[SCOPE FILTER] {INPUT_PATH} not found, nothing to filter")
        return

    patterns = load_patterns()
    if not patterns:
        print("[SCOPE FILTER] No scope patterns loaded (scope files missing/empty) - failing closed, writing empty output")
        tmp_path = f"{OUTPUT_PATH}.tmp"
        with open(tmp_path, "w") as f:
            pass
        os.replace(tmp_path, OUTPUT_PATH)
        return

    with open(INPUT_PATH) as f:
        hosts = [h.strip() for h in f if h.strip()]

    kept = []
    dropped = 0
    for host in hosts:
        h = bare_host(host)
        if any(p.match(h) for p in patterns):
            kept.append(host)
        else:
            dropped += 1

    tmp_path = f"{OUTPUT_PATH}.tmp"
    with open(tmp_path, "w") as f:
        for h in kept:
            f.write(h + "\n")
    os.replace(tmp_path, OUTPUT_PATH)

    print(f"[SCOPE FILTER] {len(hosts)} hosts checked, {len(kept)} kept, {dropped} dropped (not in declared scope)")


if __name__ == "__main__":
    main()

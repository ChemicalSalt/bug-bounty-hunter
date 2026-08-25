import os
import csv
import re
import sys
import tldextract

MAPPING_PATH = "domain_program_map.csv"
SCOPE_FILES = [
    "hackerone_scope.txt",
    "intigriti_scope.txt",
    "yeswehack_scope.txt",
    "bugcrowd_scope.txt",
    "hackenproof_scope.txt",
]
FILES_TO_FILTER = [
    "live_hosts.txt",
    "live_hosts_403.txt",
    "live_hosts_404.txt",
    "live_hosts_405.txt",
    "live_hosts_500.txt",
    "new_live_hosts.txt",
]

def root_of(value):
    # Strip leading wildcard glob chars (e.g. "*tidalhi.fi" or "*.tidalhi.fi")
    # before handing to tldextract, which doesn't understand "*" as a glob
    # and would otherwise fold it into the domain name (e.g. domain="*tidalhi").
    value = re.sub(r"^\*\.?", "", value)
    ext = tldextract.extract(value)
    if not ext.domain or not ext.suffix:
        return None
    return f"{ext.domain}.{ext.suffix}"

def load_scoped_roots(path):
    scoped = set()
    try:
        with open(path) as f:
            for row in csv.DictReader(f):
                r = root_of(row.get("domain", ""))
                if r:
                    scoped.add(r)
    except FileNotFoundError:
        pass
    return scoped

def glob_to_regex(pattern):
    # Convert a scope glob pattern (e.g. "*.3cx.com") into an anchored,
    # case-insensitive regex. "*" -> ".*", everything else literal.
    import re as _re
    parts = pattern.split("*")
    escaped = ".*".join(_re.escape(p) for p in parts)
    return f"^{escaped}$"

def load_out_of_scope_pattern():
    patterns = []
    files_found = 0
    for path in SCOPE_FILES:
        try:
            with open(path) as f:
                files_found += 1
                for line in f:
                    line = line.strip()
                    if line.startswith("OUT:"):
                        raw = line[len("OUT:"):].strip()
                        if raw:
                            patterns.append(glob_to_regex(raw))
        except FileNotFoundError:
            continue
    if files_found == 0:
        print(f"[FILTER] ERROR: 0 of {len(SCOPE_FILES)} scope files found ({SCOPE_FILES}) — "
              f"cannot verify OUT-of-scope patterns, refusing to filter. Aborting without writing.")
        sys.exit(1)
    if not patterns:
        return None
    return re.compile("|".join(patterns), re.I)

def main():
    scoped_roots = load_scoped_roots(MAPPING_PATH)
    print(f"[FILTER] Loaded {len(scoped_roots)} scoped root domains from {MAPPING_PATH}")
    if not scoped_roots:
        print(f"[FILTER] ERROR: 0 scoped root domains loaded from {MAPPING_PATH} — "
              f"refusing to filter (would wipe all host files). Aborting without writing.")
        sys.exit(1)
    out_pattern = load_out_of_scope_pattern()
    out_count = out_pattern.pattern.count("|") + 1 if out_pattern else 0
    print(f"[FILTER] Loaded {out_count} OUT-of-scope patterns from scope files")
    for fname in FILES_TO_FILTER:
        try:
            with open(fname) as f:
                hosts = [h.strip() for h in f if h.strip()]
        except FileNotFoundError:
            continue
        kept = []
        dropped_no_root = 0
        dropped_out_scope = 0
        for h in hosts:
            if root_of(h) not in scoped_roots:
                dropped_no_root += 1
                continue
            if out_pattern and out_pattern.search(h):
                dropped_out_scope += 1
                continue
            kept.append(h)
        tmp_fname = f"{fname}.tmp"
        with open(tmp_fname, "w") as f:
            f.write("\n".join(kept) + ("\n" if kept else ""))
        os.replace(tmp_fname, fname)
        print(f"[FILTER] {fname}: kept {len(kept)}, dropped {dropped_no_root} (no scope match), "
              f"dropped {dropped_out_scope} (explicit OUT-of-scope match)")

if __name__ == "__main__":
    main()

import os
import csv
import re
import sys
import tldextract

MAPPING_PATH = "domain_program_map.csv"
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

def main():
    scoped_roots = load_scoped_roots(MAPPING_PATH)
    print(f"[FILTER] Loaded {len(scoped_roots)} scoped root domains from {MAPPING_PATH}")
    if not scoped_roots:
        print(f"[FILTER] ERROR: 0 scoped root domains loaded from {MAPPING_PATH} — "
              f"refusing to filter (would wipe all host files). Aborting without writing.")
        sys.exit(1)
    for fname in FILES_TO_FILTER:
        try:
            with open(fname) as f:
                hosts = [h.strip() for h in f if h.strip()]
        except FileNotFoundError:
            continue
        kept = [h for h in hosts if root_of(h) in scoped_roots]
        dropped = len(hosts) - len(kept)
        tmp_fname = f"{fname}.tmp"
        with open(tmp_fname, "w") as f:
            f.write("\n".join(kept) + ("\n" if kept else ""))
        os.replace(tmp_fname, fname)
        print(f"[FILTER] {fname}: kept {len(kept)}, dropped {dropped} (no scope match)")

if __name__ == "__main__":
    main()

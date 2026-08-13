#!/usr/bin/env python3
"""
Dedup httpx_full.txt by (root_domain, response_hash) to collapse
wildcard-gateway noise before combined.txt is built. Requires each
line to carry an httpx -hash sha256 bracket, e.g. "... [abc123...]".
"""
import re
import tldextract

HASH_RE = re.compile(r"\[([a-f0-9]{64})\]\s*$")


def main():
    seen = set()
    out = []
    with open("httpx_full.txt") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            url = line.split()[0]
            m = HASH_RE.search(line)
            h = m.group(1) if m else None
            host = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0]
            root = tldextract.extract(host).registered_domain or host
            key = (root, h)
            if h and key in seen:
                continue
            if h:
                seen.add(key)
            out.append(line)
    with open("httpx_full.txt", "w") as f:
        f.write("\n".join(out) + "\n")
    print(f"After wildcard dedup: {len(out)}")


if __name__ == "__main__":
    main()

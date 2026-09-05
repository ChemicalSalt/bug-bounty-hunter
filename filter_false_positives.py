#!/usr/bin/env python3
"""
Generic false-positive filter for nuclei JSON export (-je) output.
Drops findings whose extracted value is actually nested under a
known non-secret JSON key (csrf, nonce, xsrf, state, session, etc)
in the raw response body - regardless of which template found it.
Works for any current or future template without per-template patches.
"""
import sys
import json
import re

NOISE_KEYS = [
    "csrf", "_csrf", "xsrf", "x-csrf", "nonce", "state",
    "sessionid", "session_id", "requestid", "request_id",
]

def value_is_noise(value: str, response: str) -> bool:
    """Check if `value` in `response` sits directly under a noise key."""
    esc = re.escape(value)
    for key in NOISE_KEYS:
        # matches: "csrf":{"token":"VALUE"  or  "csrf_token":"VALUE"
        pattern = rf'"{re.escape(key)}[^"]*"\s*:\s*(\{{[^}}]*)?"[^"]*"\s*:\s*"{esc}"'
        if re.search(pattern, response, re.IGNORECASE):
            return True
        # also catch: "csrfToken":"VALUE" directly
        pattern2 = rf'"[a-zA-Z_]*{re.escape(key)}[a-zA-Z_]*"\s*:\s*"{esc}"'
        if re.search(pattern2, response, re.IGNORECASE):
            return True
    return False

def main():
    if len(sys.argv) != 3:
        print("usage: filter_false_positives.py <in.json> <out.txt>", file=sys.stderr)
        sys.exit(1)

    src, dst = sys.argv[1], sys.argv[2]
    with open(src) as f:
        data = json.load(f)

    kept, dropped = 0, 0
    with open(dst, "w") as out:
        for entry in data:
            response = entry.get("response", "")
            extracted = entry.get("extracted-results", []) or []
            values = []
            for e in extracted:
                m = re.search(r':\s*"([^"]+)"\s*$', e)
                values.append(m.group(1) if m else e)

            is_fp = any(value_is_noise(v, response) for v in values)
            if is_fp:
                dropped += 1
                continue

            template = entry.get("template-id", "")
            sev = entry.get("info", {}).get("severity", "")
            url = entry.get("matched-at", entry.get("url", ""))
            out.write(f"[{template}] [http] [{sev}] {url} {extracted}\n")
            kept += 1

    print(f"[filter_false_positives] kept={kept} dropped={dropped}")

if __name__ == "__main__":
    main()

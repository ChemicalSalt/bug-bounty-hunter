import os
import json
import re

MAX_LEN = 3000


def load_findings(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return []


def extract_url(line):
    m = re.search(r"(https?://\S+)", line)
    return m.group(1) if m else None


def main():
    findings = load_findings("nuclei_findings.json")
    by_url = {}
    for entry in findings:
        url = entry.get("matched-at") or entry.get("host") or entry.get("url")
        if url:
            by_url.setdefault(url, []).append(entry)

    with open("new_results.txt") as f:
        lines = [l.rstrip("\n") for l in f if l.strip()]

    out = []
    for line in lines:
        out.append(line)
        url = extract_url(line)
        matched = by_url.get(url) if url else None
        if matched:
            entry = matched[0]
            req = (entry.get("request") or "").strip()[:MAX_LEN]
            resp = (entry.get("response") or "").strip()[:MAX_LEN]
            out.append("--- REQUEST ---")
            out.append(req if req else "[not captured]")
            out.append("--- RESPONSE (truncated) ---")
            out.append(resp if resp else "[not captured]")
        else:
            out.append("[raw request/response unavailable for this match]")
        out.append("")

    tmp_path = "new_results_detailed.txt.tmp"
    with open(tmp_path, "w") as f:
        f.write("\n".join(out))
    os.replace(tmp_path, "new_results_detailed.txt")


if __name__ == "__main__":
    main()

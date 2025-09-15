import re

def detect_suspicious(queries):
    findings = []

    for q in queries:
        reasons = []
        # Long domain check
        if q["length"] > 50:
            reasons.append("Long domain (>50 chars)")

        # Base64-like pattern
        if re.match(r"^[A-Za-z0-9+/=]{20,}$", q["qname"].replace(".", "")):
            reasons.append("Base64-like domain")

        # TXT record
        if q["is_txt"]:
            reasons.append("TXT record (possible data exfil)")

        if reasons:
            findings.append({**q, "reasons": reasons})

    return findings

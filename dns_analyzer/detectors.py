import re
import math

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

        # Shannon entropy check
        entropy_score = shannon_entropy(q["qname"].replace(".", ""))
        if entropy_score > 4.0:  # threshold can be tuned
            reasons.append(f"High entropy domain (entropy={entropy_score:.2f})")

        if reasons:
            findings.append({**q, "reasons": reasons})

    return findings


def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0
    probabilities = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probabilities)

import sys, os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from dns_analyzer.parser import parse_pcap
from dns_analyzer.detectors import detect_suspicious, detect_frequency
import json

def main():
    if len(sys.argv) != 2:
        print("Usage: python -m scripts.analyze_pcap <pcap_file>")
        return

    file_path = sys.argv[1]
    queries = parse_pcap(file_path)

    # Suspicious domains
    findings = detect_suspicious(queries)

    # Frequency anomalies
    freq_findings = detect_frequency(queries, threshold=50)

    print("\n=== DNS Analyzer Report ===")
    for f in findings:
        print(f"[{f['src']}] -> {f['qname']}")
        for r in f["reasons"]:
            print(f"   Reason: {r}")

    if freq_findings:
        print("\n=== Frequency Alerts ===")
        for f in freq_findings:
            print(f"[{f['src']}] -> {f['reason']}")

    # Save JSON report
    os.makedirs("reports", exist_ok=True)
    out_path = os.path.join("reports", os.path.basename(file_path) + ".json")
    report = {
        "suspicious": findings,
        "frequency": freq_findings
    }
    with open(out_path, "w") as f:
        json.dump(report, f, indent=4)

    print(f"\n[+] Report saved to {out_path}")

if __name__ == "__main__":
    main()



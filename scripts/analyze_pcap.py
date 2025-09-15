import sys, os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from dns_analyzer.parser import parse_pcap
from dns_analyzer.detectors import detect_suspicious
import json

def main():
    if len(sys.argv) != 2:
        print("Usage: python -m scripts.analyze_pcap <pcap_file>")
        return

    file_path = sys.argv[1]
    queries = parse_pcap(file_path)
    findings = detect_suspicious(queries)

    print("\n=== DNS Analyzer Report ===")
    for f in findings:
        print(f"[{f['src']}] -> {f['qname']}")
        for r in f["reasons"]:
            print(f"   Reason: {r}")

    # Save JSON report
    os.makedirs("reports", exist_ok=True)
    out_path = os.path.join("reports", os.path.basename(file_path) + ".json")
    with open(out_path, "w") as f:
        json.dump(findings, f, indent=4)
    print(f"\n[+] Report saved to {out_path}")

if __name__ == "__main__":
    main()

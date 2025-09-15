# DNS Analyzer  
![GitHub release (latest by date)](https://img.shields.io/github/v/release/ClearLotus-git/dns-analyzer)  
![GitHub last commit](https://img.shields.io/github/last-commit/ClearLotus-git/dns-analyzer)  
![GitHub repo size](https://img.shields.io/github/repo-size/ClearLotus-git/dns-analyzer)  

A lightweight Python tool to analyze DNS traffic from PCAP files and detect suspicious behavior often associated with:  

-  **DNS tunneling**  
-  **DGA (Domain Generation Algorithm) domains**  
-  **Data exfiltration over TXT records**  

The tool outputs clear findings in both **terminal** and **JSON reports** for further analysis.  

---

##  Features (v0.1.0)
-  Parse DNS queries from PCAP files  
-  Detect **long domains** (>50 characters)  
-  Detect **base64-like encoded domains**  
-  Detect **TXT record queries** (possible exfil)  
-  Save results into structured JSON reports  
-  Includes a **fake DNS PCAP generator** for safe testing  

---

##  Installation
Clone the repo and install requirements:
```bash
git clone https://github.com/ClearLotus-git/dns-analyzer.git
cd dns-analyzer
pip install -r requirements.txt
```
## Usage

```
python -m scripts.analyze_pcap examples/fake_suspicious_dns.pcap
```

## Example Output

```
=== DNS Analyzer Report ===
[192.168.0.1] -> aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.evil.com
   Reason: Long domain (>50 chars)
[192.168.0.1] -> QWxhZGRpbjpvcGVuIHNlc2FtZQ==.evil.com
   Reason: Base64-like domain
[192.168.0.1] -> exfil.evil.com
   Reason: TXT record (possible data exfil)

[+] Report saved to reports/fake_suspicious_dns.pcap.json

```

## Generate a Fake Suspicious PCAP

```
python make_fake_dns_pcap.py

```

## Project Structure

```
dns-analyzer/
├── dns_analyzer/          # Core detection logic
│   ├── detectors.py       # Suspicious domain detection rules
│   └── parser.py          # PCAP parsing with Scapy
├── scripts/               # CLI scripts
│   ├── analyze_pcap.py    # Main analyzer script
├── examples/              # Example PCAPs (real + fake)
├── reports/               # JSON reports generated
├── make_fake_dns_pcap.py  # Fake PCAP generator
└── requirements.txt

```

## Roadmap (v.0.2.0+)

-Add entropy/DGA detection (flag algorithmic domains)
- Add entropy/DGA detection (flag algorithmic domains)
- Detect query frequency anomalies (possible tunneling)
- Support live packet capture mode
- Integrate threat intel lookups (VirusTotal, AbuseIPDB, ThreatFox)
- Export to graph visualization (networkx + Graphviz)

















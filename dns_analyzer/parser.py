from scapy.all import rdpcap, DNS, DNSQR
import re

def parse_pcap(file_path):
    packets = rdpcap(file_path)
    queries = []

    for pkt in packets:
        if pkt.haslayer(DNS) and pkt.getlayer(DNS).qd is not None:
            qname = pkt[DNSQR].qname.decode(errors="ignore").strip(".")
            queries.append({
                "src": pkt[0][1].src if hasattr(pkt[0][1], "src") else "unknown",
                "qname": qname,
                "length": len(qname),
                "is_txt": (pkt[DNSQR].qtype == 16),  # TXT record
            })

    return queries

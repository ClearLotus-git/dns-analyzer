from scapy.all import IP, UDP, DNS, DNSQR, wrpcap

packets = []

# Normal queries (already in your file)
packets.append(IP(dst="8.8.8.8", src="192.168.1.10")/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname="normal.com")))

# Suspicious domains (already in your file)
packets.append(IP(dst="8.8.8.8", src="192.168.1.11")/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.evil.com")))
packets.append(IP(dst="8.8.8.8", src="192.168.1.12")/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname="QWxhZGRpbjpvcGVuIHNlc2FtZQ==.evil.com")))
packets.append(IP(dst="8.8.8.8", src="192.168.1.13")/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname="exfil.evil.com")))

# Noisy host: simulate tunneling with 100 queries
for i in range(100):
    packets.append(
        IP(dst="8.8.8.8", src="192.168.1.99")/
        UDP(dport=53)/
        DNS(rd=1,qd=DNSQR(qname=f"data{i}.tunnel.com"))
    )

# Save the PCAP
wrpcap("examples/fake_suspicious_dns.pcap", packets)
print("[+] Fake suspicious PCAP created at examples/fake_suspicious_dns.pcap")


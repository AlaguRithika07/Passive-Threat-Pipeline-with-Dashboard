import os
from scapy.all import IP, TCP, UDP, DNS, DNSQR, wrpcap

def generate_synthetic_pcap(output_path="data/sample.pcap"):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    packets = []

    print("Generating synthetic packets...")

    # 1. Normal HTTP/DNS Traffic
    for i in range(50):
        packets.append(IP(src="192.168.1.10", dst="10.0.0.1")/TCP(sport=1024+i, dport=80, flags="A"))
        packets.append(IP(src="192.168.1.10", dst="8.8.8.8")/UDP(sport=53000+i, dport=53)/DNS(qd=DNSQR(qname="google.com")))

    # 2. SYN Flood DDoS Attack
    for i in range(150):
        packets.append(IP(src="10.99.99.99", dst="10.0.0.1")/TCP(sport=2000+i, dport=80, flags="S"))

    # 3. DNS Tunnelling Attack
    for i in range(20):
        long_query = f"exfil-data-{i}-" + "a" * 50 + ".malicious-domain.com"
        packets.append(IP(src="192.168.1.88", dst="8.8.8.8")/UDP(sport=54000+i, dport=53)/DNS(qd=DNSQR(qname=long_query)))

    # 4. Reconnaissance Port Scan
    for port in range(20, 100):
        packets.append(IP(src="172.16.0.50", dst="10.0.0.2")/TCP(sport=40000, dport=port, flags="S"))

    wrpcap(output_path, packets)
    print(f"Successfully generated sample PCAP with {len(packets)} packets at: {output_path}")

if __name__ == "__main__":
    generate_synthetic_pcap()
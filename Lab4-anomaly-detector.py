from scapy.all import rdpcap, IP, TCP, UDP
from collections import defaultdict

packets = rdpcap("botnet-capture-20110812-rbot.pcap")

ip_timestamps = defaultdict(list)
suspicious_ips = set()
tcp_count = 0
udp_count = 0

for pkt in packets:
    if IP in pkt:
        src_ip = pkt[IP].src
        timestamp = pkt.time

        if TCP in pkt: tcp_count += 1
        elif UDP in pkt: udp_count += 1

        ip_timestamps[src_ip].append(timestamp)
        ip_timestamps[src_ip] = [t for t in ip_timestamps[src_ip] if timestamp - t <= 5]

        if len(ip_timestamps[src_ip]) > 20 and src_ip not in suspicious_ips:
            print(f"ALERT: Flooding detected from {src_ip}")
            suspicious_ips.add(src_ip)

print("-" * 30)
print(f"Total TCP Packets: {tcp_count}")
print(f"Total UDP Packets: {udp_count}")
print(f"Suspicious IPs Detected: {len(suspicious_ips)}")
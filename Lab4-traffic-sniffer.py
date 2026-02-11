from scapy.all import sniff, IP

stats = {"TCP": 0, "UDP": 0, "Other": 0}

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        
        proto_name = "Other"
        if proto == 6: 
            proto_name = "TCP"
            stats["TCP"] += 1
        elif proto == 17: 
            proto_name = "UDP"
            stats["UDP"] += 1
        else:
            stats["Other"] += 1
            
        print(f"SRC: {src_ip} -> DST: {dst_ip} | Protocol: {proto_name}")

print("Starting live capture (50 packets)...")
sniff(count=50, prn=packet_callback)

print("\n--- Summary ---")
for p, count in stats.items():
    print(f"{p} Packets: {count}")
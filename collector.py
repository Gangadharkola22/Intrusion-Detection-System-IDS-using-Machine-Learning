from scapy.all import sniff, IP, TCP, ICMP
import csv
import os
import time

output_file = "attack_data.csv"
fields = ['timestamp', 'src_ip', 'dst_ip', 'protocol', 'sport', 'dport', 'flags', 'packet_len', 'label']

# Write headers only if file doesn't exist
if not os.path.exists(output_file):
    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(fields)

def packet_callback(packet):
    timestamp = time.time()
    src_ip = packet[IP].src if packet.haslayer(IP) else ''
    dst_ip = packet[IP].dst if packet.haslayer(IP) else ''
    protocol = 'TCP' if packet.haslayer(TCP) else 'ICMP' if packet.haslayer(ICMP) else 'OTHER'
    sport = packet[TCP].sport if packet.haslayer(TCP) else 0
    dport = packet[TCP].dport if packet.haslayer(TCP) else 0
    flags = str(packet[TCP].flags) if packet.haslayer(TCP) else ''
    pkt_len = len(packet)

    label = ''
    while label not in ['normal', 'scan', 'dos']:
        label = input(f"[+] Packet captured from {src_ip} to {dst_ip}. Enter label (normal / scan / dos): ").strip()

    with open(output_file, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, src_ip, dst_ip, protocol, sport, dport, flags, pkt_len, label])

print("[*] Starting packet capture. Press CTRL+C to stop.")
sniff(filter="ip", prn=packet_callback, store=False)

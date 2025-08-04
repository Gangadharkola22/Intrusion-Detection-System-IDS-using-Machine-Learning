from scapy.all import sniff, IP
import csv
import time

output_file = "data/normal.csv"

def packet_to_row(pkt):
    if IP in pkt:
        return [time.time(), pkt[IP].src, pkt[IP].dst, pkt.proto, 0, 0, '', len(pkt), 'normal']
    return None

with open(output_file, 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(["timestamp", "src_ip", "dst_ip", "protocol", "sport", "dport", "flags", "packet_len", "label"])
    
    def process(pkt):
        row = packet_to_row(pkt)
        if row:
            writer.writerow(row)
            print(row)

    sniff(filter="icmp", prn=process, store=0, count=50)

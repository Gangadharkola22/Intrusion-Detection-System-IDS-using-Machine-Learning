from scapy.all import sniff, IP, TCP
import csv
import time

output_file = "data/dos.csv"

def packet_to_row(pkt):
    if IP in pkt:
        sport = pkt[TCP].sport if TCP in pkt else 0
        dport = pkt[TCP].dport if TCP in pkt else 0
        flags = str(pkt[TCP].flags) if TCP in pkt else ''
        return [time.time(), pkt[IP].src, pkt[IP].dst, pkt.proto, sport, dport, flags, len(pkt), 'dos']
    return None

with open(output_file, 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(["timestamp", "src_ip", "dst_ip", "protocol", "sport", "dport", "flags", "packet_len", "label"])
    
    def process(pkt):
        row = packet_to_row(pkt)
        if row:
            writer.writerow(row)
            print(row)

    sniff(filter="tcp", prn=process, store=0, count=500)

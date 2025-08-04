from scapy.all import sniff, IP, TCP, ICMP
import joblib
import time

# Load model and encoders
model = joblib.load("model/ids_model.pkl")
proto_encoder = joblib.load("model/protocol_encoder.pkl")
label_encoder = joblib.load("model/label_encoder.pkl")

def packet_to_features(pkt):
    if IP not in pkt:
        return None

    proto = pkt.proto
    sport = pkt[TCP].sport if TCP in pkt else 0
    dport = pkt[TCP].dport if TCP in pkt else 0
    pkt_len = len(pkt)

    try:
        proto_str = str(proto)
        proto_encoded = proto_encoder.transform([proto_str])[0]
    except:
        return None

    return [proto_encoded, sport, dport, pkt_len]

def process_packet(pkt):
    features = packet_to_features(pkt)
    if features:
        prediction = model.predict([features])[0]
        label = label_encoder.inverse_transform([prediction])[0]
        print(f"[{time.strftime('%H:%M:%S')}] 🚨 Packet detected: {label}")

print("[✔] Real-time IDS started. Listening for packets...\n")
sniff(prn=process_packet, store=0)

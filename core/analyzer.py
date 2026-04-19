from scapy.all import IP, TCP, UDP

def analyze(pkt):
    if not pkt.haslayer(IP):
        return None

    data = {
        "src": pkt[IP].src,
        "dst": pkt[IP].dst,
        "protocol": "OTHER",
        "port": None,
        "payload": ""
    }

    if pkt.haslayer(TCP):
        data["protocol"] = "TCP"
        data["port"] = pkt[TCP].dport
        payload_raw = bytes(pkt[TCP].payload)
        data["payload"] = str(payload_raw[:50]) if payload_raw else ""

    elif pkt.haslayer(UDP):
        data["protocol"] = "UDP"
        data["port"] = pkt[UDP].dport
        payload_raw = bytes(pkt[UDP].payload)
        data["payload"] = str(payload_raw[:50]) if payload_raw else ""

    return data
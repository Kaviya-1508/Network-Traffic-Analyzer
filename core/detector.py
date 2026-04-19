from collections import defaultdict
import time

ip_count = defaultdict(int)
port_map = defaultdict(set)
last_seen = defaultdict(float)

DOS_THRESHOLD = 30
PORT_SCAN_THRESHOLD = 10
TIME_WINDOW = 10

SUSPICIOUS_PORTS = [21, 23, 445, 3389, 5900]

def detect(data):
    alerts = []

    src = data.get("src")
    port = data.get("port")
    payload = data.get("payload")

    now = time.time()

    if not src:
        return alerts

    if now - last_seen[src] > TIME_WINDOW:
        ip_count[src] = 0
        port_map[src].clear()

    last_seen[src] = now

    ip_count[src] += 1
    if ip_count[src] > DOS_THRESHOLD:
        alerts.append(f"DoS alert: {ip_count[src]} packets from {src} in {TIME_WINDOW}s")

    if port:
        port_map[src].add(port)
        if len(port_map[src]) > PORT_SCAN_THRESHOLD:
            alerts.append(f"Port scan alert: {src} hit {len(port_map[src])} ports")

    if port in SUSPICIOUS_PORTS:
        port_names = {21: "FTP", 23: "Telnet", 445: "SMB", 3389: "RDP", 5900: "VNC"}
        name = port_names.get(port, "")
        alerts.append(f"Suspicious port alert: {name} ({port}) from {src}")

    if payload == "" or payload == "b''":
        alerts.append(f"Empty payload alert: {src} sent no data")

    return alerts

def reset_stats():
    ip_count.clear()
    port_map.clear()
    last_seen.clear()
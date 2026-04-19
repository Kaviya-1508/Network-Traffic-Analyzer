import csv
from datetime import datetime
import os

LOG_FILE = "data/packets.csv"

def ensure_header():
    os.makedirs("data", exist_ok=True)

    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'timestamp', 'src', 'dst', 'protocol',
                'port', 'payload_preview', 'alerts'
            ])

def log(data, alerts):
    ensure_header()

    with open(LOG_FILE, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.now().isoformat(),
            data.get('src', ''),
            data.get('dst', ''),
            data.get('protocol', ''),
            data.get('port', ''),
            data.get('payload', '')[:100],
            '; '.join(alerts)
        ])

def get_stats():
    if not os.path.exists(LOG_FILE):
        return {"total_packets": 0, "unique_ips": set()}

    with open(LOG_FILE, 'r') as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    unique_ips = set()
    for row in rows:
        unique_ips.add(row['src'])
        unique_ips.add(row['dst'])

    return {
        "total_packets": len(rows),
        "unique_ips": len(unique_ips)
    }
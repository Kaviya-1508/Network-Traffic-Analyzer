from scapy.all import sniff
from core.analyzer import analyze
from core.detector import detect
from utils.logger import log

def process(pkt):
    try:
        data = analyze(pkt)

        if data:
            print(f"\n[+] {data['protocol']} | {data['src']} -> {data['dst']} | Port: {data['port']}")

            alerts = detect(data)
            for alert in alerts:
                print(f"    [!] {alert}")

            log(data, alerts)

    except Exception as e:
        print(f"Error processing packet: {e}")

def start_sniffing(interface=None, packet_filter=None, count=0):
    print(f"Sniffing on interface: {interface or 'default'}")
    print(f"Filter: {packet_filter or 'none'}")
    print("Press Ctrl+C to stop\n")

    try:
        sniff(prn=process, store=False, iface=interface, 
              filter=packet_filter, count=count)
              
    except PermissionError:
        print("\n[ERROR] Need root/admin privileges. Run with sudo.")
    except KeyboardInterrupt:
        print("\n\nSniffing stopped by user")
    except Exception as e:
        print(f"\n[ERROR] {e}")
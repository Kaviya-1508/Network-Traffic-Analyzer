import argparse
from core.sniffer import start_sniffing
from utils.config import get_interface_info

def main():
    parser = argparse.ArgumentParser(description="Network Traffic Analyzer")
    parser.add_argument("-i", "--interface", help="Network interface to sniff")
    parser.add_argument("-f", "--filter", help="BPF filter (e.g., 'tcp port 80')")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0=infinite)")
    parser.add_argument("--list-interfaces", action="store_true", help="Show available interfaces")

    args = parser.parse_args()

    if args.list_interfaces:
        print("\nAvailable interfaces:")
        for iface in get_interface_info():
            print(f"  {iface['name']} - {iface['ip']}")
        return

    print("Network Traffic Analyzer")
    print("========================")
    start_sniffing(args.interface, args.filter, args.count)

if __name__ == "__main__":
    main()
"""
port-scan-detector.py
---------------------
Analyses a Wireshark CSV packet capture export and detects potential
port scanning activity based on SYN packet patterns.

Export from Wireshark:
  File > Export Packet Dissections > As CSV

Usage:
    python port-scan-detector.py --file capture.csv
"""

import argparse
import csv
from collections import defaultdict
from datetime import datetime


SYN_THRESHOLD = 15  # Number of unique ports before flagging as scan


def load_capture(filepath):
    """Load a Wireshark CSV export."""
    packets = []
    try:
        with open(filepath, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                packets.append(row)
    except FileNotFoundError:
        print(f"[ERROR] File not found: {filepath}")
    return packets


def detect_port_scan(packets):
    """
    Detect port scanning by identifying sources sending SYN packets
    to many different destination ports.
    """
    # Track {source_ip: set of destination ports}
    syn_targets = defaultdict(set)

    for packet in packets:
        info = packet.get("Info", "")
        source = packet.get("Source", "")
        destination = packet.get("Destination", "")
        protocol = packet.get("Protocol", "")

        # Look for TCP SYN packets (no ACK) in the Info field
        if protocol == "TCP" and "SYN" in info and "ACK" not in info:
            # Try to extract destination port from Info field
            parts = info.split()
            for i, part in enumerate(parts):
                if "→" in part or "->" in part:
                    try:
                        dest_port = parts[i + 1] if i + 1 < len(parts) else None
                        if dest_port and dest_port.isdigit():
                            syn_targets[source].add(int(dest_port))
                    except (IndexError, ValueError):
                        pass

    print("\n[*] Port Scan Detection")
    print("-" * 40)
    flagged = False
    for source_ip, ports in sorted(syn_targets.items(), key=lambda x: -len(x[1])):
        if len(ports) >= SYN_THRESHOLD:
            print(f"  [!] ALERT: {source_ip} sent SYN packets to {len(ports)} ports")
            print(f"      Ports targeted: {sorted(ports)[:20]}{'...' if len(ports) > 20 else ''}")
            flagged = True

    if not flagged:
        print("  [OK] No port scan patterns detected.")


def summarise_traffic(packets):
    """Print a summary of top talkers and protocols."""
    source_counts = defaultdict(int)
    protocol_counts = defaultdict(int)

    for packet in packets:
        source = packet.get("Source", "Unknown")
        protocol = packet.get("Protocol", "Unknown")
        source_counts[source] += 1
        protocol_counts[protocol] += 1

    print("\n[*] Top Source IPs")
    print("-" * 40)
    for ip, count in sorted(source_counts.items(), key=lambda x: -x[1])[:10]:
        print(f"  {ip}: {count} packets")

    print("\n[*] Protocol Breakdown")
    print("-" * 40)
    for proto, count in sorted(protocol_counts.items(), key=lambda x: -x[1])[:10]:
        print(f"  {proto}: {count} packets")


def main():
    parser = argparse.ArgumentParser(description="Wireshark Port Scan Detector")
    parser.add_argument("--file", required=True, help="Path to Wireshark CSV export")
    args = parser.parse_args()

    print(f"\n{'='*50}")
    print(f"  Cybersecurity Home Lab — Port Scan Detector")
    print(f"  File: {args.file}")
    print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*50}")

    packets = load_capture(args.file)

    if not packets:
        print("[ERROR] No packets loaded. Check the file format.")
        return

    print(f"\n[+] Loaded {len(packets)} packets.")

    summarise_traffic(packets)
    detect_port_scan(packets)

    print("\n[+] Analysis complete.\n")


if __name__ == "__main__":
    main()

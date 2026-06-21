"""
log-parser.py
-------------
Parses Windows Security Event Log exports (CSV or text) and flags
suspicious activity such as repeated failed logins or privilege escalation.

Usage:
    python log-parser.py --file security_events.csv
"""

import argparse
import csv
from collections import defaultdict
from datetime import datetime


# Event codes to monitor
SUSPICIOUS_EVENTS = {
    "4625": "Failed Logon",
    "4720": "User Account Created",
    "4728": "User Added to Privileged Group",
    "4672": "Special Privileges Assigned",
    "4688": "New Process Created",
}

BRUTE_FORCE_THRESHOLD = 5  # Failed logins before flagging


def parse_csv_log(filepath):
    """Parse a CSV export of Windows event logs."""
    events = []
    try:
        with open(filepath, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                events.append(row)
    except FileNotFoundError:
        print(f"[ERROR] File not found: {filepath}")
    return events


def detect_brute_force(events):
    """Detect accounts with repeated failed login attempts."""
    failed_logins = defaultdict(int)

    for event in events:
        event_id = event.get("EventID", "").strip()
        account = event.get("Account Name", "Unknown").strip()

        if event_id == "4625":
            failed_logins[account] += 1

    print("\n[*] Brute Force Detection (Failed Logins)")
    print("-" * 40)
    flagged = False
    for account, count in sorted(failed_logins.items(), key=lambda x: -x[1]):
        if count >= BRUTE_FORCE_THRESHOLD:
            print(f"  [!] ALERT: {account} — {count} failed login attempts")
            flagged = True
    if not flagged:
        print("  [OK] No brute force patterns detected.")


def detect_suspicious_events(events):
    """Flag events matching known suspicious event codes."""
    print("\n[*] Suspicious Event Detection")
    print("-" * 40)

    found = False
    for event in events:
        event_id = event.get("EventID", "").strip()
        if event_id in SUSPICIOUS_EVENTS:
            description = SUSPICIOUS_EVENTS[event_id]
            account = event.get("Account Name", "Unknown").strip()
            time = event.get("TimeCreated", "Unknown").strip()
            print(f"  [!] {description} (EventID {event_id}) — Account: {account} — Time: {time}")
            found = True

    if not found:
        print("  [OK] No suspicious events found.")


def summarise_events(events):
    """Print a summary count of all event IDs found."""
    event_counts = defaultdict(int)
    for event in events:
        event_id = event.get("EventID", "Unknown").strip()
        event_counts[event_id] += 1

    print("\n[*] Event Summary")
    print("-" * 40)
    for event_id, count in sorted(event_counts.items(), key=lambda x: -x[1]):
        label = SUSPICIOUS_EVENTS.get(event_id, "")
        label_str = f" ({label})" if label else ""
        print(f"  EventID {event_id}{label_str}: {count} occurrences")


def main():
    parser = argparse.ArgumentParser(description="Windows Event Log Parser")
    parser.add_argument("--file", required=True, help="Path to CSV event log export")
    args = parser.parse_args()

    print(f"\n{'='*50}")
    print(f"  Cybersecurity Home Lab — Log Parser")
    print(f"  File: {args.file}")
    print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*50}")

    events = parse_csv_log(args.file)

    if not events:
        print("[ERROR] No events loaded. Check the file format.")
        return

    print(f"\n[+] Loaded {len(events)} events.")

    summarise_events(events)
    detect_brute_force(events)
    detect_suspicious_events(events)

    print("\n[+] Analysis complete.\n")


if __name__ == "__main__":
    main()

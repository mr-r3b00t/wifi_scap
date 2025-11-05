from scapy.all import *
from collections import defaultdict
import csv

# Load the PCAP file (replace 'capture.pcap' with your file path)
pcap_file = 'capture2.pcap'

# Counters (use global or pass via closure; here using a class for simplicity and thread-safety)
class Counters:
    def __init__(self):
        self.unique_clients = set()
        self.unique_directed_ssids = set()  # New: Track unique directed SSIDs
        self.ssid_counts = defaultdict(int)  # New: Count directed probes per SSID
        self.client_ssid_counts = defaultdict(lambda: defaultdict(int))  # New: Count directed probes per client per SSID
        self.probe_requests = 0
        self.wildcard_probes = 0
        self.directed_probes = 0

counters = Counters()

# OUI to filter out (ignore probes from these clients)
OUI_TO_IGNORE = "00:00:00"

# SSID to exclude from directed probe counts
EXCLUDED_SSID = "SSIDNAME"
EXCLUDED_SSID_DISPLAY = EXCLUDED_SSID[:-3] + "***"

# Load Vendor OUI lookup from offline oui.csv file
VENDORS = {}
try:
    with open('oui.csv', 'r') as f:
        reader = csv.reader(f)
        next(reader)  # Skip header if present
        for row in reader:
            if len(row) == 2:
                oui = row[0].replace('-', ':').lower()
                vendor = row[1].strip().strip('"')
                if len(oui.split(':')) == 3:  # Valid OUI format
                    VENDORS[oui] = vendor
    print(f"Loaded {len(VENDORS)} OUIs from oui.csv")
    print("First 10 OUIs loaded:", list(VENDORS.keys())[:10])
except FileNotFoundError:
    print("Warning: oui.csv not found. Vendor lookup will show 'Unknown' for all.")
except Exception as e:
    print(f"Error loading oui.csv: {e}")

def get_vendor(mac):
    parts = mac.split(':')
    if len(parts) >= 3:
        oui = ':'.join(parts[:3]).lower()
        vendor = VENDORS.get(oui, "Unknown")
        if vendor == "Unknown":
            # Check for randomized MAC (locally administered unicast)
            first_octet = parts[0].lower()
            if len(first_octet) >= 2:
                second_char = first_octet[1]
                if second_char in ['2', '6', 'a', 'e']:
                    return "Randomized MAC (Possible Apple/Samsung)"
            print(f"Debug: Unknown OUI '{oui}' for MAC '{mac}'")
        return vendor
    return "Unknown"

def redact_mac(mac):
    parts = mac.split(':')
    if len(parts) == 6:
        return ':'.join(parts[:-3]) + ':***'
    return mac  # Fallback if not standard format

def process_packet(pkt):
    if pkt.haslayer(Dot11):
        # Already filtered to probe req, but double-check
        if pkt.type == 0 and pkt.subtype == 4:
            client_mac = pkt.addr2  # Source MAC (client)
            
            # Filter out probes from specified OUI
            if client_mac.startswith(OUI_TO_IGNORE):
                return  # Skip this packet entirely
            
            counters.unique_clients.add(client_mac)
            counters.probe_requests += 1
            
            # Check SSID for probe type (iterate elements for ID=0 SSID)
            ssid_found = False
            if pkt.haslayer(Dot11Elt):
                for elt in pkt[Dot11Elt]:
                    if elt.ID == 0:  # SSID element
                        ssid = elt.info.decode('utf-8', errors='ignore').strip()
                        if not ssid:  # Empty SSID = wildcard/broadcast probe
                            counters.wildcard_probes += 1
                        else:
                            # Exclude directed probes for specific SSID
                            if ssid != EXCLUDED_SSID:
                                counters.directed_probes += 1
                                counters.ssid_counts[ssid] += 1
                                counters.unique_directed_ssids.add(ssid)  # Add to unique SSIDs
                                counters.client_ssid_counts[client_mac][ssid] += 1
                            # If ssid == EXCLUDED_SSID, skip directed count but total/client already counted
                        ssid_found = True
                        break  # Typically only one SSID per probe req
            if not ssid_found:
                # No SSID element present (rare, but treat as wildcard)
                counters.wildcard_probes += 1

# Process packets on-the-fly with filter for speed (avoids loading full PCAP into memory)
print("Processing PCAP... (this may take a while for 1GB files)")
sniff(offline=pcap_file, filter="wlan type mgt subtype probe-req", prn=process_packet, store=0)

# Output results (unique clients now filtered)
print(f"\nNumber of unique wireless client devices: {len(counters.unique_clients)}")
print(f"Total probe requests (filtered): {counters.probe_requests}")
print(f"Wildcard probes (filtered): {counters.wildcard_probes}")
print(f"Directed probes (filtered, excluding '{EXCLUDED_SSID_DISPLAY}'): {counters.directed_probes}")

# New: Unique target SSIDs
print(f"\nNumber of unique target SSID names in probes (excluding '{EXCLUDED_SSID_DISPLAY}'): {len(counters.unique_directed_ssids)}")
print("Unique directed probe request SSID names:")
for ssid in sorted(counters.unique_directed_ssids):
    print(ssid)

# Table: Directed probe requests per unique SSID
print("\nCount of directed probe requests per unique SSID:")
print("| SSID | Count |")
print("|------|-------|")
for ssid in sorted(counters.ssid_counts):
    count = counters.ssid_counts[ssid]
    print(f"| {ssid} | {count} |")

# New Table: Analysis - Directed probe requests per client and SSID
print("\nAnalysis: Directed probe requests per client and SSID (excluding '{EXCLUDED_SSID_DISPLAY}'):")
print("| Client MAC | Vendor | SSID | Count |")
print("|------------|--------|------|-------|")
for client in sorted(counters.client_ssid_counts):
    redacted_client = redact_mac(client)
    vendor = get_vendor(client)
    for ssid in sorted(counters.client_ssid_counts[client]):
        count = counters.client_ssid_counts[client][ssid]
        print(f"| {redacted_client} | {vendor} | {ssid} | {count} |")

# Optional: List unique clients
print("\nUnique client MACs (filtered, redacted) with vendors:")
for mac in sorted(counters.unique_clients):
    vendor = get_vendor(mac)
    print(f"{redact_mac(mac)} ({vendor})")

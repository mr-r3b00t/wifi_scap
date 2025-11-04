from scapy.all import *
from collections import defaultdict

# Load the PCAP file (replace 'capture.pcap' with your file path)
pcap_file = 'capture.pcap'

# Counters (use global or pass via closure; here using a class for simplicity and thread-safety)
class Counters:
    def __init__(self):
        self.unique_clients = set()
        self.unique_directed_ssids = set()  # New: Track unique directed SSIDs
        self.probe_requests = 0
        self.wildcard_probes = 0
        self.directed_probes = 0

counters = Counters()

# OUI to filter out (ignore probes from these clients)
OUI_TO_IGNORE = "00:1d:63"

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
                            counters.directed_probes += 1
                            counters.unique_directed_ssids.add(ssid)  # Add to unique SSIDs
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
print(f"Directed probes (filtered): {counters.directed_probes}")

# New: Unique target SSIDs
print(f"\nNumber of unique target SSID names in probes: {len(counters.unique_directed_ssids)}")
print("Unique directed probe request SSID names:")
for ssid in sorted(counters.unique_directed_ssids):
    print(ssid)

# Optional: List unique clients
print("\nUnique client MACs (filtered):")
for mac in sorted(counters.unique_clients):
    print(mac)

import urllib.request
import re
import csv

url = 'https://standards-oui.ieee.org/oui/oui.txt'

req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'})

with urllib.request.urlopen(req) as response:
    text = response.read().decode('utf-8')

lines = text.splitlines()

with open('oui.csv', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(['OUI', 'Vendor Name'])
    for line in lines:
        match = re.match(r'^([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\((hex|base 16)\)\s+(.*)$', line)
        if match:
            oui = match.group(1)
            vendor = match.group(3).strip()
            writer.writerow([oui, vendor])

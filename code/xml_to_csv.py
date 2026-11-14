import csv
import sys
import os
from scanner_core import parse_nmap_xml as parse_scan_xml

def parse_nmap_xml(xml_file):
    """Parse Nmap XML and extract open ports to CSV"""
    if not os.path.exists(xml_file):
        print(f"Error: {xml_file} not found")
        return
    
    services, _ = parse_scan_xml(xml_file)

    if services:
        csv_file = xml_file.replace('.xml', '_parsed.csv')
        with open(csv_file, "w", newline="") as output:
            writer = csv.DictWriter(
                output,
                fieldnames=["ip", "port", "protocol", "state", "service", "product", "version", "hostname"],
            )
            writer.writeheader()
            writer.writerows(service.__dict__ for service in services)
        print(f"✓ Saved {len(services)} open ports to {csv_file}")
    else:
        print("No open ports found")

if __name__ == "__main__":
    xml_file = sys.argv[1] if len(sys.argv) > 1 else 'metasploitable-scan.xml'
    parse_nmap_xml(xml_file)

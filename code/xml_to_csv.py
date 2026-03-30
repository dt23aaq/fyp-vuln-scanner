import xml.etree.ElementTree as ET
import pandas as pd
import sys
import os

def parse_nmap_xml(xml_file):
    """Parse Nmap XML and extract open ports to CSV"""
    if not os.path.exists(xml_file):
        print(f"Error: {xml_file} not found")
        return

    tree = ET.parse(xml_file)
    root = tree.getroot()

    rows = []
    for host in root.findall('host'):
        addr = host.find('address')
        if addr is None:
            continue
        ip = addr.get('addr')

        for port in host.findall(".//port"):
            state = port.find('state')
            if state is None or state.get('state') != 'open':
                continue

            portid = port.get('portid')
            proto = port.get('protocol')
            service_el = port.find('service')
            service = service_el.get('name') if service_el else 'unknown'
            product = service_el.get('product', '') if service_el else ''
            version = service_el.get('version', '') if service_el else ''

            rows.append({
                'ip': ip,
                'port': int(portid),
                'protocol': proto,
                'service': service,
                'product': product,
                'version': version
            })

    if rows:
        df = pd.DataFrame(rows)
        csv_file = xml_file.replace('.xml', '_parsed.csv')
        df.to_csv(csv_file, index=False)
        print(f"✓ Saved {len(rows)} open ports to {csv_file}")
    else:
        print("No open ports found")

if __name__ == "__main__":
    xml_file = sys.argv[1] if len(sys.argv) > 1 else 'metasploitable-scan.xml'
    parse_nmap_xml(xml_file)

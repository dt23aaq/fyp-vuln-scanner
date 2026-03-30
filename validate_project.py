#!/usr/bin/env python3
"""Validate FYP Project Structure and Data"""

import xml.etree.ElementTree as ET
import os
import sys

print("=" * 60)
print("FYP VULNERABILITY SCANNER - PROJECT VALIDATION")
print("=" * 60)

# Check folder structure
print("\n1. FOLDER STRUCTURE CHECK:")
folders = ['code', 'scans', 'database', 'database/exports', 'screenshots', 'powerbi']
for folder in folders:
    exists = os.path.isdir(folder)
    status = "✓" if exists else "✗"
    print(f"   {status} {folder}/")

# Check files
print("\n2. FILE STRUCTURE CHECK:")
files = {
    'code': ['nmap_to_progres.py', 'xml_to_csv.py', 'README'],
    'scans': ['metasploitable-full.xml', 'metasploitable-scan.xml', 'msf_scan.csv'],
    'database': ['schema.sql', 'db_export.sql'],
    'database/exports': ['hosts.csv', 'services.csv', 'vulns.csv'],
    'screenshots': ['Dashboard.png', 'Postgres.png', 'Kali-desktop.png'],
}

for folder, file_list in files.items():
    print(f"\n   {folder}/:")
    for file in file_list:
        path = os.path.join(folder, file)
        exists = os.path.isfile(path)
        status = "✓" if exists else "✗"
        if exists:
            size = os.path.getsize(path)
            print(f"      {status} {file} ({size:,} bytes)")
        else:
            print(f"      {status} {file} (MISSING)")

# Validate XML files
print("\n3. NMAP XML VALIDATION:")
xml_files = {
    'scans/metasploitable-full.xml': 'Full Scan',
    'scans/metasploitable-scan.xml': 'Targeted Scan'
}

for xml_path, description in xml_files.items():
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        ports = root.findall('.//port')
        hosts = root.findall('host')
        
        print(f"\n   ✓ {description} ({xml_path}):")
        print(f"     - Nmap Version: {root.get('version')}")
        print(f"     - Scan Date: {root.get('startstr')}")
        print(f"     - Hosts Found: {len(hosts)}")
        print(f"     - Ports Found: {len(ports)}")
        
        # Show sample services
        if ports:
            print(f"     - Sample Services:")
            for port in ports[:3]:
                service = port.find('service')
                portid = port.get('portid')
                svc_name = service.get('name', 'unknown')
                product = service.get('product', '--')
                print(f"       • Port {portid}: {svc_name} ({product})")
    except ET.ParseError as e:
        print(f"   ✗ {description} - XML Error: {e}")
    except FileNotFoundError:
        print(f"   ✗ {description} - File not found")

# Validate CSV files
print("\n4. DATABASE EXPORTS VALIDATION:")
csv_files = {
    'database/exports/hosts.csv': 'Hosts',
    'database/exports/services.csv': 'Services',
    'database/exports/vulns.csv': 'Vulnerabilities'
}

for csv_path, description in csv_files.items():
    if os.path.isfile(csv_path):
        with open(csv_path, 'r') as f:
            lines = f.readlines()
        print(f"   ✓ {description}: {len(lines)} rows (including header)")
    else:
        print(f"   ✗ {description}: MISSING")

# Validate Database Schema
print("\n5. DATABASE SCHEMA CHECK:")
if os.path.isfile('database/schema.sql'):
    with open('database/schema.sql', 'r') as f:
        content = f.read()
        tables = ['hosts', 'services', 'vulnerabilities', 'scan_sessions']
        print("   ✓ Schema file exists")
        for table in tables:
            if f"CREATE TABLE" in content and table in content:
                print(f"     - ✓ {table} table defined")
else:
    print("   ✗ schema.sql not found")

print("\n" + "=" * 60)
print("VALIDATION COMPLETE")
print("=" * 60)

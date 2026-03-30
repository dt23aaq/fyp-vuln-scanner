import xml.etree.ElementTree as ET
import psycopg2
from psycopg2.extras import execute_values
import sys
import os
from datetime import datetime

class NmapPostgresImporter:
    """Import Nmap XML scan results into PostgreSQL database"""
    
    def __init__(self, db_host, db_name, db_user, db_password, db_port=5432):
        """Initialize database connection"""
        try:
            self.conn = psycopg2.connect(
                host=db_host,
                database=db_name,
                user=db_user,
                password=db_password,
                port=db_port
            )
            self.cursor = self.conn.cursor()
            print(f"✓ Connected to PostgreSQL database: {db_name}")
        except psycopg2.Error as e:
            print(f"Error: Could not connect to database - {e}")
            sys.exit(1)
    
    def parse_nmap_xml(self, xml_file):
        """Parse Nmap XML file and return structured data"""
        if not os.path.exists(xml_file):
            print(f"Error: {xml_file} not found")
            return None
        
        tree = ET.parse(xml_file)
        root = tree.getroot()
        
        scan_data = {
            'hosts': [],
            'services': [],
            'vulnerabilities': []
        }
        
        for host in root.findall('host'):
            addr_elem = host.find('address')
            if addr_elem is None:
                continue
            
            ip = addr_elem.get('addr')
            host_id = self.import_host(ip)
            
            for port in host.findall(".//port"):
                state = port.find('state')
                if state is None or state.get('state') != 'open':
                    continue
                
                portid = port.get('portid')
                protocol = port.get('protocol')
                service_elem = port.find('service')
                
                service_name = service_elem.get('name') if service_elem else 'unknown'
                product = service_elem.get('product', '') if service_elem else ''
                version = service_elem.get('version', '') if service_elem else ''
                
                service_id = self.import_service(host_id, int(portid), protocol, service_name, product, version)
        
        return scan_data
    
    def import_host(self, ip_address):
        """Insert host into database"""
        query = """
        INSERT INTO hosts (ip_address, scan_date)
        VALUES (%s, %s)
        ON CONFLICT (ip_address) DO UPDATE SET scan_date = EXCLUDED.scan_date
        RETURNING host_id;
        """
        self.cursor.execute(query, (ip_address, datetime.now()))
        self.conn.commit()
        return self.cursor.fetchone()[0]
    
    def import_service(self, host_id, port, protocol, service_name, product, version):
        """Insert service into database"""
        query = """
        INSERT INTO services (host_id, port, protocol, service_name, product, version)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON CONFLICT (host_id, port, protocol) DO UPDATE 
        SET service_name = EXCLUDED.service_name, product = EXCLUDED.product, version = EXCLUDED.version
        RETURNING service_id;
        """
        self.cursor.execute(query, (host_id, port, protocol, service_name, product, version))
        self.conn.commit()
        return self.cursor.fetchone()[0]
    
    def close(self):
        """Close database connection"""
        self.cursor.close()
        self.conn.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 nmap_to_progres.py <xml_file> [db_host] [db_name] [db_user] [db_password]")
        sys.exit(1)
    
    xml_file = sys.argv[1]
    db_host = sys.argv[2] if len(sys.argv) > 2 else 'localhost'
    db_name = sys.argv[3] if len(sys.argv) > 3 else 'vuln_scanner'
    db_user = sys.argv[4] if len(sys.argv) > 4 else 'postgres'
    db_password = sys.argv[5] if len(sys.argv) > 5 else 'password'
    
    importer = NmapPostgresImporter(db_host, db_name, db_user, db_password)
    data = importer.parse_nmap_xml(xml_file)
    
    if data:
        print(f"✓ Successfully imported Nmap scan data")
    
    importer.close()

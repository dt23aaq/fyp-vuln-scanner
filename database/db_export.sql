-- PostgreSQL Database Export
-- Vulnerability Scanner FYP Project
-- Export Date: 2026-03-25
-- This file contains sample data for demonstration purposes

-- Insert sample hosts
INSERT INTO hosts (ip_address, hostname, mac_address, os_detected, scan_date) VALUES
('192.168.56.102'::inet, 'metasploitable.local', '08:00:27:C6:9D:88', 'Linux 2.6.24', '2023-11-16 12:13:20'),
('192.168.56.103'::inet, 'target-01.local', '08:00:27:AA:BB:CC', 'Linux 3.10', '2023-11-16 12:15:00');

-- Insert sample services
INSERT INTO services (host_id, port, protocol, service_name, product, version, state) VALUES
(1, 22, 'tcp', 'ssh', 'OpenSSH', '4.7p1', 'open'),
(1, 80, 'tcp', 'http', 'Apache httpd', '2.2.8', 'open'),
(1, 445, 'tcp', 'microsoft-ds', 'Samba smbd', '3.X', 'open'),
(1, 3306, 'tcp', 'mysql', 'MySQL', '5.0.51a', 'open'),
(1, 5432, 'tcp', 'postgresql', 'PostgreSQL DB', '8.2.11', 'open'),
(2, 22, 'tcp', 'ssh', 'OpenSSH', '5.1p1', 'open'),
(2, 80, 'tcp', 'http', 'Apache httpd', '2.4.1', 'open'),
(2, 443, 'tcp', 'https', 'Apache httpd', '2.4.1', 'open');

-- Insert sample vulnerabilities
INSERT INTO vulnerabilities (service_id, vuln_name, description, severity, cvss_score, cve_id, remediation) VALUES
(1, 'Weak SSH Version', 'OpenSSH 4.7p1 is outdated and contains known vulnerabilities', 'medium', 5.3, 'CVE-2008-5161', 'Upgrade to OpenSSH 7.4 or later'),
(2, 'Apache Default Config', 'Apache 2.2.8 is running with default insecure configuration', 'medium', 5.3, 'CVE-2009-1891', 'Harden Apache configuration and update to latest version'),
(3, 'Samba Version Outdated', 'Samba 3.X contains multiple known exploitable vulnerabilities', 'high', 7.5, 'CVE-2012-1182', 'Upgrade Samba to version 4.0 or later'),
(4, 'MySQL Weak Authentication', 'MySQL allows remote access with weak default credentials', 'high', 8.1, 'CWE-521', 'Enforce strong password policies and restrict remote root access'),
(5, 'Postgres Weak Password', 'PostgreSQL configured with default/weak passwords', 'high', 8.0, 'CWE-521', 'Change default passwords and implement access controls'),
(6, 'SSH Version Disclosure', 'SSH service discloses version information', 'low', 2.1, 'CWE-200', 'Disable SSH version banner if not required'),
(7, 'HTTP Server Banner', 'Web server exposes version and technology information', 'low', 2.7, 'CWE-200', 'Disable server banner exposure'),
(8, 'SSL/TLS Not Enforced', 'HTTPS available but not enforced', 'medium', 5.9, 'CWE-311', 'Configure HTTPS redirect and HSTS headers');

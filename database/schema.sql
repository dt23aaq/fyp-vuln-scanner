-- PostgreSQL Database Schema for Vulnerability Scanner
-- This schema defines the structure of the database used to store scan results, hosts, services, and vulnerabilities

-- Hosts table: Stores information about scanned hosts
CREATE TABLE IF NOT EXISTS hosts (
    host_id SERIAL PRIMARY KEY,
    ip_address INET NOT NULL UNIQUE,
    hostname VARCHAR(255),
    mac_address MACADDR,
    os_detected VARCHAR(255),
    scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Services table: Stores open services/ports discovered on hosts
CREATE TABLE IF NOT EXISTS services (
    service_id SERIAL PRIMARY KEY,
    host_id INTEGER NOT NULL REFERENCES hosts(host_id) ON DELETE CASCADE,
    port INTEGER NOT NULL CHECK (port >= 1 AND port <= 65535),
    protocol VARCHAR(10) NOT NULL DEFAULT 'tcp',
    service_name VARCHAR(100),
    product VARCHAR(255),
    version VARCHAR(100),
    state VARCHAR(20) DEFAULT 'open',
    discovery_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_service UNIQUE(host_id, port, protocol)
);

-- Vulnerabilities table: Stores identified vulnerabilities
CREATE TABLE IF NOT EXISTS vulnerabilities (
    vuln_id SERIAL PRIMARY KEY,
    service_id INTEGER NOT NULL REFERENCES services(service_id) ON DELETE CASCADE,
    vuln_name VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(20) CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    cvss_score DECIMAL(3,1),
    cve_id VARCHAR(50),
    cwe_id VARCHAR(50),
    remediation TEXT,
    discovered_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    verified BOOLEAN DEFAULT FALSE
);

-- Scan Sessions table: Track when scans were performed
CREATE TABLE IF NOT EXISTS scan_sessions (
    session_id SERIAL PRIMARY KEY,
    scan_name VARCHAR(255),
    scan_type VARCHAR(50),
    scanner_tool VARCHAR(100),
    start_time TIMESTAMP,
    end_time TIMESTAMP,
    targets_count INTEGER,
    vulnerabilities_found INTEGER,
    notes TEXT
);

-- Create indexes for better query performance
CREATE INDEX idx_hosts_ip ON hosts(ip_address);
CREATE INDEX idx_services_host ON services(host_id);
CREATE INDEX idx_services_port ON services(port);
CREATE INDEX idx_vulns_service ON vulnerabilities(service_id);
CREATE INDEX idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX idx_vulns_cvss ON vulnerabilities(cvss_score);

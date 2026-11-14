import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from scanner_core import ServiceRecord, match_vulnerabilities, parse_nmap_xml


def resolve_default_xml() -> str:
    """Resolve a sensible default XML path for both repo-root and code/ execution."""
    candidates = [
        "scans/metasploitable-scan.xml",
        "../scans/metasploitable-scan.xml",
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return candidates[0]


def parse_open_services(xml_path: str) -> list[dict]:
    """Compatibility wrapper returning dictionaries for existing callers."""
    services, _ = parse_nmap_xml(xml_path)
    return [service.__dict__ for service in services]


def to_vuln_rows(service_rows: list[dict]) -> list[tuple]:
    """Convert parsed services into evidence-aware vulnerability rows."""
    services = [ServiceRecord(**row) for row in service_rows]
    return [
        (
            service.ip,
            service.port,
            service.protocol,
            service.service,
            service.product,
            service.version,
            rule.finding,
            rule.cvss,
            rule.exploited,
            rule.rule_id,
            rule.evidence_type,
        )
        for service, rule in match_vulnerabilities(services)
    ]


def load_to_postgres(vuln_rows: list[tuple], dsn: str) -> int:
    """Load findings into the canonical vulnerability table without deleting history."""
    import psycopg2

    try:
        conn = psycopg2.connect(dsn)
    except psycopg2.OperationalError as exc:
        raise RuntimeError(
            "PostgreSQL connection failed. Ensure PostgreSQL is running and DSN is correct."
        ) from exc

    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS hosts (
            host_id SERIAL PRIMARY KEY,
            ip_address INET NOT NULL UNIQUE,
            hostname VARCHAR(255),
            scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS services (
            service_id SERIAL PRIMARY KEY,
            host_id INTEGER NOT NULL REFERENCES hosts(host_id) ON DELETE CASCADE,
            port INTEGER NOT NULL,
            protocol VARCHAR(10) NOT NULL DEFAULT 'tcp',
            service_name VARCHAR(100),
            product VARCHAR(255),
            version VARCHAR(100),
            state VARCHAR(20) DEFAULT 'open',
            discovery_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(host_id, port, protocol)
        );
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            vuln_id SERIAL PRIMARY KEY,
            service_id INTEGER NOT NULL REFERENCES services(service_id) ON DELETE CASCADE,
            vuln_name VARCHAR(255) NOT NULL,
            description TEXT,
            severity VARCHAR(20),
            cvss_score NUMERIC(3,1),
            cve_id VARCHAR(50),
            cwe_id VARCHAR(50),
            discovered_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            verified BOOLEAN DEFAULT FALSE,
            rule_id VARCHAR(100),
            evidence_type VARCHAR(50)
        )
        """
    )
    cur.execute("ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS rule_id VARCHAR(100)")
    cur.execute("ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS evidence_type VARCHAR(50)")

    if vuln_rows:
        for (
            ip, port, protocol, service, product, version, finding, cvss,
            exploited, rule_id, evidence_type,
        ) in vuln_rows:
            cur.execute(
                """
                INSERT INTO hosts (ip_address)
                VALUES (%s)
                ON CONFLICT (ip_address) DO UPDATE SET last_updated = CURRENT_TIMESTAMP
                RETURNING host_id
                """,
                (ip,),
            )
            host_id = cur.fetchone()[0]
            cur.execute(
                """
                INSERT INTO services
                    (host_id, port, protocol, service_name, product, version)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (host_id, port, protocol) DO UPDATE SET
                    service_name = EXCLUDED.service_name,
                    product = EXCLUDED.product,
                    version = EXCLUDED.version
                RETURNING service_id
                """,
                (host_id, port, protocol, service, product, version),
            )
            service_id = cur.fetchone()[0]
            severity = (
                "critical" if cvss >= 9.0 else
                "high" if cvss >= 7.0 else
                "medium" if cvss >= 4.0 else "low"
            )
            cur.execute(
                """
                INSERT INTO vulnerabilities
                    (service_id, vuln_name, severity, cvss_score, verified, rule_id, evidence_type)
                SELECT %s, %s, %s, %s, %s, %s, %s
                WHERE NOT EXISTS (
                    SELECT 1 FROM vulnerabilities
                    WHERE service_id = %s AND vuln_name = %s AND rule_id = %s
                )
                """,
                (
                    service_id, finding, severity, cvss, exploited, rule_id,
                    evidence_type, service_id, finding, rule_id,
                ),
            )

    conn.commit()
    cur.close()
    conn.close()
    return len(vuln_rows)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Load live Nmap XML findings into PostgreSQL vulns table"
    )
    parser.add_argument(
        "xml_path",
        nargs="?",
        default=resolve_default_xml(),
        help="Path to Nmap XML file (default: scans/metasploitable-scan.xml)",
    )
    parser.add_argument(
        "--dsn",
        default="dbname=msf user=msf password=''",
        help="PostgreSQL DSN string",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse and display counts without writing to database",
    )
    args = parser.parse_args()

    if not os.path.exists(args.xml_path):
        raise SystemExit(f"Error: XML file not found: {args.xml_path}")

    services, _ = parse_nmap_xml(args.xml_path)
    vuln_rows = to_vuln_rows([service.__dict__ for service in services])

    if args.dry_run:
        print(f"Parsed open services: {len(services)}")
        print(f"Mapped vulnerability rows: {len(vuln_rows)}")
        return

    try:
        inserted = load_to_postgres(vuln_rows, args.dsn)
    except RuntimeError as exc:
        raise SystemExit(f"Error: {exc}")

    print(f"Loaded {inserted} vulnerability rows from {args.xml_path} into PostgreSQL.")


if __name__ == "__main__":
    main()
import argparse
import os
import xml.etree.ElementTree as ET


# Known mappings for common Metasploitable 2 exposure points.
VULN_MAP_BY_PORT = {
    21: ("CVE-2011-2523", 10.0, True),
    22: ("CWE-200", 2.1, False),
    445: ("CVE-2007-2447", 9.3, True),
    1524: ("Direct RCE", 10.0, True),
    3306: ("CWE-521", 8.1, True),
    5432: ("Weak Auth", 7.5, True),
    6667: ("CVE-2010-2075", 10.0, True),
}


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
    """Parse open service entries from Nmap XML."""
    tree = ET.parse(xml_path)
    root = tree.getroot()

    rows = []
    for host in root.findall("host"):
        address = host.find("address")
        ip = address.get("addr", "unknown") if address is not None else "unknown"

        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue

            service_el = port.find("service")
            service_name = service_el.get("name", "unknown") if service_el is not None else "unknown"
            product = service_el.get("product", "") if service_el is not None else ""
            version = service_el.get("version", "") if service_el is not None else ""

            rows.append(
                {
                    "ip": ip,
                    "port": int(port.get("portid", 0)),
                    "service": service_name,
                    "product": product,
                    "version": version,
                }
            )
    return rows


def to_vuln_rows(service_rows: list[dict]) -> list[tuple]:
    """Convert parsed services into vulnerability rows for the vulns table."""
    vuln_rows = []
    for row in service_rows:
        port = row["port"]
        mapping = VULN_MAP_BY_PORT.get(port)
        if not mapping:
            continue

        finding, cvss, exploited = mapping
        service_label = row["service"]

        # Keep version compact but informative for dashboard display.
        version_bits = [b for b in (row["product"], row["version"]) if b]
        version_text = " ".join(version_bits) if version_bits else "unknown"
        if len(version_text) > 50:
            version_text = version_text[:50]

        vuln_rows.append((port, service_label, version_text, finding, cvss, exploited))

    return vuln_rows


def load_to_postgres(vuln_rows: list[tuple], dsn: str) -> int:
    """Create/refresh vulns table with latest parsed vulnerability rows."""
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
        CREATE TABLE IF NOT EXISTS vulns (
            port INTEGER,
            service VARCHAR(50),
            version VARCHAR(50),
            finding VARCHAR(50),
            cvss FLOAT,
            exploited BOOLEAN DEFAULT FALSE
        )
        """
    )

    cur.execute("DELETE FROM vulns")
    if vuln_rows:
        cur.executemany(
            """
            INSERT INTO vulns (port, service, version, finding, cvss, exploited)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            vuln_rows,
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

    services = parse_open_services(args.xml_path)
    vuln_rows = to_vuln_rows(services)

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
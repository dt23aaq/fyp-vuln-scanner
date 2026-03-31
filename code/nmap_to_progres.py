import psycopg2

conn = psycopg2.connect("dbname=msf user=msf password=''")
cur = conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS vulns (
    port INTEGER,
    service VARCHAR(50),
    version VARCHAR(50),
    finding VARCHAR(50),
    cvss FLOAT,
    exploited BOOLEAN DEFAULT FALSE
)
""")

scan_data = [
    (21, 'vsftpd', '2.3.4', 'CVE-2011-2523', 10.0, True),
    (1524, 'bindshell', 'root shell', 'Direct RCE', 10.0, True),
    (445, 'samba', '3.0.20', 'CVE-2007-2447', 9.3, True),
    (5432, 'postgresql', '8.3.0', 'Weak Auth', 7.5, True),
    (6667, 'unrealircd', '3.2.8.1', 'CVE-2010-2075', 10.0, True)
]
cur.execute("DELETE FROM vulns")
cur.executemany("""
INSERT INTO vulns (port, service, version, finding, cvss, exploited)
VALUES (%s, %s, %s, %s, %s, %s)
""", scan_data)

conn.commit()
cur.close()
conn.close()

print("Scan data loaded to PostgreSQL.")
#!/usr/bin/env bash
set -euo pipefail

# End-to-end local pipeline:
# 1) Nmap scan -> XML
# 2) XML parse -> CSV
# 3) Vulnerability mapping -> PostgreSQL

TARGET_IP="${1:-192.168.56.102}"
SCAN_XML="${2:-scans/metasploitable-scan.xml}"
PYTHON_BIN="${PYTHON_BIN:-/usr/local/bin/python3}"
PG_HOST="${PGHOST:-localhost}"
PG_PORT="${PGPORT:-5432}"
PG_DB="${PGDATABASE:-msf}"
PG_USER="${PGUSER:-msf}"

echo "[precheck] Checking PostgreSQL connectivity..."
if ! command -v psql >/dev/null 2>&1; then
	echo "Error: psql client not found. Install PostgreSQL client tools first."
	exit 1
fi

if ! psql -h "${PG_HOST}" -p "${PG_PORT}" -U "${PG_USER}" -d "${PG_DB}" -c "SELECT 1;" >/dev/null 2>&1; then
	echo "Error: PostgreSQL is not reachable at ${PG_HOST}:${PG_PORT} (db=${PG_DB}, user=${PG_USER})."
	echo "Hint: start PostgreSQL and confirm credentials, then rerun the pipeline."
	echo "macOS example: brew services start postgresql"
	exit 1
fi

echo "[1/3] Running Nmap scan against ${TARGET_IP}..."
nmap -sS -sV -O -p- -oX "${SCAN_XML}" "${TARGET_IP}"

echo "[2/3] Parsing XML into CSV..."
"${PYTHON_BIN}" code/xml_to_csv.py "${SCAN_XML}"

echo "[3/3] Loading live findings into PostgreSQL..."
"${PYTHON_BIN}" code/nmap_to_postgresql.py "${SCAN_XML}"

echo "Pipeline complete. Power BI refresh can now load latest local data."

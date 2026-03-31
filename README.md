# Network Vulnerability Scanner with Power BI

## Repository Access
GitHub repository: https://github.com/dt23aaq/fyp-vuln-scanner

## 1. Project Title
Network Vulnerability Scanner with PostgreSQL and Power BI

## 2. Project Summary
This project implements a network vulnerability scanning workflow in a controlled virtual lab environment. Nmap and Metasploit are used on Kali Linux to scan an intentionally vulnerable target (Metasploitable 2). The resulting scan data is processed using Python scripts and prepared for storage in PostgreSQL and visualization in Power BI.

The project demonstrates:
- Automated collection of network scan results.
- Processing and preparation of vulnerability data.
- Presentation of findings in a dashboard suitable for technical reporting.

## 3. Lab Environment
Scanner:
- Kali Linux (scanner and processing host)
- IP address: 192.168.56.101

Target:
- Metasploitable 2 (intentionally vulnerable target)
- IP address: 192.168.56.102

Network range used during testing:
- 192.168.56.0/24

Tools used:
- Nmap
- Metasploit
- Python
- PostgreSQL
- Power BI

All scans were carried out in a private lab using intentionally vulnerable systems.

## 4. Purpose of This Submission Folder
This submission folder is a curated copy of the main artefacts produced during the project. It is not a full VM backup, but it contains:
- Key Python scripts used in the processing pipeline.
- Selected Nmap and Metasploit output files.
- Database schema and export files.
- The Power BI dashboard file.
- Screenshots used as evidence of the system in use.

Some parts of the project (for example, repeated scan runs and interactive work in Kali) are not fully reproduced here; these are documented in the written report.

## 5. Folder Structure
```text
fyp-vuln-scanner/
├── README.md
├── code/
│   ├── nmap_to_postgresql.py
│   ├── xml_to_csv.py
│   └── README
├── scans/
│   ├── metasploitable-full.xml
│   ├── metasploitable-scan.xml
│   └── msf_scan.csv
├── database/
│   ├── schema.sql
│   ├── db_export.sql
│   └── exports/
│       ├── hosts.csv
│       ├── services.csv
│       └── vulns.csv
├── screenshots/
└── powerbi/
    └── networkVulnScanDashboard.pbix
```

## 6. File Descriptions
### 6.1 Code (code)
- nmap_to_postgresql.py  
    Connects to PostgreSQL, creates vulnerability data structures, and inserts selected findings associated with the Metasploitable scan.

- xml_to_csv.py  
    Parses Nmap XML output and extracts open ports, protocols, services, product names, and versions into CSV format.

- README  
    Original short project note retained as a development artefact.

### 6.2 Scan and Data Artefacts (scans)
- metasploitable-full.xml  
    Full Nmap scan output against Metasploitable 2.

- metasploitable-scan.xml  
    Additional Nmap scan output used during development and testing.

- msf_scan.csv  
    CSV file containing Metasploit-related scan or vulnerability information exported during the project.

### 6.3 Database Files (database and database/exports)
These files are included as part of the project data exports:
- schema.sql: PostgreSQL schema export (hosts, services, vulnerabilities, and related structures).
- db_export.sql: Full PostgreSQL database export used to preserve data state.
- exports/hosts.csv: Export of the hosts table.
- exports/services.csv: Export of the services table.
- exports/vulns.csv: Export of the vulnerabilities table.

### 6.4 Screenshots (screenshots)
PNG/JPEG evidence images showing:
- Nmap and Metasploit scans running in Kali.
- PostgreSQL tables containing imported data.
- Power BI dashboard views.

### 6.5 Power BI Dashboard (powerbi)
- networkVulnScanDashboard.pbix  
    Power BI Desktop report file created from the processed scan data.

## 7. Workflow Summary
The intended workflow for the project is:
1. Network scanning.
   - Use Nmap (and Metasploit where applicable) on Kali Linux to scan the target host(s).
   - Save output to XML (and CSV for Metasploit where relevant).
2. Processing.
   - Use Python scripts (for example, nmap_to_postgresql.py and xml_to_csv.py) to parse scan results and prepare data for analysis.
3. Storage.
   - Store processed data in PostgreSQL tables (hosts, services, vulnerabilities, and related data).
   - Export schema and data to SQL/CSV where needed.
4. Visualization.
   - Load exported data into Power BI.
   - Build and view the dashboard defined in networkVulnScanDashboard.pbix.

## 8. How to Run
1. Run Nmap against the target and save XML output:
```bash
nmap -sS -sV -O -p- -oX scans/metasploitable-scan.xml 192.168.56.102
```

2. Parse Nmap XML to CSV:
```bash
cd code
python3 xml_to_csv.py ../scans/metasploitable-scan.xml
```

3. Load vulnerability findings into PostgreSQL:
```bash
python3 nmap_to_postgresql.py
```

4. Use data sources in Power BI:
- Use CSVs in `database/exports/` and `scans/msf_scan.csv`.
- Open `powerbi/networkVulnScanDashboard.pbix`.
- Connect to exported CSV files or database.
- View dashboard findings.

Optional one-command local automation:
```bash
./run_local_pipeline.sh
```

Optional scheduled local automation (example: every 30 minutes):
```bash
crontab -e
*/30 * * * * cd /Users/dtoledo/Desktop/fyp-vuln-scanner && ./run_local_pipeline.sh >> pipeline.log 2>&1
```

## 9. How to Re-run (If Desired)
1. Set up Kali Linux (or another Linux distribution) with:
    - Python 3
    - Nmap
    - Metasploit
    - PostgreSQL (if database storage is required)
2. Place provided XML/CSV files into a working directory, or generate new scan outputs.
3. Run the Python scripts from the code folder:
```bash
python3 nmap_to_postgresql.py
python3 xml_to_csv.py
```
4. Import or export data to PostgreSQL as described in the report and script comments.
5. Open `powerbi/networkVulnScanDashboard.pbix` with Power BI Desktop and point it to the required data sources.

## 10. Limitations and Notes
- Some runtime activity and intermediate files exist only inside the original Kali VM and are not fully reproduced in this submission.
- Several files were used for demonstration or experimentation and are not all included here.
- The artefacts in this folder are a curated subset designed to support assessment and understanding of core project components.
- The written report should be read alongside these artefacts for full context.

## 11. Ethical Considerations
All scanning for this project was carried out on intentionally vulnerable systems within a closed lab network. No scans were run against systems without explicit permission.

## 12. Design Rationale
How the pipeline works:
- Discovery: Nmap and Metasploit collect host, service, and vulnerability evidence.
- Transformation: Python scripts parse XML/CSV outputs into structured datasets.
- Storage: PostgreSQL stores normalized records for querying.
- Reporting: Power BI consumes exports to produce risk-focused visualizations.

Why Microsoft Power BI was selected:
- Fast dashboard development with strong filtering and drill-down.
- Widely used in enterprise reporting, improving practical relevance.
- Integrates well with CSV and PostgreSQL data sources.
- Supports publishing and refresh workflows that can be expanded for operational use.

## 13. Stress Testing and Overload Behavior
Stress testing approach:
- Repeated scan imports and CSV refresh cycles.
- Processing of larger scan files to observe parse/runtime behavior.
- Dashboard interaction tests under higher record counts and multi-filter usage.

Observed overload scenarios:
- High-cardinality visuals reduced responsiveness when many categories were shown.
- Simultaneous slicer filters increased render/query time on lower-resource systems.
- Dense service/vulnerability tables reduced readability in single-page views.

Mitigations applied:
- Summary visuals first (severity distribution and top vulnerable services), then drill-through.
- Reduced default visual density and tightened filter scope.
- Modular exports (hosts/services/vulns) to keep queries lighter.

## 14. Scalability, Maintainability, and Compatibility
Scalability path:
- Extend from single host to subnet ranges and multiple targets.
- Run scheduled scans and append historical results.
- Add batching/queueing for larger import workloads.

Maintainability features:
- Modular workflow (scan -> parse -> store -> visualize).
- Standard formats (XML, CSV, SQL) to reduce lock-in.
- Clear folder structure and schema separation for easier troubleshooting.

Compatibility:
- Microsoft ecosystem: Power BI, Windows-hosted PostgreSQL, and potential Azure integration.
- Beyond Microsoft: outputs can be consumed by other BI tools and SIEM/data platforms.

## 15. Cloud/Azure Future Work
Current constraint encountered:
- Azure/AWS integration attempts were limited by ISP firewall and SSL certificate interception issues, which also affected Power BI cloud connectivity.

Planned next steps:
- Use student Azure credits to deploy a small PostgreSQL-compatible endpoint.
- Publish dashboard to Power BI Service with controlled refresh testing.
- Add secure ingestion and certificate validation checks for cloud data sources.
- Prototype automation for VM lifecycle/recovery telemetry as a project extension.

## 16. Author
Darrel Toledo  
Final Year Project  
BSc (Hons) Computer Science (Cyber Security and Networks)
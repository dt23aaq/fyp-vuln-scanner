Network Vulnerability Scanner with Power B.I.

1. PROJECT TITLE
**Network Vulnerability Scanner with PostgreSQL and Power BI**

2. PROJECT SUMMARY
This project implements a network vulnerability scanning workflow in a controlled virtual lab environment. Nmap and Metasploit are used on Kali Linux to scan an intentionally vulnerable target (Metasploitable 2). The resulting scan data is processed using Python scripts and prepared for storage in PostgreSQL and visualisation in Power BI.

The focus of the project is to demonstrate:
- automated collection of network scan results,
- basic processing and preparation of vulnerability data,
- and presentation of findings in a dashboard format suitable for technical reporting.

3. LAB ENVIRONMENT

Scanner:
- Kali Linux (scanner / processing host)
- IP address: 192.168.56.101

Target:
- Metasploitable 2 (intentionally vulnerable target)
- IP address: 192.168.56.102

Network range used during testing:
- 192.168.1.0/24 (lab subnet reference)

Tools used:
- Nmap
- Metasploit
- Python
- PostgreSQL
- Power BI

All scans were carried out in a private lab using intentionally vulnerable systems.

4. PURPOSE OF THIS SUBMISSION FOLDER
This submission folder is a cleaned copy of the main artefacts produced during the project. It is not a full VM backup, but it contains:

- the key Python scripts used in the processing pipeline,
- selected Nmap and Metasploit output files,
- (optionally) database export files, if present,
- the Power BI dashboard file,
- and screenshots used as evidence of the system in use.

Some parts of the project (for example, repeated scan runs and interactive work in Kali) are not fully reproduced here but are documented in the written report.

5. FOLDER STRUCTURE

```
FYP_Submission/
├── README.txt
├── code/
│   ├── nmap_to_progres.py
│   ├── xml_to_csv
│   └── README
├── scans/
│   ├── metasploitable-full.xml
│   ├── metasploitable-scan.xml
│   └── msf_scan.csv
├── database/
│   ├── schema.sql          (if available)
│   ├── db_export.sql       (if available)
│   └── exports/
│       ├── hosts.csv       (if available)
│       ├── services.csv    (if available)
│       └── vulns.csv       (if available)
├── screenshots/
└── powerbi/
    └── networkVulnScanDashboard.pbix
```

6. FILE DESCRIPTIONS

6.1 Code (code/)

- nmap_to_progres.py
  Python script that connects to PostgreSQL, creates the vulnerability table, and inserts selected vulnerability findings associated with the Metasploitable scan.

- xml_to_csv
  Python script that automatically parses Nmap XML output and extracts open ports, protocols, services, product names, and versions into CSV format.

- README
  Original short project note file retained as a development artefact.

6.2 Scan and data artefacts (scans/)

- metasploitable-full.xml  
  Full Nmap scan output against the Metasploitable 2 target. This file demonstrates a complete scan result used in the project.

- metasploitable-scan.xml  
  Additional Nmap scan output used during development and testing.

- msf_scan.csv  
  CSV file containing Metasploit-related scan or vulnerability information exported during the project.

6.3 Database files (database/ and database/exports/)

These files are included only if database exports were generated and retained:

- schema.sql  
  PostgreSQL schema export (table definitions for hosts, services, vulnerabilities, etc.).

- db_export.sql  
  Full PostgreSQL database export used to preserve the state of the vulnerability data at the time of export.

- exports/hosts.csv  
  Export of the hosts table as CSV.

- exports/services.csv  
  Export of the services table as CSV.

- exports/vulns.csv  
  Export of the vulnerabilities table as CSV.

If any of these files are missing, it means that particular export was performed only within the Kali environment and not preserved in this final copy. The schema and table design are described in the written report.

6.4 Screenshots (screenshots/)

- Various PNG/JPEG images (filenames may vary) showing:
  - Nmap and Metasploit scans running in Kali,
  - PostgreSQL tables containing imported data,
  - the Power BI dashboard views.

These are included as visual evidence that the workflow was run successfully.

6.5 Power BI dashboard (powerbi/)

- networkVulnScanDashboard.pbix  
  Power BI Desktop report file created from the processed scan data. This file contains the main dashboard and visualisations discussed in the report.

7. WORKFLOW SUMMARY

The intended workflow for the project is:

1. Network scanning  
   - Use Nmap (and Metasploit where applicable) on Kali Linux to scan the target host(s).  
   - Save the output to XML (and CSV for Metasploit).

2. Processing  
   - Use the Python scripts (e.g. nmap_to_progres.py, xml_to_csv) to parse the scan results and prepare data for storage or further analysis.

3. Storage (optional in this folder)  
   - Store the processed data in PostgreSQL tables (hosts, services, vulnerabilities, etc.).  
   - Export schema and data to SQL/CSV where needed.

4. Visualisation  
   - Load the exported data into Power BI.  
   - Build and view the dashboard defined in networkVulnScanDashboard.pbix.

8. HOW TO RE-RUN (IF DESIRED)

To re-use the scripts in a similar environment:

1. Set up Kali Linux (or another Linux distribution) with:
   - Python 3
   - Nmap
   - Metasploit
   - PostgreSQL (if database storage is required)

2. Place the provided XML and CSV files into a working directory or generate new scan outputs using Nmap/Metasploit.

3. Run the Python scripts from the code/ folder, for example:

   - python3 nmap_to_progres.py  
   - python3 xml_to_csv

   (Exact arguments and usage depend on the implementation inside the scripts.)

4. Import or export data to PostgreSQL as described in the report and in any project-specific comments inside the scripts.

5. Open powerbi/networkVulnScanDashboard.pbix with Power BI Desktop and point it to the appropriate CSV files or database connection, if required.

9. LIMITATIONS AND NOTES

- Some runtime activity and intermediate files exist only inside the original Kali VM and are not fully reproduced in this submission.
- Several files were used purely for demonstration or experimentation and are not all included here.
- The artefacts in this folder are a cleaned and structured subset designed to support assessment and understanding of the main project components.
- The written report should be read alongside these artefacts for full context.

10. ETHICAL CONSIDERATIONS

All scanning for this project was carried out on intentionally vulnerable systems within a closed lab network. No scans were run against systems without explicit permission.

11. AUTHOR
Darrel Toledo
Final Year Project
BSc (Hons) Computer Science (Cyber Security and Networks)

# SOC Log Analyzer

## About This Project
A Python-based Security Operations Center (SOC) log analysis tool that simulates 
real-world SIEM (Security Information and Event Management) functionality. 
This tool automatically reads server log files, detects security threats using 
pattern matching, flags suspicious IP addresses, and generates a structured 
incident report — mimicking the day-to-day workflow of a SOC Analyst.

## What Problem Does It Solve?
In a real SOC environment, analysts manually review thousands of log lines daily 
to find threats. This tool automates that process — scanning logs in seconds, 
categorizing threats by severity, and producing a clean report ready for 
escalation or documentation.

## Features
- Detects 7 threat categories automatically:
  - Failed Login Attempts
  - Brute Force Attacks
  - Port Scan Detection
  - Malware and Ransomware Signatures
  - Phishing and Malicious URL Activity
  - Privilege Escalation (sudo/root abuse)
  - Data Exfiltration Attempts
- Flags known suspicious IP addresses from a watchlist
- Assigns severity levels — HIGH, MEDIUM, LOW — to each threat type
- Displays top 5 most active IPs in the log
- Generates a full console report with visual threat bars
- Exports all findings to a structured JSON report file

## Technologies Used
- Python 3
- Regular Expressions (re module)
- JSON
- Collections (Counter)
- Datetime

## Real-World Alignment
This project directly mirrors tools and workflows used in professional SOC environments:

| This Project | Real World Equivalent |
|---|---|
| Pattern matching on logs | Splunk SPL queries |
| Suspicious IP watchlist | Threat Intelligence feeds |
| Severity rating system | CVSS / SIEM alert priorities |
| JSON report export | SOAR ticketing integration |
| Brute force detection | IDS/IPS alert rules |

## How to Run

**Step 1 — Make sure Python is installed**
```bash
python --version
```

**Step 2 — Clone this repository**
```bash
git clone https://github.com/YOUR-USERNAME/soc-log-analyzer.git
cd soc-log-analyzer
```

**Step 3 — Run the analyzer**
```bash
python analyzer.py
```

**Step 4 — Check the output**
- Console will show the full threat report
- A file called `report.json` will be created automatically

## Sample Output

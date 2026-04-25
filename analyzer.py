import re
import json
from collections import Counter
from datetime import datetime

# ─── Threat Signatures ───────────────────────────────────────────────
PATTERNS = {
    "Failed Login":    r"Failed password|authentication failure|Invalid user",
    "Brute Force":     r"repeated login failure|too many authentication failures",
    "Port Scan":       r"SYN flood|port scan detected|nmap",
    "Malware":         r"malware detected|trojan|ransomware|backdoor",
    "Phishing":        r"phishing|suspicious link|malicious URL",
    "Privilege Abuse": r"sudo|root login|privilege escalation",
    "Data Exfil":      r"large outbound transfer|unusual data transfer|exfiltration",
}

SUSPICIOUS_IPS = {
    "192.168.1.99",
    "10.0.0.254",
    "172.16.0.55",
    "203.0.113.77",
}

# ─── Log Parser ──────────────────────────────────────────────────────
def parse_log(filepath):
    findings   = {k: [] for k in PATTERNS}
    ip_counter = Counter()
    total_lines = 0

    try:
        with open(filepath, "r") as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"[ERROR] File not found: {filepath}")
        return None

    for line in lines:
        total_lines += 1
        line = line.strip()

        for threat, pattern in PATTERNS.items():
            if re.search(pattern, line, re.IGNORECASE):
                findings[threat].append(line)

        ip_match = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
        for ip in ip_match:
            ip_counter[ip] += 1

    return findings, ip_counter, total_lines

# ─── Severity Rating ─────────────────────────────────────────────────
def severity(threat, count):
    high   = ["Brute Force", "Malware", "Privilege Abuse", "Data Exfil"]
    medium = ["Failed Login", "Port Scan", "Phishing"]
    if threat in high   and count > 0: return "HIGH"
    if threat in medium and count > 0: return "MEDIUM"
    return "LOW"

# ─── Report Generator ────────────────────────────────────────────────
def generate_report(filepath):
    result = parse_log(filepath)
    if result is None:
        return

    findings, ip_counter, total_lines = result
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_threats = sum(len(v) for v in findings.values())

    print("\n" + "=" * 55)
    print("        SOC LOG ANALYSIS REPORT")
    print("=" * 55)
    print(f"  Analyst    : Automated SOC Analyzer v1.0")
    print(f"  Log File   : {filepath}")
    print(f"  Timestamp  : {timestamp}")
    print(f"  Total Lines: {total_lines}")
    print(f"  Total Hits : {total_threats}")
    print("=" * 55)

    print("\n[THREAT SUMMARY]\n")
    for threat, events in findings.items():
        count = len(events)
        sev   = severity(threat, count)
        bar   = "█" * min(count, 20)
        print(f"  {threat:<20} | {sev:<6} | {count:>3} events | {bar}")

    print("\n" + "-" * 55)
    print("[TOP SUSPICIOUS IPs]\n")
    flagged = {ip: c for ip, c in ip_counter.items() if ip in SUSPICIOUS_IPS}
    if flagged:
        for ip, count in sorted(flagged.items(), key=lambda x: -x[1]):
            print(f"  [!] {ip:<18} — {count} occurrences  ← FLAGGED")
    else:
        print("  No known suspicious IPs detected.")

    print("\n" + "-" * 55)
    print("[TOP 5 MOST ACTIVE IPs]\n")
    for ip, count in ip_counter.most_common(5):
        flag = " ← SUSPICIOUS" if ip in SUSPICIOUS_IPS else ""
        print(f"  {ip:<18} — {count} hits{flag}")

    print("\n" + "-" * 55)
    print("[DETAILED FINDINGS]\n")
    for threat, events in findings.items():
        if events:
            print(f"  [{threat}]")
            for e in events[:3]:
                print(f"    → {e[:100]}")
            if len(events) > 3:
                print(f"    ... and {len(events)-3} more")
            print()

    print("=" * 55)
    print("  END OF REPORT")
    print("=" * 55 + "\n")

    report_data = {
        "timestamp": timestamp,
        "log_file": filepath,
        "total_lines": total_lines,
        "total_threats": total_threats,
        "findings": {k: len(v) for k, v in findings.items()},
        "suspicious_ips": flagged,
    }
    with open("report.json", "w") as f:
        json.dump(report_data, f, indent=2)
    print("  [+] JSON report saved to report.json\n")

# ─── Entry Point ─────────────────────────────────────────────────────
if __name__ == "__main__":
    generate_report("sample.log")

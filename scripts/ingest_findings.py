#!/usr/bin/env python3
"""
Central Normalization & Ingestion Pipeline
Parses all scanner JSON reports and normalizes into unified schema.
Outputs:
- SQLite database (reports/secmetrics.db)
- PostgreSQL-compatible SQL dump (reports/secmetrics_postgres_seed.sql)
- SonarQube Generic Issue Import JSON (reports/sonar-generic-issues.json)
- Compliance audit CSV (reports/compliance_audit_export.csv)
"""

import json
import sqlite3
import csv
import uuid
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import sys

PROJECT_ROOT = Path("/opt/data/profiles/jack/home/secure-code-review-framework")
REPORTS_DIR = PROJECT_ROOT / "reports" / "baseline"
DB_PATH = PROJECT_ROOT / "reports" / "secmetrics.db"
SQL_DUMP_PATH = PROJECT_ROOT / "reports" / "secmetrics_postgres_seed.sql"
SONAR_JSON_PATH = PROJECT_ROOT / "reports" / "sonar-generic-issues.json"
COMPLIANCE_CSV_PATH = PROJECT_ROOT / "reports" / "compliance_audit_export.csv"

# Unified severity mapping
SEVERITY_MAP = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
    "NOTE": "LOW",
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MODERATE": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
}

# CWE to OWASP mapping
CWE_TO_OWASP = {
    "78": "A03:2021 - Injection",
    "79": "A03:2021 - Injection", 
    "89": "A03:2021 - Injection",
    "95": "A03:2021 - Injection",
    "22": "A01:2021 - Broken Access Control",
    "259": "A07:2021 - Identification and Authentication Failures",
    "328": "A02:2021 - Cryptographic Failures",
    "338": "A07:2021 - Identification and Authentication Failures",
    "502": "A08:2021 - Software and Data Integrity Failures",
    "798": "A07:2021 - Identification and Authentication Failures",
    "1333": "A04:2021 - Insecure Design",
    "200": "A01:2021 - Broken Access Control",
    "918": "A10:2021 - Server-Side Request Forgery",
    "352": "A05:2021 - Security Misconfiguration",
    "434": "A01:2021 - Broken Access Control",
    "476": "A05:2021 - Security Misconfiguration",
    "862": "A01:2021 - Broken Access Control",
    "190": "A05:2021 - Security Misconfiguration",
    "287": "A07:2021 - Identification and Authentication Failures",
    "119": "A05:2021 - Security Misconfiguration",
    "276": "A05:2021 - Security Misconfiguration",
    "915": "A05:2021 - Security Misconfiguration",
    "362": "A05:2021 - Security Misconfiguration",
    "269": "A05:2021 - Security Misconfiguration",
    "1321": "A05:2021 - Security Misconfiguration",
    "306": "A07:2021 - Identification and Authentication Failures",
}

# CWE to CERT mapping
CWE_TO_CERT = {
    "78": "ENV03-C",
    "79": "IDS11-J",
    "89": "IDS00-J",
    "95": "IDS16-J",
    "22": "FIO05-J",
    "259": "MSC41-C",
    "328": "MSC32-C",
    "338": "MSC30-C",
    "502": "SER00-J",
    "798": "MSC41-C",
    "1333": "IDS17-J",
    "200": "FIO05-J",
    "918": "IDS15-J",
}

def get_severity(raw: str) -> str:
    return SEVERITY_MAP.get(raw.upper(), "MEDIUM")

def get_owasp(cwe: str) -> str:
    return CWE_TO_OWASP.get(str(cwe), "A05:2021 - Security Misconfiguration")

def get_cert(cwe: str) -> str:
    return CWE_TO_CERT.get(str(cwe), "")

def generate_finding_id(tool: str, rule: str, file: str, line: int) -> str:
    """Generate deterministic finding ID"""
    raw = f"{tool}:{rule}:{file}:{line}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]

def init_db():
    """Initialize SQLite database with unified schema"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_runs (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            tool_name TEXT NOT NULL,
            config TEXT,
            total_findings INTEGER DEFAULT 0
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            scan_run_id TEXT NOT NULL,
            tool_name TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            file_path TEXT NOT NULL,
            line_number INTEGER,
            owasp_category TEXT,
            cwe_id TEXT,
            cert_id TEXT,
            description TEXT,
            remediation TEXT,
            status TEXT DEFAULT 'OPEN',
            raw_json TEXT,
            FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id)
        )
    """)
    
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_owasp ON findings(owasp_category)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_cwe ON findings(cwe_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_tool ON findings(tool_name)")
    
    conn.commit()
    return conn

def parse_semgrep(json_data: Dict, conn: sqlite3.Connection, scan_run_id: str) -> int:
    """Parse Semgrep JSON output"""
    cursor = conn.cursor()
    count = 0
    
    for result in json_data.get("results", []):
        extra = result.get("extra", {})
        meta = extra.get("metadata", {})
        
        finding = {
            "id": generate_finding_id("semgrep", result.get("check_id", ""), result["path"], result["start"]["line"]),
            "scan_run_id": scan_run_id,
            "tool_name": "semgrep",
            "rule_id": result.get("check_id", ""),
            "severity": get_severity(extra.get("severity", "ERROR")),
            "file_path": result["path"],
            "line_number": result["start"]["line"],
            "owasp_category": meta.get("owasp", get_owasp(meta.get("cwe", "").split(":")[0])),
            "cwe_id": meta.get("cwe", "").split(":")[0] if meta.get("cwe") else "",
            "cert_id": meta.get("cert", "").split(":")[0] if meta.get("cert") else get_cert(meta.get("cwe", "").split(":")[0]),
            "description": extra.get("message", "").split("\n\n")[0] if extra.get("message") else "",
            "remediation": extra.get("message", "").split("**Remediation:**")[-1].strip() if "**Remediation:**" in extra.get("message", "") else "",
            "status": "OPEN",
            "raw_json": json.dumps(result)
        }
        
        cursor.execute("""
            INSERT OR REPLACE INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (finding["id"], finding["scan_run_id"], finding["tool_name"], finding["rule_id"],
              finding["severity"], finding["file_path"], finding["line_number"],
              finding["owasp_category"], finding["cwe_id"], finding["cert_id"],
              finding["description"], finding["remediation"], finding["status"], finding["raw_json"]))
        count += 1
    
    return count

def parse_bandit(json_data: Dict, conn: sqlite3.Connection, scan_run_id: str) -> int:
    """Parse Bandit JSON output"""
    cursor = conn.cursor()
    count = 0
    
    for result in json_data.get("results", []):
        cwe_id = str(result.get("issue_cwe", {}).get("id", ""))
        
        finding = {
            "id": generate_finding_id("bandit", result.get("test_id", ""), result["filename"], result["line_number"]),
            "scan_run_id": scan_run_id,
            "tool_name": "bandit",
            "rule_id": result.get("test_id", ""),
            "severity": get_severity(result.get("issue_severity", "MEDIUM")),
            "file_path": result["filename"],
            "line_number": result["line_number"],
            "owasp_category": get_owasp(cwe_id),
            "cwe_id": cwe_id,
            "cert_id": get_cert(cwe_id),
            "description": result.get("issue_text", ""),
            "remediation": result.get("more_info", ""),
            "status": "OPEN",
            "raw_json": json.dumps(result)
        }
        
        cursor.execute("""
            INSERT OR REPLACE INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (finding["id"], finding["scan_run_id"], finding["tool_name"], finding["rule_id"],
              finding["severity"], finding["file_path"], finding["line_number"],
              finding["owasp_category"], finding["cwe_id"], finding["cert_id"],
              finding["description"], finding["remediation"], finding["status"], finding["raw_json"]))
        count += 1
    
    return count

def parse_eslint(json_data: List, conn: sqlite3.Connection, scan_run_id: str) -> int:
    """Parse ESLint JSON output"""
    cursor = conn.cursor()
    count = 0
    
    for file_result in json_data:
        file_path = file_result.get("filePath", "")
        for msg in file_result.get("messages", []):
            rule_id = msg.get("ruleId", "")
            cwe_id = ""
            if "security/detect" in rule_id:
                if "eval" in rule_id: cwe_id = "95"
                elif "child-process" in rule_id: cwe_id = "78"
                elif "fs-filename" in rule_id: cwe_id = "22"
                elif "unsafe-regex" in rule_id: cwe_id = "1333"
                elif "ssrf" in rule_id: cwe_id = "918"
            
            finding = {
                "id": generate_finding_id("eslint", rule_id, file_path, msg.get("line", 0)),
                "scan_run_id": scan_run_id,
                "tool_name": "eslint",
                "rule_id": rule_id,
                "severity": get_severity("ERROR" if msg.get("severity", 2) == 2 else "WARNING"),
                "file_path": file_path,
                "line_number": msg.get("line", 0),
                "owasp_category": get_owasp(cwe_id),
                "cwe_id": cwe_id,
                "cert_id": get_cert(cwe_id),
                "description": msg.get("message", ""),
                "remediation": f"Fix {rule_id} pattern. See ESLint security plugin docs.",
                "status": "OPEN",
                "raw_json": json.dumps(msg)
            }
            
            cursor.execute("""
                INSERT OR REPLACE INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (finding["id"], finding["scan_run_id"], finding["tool_name"], finding["rule_id"],
                  finding["severity"], finding["file_path"], finding["line_number"],
                  finding["owasp_category"], finding["cwe_id"], finding["cert_id"],
                  finding["description"], finding["remediation"], finding["status"], finding["raw_json"]))
            count += 1
    
    return count

def parse_gitleaks(json_data: List, conn: sqlite3.Connection, scan_run_id: str) -> int:
    """Parse Gitleaks JSON output"""
    cursor = conn.cursor()
    count = 0
    
    for result in json_data:
        finding = {
            "id": generate_finding_id("gitleaks", result.get("RuleID", ""), result["File"], result["StartLine"]),
            "scan_run_id": scan_run_id,
            "tool_name": "gitleaks",
            "rule_id": result.get("RuleID", ""),
            "severity": "CRITICAL",
            "file_path": result["File"],
            "line_number": result["StartLine"],
            "owasp_category": "A07:2021 - Identification and Authentication Failures",
            "cwe_id": "798",
            "cert_id": "MSC41-C",
            "description": result.get("Description", ""),
            "remediation": "Remove secret from code. Store in environment variable or secrets manager. Rotate exposed secret immediately.",
            "status": "OPEN",
            "raw_json": json.dumps(result)
        }
        
        cursor.execute("""
            INSERT OR REPLACE INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (finding["id"], finding["scan_run_id"], finding["tool_name"], finding["rule_id"],
              finding["severity"], finding["file_path"], finding["line_number"],
              finding["owasp_category"], finding["cwe_id"], finding["cert_id"],
              finding["description"], finding["remediation"], finding["status"], finding["raw_json"]))
        count += 1
    
    return count

def parse_dependency_check(json_data: Dict, conn: sqlite3.Connection, scan_run_id: str) -> int:
    """Parse consolidated dependency-check JSON"""
    cursor = conn.cursor()
    count = 0
    
    # Python dependencies
    for dep in json_data.get("python_dependencies", []):
        for vuln in dep.get("vulnerabilities", []):
            finding = {
                "id": generate_finding_id("pip-audit", vuln.get("id", ""), f"requirements.txt:{dep['package']}", 0),
                "scan_run_id": scan_run_id,
                "tool_name": "pip-audit",
                "rule_id": vuln.get("id", ""),
                "severity": get_severity(vuln.get("cvss", "HIGH")),
                "file_path": "vulnerable-samples/python-app/requirements.txt",
                "line_number": 0,
                "owasp_category": "A06:2021 - Vulnerable and Outdated Components",
                "cwe_id": "",
                "cert_id": "",
                "description": f"{dep['package']} {dep.get('installed_version', '')}: {vuln.get('description', '')}",
                "remediation": f"Upgrade {dep['package']} to {dep.get('fixed_version', 'latest')}",
                "status": "OPEN",
                "raw_json": json.dumps({"package": dep, "vulnerability": vuln})
            }
            
            cursor.execute("""
                INSERT OR REPLACE INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (finding["id"], finding["scan_run_id"], finding["tool_name"], finding["rule_id"],
                  finding["severity"], finding["file_path"], finding["line_number"],
                  finding["owasp_category"], finding["cwe_id"], finding["cert_id"],
                  finding["description"], finding["remediation"], finding["status"], finding["raw_json"]))
            count += 1
    
    # Node.js dependencies
    for dep in json_data.get("nodejs_dependencies", []):
        for vuln in dep.get("vulnerabilities", []):
            finding = {
                "id": generate_finding_id("npm-audit", vuln.get("id", ""), f"package.json:{dep['package']}", 0),
                "scan_run_id": scan_run_id,
                "tool_name": "npm-audit",
                "rule_id": vuln.get("id", ""),
                "severity": get_severity(vuln.get("cvss", "HIGH")),
                "file_path": "vulnerable-samples/node-app/package.json",
                "line_number": 0,
                "owasp_category": "A06:2021 - Vulnerable and Outdated Components",
                "cwe_id": "",
                "cert_id": "",
                "description": f"{dep['package']} {dep.get('installed_version', '')}: {vuln.get('description', '')}",
                "remediation": f"Upgrade {dep['package']} to latest secure version",
                "status": "OPEN",
                "raw_json": json.dumps({"package": dep, "vulnerability": vuln})
            }
            
            cursor.execute("""
                INSERT OR REPLACE INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (finding["id"], finding["scan_run_id"], finding["tool_name"], finding["rule_id"],
                  finding["severity"], finding["file_path"], finding["line_number"],
                  finding["owasp_category"], finding["cwe_id"], finding["cert_id"],
                  finding["description"], finding["remediation"], finding["status"], finding["raw_json"]))
            count += 1
    
    return count

def parse_pip_audit(json_data: Dict, conn: sqlite3.Connection, scan_run_id: str) -> int:
    """Parse pip-audit JSON output directly"""
    cursor = conn.cursor()
    count = 0
    
    for dep in json_data.get("dependencies", []):
        for vuln in dep.get("vulns", []):
            aliases = vuln.get("aliases", [])
            cve_id = next((a for a in aliases if a.startswith("CVE-")), "")
            ghsa_id = next((a for a in aliases if a.startswith("GHSA-")), "")
            
            finding = {
                "id": generate_finding_id("pip-audit", vuln.get("id", ""), f"requirements.txt:{dep['name']}", 0),
                "scan_run_id": scan_run_id,
                "tool_name": "pip-audit",
                "rule_id": cve_id or ghsa_id or vuln.get("id", ""),
                "severity": "HIGH",  # Default for unpinned CVEs
                "file_path": "vulnerable-samples/python-app/requirements.txt",
                "line_number": 0,
                "owasp_category": "A06:2021 - Vulnerable and Outdated Components",
                "cwe_id": "",
                "cert_id": "",
                "description": f"{dep['name']} {dep['version']}: {vuln.get('description', '')[:200]}",
                "remediation": f"Upgrade {dep['name']} to {' or '.join(vuln.get('fix_versions', ['latest']))}",
                "status": "OPEN",
                "raw_json": json.dumps({"package": dep, "vulnerability": vuln})
            }
            
            cursor.execute("""
                INSERT OR REPLACE INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (finding["id"], finding["scan_run_id"], finding["tool_name"], finding["rule_id"],
                  finding["severity"], finding["file_path"], finding["line_number"],
                  finding["owasp_category"], finding["cwe_id"], finding["cert_id"],
                  finding["description"], finding["remediation"], finding["status"], finding["raw_json"]))
            count += 1
    
    return count

def export_sonar_generic_issues(conn: sqlite3.Connection):
    """Export findings in SonarQube Generic Issue Import format"""
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM findings WHERE tool_name != 'pip-audit' AND tool_name != 'npm-audit'")
    rows = cursor.fetchall()
    
    issues = []
    for row in rows:
        issues.append({
            "engineId": row[2],  # tool_name
            "ruleId": row[3],    # rule_id
            "severity": row[4].upper(),  # severity
            "type": "CODE_SMELL",
            "primaryLocation": {
                "message": row[10],  # description
                "filePath": row[5].replace(str(PROJECT_ROOT) + "/", ""),  # file_path relative
                "textRange": {
                    "startLine": row[6] or 1,
                    "endLine": row[6] or 1
                }
            },
            "secondaryLocations": [],
            "effortMinutes": 30
        })
    
    sonar_output = {
        "issues": issues
    }
    
    with open(SONAR_JSON_PATH, "w") as f:
        json.dump(sonar_output, f, indent=2)
    
    print(f"Exported {len(issues)} issues to SonarQube format: {SONAR_JSON_PATH}")

def export_compliance_csv(conn: sqlite3.Connection):
    """Export full compliance audit CSV"""
    cursor = conn.cursor()
    cursor.execute("""
        SELECT tool_name, rule_id, severity, file_path, line_number, 
               owasp_category, cwe_id, cert_id, description, remediation, status
        FROM findings
        ORDER BY 
            CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 END,
            tool_name, file_path, line_number
    """)
    rows = cursor.fetchall()
    
    with open(COMPLIANCE_CSV_PATH, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Tool", "Rule ID", "Severity", "File Path", "Line Number",
            "OWASP Category", "CWE ID", "CERT ID", "Description", "Remediation", "Status"
        ])
        for row in rows:
            writer.writerow(row)
    
    print(f"Exported {len(rows)} findings to CSV: {COMPLIANCE_CSV_PATH}")

def export_postgres_sql(conn: sqlite3.Connection):
    """Export PostgreSQL-compatible SQL dump"""
    cursor = conn.cursor()
    
    with open(SQL_DUMP_PATH, "w") as f:
        f.write("-- PostgreSQL-compatible seed data for secmetrics\n")
        f.write(f"-- Generated: {datetime.utcnow().isoformat()}Z\n\n")
        
        # Schema
        f.write("""CREATE TABLE IF NOT EXISTS scan_runs (
    id UUID PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    tool_name VARCHAR(100) NOT NULL,
    config JSONB,
    total_findings INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    id UUID PRIMARY KEY,
    scan_run_id UUID NOT NULL REFERENCES scan_runs(id),
    tool_name VARCHAR(100) NOT NULL,
    rule_id VARCHAR(200) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    file_path TEXT NOT NULL,
    line_number INTEGER,
    owasp_category VARCHAR(100),
    cwe_id VARCHAR(20),
    cert_id VARCHAR(20),
    description TEXT,
    remediation TEXT,
    status VARCHAR(20) DEFAULT 'OPEN',
    raw_json JSONB
);

CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_owasp ON findings(owasp_category);
CREATE INDEX IF NOT EXISTS idx_findings_cwe ON findings(cwe_id);
CREATE INDEX IF NOT EXISTS idx_findings_tool ON findings(tool_name);

""")
        
        # Data
        cursor.execute("SELECT * FROM scan_runs")
        for row in cursor.fetchall():
            f.write(f"INSERT INTO scan_runs (id, timestamp, tool_name, config, total_findings) VALUES "
                   f"('{row[0]}', '{row[1]}', '{row[2]}', '{row[3] or '{}'}', {row[4]});\n")
        
        f.write("\n")
        
        cursor.execute("SELECT * FROM findings")
        for row in cursor.fetchall():
            raw_json = row[13].replace("'", "''") if row[13] else "{}"
            desc = row[10].replace("'", "''") if row[10] else ""
            rem = row[11].replace("'", "''") if row[11] else ""
            f.write(f"INSERT INTO findings (id, scan_run_id, tool_name, rule_id, severity, file_path, line_number, "
                   f"owasp_category, cwe_id, cert_id, description, remediation, status, raw_json) VALUES "
                   f"('{row[0]}', '{row[1]}', '{row[2]}', '{row[3]}', '{row[4]}', '{row[5]}', "
                   f"{row[6] or 'NULL'}, '{row[7] or ''}', '{row[8] or ''}', '{row[9] or ''}', "
                   f"'{desc}', '{rem}', '{row[12]}', '{raw_json}');\n")
    
    print(f"Exported PostgreSQL SQL dump: {SQL_DUMP_PATH}")

def main():
    print("=== Central Normalization & Ingestion Pipeline ===")
    
    conn = init_db()
    cursor = conn.cursor()
    
    scan_run_id = str(uuid.uuid4())
    timestamp = datetime.utcnow().isoformat() + "Z"
    
    # Register scan run
    cursor.execute("""
        INSERT INTO scan_runs (id, timestamp, tool_name, config, total_findings)
        VALUES (?, ?, ?, ?, ?)
    """, (scan_run_id, timestamp, "aggregated", "{}", 0))
    
    total_findings = 0
    
    # Parse each report
    parsers = [
        ("semgrep-custom.json", parse_semgrep, "semgrep"),
        ("bandit.json", parse_bandit, "bandit"),
        ("eslint.json", parse_eslint, "eslint"),
        ("gitleaks.json", parse_gitleaks, "gitleaks"),
        ("dependency-check.json", parse_dependency_check, "dependency-check"),
        ("pip-audit.json", parse_pip_audit, "pip-audit"),
    ]
    
    for filename, parser, tool_name in parsers:
        filepath = REPORTS_DIR / filename
        if not filepath.exists():
            print(f"  Skipping {filename} (not found)")
            continue
        
        print(f"  Parsing {filename}...")
        try:
            with open(filepath) as f:
                data = json.load(f)
            count = parser(data, conn, scan_run_id)
            total_findings += count
            print(f"    → {count} findings normalized")
        except Exception as e:
            print(f"    → ERROR: {e}")
    
    # Update scan run total
    cursor.execute("UPDATE scan_runs SET total_findings = ? WHERE id = ?", (total_findings, scan_run_id))
    conn.commit()
    
    # Export artifacts
    print("\n  Exporting artifacts...")
    export_sonar_generic_issues(conn)
    export_compliance_csv(conn)
    export_postgres_sql(conn)
    
    # Print summary
    print("\n=== Aggregation Summary ===")
    cursor.execute("""
        SELECT tool_name, severity, COUNT(*) as count
        FROM findings
        GROUP BY tool_name, severity
        ORDER BY tool_name, 
            CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 END
    """)
    for row in cursor.fetchall():
        print(f"  {row[0]:15s} | {row[1]:8s} | {row[2]:3d}")
    
    cursor.execute("""
        SELECT owasp_category, COUNT(*) as count
        FROM findings
        WHERE owasp_category IS NOT NULL AND owasp_category != ''
        GROUP BY owasp_category
        ORDER BY count DESC
    """)
    print("\n  By OWASP Category:")
    for row in cursor.fetchall():
        print(f"    {row[0]:50s} | {row[1]:3d}")
    
    cursor.execute("""
        SELECT cwe_id, COUNT(*) as count
        FROM findings
        WHERE cwe_id IS NOT NULL AND cwe_id != ''
        GROUP BY cwe_id
        ORDER BY count DESC
        LIMIT 10
    """)
    print("\n  Top CWEs:")
    for row in cursor.fetchall():
        print(f"    CWE-{row[0]:4s} | {row[1]:3d}")
    
    conn.close()
    print(f"\n✅ Pipeline complete. Database: {DB_PATH}")

if __name__ == "__main__":
    main()
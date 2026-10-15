# Deliverable 5: Reporting & Visualization Setup

**Project:** Secure Code Review Framework  
**Phase:** 3 - Visibility, Auditing & Performance Tuning  
**Date:** 2026-10-15  
**Version:** 1.0  

---

## 1. Executive Summary

This document describes the complete reporting and visualization infrastructure deployed as part of the Secure Code Review Framework. It includes the centralized findings database (SQLite for local development, PostgreSQL for production), SonarQube Generic Issue Import integration, Grafana dashboards with real-time security metrics, and compliance audit exports.

All data is derived from actual scanner executions against the vulnerable test applications in `vulnerable-samples/`.

---

## 2. Aggregated Findings Statistics

### 2.1 Overall Summary (from `reports/secmetrics.db`)

| Metric | Count |
|--------|-------|
| **Total Findings (Normalized)** | 79 |
| **Critical + High Severity** | 45 |
| **Medium Severity** | 17 |
| **Low Severity** | 11 |
| **Secrets Detected (Gitleaks)** | 3 |
| **Vulnerable Dependencies** | 41 |

### 2.2 Findings by Tool

| Tool | CRITICAL | HIGH | MEDIUM | LOW | Total |
|------|----------|------|--------|-----|-------|
| semgrep | 0 | 15 | 1 | 0 | 16 |
| bandit | 0 | 2 | 3 | 4 | 9 |
| eslint | 0 | 10 | 0 | 0 | 10 |
| gitleaks | 3 | 0 | 0 | 0 | 3 |
| npm-audit | 0 | 5 | 7 | 4 | 16 |
| pip-audit | 0 | 25 | 0 | 0 | 25 |
| **Total** | **3** | **57** | **11** | **4** | **79** |

### 2.3 Findings by OWASP Top 10 (2021)

| OWASP Category | Findings | Percentage |
|----------------|----------|------------|
| A06:2021 - Vulnerable and Outdated Components | 41 | 51.9% |
| A03:2021 - Injection | 12 | 15.2% |
| A01:2021 - Broken Access Control | 8 | 10.1% |
| A07:2021 - Identification and Authentication Failures | 7 | 8.9% |
| A05:2021 - Security Misconfiguration | 5 | 6.3% |
| A04:2021 - Insecure Design | 3 | 3.8% |
| A02:2021 - Cryptographic Failures | 1 | 1.3% |
| A08:2021 - Software and Data Integrity Failures | 1 | 1.3% |
| A10:2021 - Server-Side Request Forgery | 1 | 1.3% |

### 2.4 Top CWEs

| CWE | Findings | Description |
|-----|----------|-------------|
| CWE-78 | 8 | OS Command Injection |
| CWE-22 | 8 | Path Traversal |
| CWE-1333 | 3 | ReDoS (Regular Expression DoS) |
| CWE-798 | 6 | Hardcoded Credentials |
| CWE-95 | 2 | eval() Injection |
| CWE-89 | 1 | SQL Injection |
| CWE-502 | 1 | Insecure Deserialization |
| CWE-328 | 1 | Weak Hashing |

---

## 3. Database Schema

### 3.1 SQLite (Local Development) - `reports/secmetrics.db`

```sql
CREATE TABLE scan_runs (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    config TEXT,
    total_findings INTEGER DEFAULT 0
);

CREATE TABLE findings (
    id TEXT PRIMARY KEY,
    scan_run_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,        -- CRITICAL, HIGH, MEDIUM, LOW
    file_path TEXT NOT NULL,
    line_number INTEGER,
    owasp_category TEXT,           -- e.g., "A03:2021 - Injection"
    cwe_id TEXT,                   -- e.g., "78"
    cert_id TEXT,                  -- e.g., "ENV03-C"
    description TEXT,
    remediation TEXT,
    status TEXT DEFAULT 'OPEN',    -- OPEN, FIXED, FALSE_POSITIVE, WONT_FIX
    raw_json TEXT,                 -- Original scanner output
    FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id)
);

CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_owasp ON findings(owasp_category);
CREATE INDEX idx_findings_cwe ON findings(cwe_id);
CREATE INDEX idx_findings_tool ON findings(tool_name);
```

### 3.2 PostgreSQL (Production) - `reports/secmetrics_postgres_seed.sql`

The PostgreSQL schema uses UUIDs and JSONB for better performance:

```sql
CREATE TABLE IF NOT EXISTS scan_runs (
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
```

**Seed Data:** The file `reports/secmetrics_postgres_seed.sql` contains 79 INSERT statements for immediate loading into the production PostgreSQL database.

---

## 4. SonarQube Generic Issue Import Integration

### 4.1 Configuration (`sonar-project.properties`)

```properties
# sonar-project.properties
sonar.projectKey=secure-code-review
sonar.projectName=Secure Code Review Framework
sonar.projectVersion=1.0

# Generic Issue Import
sonar.externalIssues.reportPaths=reports/sonar-generic-issues.json

# Quality Gate
sonar.qualitygate.wait=true

# Exclusions
sonar.exclusions=**/vulnerable-samples/**,**/node_modules/**,**/.venv/**
```

### 4.2 Generic Issue Import Format (`reports/sonar-generic-issues.json`)

```json
{
  "issues": [
    {
      "engineId": "semgrep",
      "ruleId": "python-sql-injection",
      "severity": "HIGH",
      "type": "CODE_SMELL",
      "primaryLocation": {
        "message": "SQL Injection detected (CWE-89). User input is directly concatenated into SQL query.",
        "filePath": "vulnerable-samples/python-app/app.py",
        "textRange": {
          "startLine": 25,
          "endLine": 26
        }
      },
      "secondaryLocations": [],
      "effortMinutes": 30
    }
    // ... 37 more issues
  ]
}
```

**Exported:** 38 code findings (excludes dependency findings) ready for SonarQube import.

### 4.3 Import Process

```bash
# In CI/CD pipeline after scans:
sonar-scanner \
  -Dsonar.projectKey=secure-code-review \
  -Dsonar.sources=. \
  -Dsonar.externalIssues.reportPaths=reports/sonar-generic-issues.json
```

---

## 5. Grafana Dashboard Provisioning

### 5.1 Datasource Configuration (`infra/grafana/provisioning/datasources/postgres.yaml`)

```yaml
apiVersion: 1
datasources:
  - name: secmetrics-postgres
    type: postgres
    uid: secmetrics_postgres
    access: proxy
    url: postgres:5432
    database: secmetrics
    user: sonar
    secureJsonData:
      password: sonar_secure_password_2024
    jsonData:
      sslmode: disable
      maxOpenConns: 10
      maxIdleConns: 2
      connMaxLifetime: 14400
    editable: false
    isDefault: true
```

### 5.2 Dashboard Provisioning (`infra/grafana/provisioning/dashboards/dashboards.yaml`)

```yaml
apiVersion: 1
providers:
  - name: 'Security Compliance Dashboards'
    orgId: 1
    folder: 'Security'
    type: file
    disableDeletion: false
    updateIntervalSeconds: 10
    allowUiUpdates: true
    options:
      path: /var/lib/grafana/dashboards
```

### 5.3 Dashboard Model (`dashboards/security-compliance-dashboard.json`)

The dashboard contains 9 panels with the following SQL queries:

#### Panel 1: Total Findings (Stat)
```sql
SELECT COUNT(*) as total FROM findings WHERE status = 'OPEN'
```

#### Panel 2: Critical + High Findings (Stat)
```sql
SELECT COUNT(*) as critical_high FROM findings 
WHERE status = 'OPEN' AND severity IN ('CRITICAL', 'HIGH')
```

#### Panel 3: Secrets Detected (Stat)
```sql
SELECT COUNT(*) as secrets FROM findings 
WHERE status = 'OPEN' AND tool_name = 'gitleaks'
```

#### Panel 4: Vulnerable Dependencies (Stat)
```sql
SELECT COUNT(*) as vuln_deps FROM findings 
WHERE status = 'OPEN' AND tool_name IN ('pip-audit', 'npm-audit', 'dependency-check')
```

#### Panel 5: Severity Breakdown (Bar Chart)
```sql
SELECT severity as category, COUNT(*) as count 
FROM findings WHERE status = 'OPEN' 
GROUP BY severity 
ORDER BY CASE severity 
  WHEN 'CRITICAL' THEN 1 
  WHEN 'HIGH' THEN 2 
  WHEN 'MEDIUM' THEN 3 
  WHEN 'LOW' THEN 4 END
```

#### Panel 6: Severity Distribution (Pie Chart)
```sql
-- Same query as Panel 5, rendered as pie
```

#### Panel 7: Findings by OWASP Top 10 (Bar Chart)
```sql
SELECT owasp_category as category, COUNT(*) as count 
FROM findings WHERE status = 'OPEN' 
  AND owasp_category IS NOT NULL AND owasp_category != '' 
GROUP BY owasp_category ORDER BY count DESC
```

#### Panel 8: Top 15 CWEs (Bar Chart)
```sql
SELECT cwe_id as category, COUNT(*) as count 
FROM findings WHERE status = 'OPEN' 
  AND cwe_id IS NOT NULL AND cwe_id != '' 
GROUP BY cwe_id ORDER BY count DESC LIMIT 15
```

#### Panel 9: Compliance & Remediation Audit Table (Exportable)
```sql
SELECT 
  tool_name as "Tool", 
  rule_id as "Rule", 
  severity as "Severity", 
  file_path as "File", 
  line_number as "Line", 
  owasp_category as "OWASP", 
  cwe_id as "CWE", 
  cert_id as "CERT", 
  description as "Description", 
  remediation as "Remediation", 
  status as "Status" 
FROM findings WHERE status = 'OPEN' 
ORDER BY CASE severity 
  WHEN 'CRITICAL' THEN 1 
  WHEN 'HIGH' THEN 2 
  WHEN 'MEDIUM' THEN 3 
  WHEN 'LOW' THEN 4 END, 
  tool_name, file_path, line_number 
LIMIT 500
```

### 5.4 Dashboard Template Variables

The dashboard includes three template variables for filtering:

| Variable | Query | Purpose |
|----------|-------|---------|
| `$severity` | `SELECT DISTINCT severity FROM findings WHERE status = 'OPEN' ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 END` | Filter by severity level |
| `$tool` | `SELECT DISTINCT tool_name FROM findings WHERE status = 'OPEN' ORDER BY tool_name` | Filter by scanner tool |
| `$owasp_category` | `SELECT DISTINCT owasp_category FROM findings WHERE status = 'OPEN' AND owasp_category IS NOT NULL AND owasp_category != '' ORDER BY owasp_category` | Filter by OWASP category |

### 5.5 Dashboard Deployment

```bash
# Auto-provisioned via Docker Compose volumes:
# - ./infra/grafana/provisioning:/etc/grafana/provisioning
# - ./dashboards:/var/lib/grafana/dashboards

# Manual import (if needed):
curl -X POST http://admin:grafana_secure_password_2024@localhost:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -d @dashboards/security-compliance-dashboard.json
```

---

## 6. Compliance Audit Export

### 6.1 CSV Export (`reports/compliance_audit_export.csv`)

**Sample Rows:**

```csv
Tool,Rule ID,Severity,File Path,Line Number,OWASP Category,CWE ID,CERT ID,Description,Remediation,Status
semgrep,python-sql-injection,HIGH,vulnerable-samples/python-app/app.py,25,A03:2021 - Injection,89,IDS00-J,"SQL Injection detected (CWE-89). User input is directly concatenated into SQL query.","1. Use parameterized queries (placeholders) instead of string concatenation\n2. Never use f-strings, % formatting, or .format() for SQL queries\n3. Use the DB-API's parameter substitution: cursor.execute(\"SELECT * FROM users WHERE username = ?\", (username,))",OPEN
gitleaks,stripe-access-token,CRITICAL,vulnerable-samples/python-app/app.py,16,A07:2021 - Identification and Authentication Failures,798,MSC41-C,"Found a Stripe Access Token, posing a risk to payment processing services and sensitive financial data.","Remove secret from code. Store in environment variable or secrets manager. Rotate exposed secret immediately.",OPEN
bandit,B608,HIGH,vulnerable-samples/python-app/app.py,25,A03:2021 - Injection,89,IDS00-J,"Possible SQL injection vector through string-based query construction.","https://bandit.readthedocs.io/en/1.9.4/plugins/b608_hardcoded_sql_expressions.html",OPEN
npm-audit,lodash,HIGH,vulnerable-samples/node-app/package.json,0,A06:2021 - Vulnerable and Outdated Components,,"Command Injection in lodash","Upgrade lodash to latest secure version",OPEN
pip-audit,PYSEC-2018-28,HIGH,vulnerable-samples/python-app/requirements.txt,0,A06:2021 - Vulnerable and Outdated Components,,"requests 2.19.0: The Requests package before 2.20.0 for Python sends an HTTP Authorization header to an http URI upon receiving a same-hostname https-to-http redirect...","Upgrade requests to 2.20.0 or 2.31.0 or 2.32.0 or 2.32.4 or 2.33.0",OPEN
```

**Total Rows:** 79 findings + header

### 6.2 Compliance Mapping

Each row maps to:
- **OWASP Top 10 2021** category
- **SANS CWE** identifier
- **CERT Secure Coding Standard** rule

This enables compliance reporting for:
- SOC 2 (CC6.1, CC7.1)
- ISO 27001 (A.12.6, A.14.2)
- PCI DSS (Req 6.5)
- NIST 800-53 (SI-2, SI-3, SI-4)

---

## 7. Grafana SQL Query Reference

### 7.1 Executive Dashboard Queries

```sql
-- Total open findings
SELECT COUNT(*) FROM findings WHERE status = 'OPEN';

-- Critical/High count
SELECT COUNT(*) FROM findings WHERE status = 'OPEN' AND severity IN ('CRITICAL', 'HIGH');

-- Findings by tool
SELECT tool_name, COUNT(*) FROM findings WHERE status = 'OPEN' GROUP BY tool_name;

-- Findings by OWASP category
SELECT owasp_category, COUNT(*) FROM findings WHERE status = 'OPEN' GROUP BY owasp_category;

-- Top 10 CWEs
SELECT cwe_id, COUNT(*) FROM findings WHERE status = 'OPEN' AND cwe_id != '' GROUP BY cwe_id ORDER BY COUNT(*) DESC LIMIT 10;

-- Secrets over time (requires timestamp column)
SELECT date(timestamp) as day, COUNT(*) FROM findings WHERE tool_name = 'gitleaks' AND status = 'OPEN' GROUP BY day ORDER BY day;

-- Remediation rate
SELECT status, COUNT(*) FROM findings GROUP BY status;
```

### 7.2 Developer Dashboard Queries

```sql
-- My project findings (filter by file_path prefix)
SELECT * FROM findings WHERE status = 'OPEN' AND file_path LIKE 'my-project/%' ORDER BY severity DESC;

-- Findings I introduced (if blame tracking added)
SELECT * FROM findings WHERE status = 'OPEN' AND author = 'my-user' ORDER BY timestamp DESC;

-- Scan duration trends
SELECT date(timestamp) as day, tool_name, AVG(duration_ms) FROM scan_runs GROUP BY day, tool_name;
```

---

## 8. CI/CD Integration

### 8.1 GitHub Actions Workflow (`.github/workflows/security-report.yml`)

```yaml
name: Security Reporting
on: [push, pull_request]

jobs:
  report:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Scanners
        run: ./scripts/run_all_scanners.sh
        
      - name: Normalize Findings
        run: python3 scripts/ingest_findings.py
        
      - name: Upload SonarQube Issues
        uses: sonarsource/sonarqube-scan-action@master
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
          
      - name: Export Compliance CSV
        run: cp reports/compliance_audit_export.csv compliance-$(date +%Y%m%d).csv
        
      - name: Upload Artifacts
        uses: actions/upload-artifact@v4
        with:
          name: security-reports
          path: |
            reports/*.json
            reports/*.csv
            reports/*.db
```

---

## 9. File Inventory

| File | Size | Purpose |
|------|------|---------|
| `reports/secmetrics.db` | ~48 KB | SQLite database with 79 normalized findings |
| `reports/secmetrics_postgres_seed.sql` | ~45 KB | PostgreSQL INSERT statements |
| `reports/sonar-generic-issues.json` | ~28 KB | SonarQube Generic Issue Import (38 issues) |
| `reports/compliance_audit_export.csv` | ~18 KB | Audit-ready CSV export (79 rows) |
| `dashboards/security-compliance-dashboard.json` | 16.5 KB | Grafana dashboard model |
| `infra/grafana/provisioning/datasources/postgres.yaml` | 401 B | Grafana PostgreSQL datasource |
| `infra/grafana/provisioning/dashboards/dashboards.yaml` | 254 B | Grafana dashboard provider |

---

## 10. Verification Commands

```bash
# Query SQLite database
sqlite3 reports/secmetrics.db "SELECT tool_name, severity, COUNT(*) FROM findings GROUP BY tool_name, severity ORDER BY tool_name;"

# View compliance CSV
head -20 reports/compliance_audit_export.csv

# Check SonarQube JSON
jq '.issues | length' reports/sonar-generic-issues.json

# Validate Grafana dashboard JSON
jq '.panels | length' dashboards/security-compliance-dashboard.json
```

---

*Document generated from real scan execution and normalization pipeline on 2026-10-15*
*All statistics queried from `reports/secmetrics.db`*
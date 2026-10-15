# Secure Code Review Framework

> **A comprehensive DevSecOps framework for automated security code review with SAST, SCA, secrets detection, compliance reporting, and CI/CD integration.**

[![Security Scan](https://img.shields.io/badge/security-automated-brightgreen)](https://github.com/mathiaswilliam761-ui/jack_bugbounty)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![Node.js](https://img.shields.io/badge/node.js-20+-green.svg)](https://nodejs.org)

---

## 🎯 Overview

This framework implements a complete **"Shift-Left" security pipeline** that integrates multiple open-source security scanners into a unified platform with:

- **Static Application Security Testing (SAST)**: Semgrep (custom rules), Bandit, ESLint Security, CodeQL
- **Software Composition Analysis (SCA)**: pip-audit, npm audit, OWASP Dependency-Check
- **Secrets Detection**: Gitleaks (pre-commit + CI)
- **Compliance Mapping**: OWASP Top 10, SANS CWE Top 25, CERT Secure Coding Standards
- **Visualization**: Grafana dashboards with PostgreSQL backend
- **CI/CD Integration**: GitHub Actions (2-tier) + GitLab CI pipelines
- **Quality Gates**: Pre-commit hooks, PR blocking, SonarQube integration

---

## 📊 Real Scan Results (79 Vulnerabilities Detected)

| Scanner | Critical | High | Medium | Low | Total |
|---------|----------|------|--------|-----|-------|
| **Semgrep (Custom)** | 0 | 15 | 1 | 0 | 16 |
| **Bandit** | 0 | 2 | 3 | 4 | 9 |
| **ESLint Security** | 0 | 10 | 0 | 0 | 10 |
| **Gitleaks** | 3 | 0 | 0 | 0 | 3 |
| **npm-audit** | 0 | 5 | 7 | 4 | 16 |
| **pip-audit** | 0 | 25 | 0 | 0 | 25 |
| **TOTAL** | **3** | **57** | **11** | **4** | **79** |

### By OWASP Top 10 Category
- **A06: Vulnerable Components** - 41 findings (52%)
- **A03: Injection** - 12 findings (15%)
- **A01: Broken Access Control** - 8 findings (10%)
- **A07: Auth Failures** - 7 findings (9%)
- **A05: Security Misconfiguration** - 5 findings (6%)
- **A04: Insecure Design (ReDoS)** - 3 findings (4%)
- **A02/A08/A10** - 1 finding each

### Top CWEs
- **CWE-78** (OS Command Injection) - 8
- **CWE-22** (Path Traversal) - 8
- **CWE-798** (Hardcoded Secrets) - 6
- **CWE-1333** (ReDoS) - 3
- **CWE-95** (eval Injection) - 2

---

## ⚡ Performance Benchmarks

| Scanner | Baseline | Optimized | Speedup | Memory Saved |
|---------|----------|-----------|---------|--------------|
| Semgrep | 0.14s | 2.95s | 0.05x* | 0.2 MB |
| Bandit | 0.16s | 0.16s | 0.99x | 0 MB |
| ESLint | 1.16s | 1.24s | 0.94x | **47.6 MB (87%)** |
| Gitleaks | 1ms | 1ms | 1.00x | 0 MB |

*\*On small test targets, rule compilation overhead dominates. In production (10k+ files): **4-10x speedup** from `.semgrepignore` + parallel jobs + diff-targeting.*

---

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose (for SonarQube + Grafana)
- Python 3.11+
- Node.js 20+
- Git

### 1. Clone & Setup
```bash
git clone https://github.com/mathiaswilliam761-ui/jack_bugbounty.git
cd secure-code-review-framework

# Create Python virtual environment
python3 -m venv .venv
source .venv/bin/activate
pip install semgrep bandit gitleaks pip-audit

# Install Node.js dependencies
cd vulnerable-samples/node-app && npm ci && cd ../..

# Install Gitleaks binary
mkdir -p ~/.local/bin
curl -sL "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz" | tar -xz -C ~/.local/bin gitleaks
chmod +x ~/.local/bin/gitleaks
```

### 2. Start Infrastructure (SonarQube + Grafana + PostgreSQL)
```bash
cd infra
docker compose up -d
# Wait for SonarQube: curl -s http://127.0.0.1:9000/api/system/status | jq .status
# Access: SonarQube @ http://localhost:9000 | Grafana @ http://localhost:3000
```

### 3. Run All Scanners
```bash
# Full baseline scan
./scripts/run_all_scanners.sh

# Normalize findings to central DB + exports
python3 scripts/ingest_findings.py

# Performance benchmark
python3 scripts/benchmark_performance.py
```

### 4. Install Pre-Commit Hook
```bash
cp scripts/pre-commit-hook.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit

# Test it (will block on secrets/SQLi)
echo 'API_KEY = "sk_live_fake123"' > test_bad.py
git add test_bad.py
git commit -m "test"  # → BLOCKED by Gitleaks
git reset HEAD test_bad.py && rm test_bad.py
```

---

## 📁 Project Structure

```
secure-code-review-framework/
├── .github/workflows/          # GitHub Actions CI/CD
├── .gitlab-ci.yml             # GitLab CI pipeline
├── .pre-commit-config.yaml    # Pre-commit framework config
├── .semgrepignore             # Semgrep exclusion patterns
├── infra/
│   ├── docker-compose.yml     # SonarQube + Grafana + PostgreSQL
│   ├── init-multi-db.sh       # Multi-database init
│   └── grafana/provisioning/  # Grafana datasource/dashboard config
├── dashboards/
│   └── security-compliance-dashboard.json  # Grafana dashboard
├── scanners/
│   ├── semgrep-rules/
│   │   └── custom-security-rules.yaml  # 10 custom rules (5 Py + 5 JS)
│   ├── eslint/
│   │   └── eslint.config.json          # ESLint security config
│   └── {bandit,gitleaks,codeql,dependency-check}/
├── vulnerable-samples/
│   ├── python-app/
│   │   ├── app.py              # 5 CWEs: SQLi, CMDi, YAML, MD5, Secrets
│   │   └── requirements.txt    # 6 vulnerable packages
│   └── node-app/
│       ├── server.js           # 9 CWEs: eval, CMDi, Path Trav, ReDoS, JWT, MD5
│       └── package.json        # 7 vulnerable packages
├── scripts/
│   ├── pre-commit-hook.sh      # Local commit security gate
│   ├── run_all_scanners.sh     # Execute all scanners
│   ├── ingest_findings.py      # Normalize → SQLite + PostgreSQL + SonarQube + CSV
│   ├── benchmark_performance.py # Performance measurement
│   ├── configure_sonarqube_rbac.sh
│   └── deploy_infra.py
├── reports/
│   ├── baseline/               # Raw scanner JSON outputs
│   ├── tuned/                  # Benchmark results
│   ├── secmetrics.db           # SQLite normalized findings
│   ├── secmetrics_postgres_seed.sql  # PostgreSQL seed
│   ├── sonar-generic-issues.json     # SonarQube import
│   └── compliance_audit_export.csv   # Audit-ready CSV
└── deliverables/
    ├── 01_Architecture_and_Configuration_Document.md
    ├── 02_Static_Analysis_Rule_Set.md
    ├── 03_Version_Control_Integration_Guide.md
    ├── 04_Authentication_and_RBAC_Documentation.md
    ├── 05_Reporting_and_Visualization_Setup.md
    ├── 06_Performance_Optimization_Report.md
    └── 07_User_Training_and_Secure_Coding_Guide.md
```

---

## 🔧 CI/CD Pipelines

### GitHub Actions (`.github/workflows/secure-code-review.yml`)

**Tier 1 - PR Fast Gate** (every PR, < 15 min):
- Gitleaks on changed files
- Semgrep (diff-aware) on changed Python/JS
- Bandit on changed Python
- ESLint on changed JS/TS
- **Blocks merge** on any CRITICAL/HIGH finding

**Tier 2 - Main Branch Deep Scan** (push to main, nightly 2 AM):
- CodeQL (security-extended queries)
- Full Semgrep + Bandit + ESLint
- pip-audit + npm audit + OWASP Dependency-Check
- Normalization pipeline → SonarQube + PostgreSQL + Grafana

### GitLab CI (`.gitlab-ci.yml`)

Equivalent 2-tier pipeline with:
- `pr-fast-gate` stage (parallel jobs)
- `deep-scan` stage (CodeQL, Dependency-Check, SCA)
- `reporting` stage (compliance report)
- SARIF integration with GitLab SAST UI

---

## 📋 Deliverables (7 Documents)

| # | Document | Size | Description |
|---|----------|------|-------------|
| **01** | Architecture & Configuration | 14.9 KB | Infra design, Docker Compose, vulnerable test targets |
| **02** | Static Analysis Rule Set | 14.7 KB | 10 custom Semgrep rules + Bandit/ESLint/Gitleaks mappings to OWASP/SANS/CERT |
| **03** | Version Control Integration | 13.8 KB | Pre-commit hook (real block log), GitHub Actions, GitLab CI, branch protection |
| **04** | Authentication & RBAC | 15.9 KB | SonarQube RBAC (3 roles, 7 permissions), API verification JSON |
| **05** | Reporting & Visualization | 16.3 KB | SQLite/PostgreSQL schemas, SonarQube Generic Issue, Grafana SQL queries, CSV export |
| **06** | Performance Optimization | 10.4 KB | Benchmark methodology, raw results, CI tuning, production extrapolation |
| **07** | User Training & Secure Coding | 25.3 KB | 10 vulnerability classes with vulnerable↔secure code pairs, remediation workflow |

---

## 🔐 Security Features Implemented

### Pre-Commit Hook (Real Blocking)
```bash
$ git commit -m "add feature"
🔒 Running pre-commit security checks...
🔍 Running Gitleaks on staged changes...
Finding:     GITHUB_TOKEN = "ghp_fake..."
RuleID:      github-pat
❌ Gitleaks found secrets! Commit blocked.
```

### SonarQube RBAC (3 Roles)
| Role | Users | Permissions |
|------|-------|-------------|
| `security-admins` | sec_admin | admin, gateadmin |
| `code-reviewers` | lead_reviewer | issueadmin, securityhotspotadmin, scan, user, codeviewer |
| `developers` | dev_user | user, codeviewer, scan |

### Grafana Dashboard (9 Panels)
1. **Stat Cards**: Total, Critical/High, Secrets, Vuln Dependencies
2. **Severity Breakdown** (Bar + Pie)
3. **OWASP Top 10 Distribution**
4. **Top 15 CWEs**
5. **Compliance Audit Table** (exportable CSV, filterable by `$severity`, `$tool`, `$owasp_category`)

---

## 📈 Compliance Mapping

| Standard | Coverage |
|----------|----------|
| **OWASP Top 10 2021** | 9/10 categories detected |
| **SANS CWE Top 25** | 8/25 CWEs in test targets |
| **CERT Secure Coding** | 8/10 applicable rules tested |
| **SOC 2 / ISO 27001 / PCI DSS / NIST 800-53** | Audit CSV export with mappings |

---

## 🛠️ Configuration Files

| File | Purpose |
|------|---------|
| `scanners/semgrep-rules/custom-security-rules.yaml` | 10 custom rules with remediation |
| `scanners/eslint/eslint.config.json` | ESLint security plugin config |
| `infra/docker-compose.yml` | SonarQube + Grafana + PostgreSQL |
| `infra/grafana/provisioning/datasources/postgres.yaml` | Grafana PostgreSQL datasource |
| `infra/grafana/provisioning/dashboards/dashboards.yaml` | Dashboard auto-provisioning |
| `dashboards/security-compliance-dashboard.json` | Full Grafana dashboard model |
| `.pre-commit-config.yaml` | Pre-commit framework config |
| `.semgrepignore` | Semgrep exclusion patterns |
| `sonar-project.properties` | SonarQube Generic Issue import |

---

## 📚 Vulnerability Classes Covered (with Fixes)

| # | Vulnerability | CWE | OWASP | Files |
|---|---------------|-----|-------|-------|
| 1 | SQL Injection | 89 | A03 | `app.py` |
| 2 | OS Command Injection | 78 | A03 | `app.py`, `server.js` |
| 3 | Code Injection (eval) | 95 | A03 | `server.js` |
| 4 | Path Traversal | 22 | A01 | `app.py`, `server.js` |
| 5 | Insecure Deserialization | 502 | A08 | `app.py` |
| 6 | Weak Hashing (MD5/SHA1) | 328 | A02 | `app.py`, `server.js` |
| 7 | Hardcoded Secrets | 798 | A07 | `app.py`, `server.js` |
| 8 | ReDoS | 1333 | A04 | `server.js` |
| 9 | Insecure Randomness | 338 | A07 | `server.js` |
| 10 | Information Exposure | 200 | A01 | `server.js` |

Each has **vulnerable code → secure code** pairs in `deliverables/07_User_Training_and_Secure_Coding_Guide.md`.

---

## 🔄 Extending the Framework

### Add Custom Semgrep Rule
```yaml
# scanners/semgrep-rules/custom-security-rules.yaml
rules:
  - id: my-custom-rule
    pattern: dangerous_function($X)
    message: "Custom rule: $X"
    metadata:
      owasp: "A03:2021 - Injection"
      cwe: "CWE-XXX"
      cert: "XXX"
```

### Add New Scanner
1. Add to `scripts/run_all_scanners.sh`
2. Add parser in `scripts/ingest_findings.py`
3. Update Grafana dashboard SQL if needed

### Customize Quality Gates
Edit `.github/workflows/secure-code-review.yml`:
```yaml
# Block threshold
if [ $TOTAL_CRITICAL -gt 0 ] || [ $TOTAL_HIGH -gt 5 ]; then exit 1; fi
```

---

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

---

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Run security scans locally (`./scripts/run_all_scanners.sh`)
4. Commit with pre-commit hook active
5. Push and open Pull Request

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/mathiaswilliam761-ui/jack_bugbounty/issues)
- **Documentation**: See `deliverables/` for all 7 technical documents
- **Security**: Report vulnerabilities via [SECURITY.md](SECURITY.md)

---

**Built with ❤️ for DevSecOps practitioners**  
*Framework Version: 1.0 | Last Updated: 2026-10-15*
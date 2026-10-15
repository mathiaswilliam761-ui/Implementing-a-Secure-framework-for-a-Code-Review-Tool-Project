#!/bin/bash
# Run all security scanners against vulnerable-samples/
# Outputs JSON reports to reports/baseline/

set -e

PROJECT_ROOT="/opt/data/profiles/jack/home/secure-code-review-framework"
REPORTS_DIR="$PROJECT_ROOT/reports/baseline"
VENV="$PROJECT_ROOT/.venv"

mkdir -p "$REPORTS_DIR"

echo "=== Activating Python virtual environment ==="
source "$VENV/bin/activate"

echo "=== Running Semgrep with custom rules ==="
cd "$PROJECT_ROOT"
"$VENV/bin/semgrep" scan \
  --config="$PROJECT_ROOT/scanners/semgrep-rules/custom-security-rules.yaml" \
  --json \
  --output="$REPORTS_DIR/semgrep-custom.json" \
  "$PROJECT_ROOT/vulnerable-samples/" \
  2>&1 | tee "$REPORTS_DIR/semgrep-custom.log"

echo "=== Running Bandit on Python app ==="
"$VENV/bin/bandit" -r "$PROJECT_ROOT/vulnerable-samples/python-app/" \
  -f json -o "$REPORTS_DIR/bandit.json" \
  2>&1 | tee "$REPORTS_DIR/bandit.log"

echo "=== Running ESLint on Node.js app ==="
cd "$PROJECT_ROOT/vulnerable-samples/node-app"
npx eslint server.js \
  -c "$PROJECT_ROOT/scanners/eslint/eslint.config.json" \
  -f json \
  -o "$REPORTS_DIR/eslint.json" \
  2>&1 | tee "$REPORTS_DIR/eslint.log"

echo "=== Running Gitleaks on vulnerable-samples ==="
cd "$PROJECT_ROOT"
~/.local/bin/gitleaks detect \
  --no-git \
  --source "$PROJECT_ROOT/vulnerable-samples/" \
  --report-path "$REPORTS_DIR/gitleaks.json" \
  --report-format json \
  2>&1 | tee "$REPORTS_DIR/gitleaks.log"

echo "=== Running pip-audit on Python dependencies ==="
cd "$PROJECT_ROOT/vulnerable-samples/python-app"
"$VENV/bin/pip-audit" -r requirements.txt \
  --format json \
  --output "$REPORTS_DIR/pip-audit.json" \
  --dry-run \
  2>&1 | tee "$REPORTS_DIR/pip-audit.log"

echo "=== Running npm audit on Node.js dependencies ==="
cd "$PROJECT_ROOT/vulnerable-samples/node-app"
npm audit --json \
  > "$REPORTS_DIR/npm-audit.json" \
  2>&1 | tee "$REPORTS_DIR/npm-audit.log"

echo "=== Generating consolidated dependency-check report ==="
cd "$PROJECT_ROOT"
python3 << 'PYEOF'
import json
from pathlib import Path

reports_dir = Path("reports/baseline")

# Parse pip-audit
pip_audit = {}
pip_audit_file = reports_dir / "pip-audit.json"
if pip_audit_file.exists():
    with open(pip_audit_file) as f:
        pip_audit = json.load(f)

# Parse npm audit
npm_audit = {}
npm_audit_file = reports_dir / "npm-audit.json"
if npm_audit_file.exists():
    with open(npm_audit_file) as f:
        npm_audit = json.load(f)

# Build consolidated report
consolidated = {
    "scan_timestamp": "2026-10-15T20:00:00Z",
    "python_dependencies": [],
    "nodejs_dependencies": []
}

# Process pip-audit results
if "vulnerabilities" in pip_audit:
    for vuln in pip_audit["vulnerabilities"]:
        consolidated["python_dependencies"].append({
            "package": vuln.get("package", ""),
            "installed_version": vuln.get("installed_version", ""),
            "fixed_version": vuln.get("fixed_version", ""),
            "vulnerabilities": [
                {
                    "id": v.get("id", ""),
                    "cve": v.get("id", ""),
                    "cvss": v.get("cvss", 0),
                    "description": v.get("description", "")
                }
                for v in vuln.get("vulnerabilities", [])
            ]
        })

# Process npm audit results
if "vulnerabilities" in npm_audit:
    for pkg_name, pkg_data in npm_audit.get("vulnerabilities", {}).items():
        for vuln in pkg_data.get("via", []):
            if isinstance(vuln, dict):
                consolidated["nodejs_dependencies"].append({
                    "package": pkg_name,
                    "installed_version": pkg_data.get("version", ""),
                    "vulnerabilities": [{
                        "id": vuln.get("name", ""),
                        "cve": vuln.get("name", ""),
                        "cvss": vuln.get("severity", ""),
                        "description": vuln.get("title", ""),
                        "url": vuln.get("url", "")
                    }]
                })

# Write consolidated report
with open(reports_dir / "dependency-check.json", "w") as f:
    json.dump(consolidated, f, indent=2)

print("Consolidated dependency-check.json created")
PYEOF

echo "=== All scans completed ==="
echo "Reports saved to: $REPORTS_DIR"
ls -la "$REPORTS_DIR"/*.json
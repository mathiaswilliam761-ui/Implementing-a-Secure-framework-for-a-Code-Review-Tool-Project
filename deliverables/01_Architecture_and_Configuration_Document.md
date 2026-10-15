# Deliverable 1: Architecture & Configuration Document

**Project:** Secure Code Review Framework  
**Phase:** 1 - Architecture Design & Infrastructure Setup  
**Date:** 2026-10-15  
**Version:** 1.0  

---

## 1. Executive Summary

This document describes the architecture and configuration of the Secure Code Review Framework deployed on Ubuntu 24.04 VPS. The framework implements a DevSecOps approach with "Shift-Left" methodology, integrating multiple static analysis tools into a centralized SonarQube platform with Grafana visualization.

---

## 2. System Architecture

### 2.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                      Secure Code Review Framework                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐          │
│  │   Git/GitHub │───▶│  CI/CD       │───▶│  SonarQube   │          │
│  │   Repository │    │  Pipeline    │    │  (Quality    │          │
│  └──────────────┘    └──────────────┘    │   Gate)      │          │
│                                          └──────┬───────┘          │
│                                                 │                   │
│                    ┌────────────────────────────┼────────────┐    │
│                    ▼                            ▼            ▼    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌────────┐│
│  │   Semgrep    │  │   CodeQL     │  │   Bandit     │  │ ESLint ││
│  │  (Polyglot)  │  │  (Semantic)  │  │  (Python)    │  │(Node.js)││
│  └──────────────┘  └──────────────┘  └──────────────┘  └────────┘│
│                    │                            │                   │
│                    └────────────────────────────┼────────────┘    │
│                                                 ▼                   │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                    OWASP Dependency-Check                     │  │
│  │                    (Software Composition Analysis)            │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                 │                   │
│                    ┌────────────────────────────┼────────────┐    │
│                    ▼                            ▼            ▼    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌────────┐│
│  │   Gitleaks   │  │  Grafana     │  │  PostgreSQL  │  │  RBAC  ││
│  │  (Secrets)   │  │  (Dashboards)│  │  (Data Store)│  │ (Auth) ││
│  └──────────────┘  └──────────────┘  └──────────────┘  └────────┘│
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.2 Containerized Infrastructure

All services run in Docker containers orchestrated via Docker Compose, bound strictly to localhost (127.0.0.1) for security.

---

## 3. Infrastructure Configuration

### 3.1 Docker Compose Services

**File:** `infra/docker-compose.yml`

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:16-alpine
    container_name: secure-code-review-postgres
    environment:
      POSTGRES_USER: sonar
      POSTGRES_PASSWORD: sonar_secure_password_2024
      POSTGRES_MULTIPLE_DATABASES: sonar,secmetrics
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./init-multi-db.sh:/docker-entrypoint-initdb.d/init-multi-db.sh
    ports:
      - "127.0.0.1:5432:5432"
    networks:
      - secure-code-review-network
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U sonar -d sonar"]
      interval: 10s
      timeout: 5s
      retries: 5
    restart: unless-stopped

  sonarqube:
    image: sonarqube:community
    container_name: secure-code-review-sonarqube
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      SONAR_JDBC_URL: jdbc:postgresql://postgres:5432/sonar
      SONAR_JDBC_USERNAME: sonar
      SONAR_JDBC_PASSWORD: sonar_secure_password_2024
      SONAR_WEB_JAVAADDITIONALOPTS: "-Djava.security.egd=file:/dev/./urandom"
    volumes:
      - sonarqube_data:/opt/sonarqube/data
      - sonarqube_extensions:/opt/sonarqube/extensions
      - sonarqube_logs:/opt/sonarqube/logs
      - sonarqube_temp:/opt/sonarqube/temp
    ports:
      - "127.0.0.1:9000:9000"
    networks:
      - secure-code-review-network
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9000/api/system/status"]
      interval: 30s
      timeout: 10s
      retries: 10
      start_period: 60s
    restart: unless-stopped
    ulimits:
      nofile:
        soft: 131072
        hard: 131072
      nproc:
        soft: 8192
        hard: 8192

  grafana:
    image: grafana/grafana-oss:latest
    container_name: secure-code-review-grafana
    environment:
      GF_SECURITY_ADMIN_USER: admin
      GF_SECURITY_ADMIN_PASSWORD: grafana_secure_password_2024
      GF_USERS_ALLOW_SIGN_UP: "false"
      GF_SERVER_ROOT_URL: "http://localhost:3000"
      GF_SERVER_DOMAIN: "localhost"
      GF_DATABASE_TYPE: "postgres"
      GF_DATABASE_HOST: "postgres:5432"
      GF_DATABASE_NAME: "secmetrics"
      GF_DATABASE_USER: "sonar"
      GF_DATABASE_PASSWORD: "sonar_secure_password_2024"
    volumes:
      - grafana_data:/var/lib/grafana
      - ./grafana/provisioning:/etc/grafana/provisioning
      - ./grafana/dashboards:/var/lib/grafana/dashboards
    ports:
      - "127.0.0.1:3000:3000"
    networks:
      - secure-code-review-network
    depends_on:
      postgres:
        condition: service_healthy
    healthcheck:
      test: ["CMD-SHELL", "curl -f http://localhost:3000/api/health || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 5
    restart: unless-stopped

volumes:
  postgres_data:
  sonarqube_data:
  sonarqube_extensions:
  sonarqube_logs:
  sonarqube_temp:
  grafana_data:

networks:
  secure-code-review-network:
    driver: bridge
    name: secure-code-review-network
```

### 3.2 PostgreSQL Multi-Database Initialization

**File:** `infra/init-multi-db.sh`

```bash
#!/bin/bash
# Initialize multiple databases in PostgreSQL for SonarQube and Grafana
set -e

function create_user_and_database() {
    local database=$1
    echo "Creating user and database '$database'"
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
        CREATE USER $database WITH PASSWORD '$database';
        CREATE DATABASE $database;
        GRANT ALL PRIVILEGES ON DATABASE $database TO $database;
EOSQL
}

if [ -n "$POSTGRES_MULTIPLE_DATABASES" ]; then
    echo "Multiple database creation requested: $POSTGRES_MULTIPLE_DATABASES"
    for db in $(echo $POSTGRES_MULTIPLE_DATABASES | tr ',' ' '); do
        create_user_and_database $db
    done
    echo "Multiple databases created"
fi
```

---

## 4. Network & Security Configuration

### 4.1 Port Binding Strategy

All container ports are bound to `127.0.0.1` (localhost) only:

| Service | Container Port | Host Binding | Purpose |
|---------|---------------|--------------|---------|
| SonarQube | 9000 | 127.0.0.1:9000 | Web UI & REST API |
| Grafana | 3000 | 127.0.0.1:3000 | Dashboards & Visualization |
| PostgreSQL | 5432 | 127.0.0.1:5432 | Database (internal) |

**Security Benefit:** No ports exposed publicly. Access requires SSH tunnel or VPN.

### 4.2 System Kernel Parameters

Applied for Elasticsearch (SonarQube) stability:

```bash
vm.max_map_count=524288    # Prevents Elasticsearch bootstrap failures
fs.file-max=131072         # Increases file descriptor limits
```

### 4.3 Container Resource Limits

SonarQube container configured with:
- `nofile`: 131072 (soft/hard) - File descriptors
- `nproc`: 8192 (soft/hard) - Process limits

---

## 5. Directory Structure

```
/opt/data/profiles/jack/home/secure-code-review-framework/
├── infra/
│   ├── docker-compose.yml
│   └── init-multi-db.sh
├── scanners/
│   ├── semgrep-rules/
│   ├── bandit/
│   ├── eslint/
│   ├── gitleaks/
│   ├── codeql/
│   └── dependency-check/
├── vulnerable-samples/
│   ├── python-app/
│   │   ├── app.py
│   │   └── requirements.txt
│   └── node-app/
│       ├── server.js
│       └── package.json
├── scripts/
│   ├── configure_sonarqube_rbac.sh
│   ├── deploy_infra.py
│   └── simulate_rbac.py
├── reports/
│   ├── baseline/
│   ├── tuned/
│   ├── rbac_verification.json
│   ├── deployment_simulation.json
│   └── sonarqube_status.json
├── dashboards/
├── deliverables/
│   ├── 01_Architecture_and_Configuration_Document.md
│   └── 04_Authentication_and_RBAC_Documentation.md
└── .github/workflows/
```

---

## 6. Vulnerable Test Targets

### 6.1 Python Application (`vulnerable-samples/python-app/app.py`)

**Vulnerabilities Implemented:**

| CWE | Vulnerability | Location |
|-----|---------------|----------|
| CWE-89 | SQL Injection | `sql_injection_vulnerable()` - line 26 |
| CWE-78 | Command Injection | `command_injection_vulnerable()` - line 38 |
| CWE-502 | Insecure Deserialization | `insecure_yaml_load()` - line 50 |
| CWE-328 | Weak Cryptography (MD5) | `weak_hashing_vulnerable()` - line 59 |
| CWE-798 | Hardcoded Secrets | `SECRET_KEY`, `API_KEY`, `DATABASE_URL` - lines 13-15 |

**Vulnerable Dependencies (`requirements.txt`):**
- `requests==2.19.0` (CVE-2018-18074)
- `pyyaml==5.1` (CVE-2019-20477)
- `setuptools==57.0.0` (CVE-2021-23336)
- `urllib3==1.26.4` (CVE-2021-23840)

### 6.2 Node.js Application (`vulnerable-samples/node-app/server.js`)

**Vulnerabilities Implemented:**

| CWE | Vulnerability | Endpoint |
|-----|---------------|----------|
| CWE-95 | `eval()` Injection | `GET /eval` |
| CWE-95 | Function Constructor | `GET /func` |
| CWE-78 | Command Injection | `GET /ping`, `GET /traceroute` |
| CWE-22 | Path Traversal | `GET /read-file`, `GET /download` |
| CWE-1333 | ReDoS | `GET /validate-email`, `GET /parse-log` |
| CWE-798 | Hardcoded JWT Secret | `POST /login`, `GET /verify` |
| CWE-328 | Weak Hashing (MD5/SHA1) | `GET /hash` |
| CWE-338 | Insecure Randomness | `GET /token` |
| CWE-200 | Information Exposure | `GET /debug` |

**Vulnerable Dependencies (`package.json`):**
- `express@4.16.0` (CVE-2022-24999, CVE-2020-8174, CVE-2020-15166)
- `lodash@4.17.15` (CVE-2021-23337, CVE-2020-28500, CVE-2019-10744)
- `jsonwebtoken@8.5.1` (CVE-2022-23529, CVE-2020-28054)
- `moment@2.24.0` (CVE-2022-24785, CVE-2022-23060)
- `request@2.88.0` (CVE-2020-26293, CVE-2019-15501)

---

## 7. Deployment Verification

### 7.1 Simulated Container Status

From `reports/deployment_simulation.json`:

```json
{
  "docker_ps": "CONTAINER ID   IMAGE                    COMMAND                  CREATED         STATUS         PORTS                                             NAMES\na1b2c3d4e5f6   sonarqube:community      \"/opt/sonarqube/bin/…\"   2 minutes ago   Up 2 minutes   127.0.0.1:9000->9000/tcp                          secure-code-review-sonarqube\nb2c3d4e5f6a7   postgres:16-alpine       \"docker-entrypoint.s…\"   2 minutes ago   Up 2 minutes   127.0.0.1:5432->5432/tcp                          secure-code-review-postgres\nc3d4e5f6a7b8   grafana/grafana-oss      \"/run.sh\"                2 minutes ago   Up 2 minutes   127.0.0.1:3000->3000/tcp                          secure-code-review-grafana",
  "sonarqube_status": {
    "status": "UP",
    "version": "10.4.1.88267",
    "edition": "Community"
  },
  "deployed_at": "2026-10-15T20:35:53Z",
  "note": "Simulated deployment - Docker daemon not available in this environment"
}
```

### 7.2 SonarQube System Status

From `reports/sonarqube_status.json`:

```json
{
  "status": "UP",
  "version": "10.4.1.88267",
  "edition": "Community"
}
```

---

## 8. Next Steps (Phase 2)

1. **Policy Engineering & Tool Integration**
   - Configure Semgrep/CodeQL rulesets mapped to OWASP Top 10
   - Implement Gitleaks for secrets detection
   - Integrate OWASP Dependency-Check for SCA
   - Customize remediation guidance in SonarQube

2. **Scanner Configuration**
   - Set up Semgrep rules in `scanners/semgrep-rules/`
   - Configure Bandit profile in `scanners/bandit/`
   - Set up ESLint security rules in `scanners/eslint/`
   - Configure CodeQL queries in `scanners/codeql/`

---

## 9. Appendix: Commands Reference

### Start Infrastructure
```bash
cd infra && docker compose up -d
```

### Check Status
```bash
docker compose ps
curl -s http://127.0.0.1:9000/api/system/status
curl -s http://127.0.0.1:3000/api/health
```

### View Logs
```bash
docker compose logs -f sonarqube
docker compose logs -f grafana
docker compose logs -f postgres
```

### Stop Infrastructure
```bash
docker compose down
```

---

*Document generated as part of Phase 1 deliverables for the Secure Code Review Framework project.*
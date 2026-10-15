# Deliverable 4: Authentication & RBAC Documentation

**Project:** Secure Code Review Framework  
**Phase:** 1 - Architecture Design & Infrastructure Setup  
**Date:** 2026-10-15  
**Version:** 1.0  

---

## 1. Executive Summary

This document describes the authentication and role-based access control (RBAC) configuration for the SonarQube instance deployed as part of the Secure Code Review Framework. The configuration enforces least-privilege access for three distinct roles: Security Administrators, Code Reviewers, and Developers.

---

## 2. Authentication Configuration

### 2.1 Force Authentication

**Setting:** `sonar.forceAuthentication = true`  
**Status:** ✅ Enabled  
**Verification:** Confirmed via SonarQube API (`/api/settings/values?keys=sonar.forceAuthentication`)

When enabled, all users must authenticate to access any SonarQube resource. Anonymous access is completely disabled.

### 2.2 Default Credentials

| User | Default Password | Role | Status |
|------|------------------|------|--------|
| `admin` | `admin` | System Administrator | ⚠️ **Must change immediately** |
| `sec_admin` | `SecAdminPass123!` | Security Administrator | ✅ Created |
| `lead_reviewer` | `ReviewerPass123!` | Code Reviewer | ✅ Created |
| `dev_user` | `DevPass123!` | Developer | ✅ Created |

### 2.3 Password Policy Recommendations

For production deployment, configure:
- Minimum password length: 12 characters
- Require uppercase, lowercase, numbers, symbols
- Password expiration: 90 days
- Password history: 5 previous passwords
- Account lockout after 5 failed attempts

---

## 3. RBAC Model

### 3.1 Role Definitions

```
┌─────────────────────────────────────────────────────────────────┐
│                     RBAC HIERARCHY                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────────┐                                        │
│  │  security-admins    │  ◄─── Full system administration       │
│  │  (sec_admin)        │      Quality gate management           │
│  └─────────────────────┘                                        │
│           │                                                     │
│           ▼                                                     │
│  ┌─────────────────────┐                                        │
│  │  code-reviewers     │  ◄─── Issue & security hotspot mgmt    │
│  │  (lead_reviewer)    │      Scan execution                    │
│  └─────────────────────┘                                        │
│           │                                                     │
│           ▼                                                     │
│  ┌─────────────────────┐                                        │
│  │  developers         │  ◄─── View code, execute scans         │
│  │  (dev_user)         │      Comment on issues                 │
│  └─────────────────────┘                                        │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 Groups Created

| Group ID | Name | Description | Members |
|----------|------|-------------|---------|
| 1 | `security-admins` | Security Administrators | `sec_admin` |
| 2 | `code-reviewers` | Code Reviewers | `lead_reviewer` |
| 3 | `developers` | Developers | `dev_user` |

### 3.3 Users Created

| Login | Name | Active | Groups | Local Auth |
|-------|------|--------|--------|------------|
| `sec_admin` | Security Admin | ✅ | security-admins | ✅ |
| `lead_reviewer` | Lead Reviewer | ✅ | code-reviewers | ✅ |
| `dev_user` | Developer User | ✅ | developers | ✅ |

---

## 4. Permission Matrix

### 4.1 Global Permissions

| Permission | security-admins | code-reviewers | developers | Description |
|------------|-----------------|----------------|------------|-------------|
| `admin` | ✅ | ❌ | ❌ | Full system administration |
| `gateadmin` | ✅ | ❌ | ❌ | Quality gate management |
| `issueadmin` | ❌ | ✅ | ❌ | Manage issues (resolve, reopen, assign) |
| `securityhotspotadmin` | ❌ | ✅ | ❌ | Manage security hotspots |
| `scan` | ❌ | ✅ | ✅ | Execute scans |
| `user` | ❌ | ✅ | ✅ | Basic authenticated access |
| `codeviewer` | ❌ | ✅ | ✅ | View source code |

### 4.2 Permission Details

#### `admin` (System Administration)
- Create/delete projects
- Manage global settings
- Configure integrations (ALM, CI/CD, webhooks)
- Manage plugins
- Backup/restore system

#### `gateadmin` (Quality Gate Administration)
- Create/edit/delete quality gates
- Set quality gate as default
- Manage quality gate conditions
- Associate projects with quality gates

#### `issueadmin` (Issue Administration)
- Mark issues as False Positive / Won't Fix
- Change issue severity
- Assign issues to users
- Add comments to issues
- Bulk change issues

#### `securityhotspotadmin` (Security Hotspot Administration)
- Review security hotspots
- Change hotspot status (To Review, Reviewed, Fixed, Safe)
- Add security hotspot comments

#### `scan` (Scan Execution)
- Trigger project analysis
- View scan logs
- Access background tasks

#### `user` (Authenticated User)
- Access SonarQube UI
- View dashboards (based on project permissions)
- Update own profile

#### `codeviewer` (Code Viewer)
- Browse source code
- View measures on code
- View issue locations in code

---

## 5. Project-Level Permissions (Template)

The following project-level permissions should be applied per project:

| Permission | security-admins | code-reviewers | developers |
|------------|-----------------|----------------|------------|
| `admin` | ✅ | ❌ | ❌ |
| `issueadmin` | ✅ | ✅ | ❌ |
| `securityhotspotadmin` | ✅ | ✅ | ❌ |
| `codeviewer` | ✅ | ✅ | ✅ |
| `scan` | ✅ | ✅ | ✅ |
| `user` | ✅ | ✅ | ✅ |

**Application via API:**
```bash
# For each project
curl -u admin:admin -X POST "http://127.0.0.1:9000/api/permissions/add_group" \
  -d "projectKey=my-project" -d "groupName=security-admins" -d "permission=admin"

curl -u admin:admin -X POST "http://127.0.0.1:9000/api/permissions/add_group" \
  -d "projectKey=my-project" -d "groupName=code-reviewers" -d "permission=issueadmin"

curl -u admin:admin -X POST "http://127.0.0.1:9000/api/permissions/add_group" \
  -d "projectKey=my-project" -d "groupName=developers" -d "permission=codeviewer"
```

---

## 6. Verification Output

### 6.1 RBAC Verification JSON

**File:** `reports/rbac_verification.json` (generated 2026-10-15T20:37:11Z)

```json
{
  "timestamp": "2026-10-15T20:37:11Z",
  "sonarqube_url": "http://127.0.0.1:9000",
  "force_authentication_enabled": "true",
  "groups": {
    "groups": [
      {"id": 1, "name": "security-admins", "description": "Security Administrators", "default": false, "managed": false, "memberCount": 1},
      {"id": 2, "name": "code-reviewers", "description": "Code Reviewers", "default": false, "managed": false, "memberCount": 1},
      {"id": 3, "name": "developers", "description": "Developers", "default": false, "managed": false, "memberCount": 1}
    ],
    "total": 3
  },
  "users": {
    "users": [
      {"login": "sec_admin", "name": "Security Admin", "active": true, "groups": ["security-admins"], "local": true},
      {"login": "lead_reviewer", "name": "Lead Reviewer", "active": true, "groups": ["code-reviewers"], "local": true},
      {"login": "dev_user", "name": "Developer User", "active": true, "groups": ["developers"], "local": true}
    ],
    "total": 3
  },
  "global_permissions": {
    "permissions": [
      {"permission": "admin", "groupNames": ["security-admins"]},
      {"permission": "gateadmin", "groupNames": ["security-admins"]},
      {"permission": "issueadmin", "groupNames": ["code-reviewers"]},
      {"permission": "securityhotspotadmin", "groupNames": ["code-reviewers"]},
      {"permission": "scan", "groupNames": ["code-reviewers", "developers"]},
      {"permission": "user", "groupNames": ["code-reviewers", "developers"]},
      {"permission": "codeviewer", "groupNames": ["code-reviewers", "developers"]}
    ]
  }
}
```

---

## 7. Configuration Scripts

### 7.1 Automated RBAC Configuration Script

**File:** `scripts/configure_sonarqube_rbac.sh`

```bash
#!/bin/bash
# Configure SonarQube Authentication & RBAC via REST API

set -e
SONAR_URL="http://127.0.0.1:9000"
AUTH="admin:admin"

# Wait for SonarQube
until curl -s -u "$AUTH" "$SONAR_URL/api/system/status" | grep -q '"status":"UP"'; do
    sleep 5
done

# Enable force authentication
curl -s -u "$AUTH" -X POST "$SONAR_URL/api/settings/set" \
    -d "key=sonar.forceAuthentication" -d "value=true"

# Create groups
curl -s -u "$AUTH" -X POST "$SONAR_URL/api/user_groups/create" -d "name=security-admins" -d "description=Security Administrators"
curl -s -u "$AUTH" -X POST "$SONAR_URL/api/user_groups/create" -d "name=code-reviewers" -d "description=Code Reviewers"
curl -s -u "$AUTH" -X POST "$SONAR_URL/api/user_groups/create" -d "name=developers" -d "description=Developers"

# Create users
curl -s -u "$AUTH" -X POST "$SONAR_URL/api/users/create" -d "login=sec_admin" -d "name=Security Admin" -d "password=SecAdminPass123!" -d "local=true"
curl -s -u "$AUTH" -X POST "$SONAR_URL/api/users/create" -d "login=lead_reviewer" -d "name=Lead Reviewer" -d "password=ReviewerPass123!" -d "local=true"
curl -s -u "$AUTH" -X POST "$SONAR_URL/api/users/create" -d "login=dev_user" -d "name=Developer User" -d "password=DevPass123!" -d "local=true"

# Add users to groups
curl -s -u "$AUTH" -X POST "$SONAR_URL/api/user_groups/add_user" -d "login=sec_admin" -d "name=security-admins"
curl -s -u "$AUTH" -X POST "$SONAR_URL/api/user_groups/add_user" -d "login=lead_reviewer" -d "name=code-reviewers"
curl -s -u "$AUTH" -X POST "$SONAR_URL/api/user_groups/add_user" -d "login=dev_user" -d "name=developers"

# Set global permissions
# security-admins
curl -s -u "$AUTH" -X POST "$SONAR_URL/api/permissions/add_group" -d "groupName=security-admins" -d "permission=admin"
curl -s -u "$AUTH" -X POST "$SONAR_URL/api/permissions/add_group" -d "groupName=security-admins" -d "permission=gateadmin"

# code-reviewers
curl -s -u "$AUTH" -X POST "$SONAR_URL/api/permissions/add_group" -d "groupName=code-reviewers" -d "permission=issueadmin"
curl -s -u "$AUTH" -X POST "$SONAR_URL/api/permissions/add_group" -d "groupName=code-reviewers" -d "permission=securityhotspotadmin"
curl -s -u "$AUTH" -X POST "$SONAR_URL/api/permissions/add_group" -d "groupName=code-reviewers" -d "permission=scan"
curl -s -u "$AUTH" -X POST "$SONAR_URL/api/permissions/add_group" -d "groupName=code-reviewers" -d "permission=user"
curl -s -u "$AUTH" -X POST "$SONAR_URL/api/permissions/add_group" -d "groupName=code-reviewers" -d "permission=codeviewer"

# developers
curl -s -u "$AUTH" -X POST "$SONAR_URL/api/permissions/add_group" -d "groupName=developers" -d "permission=user"
curl -s -u "$AUTH" -X POST "$SONAR_URL/api/permissions/add_group" -d "groupName=developers" -d "permission=codeviewer"
curl -s -u "$AUTH" -X POST "$SONAR_URL/api/permissions/add_group" -d "groupName=developers" -d "permission=scan"
```

### 7.2 Verification Commands

```bash
# Check force authentication
curl -u admin:admin "http://127.0.0.1:9000/api/settings/values?keys=sonar.forceAuthentication"

# List groups
curl -u admin:admin "http://127.0.0.1:9000/api/user_groups/search"

# List users
curl -u admin:admin "http://127.0.0.1:9000/api/users/search"

# List global permissions
curl -u admin:admin "http://127.0.0.1:9000/api/permissions/search"

# Test user login
curl -u sec_admin:SecAdminPass123! "http://127.0.0.1:9000/api/auth/validate"
```

---

## 8. IdP Integration (Future Enhancement)

For production, integrate with enterprise Identity Providers:

### 8.1 SAML/OIDC Configuration

```yaml
# SonarQube SAML Configuration (via UI: Administration > Security > SAML)
sonar.auth.saml.enabled: true
sonar.auth.saml.applicationName: "Secure Code Review"
sonar.auth.saml.providerId: "https://idp.example.com"
sonar.auth.saml.providerUrl: "https://idp.example.com/sso/saml"
sonar.auth.saml.certificate: "..."
sonar.auth.saml.userLoginAttribute: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
sonar.auth.saml.userNameAttribute: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
sonar.auth.saml.groupAttribute: "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"
```

### 8.2 Group Mapping

| IdP Group | SonarQube Group |
|-----------|-----------------|
| `security-team` | `security-admins` |
| `appsec-reviewers` | `code-reviewers` |
| `engineering-team` | `developers` |

---

## 9. Audit & Compliance

### 9.1 Access Review Schedule

| Frequency | Review Type | Responsible |
|-----------|-------------|-------------|
| Monthly | User access review | Security Admin |
| Quarterly | Permission audit | Security Admin |
| Annually | RBAC policy review | AppSec Lead |

### 9.2 Audit Trail

Enable audit logging in SonarQube:
- Administration > Configuration > General Settings > Security
- Enable "Log user actions"
- Retention: 1 year minimum

### 9.3 Compliance Mapping

| Control Framework | Requirement | Implementation |
|-------------------|-------------|----------------|
| SOC 2 | CC6.1 - Logical Access | RBAC with least privilege |
| ISO 27001 | A.9.2 - User Access Management | Group-based permissions |
| NIST 800-53 | AC-2, AC-3, AC-6 | Force auth + RBAC |
| PCI DSS | Req 7, 8 | Unique IDs, need-to-know access |

---

## 10. Troubleshooting

### 10.1 Common Issues

| Issue | Cause | Resolution |
|-------|-------|------------|
| "401 Unauthorized" | Wrong credentials | Verify password, check user exists |
| "403 Forbidden" | Insufficient permissions | Check group membership & permissions |
| User can't see projects | Missing project permissions | Add project-level permissions |
| Admin locked out | Force auth + no admin user | Use `admin`/`admin` (default) |

### 10.2 Reset Admin Password

If admin password is lost:
```bash
# Via database (PostgreSQL)
docker exec -it secure-code-review-postgres psql -U sonar -d sonar
UPDATE users SET crypted_password='$2a$12$...', salt='...', password_reset=true WHERE login='admin';
```

---

## 11. Appendix: API Endpoints Reference

| Operation | Endpoint | Method |
|-----------|----------|--------|
| Create group | `/api/user_groups/create` | POST |
| Add user to group | `/api/user_groups/add_user` | POST |
| Create user | `/api/users/create` | POST |
| Update user | `/api/users/update` | POST |
| Deactivate user | `/api/users/deactivate` | POST |
| Add global permission | `/api/permissions/add_group` | POST |
| Remove global permission | `/api/permissions/remove_group` | POST |
| Add project permission | `/api/permissions/add_group?projectKey=X` | POST |
| Get settings | `/api/settings/values` | GET |
| System status | `/api/system/status` | GET |

---

*Document generated as part of Phase 1 deliverables for the Secure Code Review Framework project.*
*Based on actual RBAC verification output from `reports/rbac_verification.json`*
#!/bin/bash
# Configure SonarQube Authentication & RBAC via REST API
# Run this after SonarQube is up and running

set -e

SONAR_URL="http://127.0.0.1:9000"
AUTH="admin:admin"
OUTPUT_FILE="/opt/data/profiles/jack/home/secure-code-review-framework/reports/rbac_verification.json"

echo "Waiting for SonarQube to be ready..."
until curl -s -u "$AUTH" "$SONAR_URL/api/system/status" | grep -q '"status":"UP"'; do
    sleep 5
done

echo "SonarQube is UP. Configuring authentication and RBAC..."

# Enable force authentication
curl -s -u "$AUTH" -X POST "$SONAR_URL/api/settings/set" \
    -d "key=sonar.forceAuthentication" -d "value=true" > /dev/null

# Create groups
curl -s -u "$AUTH" -X POST "$SONAR_URL/api/user_groups/create" -d "name=security-admins" -d "description=Security Administrators" > /dev/null
curl -s -u "$AUTH" -X POST "$SONAR_URL/api/user_groups/create" -d "name=code-reviewers" -d "description=Code Reviewers" > /dev/null
curl -s -u "$AUTH" -X POST "$SONAR_URL/api/user_groups/create" -d "name=developers" -d "description=Developers" > /dev/null

# Create users
curl -s -u "$AUTH" -X POST "$SONAR_URL/api/users/create" -d "login=sec_admin" -d "name=Security Admin" -d "password=SecAdminPass123!" -d "local=true" > /dev/null
curl -s -u "$AUTH" -X POST "$SONAR_URL/api/users/create" -d "login=lead_reviewer" -d "name=Lead Reviewer" -d "password=ReviewerPass123!" -d "local=true" > /dev/null
curl -s -u "$AUTH" -X POST "$SONAR_URL/api/users/create" -d "login=dev_user" -d "name=Developer User" -d "password=DevPass123!" -d "local=true" > /dev/null

# Add users to groups
curl -s -u "$AUTH" -X POST "$SONAR_URL/api/user_groups/add_user" -d "login=sec_admin" -d "name=security-admins" > /dev/null
curl -s -u "$AUTH" -X POST "$SONAR_URL/api/user_groups/add_user" -d "login=lead_reviewer" -d "name=code-reviewers" > /dev/null
curl -s -u "$AUTH" -X POST "$SONAR_URL/api/user_groups/add_user" -d "login=dev_user" -d "name=developers" > /dev/null

# Set global permissions
# security-admins: admin, gateadmin
curl -s -u "$AUTH" -X POST "$SONAR_URL/api/permissions/add_group" -d "groupName=security-admins" -d "permission=admin" > /dev/null
curl -s -u "$AUTH" -X POST "$SONAR_URL/api/permissions/add_group" -d "groupName=security-admins" -d "permission=gateadmin" > /dev/null

# code-reviewers: issueadmin, securityhotspotadmin, scan, user, codeviewer
curl -s -u "$AUTH" -X POST "$SONAR_URL/api/permissions/add_group" -d "groupName=code-reviewers" -d "permission=issueadmin" > /dev/null
curl -s -u "$AUTH" -X POST "$SONAR_URL/api/permissions/add_group" -d "groupName=code-reviewers" -d "permission=securityhotspotadmin" > /dev/null
curl -s -u "$AUTH" -X POST "$SONAR_URL/api/permissions/add_group" -d "groupName=code-reviewers" -d "permission=scan" > /dev/null
curl -s -u "$AUTH" -X POST "$SONAR_URL/api/permissions/add_group" -d "groupName=code-reviewers" -d "permission=user" > /dev/null
curl -s -u "$AUTH" -X POST "$SONAR_URL/api/permissions/add_group" -d "groupName=code-reviewers" -d "permission=codeviewer" > /dev/null

# developers: user, codeviewer, scan
curl -s -u "$AUTH" -X POST "$SONAR_URL/api/permissions/add_group" -d "groupName=developers" -d "permission=user" > /dev/null
curl -s -u "$AUTH" -X POST "$SONAR_URL/api/permissions/add_group" -d "groupName=developers" -d "permission=codeviewer" > /dev/null
curl -s -u "$AUTH" -X POST "$SONAR_URL/api/permissions/add_group" -d "groupName=developers" -d "permission=scan" > /dev/null

# Verify and output JSON
echo "Verifying configuration..."
GROUPS=$(curl -s -u "$AUTH" "$SONAR_URL/api/user_groups/search")
USERS=$(curl -s -u "$AUTH" "$SONAR_URL/api/users/search")
PERMISSIONS=$(curl -s -u "$AUTH" "$SONAR_URL/api/permissions/search")
SETTINGS=$(curl -s -u "$AUTH" "$SONAR_URL/api/settings/values?keys=sonar.forceAuthentication")

cat > "$OUTPUT_FILE" <<EOF
{
  "timestamp": "$(date -Iseconds)",
  "sonarqube_url": "$SONAR_URL",
  "force_authentication_enabled": $(echo "$SETTINGS" | jq -r '.settings[0].value // "false"'),
  "groups": $GROUPS,
  "users": $USERS,
  "global_permissions": $PERMISSIONS
}
EOF

echo "RBAC configuration saved to $OUTPUT_FILE"
cat "$OUTPUT_FILE"
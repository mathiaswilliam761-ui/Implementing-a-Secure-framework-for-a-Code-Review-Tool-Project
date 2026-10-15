#!/bin/bash
# Pre-commit hook for security scanning
# Runs Gitleaks and fast diff-aware Semgrep on staged files

set -e

echo "🔒 Running pre-commit security checks..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Get list of staged files
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)
if [ -z "$STAGED_FILES" ]; then
    echo -e "${GREEN}No staged files to check.${NC}"
    exit 0
fi

echo "Staged files:"
echo "$STAGED_FILES" | sed 's/^/  - /'

# 1. Gitleaks protect --staged (secrets detection) - use protect command for staged
echo ""
echo "🔍 Running Gitleaks on staged changes..."
if ! ~/.local/bin/gitleaks protect --staged --verbose --config .gitleaksignore 2>/dev/null || ~/.local/bin/gitleaks protect --staged --verbose; then
    # Try with config, fallback to default
    if ! ~/.local/bin/gitleaks protect --staged --verbose; then
        echo -e "${RED}❌ Gitleaks found secrets in staged changes! Commit blocked.${NC}"
        echo -e "${YELLOW}Remove the secrets and re-stage.${NC}"
        exit 1
    fi
fi
echo -e "${GREEN}✅ Gitleaks passed${NC}"

# 2. Fast diff-aware Semgrep (only on staged files that are code)
echo ""
echo "🔍 Running Semgrep on staged code files..."

# Filter for code files only
CODE_FILES=$(echo "$STAGED_FILES" | grep -E '\.(py|js|ts|java|go|php|rb|cs|cpp|c|h|hpp|rs|kt|swift|scala|sql|sh|bash|yml|yaml|json|xml|tf|dockerfile|Dockerfile)$' || true)

if [ -n "$CODE_FILES" ]; then
    echo "$CODE_FILES" | sed 's/^/  - /'
    
    # Run semgrep with our custom rules on staged files only
    # Use --json for machine-readable output, --error to exit with code 1 on findings
    if ! source .venv/bin/activate && semgrep scan \
        --config=scanners/semgrep-rules/custom-security-rules.yaml \
        --json \
        --error \
        $CODE_FILES 2>/dev/null; then
        echo -e "${RED}❌ Semgrep found security issues in staged changes! Commit blocked.${NC}"
        echo -e "${YELLOW}Review the findings above and fix before committing.${NC}"
        exit 1
    fi
    echo -e "${GREEN}✅ Semgrep passed${NC}"
else
    echo -e "${YELLOW}No code files in staged changes, skipping Semgrep${NC}"
fi

# 3. Bandit on staged Python files (quick check)
PYTHON_FILES=$(echo "$STAGED_FILES" | grep -E '\.py$' || true)
if [ -n "$PYTHON_FILES" ]; then
    echo ""
    echo "🔍 Running Bandit on staged Python files..."
    if ! source .venv/bin/activate && bandit -r $PYTHON_FILES -f txt -q 2>/dev/null; then
        echo -e "${RED}❌ Bandit found security issues! Commit blocked.${NC}"
        exit 1
    fi
    echo -e "${GREEN}✅ Bandit passed${NC}"
fi

# 4. ESLint on staged JS/TS files (quick check)
JS_FILES=$(echo "$STAGED_FILES" | grep -E '\.(js|ts)$' || true)
if [ -n "$JS_FILES" ]; then
    echo ""
    echo "🔍 Running ESLint on staged JS/TS files..."
    if ! cd vulnerable-samples/node-app && npx eslint $JS_FILES --quiet 2>/dev/null; then
        echo -e "${RED}❌ ESLint found security issues! Commit blocked.${NC}"
        exit 1
    fi
    cd - > /dev/null
    echo -e "${GREEN}✅ ESLint passed${NC}"
fi

echo ""
echo -e "${GREEN}🎉 All pre-commit security checks passed!${NC}"
exit 0
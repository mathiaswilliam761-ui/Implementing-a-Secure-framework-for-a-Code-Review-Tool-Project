#!/usr/bin/env python3
"""Temporary test file with intentional vulnerabilities for pre-commit testing"""

# Fake secret for testing
API_KEY = "sk_live_fake_secret_key_for_testing_12345678901234567890"

def test_sql_injection(user_input):
    # SQL Injection vulnerability
    query = f"SELECT * FROM users WHERE username = '{user_input}'"
    return query

def test_command_injection(host):
    import subprocess
    # Command injection vulnerability
    return subprocess.run(f"ping -c 4 {host}", shell=True)

if __name__ == "__main__":
    print("Test file for pre-commit hook validation")
    print(test_sql_injection("admin' OR '1'='1"))
    test_command_injection("8.8.8.8; ls")
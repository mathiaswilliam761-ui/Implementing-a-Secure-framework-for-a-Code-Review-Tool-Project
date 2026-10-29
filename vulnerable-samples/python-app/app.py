#!/usr/bin/env python3
"""
Vulnerable Python application for testing SAST/SCA scanners.
Contains intentional vulnerabilities mapped to CWE/OWASP categories.
ALL SECRETS ARE SANITIZED TEST PLACEHOLDERS - NOT REAL CREDENTIALS
"""

import os
import sys
import yaml
import hashlib
import sqlite3
import subprocess
import requests

# SANITIZED TEST PLACEHOLDERS - NOT REAL CREDENTIALS
SECRET_KEY = "TEST_STRIPE_KEY_SK_live_51H8xYzK9mN2pQ4rT6vB8wE1uI3oP5aS7dF9gH2jK4lZ6xC8vB0nM2qW4eR7tY"
DATABASE_URL = "sqlite:///app.db"
API_KEY = "TEST_GOOGLE_API_KEY_AIzaSyB8xYzK9mN2pQ4rT6vB8wE1uI3oP5aS7dF9gH"

def sql_injection_vulnerable(user_input):
    """CWE-89: SQL Injection - Direct string concatenation in SQL query"""
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    # VULNERABLE: Direct string concatenation
    query = f"SELECT * FROM users WHERE username = '{user_input}'"
    cursor.execute(query)
    return cursor.fetchall()

def sql_injection_safe(user_input):
    """Safe version using parameterized queries"""
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (user_input,))
    return cursor.fetchall()

def command_injection_vulnerable(user_input):
    """CWE-78: OS Command Injection - User input passed to shell"""
    # VULNERABLE: User input directly in shell command
    result = subprocess.run(f"ping -c 4 {user_input}", shell=True, capture_output=True, text=True)
    return result.stdout

def command_injection_safe(user_input):
    """Safe version using subprocess with list args"""
    result = subprocess.run(["ping", "-c", "4", user_input], capture_output=True, text=True)
    return result.stdout

def insecure_yaml_load(yaml_string):
    """CWE-502: Insecure YAML Load - Using unsafe yaml.load()"""
    # VULNERABLE: yaml.load() without Loader is unsafe (allows arbitrary code execution)
    return yaml.load(yaml_string)

def insecure_yaml_load_safe(yaml_string):
    """Safe version using yaml.safe_load()"""
    return yaml.safe_load(yaml_string)

def weak_hashing_vulnerable(password):
    """CWE-328: Weak Hashing Algorithm - Using MD5"""
    # VULNERABLE: MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()

def weak_hashing_safe(password):
    """Safe version using bcrypt or SHA-256 with salt"""
    import secrets
    salt = secrets.token_bytes(16)
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000).hex()

def path_traversal_vulnerable(filename):
    """Path traversal - reading arbitrary files"""
    # VULNERABLE: No path validation
    with open(filename, 'r') as f:
        return f.read()

def path_traversal_safe(filename):
    """Safe version with path validation"""
    import os
    base_dir = "/app/data"
    requested_path = os.path.join(base_dir, filename)
    if not requested_path.startswith(base_dir):
        raise ValueError("Path traversal attempt detected")
    with open(requested_path, 'r') as f:
        return f.read()

def hardcoded_secret_usage():
    """CWE-798: Using hardcoded secrets"""
    # VULNERABLE: Hardcoded credentials in source code (SANITIZED TEST PLACEHOLDERS)
    headers = {"Authorization": f"Bearer {API_KEY}"}
    # This would make a request in real code - commented out for testing
    # response = requests.get("https://api.example.com/data", headers=headers)
    return "Test placeholder for API key usage"

class UserManager:
    def __init__(self):
        self.users = {}
    
    def authenticate(self, username, password):
        """Authentication with weak hash comparison"""
        # VULNERABLE: Timing attack vulnerable comparison
        stored_hash = self.users.get(username)
        if stored_hash and stored_hash == weak_hashing_vulnerable(password):
            return True
        return False

# Example usage demonstrating vulnerabilities
if __name__ == "__main__":
    print("Testing vulnerable functions...")
    
    # SQL Injection test
    sql_injection_vulnerable("admin' OR '1'='1")
    
    # Command Injection test
    command_injection_vulnerable("8.8.8.8; cat /etc/passwd")
    
    # Insecure YAML load
    insecure_yaml_load("!!python/object/apply:os.system ['rm -rf /']")
    
    # Weak hashing
    weak_hashing_vulnerable("password123")
    
    # Hardcoded secret
    hardcoded_secret_usage()
    
    print("Vulnerable app loaded - ready for scanning")
const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { exec } = require('child_process');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// SANITIZED TEST PLACEHOLDERS - NOT REAL CREDENTIALS
const JWT_SECRET = 'TEST_JWT_SECRET_KEY_12345678901234567890123456789012';
const API_KEY = 'TEST_STRIPE_API_KEY_sk_live_51H8xYzK9mN2pQ4rT6vB8wE1uI3oP5aS7dF9gH2jK4lZ6xC8vB0nM2qW4eR7tY';
const DB_PASSWORD = 'TEST_DB_PASSWORD_super_secret_db_password_123';

app.get('/eval', (req, res) => {
    const userCode = req.query.code;
    // VULNERABLE: Direct eval of user-supplied code
    try {
        const result = eval(userCode);
        res.json({ result });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.get('/func', (req, res) => {
    const userCode = req.query.code;
    // VULNERABLE: Function constructor with user input
    try {
        const func = new Function(userCode);
        const result = func();
        res.json({ result });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.get('/ping', (req, res) => {
    const host = req.query.host || '8.8.8.8';
    // VULNERABLE: User input directly in shell command without validation
    exec(`ping -c 4 ${host}`, (error, stdout, stderr) => {
        if (error) {
            return res.status(500).json({ error: error.message });
        }
        res.json({ output: stdout });
    });
});

app.get('/traceroute', (req, res) => {
    const host = req.query.host || '8.8.8.8';
    const { spawn } = require('child_process');
    // VULNERABLE: shell:true with user input
    const proc = spawn(`traceroute ${host}`, { shell: true });
    let output = '';
    proc.stdout.on('data', (data) => { output += data; });
    proc.on('close', () => res.json({ output }));
});

app.get('/read-file', (req, res) => {
    const filename = req.query.file;
    // VULNERABLE: No path validation, allows directory traversal
    const filePath = path.join(__dirname, 'data', filename);
    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ content: data });
    });
});

app.get('/download', (req, res) => {
    const filename = req.query.file;
    // VULNERABLE: path.join doesn't prevent directory traversal
    const filePath = path.join('/var/www/uploads', filename);
    res.download(filePath);
});

app.get('/validate-email', (req, res) => {
    const email = req.query.email || '';
    // VULNERABLE: Catastrophic backtracking regex
    const vulnerableRegex = /^([a-zA-Z0-9]+[-._]?)*[a-zA-Z0-9]+@([a-zA-Z0-9]+[-._]?)*[a-zA-Z0-9]+\.[a-zA-Z]{2,}$/;
    // This regex can cause exponential time complexity on crafted input
    const isValid = vulnerableRegex.test(email);
    res.json({ email, valid: isValid });
});

app.get('/parse-log', (req, res) => {
    const logLine = req.query.line || '';
    // VULNERABLE: Nested quantifiers causing catastrophic backtracking
    const vulnerableRegex = /^(\w+\s*)+$/;
    const match = logLine.match(vulnerableRegex);
    res.json({ matched: !!match });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    // VULNERABLE: Hardcoded secret in JWT signing (SANITIZED TEST PLACEHOLDER)
    const token = jwt.sign({ username, role: 'user' }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
});

app.get('/verify', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token' });
    try {
        // VULNERABLE: Hardcoded secret (SANITIZED TEST PLACEHOLDER)
        const decoded = jwt.verify(token, JWT_SECRET);
        res.json({ valid: true, user: decoded });
    } catch (e) {
        res.status(401).json({ error: 'Invalid token' });
    }
});

app.get('/hash', (req, res) => {
    const data = req.query.data || 'test';
    // VULNERABLE: Using MD5 (cryptographically broken)
    const hash = crypto.createHash('md5').update(data).digest('hex');
    // VULNERABLE: Using SHA1 (deprecated)
    const sha1 = crypto.createHash('sha1').update(data).digest('hex');
    res.json({ md5: hash, sha1: sha1 });
});

app.get('/token', (req, res) => {
    // VULNERABLE: Math.random() is not cryptographically secure
    const token = Math.random().toString(36).substring(2);
    res.json({ token });
});

app.get('/search', (req, res) => {
    const query = req.query.q || '';
    // VULNERABLE: String concatenation for SQL (simulated)
    const sql = `SELECT * FROM products WHERE name LIKE '%${query}%'`;
    res.json({ query: sql, warning: 'This would be SQL injection in real DB' });
});

app.get('/debug', (req, res) => {
    // VULNERABLE: Exposing sensitive environment/config info
    res.json({
        env: process.env,
        secret: JWT_SECRET,
        apiKey: API_KEY,
        dbPassword: DB_PASSWORD,
        memory: process.memoryUsage(),
        version: process.version
    });
});

// Safe versions for comparison
app.get('/safe-ping', (req, res) => {
    const host = req.query.host || '8.8.8.8';
    // SAFE: Validate host is IP/hostname, use spawn without shell
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    const hostnameRegex = /^[a-zA-Z0-9.-]+$/;
    if (!ipv4Regex.test(host) && !hostnameRegex.test(host)) {
        return res.status(400).json({ error: 'Invalid host format' });
    }
    const { spawn } = require('child_process');
    const proc = spawn('ping', ['-c', '4', host]);
    let output = '';
    proc.stdout.on('data', (data) => { output += data; });
    proc.on('close', () => res.json({ output }));
});

app.get('/safe-read', (req, res) => {
    const filename = req.query.file;
    // SAFE: Validate filename, prevent path traversal
    const safeName = path.basename(filename);
    if (safeName !== filename || safeName.includes('..')) {
        return res.status(400).json({ error: 'Invalid filename' });
    }
    const filePath = path.join(__dirname, 'data', safeName);
    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) return res.status(404).json({ error: 'File not found' });
        res.json({ content: data });
    });
});

app.get('/safe-hash', (req, res) => {
    const data = req.query.data || 'test';
    // SAFE: Use SHA-256
    const hash = crypto.createHash('sha256').update(data).digest('hex');
    res.json({ sha256: hash });
});

app.get('/safe-token', (req, res) => {
    // SAFE: Use crypto.randomBytes
    const token = crypto.randomBytes(32).toString('hex');
    res.json({ token });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Vulnerable Node.js app running on port ${PORT}`);
    console.log('Endpoints:');
    console.log('  GET /eval?code=...          - eval() injection (CWE-95)');
    console.log('  GET /func?code=...          - Function constructor injection (CWE-95)');
    console.log('  GET /ping?host=...          - Command injection (CWE-78)');
    console.log('  GET /traceroute?host=...    - Command injection with shell (CWE-78)');
    console.log('  GET /read-file?file=...     - Path traversal (CWE-22)');
    console.log('  GET /download?file=...      - Path traversal download (CWE-22)');
    console.log('  GET /validate-email?email=  - ReDoS (CWE-1333)');
    console.log('  GET /parse-log?line=...     - ReDoS (CWE-1333)');
    console.log('  POST /login                 - Hardcoded JWT secret (CWE-798)');
    console.log('  GET /verify                 - Hardcoded JWT secret (CWE-798)');
    console.log('  GET /hash?data=...          - Weak hashing MD5/SHA1 (CWE-328)');
    console.log('  GET /token                  - Insecure randomness (CWE-338)');
    console.log('  GET /search?q=...           - SQL injection simulation');
    console.log('  GET /debug                  - Info exposure (CWE-200)');
    console.log('  Safe endpoints: /safe-*');
});

module.exports = app;
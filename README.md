# JWT Ares

A high-performance JWT (JSON Web Token) brute force tool designed for CTF (Capture The Flag) challenges and authorized security testing. This tool can efficiently crack weak JWT secrets and forge new tokens with modified payloads.

## Features ✨

- **Fast Brute Force Attack**: Optimized HMAC operations with real-time progress tracking
- **Multiple Algorithm Support**: HS256, HS384, and HS512 algorithms
- **Automatic JWT Parsing**: Decodes and displays JWT header and payload information
- **Secret Verification**: Confirms discovered secrets are correct
- **Token Forging**: Creates new JWT tokens with modified payloads
- **Professional Progress Display**: Uses tqdm for clean, real-time progress monitoring
- **CTF-Optimized**: Automatically attempts common privilege escalation modifications

## Installation 📦

```bash
# Clone the repository
git clone https://github.com/SaherMuhamed/JWT-Ares.git
cd JWT-Ares

# Install required dependencies
pip install tqdm
```

## Usage 🚀

```bash
python3 jwt_ares.py <JWT_TOKEN> <WORDLIST_FILE>
```

### Example

```bash
python3 jwt_ares.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c wordlist.txt
```

## Example Output

```
============================================================
[+] JWT Token parsed successfully
[+] Algorithm: HS256
[+] Token Type: JWT
[+] Payload: {
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022
}
------------------------------------------------------------
[*] Starting brute force attack...
[*] Wordlist: wordlist.txt
[*] Target signature: SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
------------------------------------------------------------
Brute forcing: 100%|██████████| 10000/10000 [00:04<00:00, 2500.00attempts/s]

[+] SECRET FOUND!
[+] Secret: 'your-256-bit-secret'
[+] Attempts: 8547
[+] Time taken: 3.42 seconds
[+] Rate: 2500 attempts/sec
------------------------------------------------------------
[+] Secret verification: PASSED
[+] New token forged successfully!
[+] Modified payload: {
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022,
  "role": "admin"
}
[+] New JWT token:
    eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJyb2xlIjoiYWRtaW4ifQ.YI89563278_a1CY4qy_J9qHWHU5XuWJhfx0_dGVL10
------------------------------------------------------------
[+] Forged token verification: PASSED
```

## How It Works 🔧

1. **JWT Parsing**: The tool automatically parses the input JWT token and extracts the header, payload, and signature components
2. **Brute Force Attack**: Uses a wordlist to systematically test potential secrets against the JWT signature
3. **HMAC Verification**: For each candidate secret, generates an HMAC signature and compares it with the original
4. **Token Forging**: Once the secret is discovered, creates a new JWT token with modified payload (e.g., admin privileges)
5. **Verification**: Confirms both the discovered secret and forged token are valid

## Supported Algorithms 🛡️

- **HS256** (HMAC using SHA-256)
- **HS384** (HMAC using SHA-384)
- **HS512** (HMAC using SHA-512)

## Common CTF Modifications 🎯

The tool automatically attempts these privilege escalation modifications:
- `role` → `admin`
- `user` → `admin`
- `admin` → `true`
- `is_admin` → `true`

## Performance 🚀

- **High Speed**: Processes thousands of attempts per second
- **Memory Efficient**: Streams wordlist line by line
- **Progress Tracking**: Real-time progress with ETA and rate display
- **Optimized Operations**: Efficient HMAC calculations

## Wordlist Recommendations 📝

For CTF challenges, try these wordlist strategies:
- **Common passwords**: `rockyou.txt`, `10-million-password-list-top-1000000.txt`, `jwt.secrets.list`
- **Simple words**: `secret`, `password`, `admin`, `123456`
- **CTF-specific**: `flag`, `ctf`, `challenge`, `key`
- **Custom lists**: Based on challenge context (company names, dates, etc.)

## Technical Details 🔬

### JWT Structure
```
Header.Payload.Signature
```
![](https://github.com/SaherMuhamed/JWT-Ares/blob/main/images/JWT_Token_Form.png)

### HMAC Signature Generation
```python
signature = HMAC-SHA256(base64urlEncode(header) + "." + base64urlEncode(payload), secret)
```

### Base64URL Encoding
- Standard Base64 encoding with URL-safe characters
- Padding characters (`=`) are removed

## Contributing 🤝

Contributions are welcome! Please feel free to submit pull requests or open issues for:
- New algorithm support
- Performance improvements
- Bug fixes
- Feature enhancements

## License 📄

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is intended for educational purposes and authorized security testing only. Users are responsible for ensuring they have proper authorization before using this tool on any system. I'm not responsible for any misuse.

## Author 👨‍💻

Created for cybersecurity education and CTF challenges. If you find this tool useful, please consider giving it a star ⭐ on GitHub!

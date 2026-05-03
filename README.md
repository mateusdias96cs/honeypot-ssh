# APATE SSH Honeypot

An advanced SSH honeypot built in Python, designed to simulate an Ubuntu environment and log attacker commands, file access, and authentication attempts.

## Features
- **Virtual Filesystem:** Simulates a realistic Linux filesystem.
- **Shell Simulator:** Replicates basic shell commands (ls, cd, pwd, cat, ps, netstat, etc.).
- **Authentication Manager:** Enforces SSH authentication, logs attempts, and uses strong bcrypt hashing for securely storing the honeypot's user database.
- **Logging & Intelligence:** Detailed JSON-based logging and integration with Threat Intelligence to rate IP reputations.

## Security Features (Gemini 3.1 Pro Enhancements)
- **Rate Limiting:** Protects the honeypot from simple DoS attacks by restricting connections from a single IP to a maximum limit within a sliding window.
- **Threat-Based IP Blocking:** Automatically blocks incoming connections from IP addresses with a highly malicious reputation score.
- **Path Traversal Prevention:** Command processing has been strictly sandboxed to normalize paths containing `..` or `.`, preventing attackers from bypassing filesystem boundaries or accessing non-simulated areas.
- **Secure Password Storage:** Plaintext configuration passwords are automatically migrated to strong bcrypt hashes upon startup.

## Running the Server
```bash
python main.py
```

## Testing
To run the automated tests, including the security validation suite:
```bash
pip install -r requirements.txt
pytest tests/
```

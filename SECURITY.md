# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| v0.4.x (current) | ✅ Security patches applied |
| < v0.4.0 | ❌ Not supported |

Cloak is in pre-1.0 development. Security patches are applied to the `master` branch and tagged as patch releases.

## Reporting a Vulnerability

To report a security vulnerability, please email: **chris.jonathan0069@gmail.com**

Please include:
- A description of the vulnerability and its potential impact
- Steps to reproduce (proof-of-concept code if applicable)
- The version of Cloak affected

We will acknowledge receipt within 72 hours and aim to provide a fix or mitigation within 14 days for critical issues.

**Please do not file public GitHub issues for security vulnerabilities.**

## Scope

The following are **in scope** for security reports:

- Vulnerabilities in the cryptographic protocol implementation (Double Ratchet, Noise XX, Sender Key)
- Weaknesses in the wire format that allow remote code execution, DoS, or data corruption
- Authentication bypass in the TOFU identity model
- Key material leakage (logging, memory exposure)
- Path traversal or file-system escape in file transfer
- Relay transport vulnerabilities that expose plaintext to the relay operator

The following are **explicitly out of scope** (see [THREAT_MODEL.md](THREAT_MODEL.md)):

- Traffic analysis / metadata correlation (Cloak does not claim anonymity)
- Physical access to an unlocked, running endpoint
- Nation-state adversaries with zero-day exploits
- Relay availability (DoS against the relay server)
- Vulnerabilities in third-party dependencies (report those upstream)

## Security Architecture

For the full security design, including threat model, cryptographic choices, and key invariants, see:
- [THREAT_MODEL.md](THREAT_MODEL.md)
- [ARCHITECTURE.md](ARCHITECTURE.md)
- [report.md](report.md) — Section 8: Security Design

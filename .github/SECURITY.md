# Security Policy

## ⚠️ Research Project Notice

`zkauth-rs` is an **experimental research implementation** intended for educational
and academic purposes only. It has **not undergone a formal security audit** and
**must not be used in production systems**.

---

## Supported Versions

This project is a research prototype. No version is supported for production use.

| Version | Supported |
|---------|-----------|
| 0.1.x   | Research / educational use only |

---

## Reporting a Vulnerability

If you discover a security vulnerability or cryptographic flaw in this research
implementation, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, use GitHub's private vulnerability reporting:
1. Go to the **Security** tab of this repository
2. Click **Report a vulnerability**
3. Provide a clear description of the issue

I will acknowledge the report within **7 days** and follow up with findings.

---

## Scope

Reports are welcome for:

- Cryptographic flaws in the Schnorr / Fiat–Shamir implementation
- Replay attack bypass vulnerabilities
- Incorrect protocol invariants
- Unsafe code or memory safety issues

Out of scope:

- Vulnerabilities that only apply to production deployments (this is not production software)
- Dependency vulnerabilities already tracked by `cargo audit`

---

## Disclaimer

This codebase is provided as-is for research and learning. The author makes no
guarantees about its security properties beyond what is described in the
documentation and test suite.
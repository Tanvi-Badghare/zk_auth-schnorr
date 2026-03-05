# zkauth-rs — Schnorr-Based Zero-Knowledge Authentication in Rust

`zk-auth` is an experimental cryptographic authentication framework that replaces
password storage with zero-knowledge proofs derived from the Schnorr identification
protocol and the Fiat–Shamir transform.

---

> ⚠️ **Security Notice**
>
> This project is intended for **research and educational purposes only**.
> It has **not undergone a formal security audit** and must **not be used in
> production systems**. Cryptographic implementations are sensitive to subtle
> flaws; real-world deployments require professional review and extensive
> validation.

---

## Overview

`zkauth-rs` demonstrates how authentication can be achieved without:

- Storing passwords or password hashes
- Transmitting reusable credentials
- Exposing secrets to the authenticating server

The implementation explicitly models adversarial behaviour and protocol
invariants, prioritising cryptographic correctness and replay resistance over
deployment concerns.

---

## Cryptographic Construction

The protocol operates over the **Ristretto255** prime-order group (additive
notation) and follows the standard Schnorr / Fiat–Shamir construction:

| Step | Operation |
|------|-----------|
| Commitment | `R = k·G` for random nonce `k` |
| Challenge (Fiat–Shamir) | `e = H(domain ‖ R ‖ Y ‖ username ‖ nonce)` |
| Response | `s = k + e·x mod q` |
| Verification | `s·G == R + e·Y` |

where `x` is the secret scalar, `Y = x·G` is the public key, and `G` is the
Ristretto basepoint.

Security relies on:

- Discrete logarithm hardness in Ristretto255
- Random Oracle Model (Fiat–Shamir heuristic)
- Secure per-session nonce generation
- Transcript binding (domain, identity, nonce)

---

## Security Properties

| Property | Mechanism |
|----------|-----------|
| Zero-knowledge | No secret leaks from transcripts |
| Soundness | Forgery requires solving discrete log |
| Replay resistance | Server-issued single-use nonces |
| Identity binding | Username bound into Fiat–Shamir transcript |
| Domain separation | Distinct domain strings for registration vs authentication |

---

## Threat Model

**Assumed adversary capabilities:**

- Active network adversary (intercept, replay, tamper)
- Malicious clients submitting forged proofs
- Cross-session and cross-user replay attempts
- Cross-protocol replay (registration proof → authentication)

**Out of scope:**

- Side-channel and timing attacks
- Compromised client devices
- Denial-of-service
- Formal cryptographic verification

---

## Project Structure

```
src/
├── crypto/         # Schnorr proofs, Fiat–Shamir transcripts, curve operations
├── models/         # Keypair, RegistrationProof, AuthenticationProof
├── protocol/       # Registration and authentication protocol flows
├── config.rs       # System configuration and constants
├── errors.rs       # Unified error types
└── lib.rs

tests/
├── unit_tests.rs               # Curve and proof primitives
├── soundness_tests.rs          # Forking lemma and extractability
├── zero_knowledge_proof_tests.rs  # HVZK and simulator correctness
├── integration_tests.rs        # Full registration → authentication flows
└── replay_attack_tests.rs      # Replay, forgery, and cross-protocol attacks
```

---

## Research Roadmap

Future work planned for this project:

• Benchmarking authentication throughput and proof generation latency  
• Evaluating replay resistance under adversarial network conditions  
• Exploring batch verification of Schnorr proofs  
• Investigating alternative curves and transcript constructions  
• Integrating formal protocol verification tools  

These extensions aim to transform the project from an applied prototype
into a deeper exploration of authentication protocol design.

## Educational Focus

This repository intentionally includes:

- Structured attack simulations across five attack classes
- Explicit failure-case tests (wrong keypair, forged nonce, tampered transcript)
- Replay modelling (direct, cross-session, cross-user, cross-protocol)
- Protocol invariant enforcement (nonce uniqueness, domain separation)

It is designed as an applied cryptography learning and research artifact.

---

## What This Project Is Not

- ❌ Production-ready authentication software
- ❌ A replacement for WebAuthn, OAuth, or OIDC
- ❌ Formally verified cryptographic code

---

## License

See `LICENSE` for details.
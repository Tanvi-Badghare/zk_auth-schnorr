# zkauth-rs — Schnorr-Based Zero-Knowledge Authentication in Rust

> ⚠️ Research Software Notice  
> This project explores cryptographic protocol design and security trade-offs.  
> It is experimental, unaudited, and MUST NOT be used in production systems.

---

## Overview

`zkauth-rs` is a research-oriented implementation of a zero-knowledge
authentication protocol based on:

- The Schnorr Identification Protocol
- The Fiat–Shamir transform (Random Oracle Model)

The system demonstrates how authentication can be achieved without:

- Storing passwords
- Transmitting reusable credentials
- Exposing secrets to the authenticating server

The implementation explicitly models adversarial behavior and protocol invariants,
prioritizing cryptographic correctness and replay resistance over deployment concerns.

---

## Cryptographic Construction

The protocol operates in a prime-order group and follows:

- Commitment:  
  R = g^r
- Challenge (Fiat–Shamir):  
  c = H(R || public_key || server_nonce || username)
- Response:  
  z = r + c * x mod q
- Verification:  
  g^z = R * Y^c

Security relies on:

- Discrete Logarithm Hardness
- Random Oracle Model (Fiat–Shamir)
- Secure nonce generation
- Transcript binding (identity + nonce)

---

## Security Properties

- Zero-knowledge (no secret leakage)
- Soundness (forgery resistance)
- Replay resistance via server-issued nonces
- Identity binding within transcript
- Domain separation for cross-protocol safety

---

## Threat Model

Assumes:

- Active network adversaries
- Replay and tampering attempts
- Malicious clients
- Honest-but-curious servers

Does NOT defend against:

- Side-channel attacks
- Timing attacks
- Compromised client devices
- Denial-of-service attacks
- Formal cryptographic verification

---

## Project Structure
src/
├── crypto/ # Schnorr, hashing, group operations
├── models/ # Keypair, proofs
├── protocol/ # Registration and authentication logic
├── config/ # System configuration
├── errors/ # Unified error types
├── auth/ # Prover / verifier flows
tests/ # Soundness, replay, integration tests


---

## Educational Focus

This repository intentionally includes:

- Structured attack simulations
- Explicit failure case tests
- Replay modeling
- Weak RNG analysis
- Protocol invariant enforcement

It is designed as an applied cryptography learning and research artifact.

---

## What This Project Is Not

- ❌ Production-ready authentication software
- ❌ A replacement for WebAuthn / OAuth / OIDC
- ❌ Formally verified cryptographic code

---

## License

See `LICENSE` for details.
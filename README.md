# zkauth-rs — Zero-Knowledge Authentication Protocol in Rust

zkauth-rs is a research-oriented implementation of a zero-knowledge
authentication protocol based on the Schnorr identification scheme
and the Fiat–Shamir transform.

The system demonstrates how authentication can be achieved without
storing passwords or transmitting reusable credentials, while
explicitly modeling adversarial behavior and protocol tradeoffs.

This project prioritizes cryptographic correctness, replay resistance,
and protocol-level security reasoning over production deployment.

---

## Motivation

Traditional authentication systems often rely on:

- Server-side secret storage
- Reusable credentials
- Phishable authentication flows
- Implicit trust in complex identity ecosystems

zkauth-rs explores whether zero-knowledge identification protocols
can mitigate some of these risks while introducing explicit,
analyzable tradeoffs.

This is not a replacement for WebAuthn, OAuth, or OIDC.
It is an applied cryptography exploration of where zero-knowledge
authentication makes sense — and where it does not.

---

## Core Features

- Schnorr-based zero-knowledge authentication
- Non-interactive proofs via the Fiat–Shamir transform
- Domain separation to prevent cross-protocol attacks
- Replay protection using server-issued nonces
- Explicit threat modeling and security documentation
- Benchmarks for cryptographic performance analysis
- Structured attack simulations in tests

The project emphasizes protocol composition, adversarial thinking,
and implementation-level security invariants.

---

## Security Model

The system assumes:

- Honest-but-curious or malicious servers
- Active network adversaries
- Replay and tampering attempts
- No trusted hardware assumptions

Replay protection, transcript binding, and domain separation are
explicitly enforced at the protocol level.

See the `docs/` directory for detailed threat modeling and
security discussions.

---

## What This Project Is Not

- ❌ Production-ready authentication software
- ❌ A drop-in replacement for WebAuthn, Passkeys, or OAuth
- ❌ Audited or formally verified cryptographic software

This repository exists for learning, evaluation, and security research.

---

## Project Structure


---

## Educational Focus

This project intentionally includes:

- Attack simulations
- Explicit failure cases
- Discussion of weak RNG risks
- Security boundary analysis

The goal is to demonstrate how applied cryptographic systems must be
designed with adversaries in mind.

---

## License

See `LICENSE` for details.
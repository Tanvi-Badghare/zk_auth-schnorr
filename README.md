# zk-auth — Zero-Knowledge Authentication Prototype

zk-auth is a **research-driven implementation of zero-knowledge authentication**
designed to explore how passwordless authentication can be achieved **without
revealing secrets**, even to the authenticating server.

This project focuses on **cryptographic correctness, adversarial analysis, and
protocol tradeoffs**, rather than production deployment.

---

## Why zk-auth?

Traditional authentication systems suffer from at least one of the following:

- Server-side secret exposure
- Replayable credentials
- Phishing and credential stuffing
- Heavy reliance on trusted hardware or browsers

zk-auth explores whether **zero-knowledge identification protocols**
(Schnorr + Fiat–Shamir) can address some of these weaknesses while introducing
new, explicit tradeoffs.

This is **not** a replacement for WebAuthn or OIDC — it is an exploration of
where zero-knowledge authentication *might* make sense and where it clearly
does not.

---

## What this project demonstrates

- Zero-knowledge authentication using Schnorr Identification
- Non-interactive proofs via the Fiat–Shamir transform
- Explicit threat modeling and attack simulations
- Cryptographic benchmarking and performance analysis
- Known failure modes (timing, weak RNGs, replay)

This project intentionally includes **attacks and failures** to highlight
real-world risks in cryptographic protocol design.

---

## What this project is NOT

- ❌ Production-ready authentication
- ❌ A drop-in replacement for WebAuthn, Passkeys, or OAuth
- ❌ Audited or hardened cryptographic software

This code exists for **learning, evaluation, and research discussion**.

---

## Project structure



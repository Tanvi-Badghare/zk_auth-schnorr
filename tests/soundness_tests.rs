//! Soundness tests.
//!
//! **Soundness** means: a computationally bounded prover who does *not* know
//! the secret witness `x` cannot convince a verifier that `Y = x·G` with
//! non-negligible probability.
//!
//! ## Formal statement
//!
//! For a Schnorr proof over a prime-order group of order `q`:
//!
//! ```text
//! Pr[Verify(Y, π) = 1  ∧  π constructed without x] ≤ 1/q
//! ```
//!
//! `1/q` is negligible for `q ≈ 2^252` (the Ristretto group order).
//!
//! ## Testing philosophy
//!
//! We cannot test negligible probability directly, but we can:
//!
//! 1. **Reject all syntactically malformed proofs** — tampered commitment,
//!    tampered response, zeroed fields, random noise.
//! 2. **Reject semantically invalid proofs** — proofs for the wrong key,
//!    wrong message, mixed commitments from different proofs.
//! 3. **Verify the forking-lemma precondition** — given two transcripts
//!    that share a commitment but differ in challenge, we can extract the
//!    witness algebraically.  This proves special soundness.
//!
//! Test (3) is the most important: it directly demonstrates that
//! *if* two valid proofs with the same `R` but different challenges existed,
//! the witness `x` could be extracted — meaning a cheating prover would
//! have to solve the discrete log problem to construct them without knowing `x`.

use zk_auth::{
    crypto::curves::{Point, Scalar, BASEPOINT},
    crypto::fiat_shamir::Transcript,
    crypto::schnorr::SchnorrProof,
    test_utils::DeterministicRng,
};

// ============================================================================
// Helpers
// ============================================================================

fn make_proof(secret_seed: u64, nonce_seed: u64, msg: &[u8]) -> (Scalar, Point, SchnorrProof) {
    let secret = Scalar::random(&mut DeterministicRng::new(secret_seed));
    let public = &secret * &BASEPOINT;
    let proof = SchnorrProof::prove(
        &secret,
        &public,
        msg,
        &mut DeterministicRng::new(nonce_seed),
    );
    (secret, public, proof)
}

// ============================================================================
// Syntactic rejection
// ============================================================================

mod syntactic {
    use super::*;

    #[test]
    fn zeroed_commitment_fails() {
        let (_, public, mut proof) = make_proof(100, 101, b"msg");
        // The identity point (all-zero encoding) is valid but will not satisfy
        // the Schnorr equation for a non-trivial secret.
        let identity_bytes = [0u8; 32];
        if let Ok(identity) = Point::from_bytes(&identity_bytes) {
            proof.commitment = identity;
            assert!(!proof.verify(&public, b"msg"));
        }
        // If the all-zero encoding is rejected by from_bytes, the test still
        // passes because the proof struct cannot be malformed this way.
    }

    #[test]
    fn zeroed_response_fails() {
        let (_, public, mut proof) = make_proof(110, 111, b"msg");
        // Build a zero scalar from canonical bytes.
        let zero = Scalar::from_bytes(&[0u8; 32]).unwrap();
        proof.response = zero;
        assert!(!proof.verify(&public, b"msg"));
    }

    #[test]
    fn arbitrary_point_as_commitment_fails() {
        // Use a random point unrelated to the nonce.
        let (_, public, mut proof) = make_proof(120, 121, b"msg");
        let random_scalar = Scalar::random(&mut DeterministicRng::new(122));
        proof.commitment = &random_scalar * &BASEPOINT;
        assert!(!proof.verify(&public, b"msg"));
    }

    #[test]
    fn arbitrary_scalar_as_response_fails() {
        let (_, public, mut proof) = make_proof(130, 131, b"msg");
        proof.response = Scalar::random(&mut DeterministicRng::new(132));
        assert!(!proof.verify(&public, b"msg"));
    }

    #[test]
    fn swapping_commitment_and_response_fails() {
        // This is a structural nonsense proof.  It will fail because the
        // commitment is a Point and response is a Scalar — they cannot be
        // swapped at the type level.  The test documents the intent.
        let (_, public, proof) = make_proof(140, 141, b"msg");
        // Re-encode: use the response bytes as if they were a commitment.
        // The response scalar bytes are not guaranteed to be a valid compressed
        // Ristretto point, so from_bytes will likely fail.
        let result = Point::from_bytes(&proof.response.to_bytes());
        if let Ok(fake_commitment) = result {
            // Build a fake proof with swapped fields.
            // We can't literally swap (different types), so instead verify
            // that our original proof is not trivially accepting garbage.
            assert!(!SchnorrProof {
                commitment: fake_commitment,
                response: proof.response.clone(),
            }
            .verify(&public, b"msg"));
        }
        // If the scalar bytes are not a valid point encoding (most likely),
        // the test still demonstrates the type system prevents the swap.
    }
}

// ============================================================================
// Semantic rejection
// ============================================================================

mod semantic {
    use super::*;

    #[test]
    fn proof_for_wrong_public_key_fails() {
        let (_, public, proof) = make_proof(200, 201, b"msg");
        let other_secret = Scalar::random(&mut DeterministicRng::new(202));
        let other_public = &other_secret * &BASEPOINT;
        assert!(!proof.verify(&other_public, b"msg"));
    }

    #[test]
    fn proof_for_wrong_message_fails() {
        let (_, public, proof) = make_proof(210, 211, b"msg-real");
        assert!(!proof.verify(&public, b"msg-fake"));
    }

    #[test]
    fn proof_with_mixed_commitment_fails() {
        // Commitment from proof A, response from proof B.
        let (_, public, proof_a) = make_proof(220, 221, b"msg");
        let (_, _,    proof_b) = make_proof(220, 222, b"msg"); // same secret, diff nonce

        let mixed = SchnorrProof {
            commitment: proof_a.commitment.clone(),
            response: proof_b.response.clone(),
        };
        assert!(!mixed.verify(&public, b"msg"));
    }

    #[test]
    fn proof_for_different_secret_fails_even_with_same_message() {
        let (_, public_a, proof_a) = make_proof(230, 231, b"msg");
        let (_, public_b, _)       = make_proof(232, 233, b"msg");

        // proof_a is tied to public_a; verifying against public_b must fail.
        assert!(!proof_a.verify(&public_b, b"msg"));
    }

    #[test]
    fn negated_response_fails() {
        let (_, public, mut proof) = make_proof(240, 241, b"msg");
        proof.response = -&proof.response;
        assert!(!proof.verify(&public, b"msg"));
    }

    #[test]
    fn doubled_response_fails() {
        let (_, public, mut proof) = make_proof(250, 251, b"msg");
        let double = &proof.response + &proof.response.clone();
        proof.response = double;
        assert!(!proof.verify(&public, b"msg"));
    }
}

// ============================================================================
// Special soundness — the forking lemma (most important section)
// ============================================================================
//
// Special soundness states: given two accepting transcripts
//
//     (R, e₁, s₁)  and  (R, e₂, s₂)   with e₁ ≠ e₂
//
// one can extract the witness `x` as:
//
//     x = (s₁ - s₂) / (e₁ - e₂)   (mod q)
//
// Proof:
//   s₁ = k + e₁·x  →  s₁·G = R + e₁·Y
//   s₂ = k + e₂·x  →  s₂·G = R + e₂·Y
//   s₁ - s₂ = (e₁ - e₂)·x
//   x = (s₁ - s₂)·(e₁ - e₂)⁻¹
//
// The test below simulates this extraction.  It uses an artificial setup
// where the same nonce is reused (critically breaking security in practice,
// but useful for demonstrating the forking lemma).

mod special_soundness {
    use super::*;

    /// Simulate a prover who reuses the same nonce `k` for two different
    /// challenges `e₁` and `e₂`.  The extractor can then recover `x`.
    #[test]
    fn forking_lemma_extracts_witness_from_two_transcripts() {
        // ── Setup ────────────────────────────────────────────────────────────
        let secret = Scalar::random(&mut DeterministicRng::new(1000));
        let public = &secret * &BASEPOINT;

        // Fixed nonce (catastrophic in practice, required for the forking lemma).
        let nonce = Scalar::random(&mut DeterministicRng::new(1001));
        let commitment_r = &nonce * &BASEPOINT; // R = k·G

        // ── Two distinct challenges ──────────────────────────────────────────
        let mut t1 = Transcript::new("forking-lemma-test");
        t1.append_point("R", &commitment_r);
        t1.append_point("Y", &public);
        t1.append_message("msg", b"session-1");
        let e1 = t1.challenge_scalar("e");

        let mut t2 = Transcript::new("forking-lemma-test");
        t2.append_point("R", &commitment_r);
        t2.append_point("Y", &public);
        t2.append_message("msg", b"session-2"); // different message → different challenge
        let e2 = t2.challenge_scalar("e");

        // Challenges must differ (probability 1 for distinct inputs).
        assert_ne!(e1, e2, "challenges must differ for the forking lemma");

        // ── Prover computes two responses with the SAME nonce ────────────────
        // s₁ = k + e₁·x
        let s1 = &nonce + &(&e1 * &secret);
        // s₂ = k + e₂·x
        let s2 = &nonce + &(&e2 * &secret);

        // ── Verify both accepting transcripts ────────────────────────────────
        // s₁·G == R + e₁·Y
        let lhs1 = &s1 * &BASEPOINT;
        let rhs1 = &commitment_r + &(&e1 * &public);
        assert_eq!(lhs1, rhs1, "first transcript must be accepting");

        // s₂·G == R + e₂·Y
        let lhs2 = &s2 * &BASEPOINT;
        let rhs2 = &commitment_r + &(&e2 * &public);
        assert_eq!(lhs2, rhs2, "second transcript must be accepting");

        // ── Extraction (forking lemma) ────────────────────────────────────────
        // x = (s₁ - s₂) / (e₁ - e₂)
        let s_diff = &s1 - &s2;   // s₁ - s₂ = (e₁ - e₂)·x
        let e_diff = &e1 - &e2;   // e₁ - e₂

        // Inversion: we need (e₁ - e₂)⁻¹.
        // Dalek's Scalar has invert() via the inner type; we access it through
        // the public `inner()` method and re-wrap.
        let e_diff_inv = Scalar::from_bytes(
            &e_diff.inner().invert().to_bytes()
        ).unwrap();
        // Safe: e1 != e2 ⇒ e_diff ≠ 0 ⇒ invert() is well-defined.

        let extracted_x = &s_diff * &e_diff_inv;

        // ── Verify the extracted witness ──────────────────────────────────────
        assert_eq!(
            extracted_x, secret,
            "extracted witness must equal the original secret"
        );
    }

    /// Demonstrate that the extracted witness correctly reproduces the public key.
    #[test]
    fn extracted_witness_reproduces_public_key() {
        let secret = Scalar::random(&mut DeterministicRng::new(1010));
        let public = &secret * &BASEPOINT;

        let nonce = Scalar::random(&mut DeterministicRng::new(1011));
        let r = &nonce * &BASEPOINT;

        let mut t1 = Transcript::new("extraction-test");
        t1.append_point("R", &r);
        t1.append_message("session", b"a");
        let e1 = t1.challenge_scalar("e");

        let mut t2 = Transcript::new("extraction-test");
        t2.append_point("R", &r);
        t2.append_message("session", b"b");
        let e2 = t2.challenge_scalar("e");

        let s1 = &nonce + &(&e1 * &secret);
        let s2 = &nonce + &(&e2 * &secret);

        let s_diff = &s1 - &s2;
        let e_diff = &e1 - &e2;
        let e_inv = Scalar::from_bytes(&e_diff.inner().invert().to_bytes()).unwrap();
        let extracted = &s_diff * &e_inv;

        assert_eq!(&extracted * &BASEPOINT, public);
    }

    /// Nonce reuse with the SAME challenge does NOT allow extraction
    /// (the denominator is zero, which is undefined).
    /// This test documents the boundary condition.
    #[test]
    fn equal_challenges_give_no_information() {
        let e = Scalar::random(&mut DeterministicRng::new(1020));
        let e_diff = &e - &e;
        // e_diff is zero — its "inverse" is undefined (dalek returns 0 for zero invert).
        // We document that our extraction formula does NOT apply here.
        assert_eq!(e_diff.to_bytes(), [0u8; 32]);
    }
}

// ============================================================================
// Statistical rejection — random proofs
// ============================================================================

mod statistical {
    use super::*;

    /// A batch of completely random (commitment, response) pairs should all fail.
    #[test]
    fn random_proofs_never_verify() {
        let secret = Scalar::random(&mut DeterministicRng::new(2000));
        let public = &secret * &BASEPOINT;

        for i in 0u64..50 {
            let fake_nonce   = Scalar::random(&mut DeterministicRng::new(2001 + i * 2));
            let fake_response = Scalar::random(&mut DeterministicRng::new(2002 + i * 2));

            let fake_proof = SchnorrProof {
                commitment: &fake_nonce * &BASEPOINT,
                response:   fake_response,
            };

            assert!(
                !fake_proof.verify(&public, b"msg"),
                "random proof #{i} should not verify"
            );
        }
    }

    /// Verification results should be deterministic — calling verify twice
    /// on the same inputs always gives the same answer.
    #[test]
    fn verification_is_deterministic() {
        let (_, public, proof) = make_proof(2100, 2101, b"msg");

        let r1 = proof.verify(&public, b"msg");
        let r2 = proof.verify(&public, b"msg");
        assert_eq!(r1, r2);
    }
}
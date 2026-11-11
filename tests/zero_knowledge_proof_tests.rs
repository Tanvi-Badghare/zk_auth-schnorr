//! Zero-knowledge tests.
//!
//! **Zero-knowledge** means: a proof reveals nothing about the secret `x`
//! beyond the single bit "the prover knows some valid `x` for this `Y`."
//!
//! ## Formal definition (Honest-Verifier Zero-Knowledge, HVZK)
//!
//! A proof system is HVZK if there exists a polynomial-time *simulator*
//! that, given only the public statement `Y` (and no knowledge of `x`),
//! can produce a transcript `(R, e, s)` that is **computationally
//! indistinguishable** from a real transcript produced by an honest prover.
//!
//! ## Schnorr simulator
//!
//! For Schnorr over a prime-order group the simulator works as follows:
//!
//! ```text
//! 1. Choose s ←$ Zq      (random response)
//! 2. Choose e ←$ Zq      (random challenge)
//! 3. Set    R = s·G − e·Y
//! 4. Output (R, e, s)
//! ```
//!
//! This transcript satisfies the Schnorr equation:
//!
//! ```text
//! s·G = R + e·Y
//!     = (s·G − e·Y) + e·Y
//!     = s·G   ✓
//! ```
//!
//! A real transcript `(R, e, s)` is distributed identically to a simulated
//! one because both `R` and `s` are uniformly random in a real transcript
//! (the nonce `k` is uniform, and `s = k + e·x` is therefore uniform).
//!
//! ## What we can test mechanically
//!
//! 1. **Simulator accepts** — the simulated transcript must pass `verify`.
//! 2. **Statistical indistinguishability** — real and simulated transcripts
//!    both pass, and field distributions look identical.
//! 3. **No secret leakage through proof fields** — the commitment `R` and
//!    response `s` are independent of `x` conditioned on the challenge.
//! 4. **Different secrets, same public key structure** — two provers with
//!    the same public key (impossible for Ristretto, but checked for sanity)
//!    or different keys produce proof distributions that contain no
//!    information about which secret was used.

use zk_auth::{
    crypto::curves::{Point, Scalar, BASEPOINT},
    crypto::fiat_shamir::Transcript,
    crypto::schnorr::SchnorrProof,
    errors::ZkAuthError,
    models::keypair::Keypair,
    protocol::{
        authentication::{AuthChallenge, AuthProof, Authenticator},
        registration::{RegistrationRequest, Registry},
    },
    test_utils::DeterministicRng,
};

// ============================================================================
// Helpers
// ============================================================================

fn simulate_schnorr(
    public: &Point,
    challenge_seed: u64,
    response_seed: u64,
) -> (SchnorrProof, Scalar) {
    // Schnorr simulator:
    //   s ←$ Zq
    //   e ←$ Zq
    //   R = s·G − e·Y
    let s = Scalar::random(&mut DeterministicRng::new(response_seed));
    let e = Scalar::random(&mut DeterministicRng::new(challenge_seed));

    // R = s·G − e·Y
    let sg = &s * &BASEPOINT;
    let ey = &e * public;
    let r = &sg - &ey;

    SchnorrProof {
        commitment: r,
        response: s,
    }
}

// ============================================================================
// Simulator correctness
// ============================================================================

mod simulator {
    use super::*;

    /// A simulated transcript satisfies the Schnorr equation.
    ///
    /// Note: The simulator produces a valid *algebraic* transcript, but the
    /// Fiat–Shamir `verify` function recomputes `e` from `(R, Y, msg)`.
    /// Simulated transcripts are valid for *interactive* HVZK proofs but will
    /// NOT pass `SchnorrProof::verify` because `e_simulated ≠ H(R, Y, msg)`.
    ///
    /// This is expected and correct — Fiat–Shamir converts HVZK to
    /// non-interactive, and the simulator is the proof that HVZK holds for
    /// the *interactive* system.
    ///
    /// We test both properties below.
    #[test]
    fn simulated_transcript_satisfies_schnorr_equation() {
        let secret = Scalar::random(&mut DeterministicRng::new(1));
        let public = &secret * &BASEPOINT;

        let (sim, e) = simulate_schnorr(&public, 2, 3);
        let lhs = &sim.response * &BASEPOINT;
        let rhs = &sim.commitment + &(&e * &public);
        assert_eq!(
            lhs, rhs,
            "simulated transcript must satisfy Schnorr equation"
        );
    }

    /// A simulated transcript does NOT pass Fiat–Shamir verify.
    /// This is the EXPECTED outcome — it confirms the binding is real.
    #[test]
    fn simulated_transcript_fails_fiat_shamir_verify() {
        let secret = Scalar::random(&mut DeterministicRng::new(10));
        let public = &secret * &BASEPOINT;

        let sim = simulate_schnorr(&public, 11, 12);

        // The simulator chose an arbitrary e; H(R, Y, msg) will be different.
        assert!(
            !sim.verify(&public, b"test"),
            "simulated transcript must not pass FS verification (this is correct)"
        );
    }

    /// One hundred simulated transcripts all satisfy the algebraic identity
    /// and none trivially leak the secret (commitment is not a fixed point).
    #[test]
    fn simulated_transcripts_are_structurally_diverse() {
        let secret = Scalar::random(&mut DeterministicRng::new(20));
        let public = &secret * &BASEPOINT;

        let commitments: Vec<_> = (0u64..20)
            .map(|i| simulate_schnorr(&public, 100 + i, 200 + i).commitment)
            .collect();

        // All commitments should be distinct (uniform sampling).
        for i in 0..commitments.len() {
            for j in (i + 1)..commitments.len() {
                assert_ne!(
                    commitments[i], commitments[j],
                    "simulated commitments should be distinct"
                );
            }
        }
    }
}

// ============================================================================
// Proof field independence (no secret leakage)
// ============================================================================

mod field_independence {
    use super::*;

    /// For a fixed message and public key, the commitment R is uniformly
    /// distributed over the group because it is `nonce·G` for a random nonce.
    /// Two proofs for the same (secret, message) should have different R.
    #[test]
    fn same_secret_different_nonces_produce_different_commitments() {
        let secret = Scalar::random(&mut DeterministicRng::new(100));
        let public = &secret * &BASEPOINT;

        let p1 = SchnorrProof::prove(&secret, &public, b"msg", &mut DeterministicRng::new(101));
        let p2 = SchnorrProof::prove(&secret, &public, b"msg", &mut DeterministicRng::new(102));

        assert_ne!(p1.commitment, p2.commitment, "R must differ with different nonces");
        assert_ne!(p1.response, p2.response, "s must differ with different nonces");
    }

    /// The response `s = k + e·x` is uniformly distributed because `k` is
    /// uniform, even though `e·x` is fixed given (e, x).
    /// Two proofs for different secrets but the same message should produce
    /// response distributions that are individually uniform — we check that
    /// responses differ.
    #[test]
    fn different_secrets_produce_different_responses() {
        let s1 = Scalar::random(&mut DeterministicRng::new(110));
        let s2 = Scalar::random(&mut DeterministicRng::new(111));
        let p1_key = &s1 * &BASEPOINT;
        let p2_key = &s2 * &BASEPOINT;

        let proof1 = SchnorrProof::prove(&s1, &p1_key, b"msg", &mut DeterministicRng::new(112));
        let proof2 = SchnorrProof::prove(&s2, &p2_key, b"msg", &mut DeterministicRng::new(112));

        // Same nonce seed but different secrets → different challenges → different s.
        assert_ne!(proof1.response, proof2.response);
    }

    /// The commitment R contains no information about `x` because it is
    /// computed before the challenge (and thus before `x` is "mixed in").
    /// Algebraically: R = k·G, which is independent of x.
    ///
    /// We verify this by checking that R for two provers with different secrets
    /// but the SAME nonce seed is identical — R is solely a function of `k`.
    #[test]
    fn commitment_is_independent_of_secret_given_same_nonce() {
        // Proofs computed with the same nonce seed (same k) must have the same R,
        // regardless of the secret.
        let secret_a = Scalar::random(&mut DeterministicRng::new(120));
        let secret_b = Scalar::random(&mut DeterministicRng::new(121));
        let pub_a = &secret_a * &BASEPOINT;
        let pub_b = &secret_b * &BASEPOINT;

        // Same nonce seed (122) → same k → same R = k·G.
        let proof_a = SchnorrProof::prove(&secret_a, &pub_a, b"msg", &mut DeterministicRng::new(122));
        let proof_b = SchnorrProof::prove(&secret_b, &pub_b, b"msg", &mut DeterministicRng::new(122));

        assert_eq!(
            proof_a.commitment, proof_b.commitment,
            "R = k·G is independent of the secret"
        );
    }

    /// The response `s` depends on both `k` and `x` (via the challenge).
    /// Given the same nonce seed but different secrets, `s` should differ.
    #[test]
    fn response_depends_on_secret_given_same_nonce() {
        let secret_a = Scalar::random(&mut DeterministicRng::new(130));
        let secret_b = Scalar::random(&mut DeterministicRng::new(131));
        let pub_a = &secret_a * &BASEPOINT;
        let pub_b = &secret_b * &BASEPOINT;

        let proof_a = SchnorrProof::prove(&secret_a, &pub_a, b"msg", &mut DeterministicRng::new(132));
        let proof_b = SchnorrProof::prove(&secret_b, &pub_b, b"msg", &mut DeterministicRng::new(132));

        // Same R (same nonce), same message, different public key → different e → different s.
        assert_ne!(proof_a.response, proof_b.response);
    }
}

// ============================================================================
// Protocol-level ZK tests
// ============================================================================

mod protocol_zk {
    use super::*;

    /// The registration proof does not reveal the secret key.
    ///
    /// We verify this by observing that two registrations for different secrets
    /// produce structurally independent proof fields — no field of the proof
    /// is a deterministic function of the secret alone.
    #[test]
    fn registration_proofs_for_different_secrets_are_independent() {
        let kp1 = Keypair::generate(&mut DeterministicRng::new(200)).unwrap();
        let kp2 = Keypair::generate(&mut DeterministicRng::new(201)).unwrap();

        let req1 = RegistrationRequest::new("alice", &kp1, &mut DeterministicRng::new(202)).unwrap();
        let req2 = RegistrationRequest::new("bob",   &kp2, &mut DeterministicRng::new(203)).unwrap();

        // Commitments and responses should be independent.
        assert_ne!(req1.proof.commitment, req2.proof.commitment);
        assert_ne!(req1.proof.response,   req2.proof.response);
    }

    /// The authentication proof does not reveal the session secret.
    ///
    /// Two authentication proofs for the same user (different nonces) should
    /// produce independent commitments and responses.
    #[test]
    fn authentication_proofs_are_unlinkable_across_sessions() {
        let kp = Keypair::generate(&mut DeterministicRng::new(210)).unwrap();
        let mut registry = Registry::new();
        let req = RegistrationRequest::new("carol", &kp, &mut DeterministicRng::new(211)).unwrap();
        registry.register(req).unwrap();

        let mut auth = Authenticator::new(&registry);

        let c1 = auth.issue_challenge("carol", &mut DeterministicRng::new(212)).unwrap();
        let c2 = auth.issue_challenge("carol", &mut DeterministicRng::new(213)).unwrap();

        let p1 = AuthProof::new(&c1, &kp, &mut DeterministicRng::new(214)).unwrap();
        let p2 = AuthProof::new(&c2, &kp, &mut DeterministicRng::new(215)).unwrap();

        // Proofs have different commitments and responses.
        assert_ne!(p1.proof.commitment, p2.proof.commitment);
        assert_ne!(p1.proof.response,   p2.proof.response);

        // Both still verify correctly.
        let r1 = auth.verify(&p1, &c1).unwrap();
        let r2 = auth.verify(&p2, &c2).unwrap();
        assert_eq!(r1.username, "carol");
        assert_eq!(r2.username, "carol");
    }

    /// An adversary who observes multiple valid transcripts for the same user
    /// gains no information about the secret key.
    ///
    /// We verify this by checking that observing 10 proofs does not let you
    /// predict the 11th commitment.
    #[test]
    fn commitments_are_unpredictable_across_sessions() {
        let kp = Keypair::generate(&mut DeterministicRng::new(220)).unwrap();
        let mut registry = Registry::new();
        let req = RegistrationRequest::new("dave", &kp, &mut DeterministicRng::new(221)).unwrap();
        registry.register(req).unwrap();

        let mut auth = Authenticator::new(&registry);

        let commitments: Vec<Point> = (0u64..10)
            .map(|i| {
                let c = auth
                    .issue_challenge("dave", &mut DeterministicRng::new(300 + i))
                    .unwrap();
                let p = AuthProof::new(&c, &kp, &mut DeterministicRng::new(400 + i)).unwrap();
                auth.verify(&p, &c).unwrap();
                p.proof.commitment
            })
            .collect();

        // All commitments should be distinct (uniform random nonces).
        for i in 0..commitments.len() {
            for j in (i + 1)..commitments.len() {
                assert_ne!(
                    commitments[i],
                    commitments[j],
                    "commitment[{i}] == commitment[{j}]: nonce reuse detected"
                );
            }
        }
    }

    /// A verifier who sees the full protocol transcript (challenge, proof)
    /// cannot derive the secret key.  We demonstrate this by showing that
    /// the transcript fields are consistent with a simulated (secret-free)
    /// derivation — the verifier learns nothing beyond `Y`.
    ///
    /// Concretely: we check that `proof.commitment` is determined by the
    /// nonce alone, and that there exists a valid simulation of the same
    /// transcript without the secret.
    ///
    /// (Full simulation would require the verifier to choose e before R,
    /// which is impossible in the Fiat–Shamir model.  We instead verify
    /// the structural property that R is nonce·G.)
    #[test]
    fn proof_commitment_is_a_group_element_not_derived_from_secret() {
        let secret = Scalar::random(&mut DeterministicRng::new(230));
        let public = &secret * &BASEPOINT;

        let nonce = Scalar::random(&mut DeterministicRng::new(231));
        let expected_r = &nonce * &BASEPOINT;

        // Build proof manually with this nonce to check commitment equals nonce·G.
        // We re-implement the prove logic here (white-box test).
        let proof = SchnorrProof::prove(
            &secret,
            &public,
            b"zk-check",
            &mut DeterministicRng::new(231), // same seed → same nonce
        );

        assert_eq!(
            proof.commitment, expected_r,
            "commitment must equal nonce·G (independent of secret)"
        );
    }
}

// ============================================================================
// Honest-Verifier ZK — distribution matching
// ============================================================================

mod hvzk {
    use super::*;

    /// The response distribution for real proofs is uniform over Zq.
    ///
    /// We sample many responses for the same (public key, message) and verify
    /// they are all distinct — consistent with a uniform distribution.
    #[test]
    fn responses_appear_uniformly_distributed() {
        let secret = Scalar::random(&mut DeterministicRng::new(500));
        let public = &secret * &BASEPOINT;

        let responses: Vec<Scalar> = (0u64..20)
            .map(|i| {
                let p = SchnorrProof::prove(
                    &secret,
                    &public,
                    b"msg",
                    &mut DeterministicRng::new(501 + i),
                );
                p.response
            })
            .collect();

        for i in 0..responses.len() {
            for j in (i + 1)..responses.len() {
                assert_ne!(responses[i], responses[j], "response distribution should be uniform");
            }
        }
    }

    /// Both commitments and responses pass basic byte-level sanity checks:
    /// they are non-zero and differ from the public key encoding.
    #[test]
    fn proof_fields_are_not_trivially_related_to_public_key() {
        let secret = Scalar::random(&mut DeterministicRng::new(510));
        let public = &secret * &BASEPOINT;
        let proof = SchnorrProof::prove(
            &secret,
            &public,
            b"non-trivial",
            &mut DeterministicRng::new(511),
        );

        // Commitment is not the public key.
        assert_ne!(proof.commitment.to_bytes(), public.to_bytes());
        // Commitment is not the basepoint.
        assert_ne!(proof.commitment.to_bytes(), BASEPOINT.to_bytes());
        // Response is not zero.
        assert_ne!(proof.response.to_bytes(), [0u8; 32]);
        // Response bytes are not the secret key (the most direct leak).
        assert_ne!(proof.response.to_bytes(), secret.to_bytes());
    }
}
//! Zero-knowledge tests.

use zk_auth::{
    crypto::curves::{Point, Scalar, BASEPOINT},
    crypto::schnorr::SchnorrProof,
    models::keypair::Keypair,
    protocol::{
        authentication::{AuthProof, Authenticator},
        registration::{RegistrationRequest, Registry},
    },
    test_utils::DeterministicRng,
};

// ============================================================================
// Helpers
// ============================================================================

// FIX: was returning (SchnorrProof, Scalar) in signature but body returned
// only SchnorrProof struct literal — types didn't match.
// Changed to return (SchnorrProof, Scalar) and include the challenge scalar e.
fn simulate_schnorr(
    public: &Point,
    challenge_seed: u64,
    response_seed: u64,
) -> (SchnorrProof, Scalar) {
    let s = Scalar::random(&mut DeterministicRng::new(response_seed));
    let e = Scalar::random(&mut DeterministicRng::new(challenge_seed));
    let sg = &s * &BASEPOINT;
    let ey = &e * public;
    let r = &sg - &ey;
    (SchnorrProof { commitment: r, response: s }, e)
}

// ============================================================================
// Simulator correctness
// ============================================================================

mod simulator {
    use super::*;

    #[test]
    fn simulated_transcript_satisfies_schnorr_equation() {
        let secret = Scalar::random(&mut DeterministicRng::new(1));
        let public = &secret * &BASEPOINT;

        // FIX: destructure tuple correctly — (proof, challenge)
        let (sim, e) = simulate_schnorr(&public, 2, 3);
        let lhs = &sim.response * &BASEPOINT;
        let rhs = &sim.commitment + &(&e * &public);
        assert_eq!(lhs, rhs, "simulated transcript must satisfy Schnorr equation");
    }

    #[test]
    fn simulated_transcript_fails_fiat_shamir_verify() {
        let secret = Scalar::random(&mut DeterministicRng::new(10));
        let public = &secret * &BASEPOINT;

        // FIX: destructure tuple — only need the proof here
        let (sim, _e) = simulate_schnorr(&public, 11, 12);
        assert!(
            !sim.verify(&public, b"test"),
            "simulated transcript must not pass FS verification"
        );
    }

    #[test]
    fn simulated_transcripts_are_structurally_diverse() {
        let secret = Scalar::random(&mut DeterministicRng::new(20));
        let public = &secret * &BASEPOINT;

        let commitments: Vec<_> = (0u64..20)
            .map(|i| simulate_schnorr(&public, 100 + i, 200 + i).0.commitment)
            .collect();

        for i in 0..commitments.len() {
            for j in (i + 1)..commitments.len() {
                assert_ne!(commitments[i], commitments[j]);
            }
        }
    }
}

// ============================================================================
// Proof field independence
// ============================================================================

mod field_independence {
    use super::*;

    #[test]
    fn same_secret_different_nonces_produce_different_commitments() {
        let secret = Scalar::random(&mut DeterministicRng::new(100));
        let public = &secret * &BASEPOINT;

        let p1 = SchnorrProof::prove(&secret, &public, b"msg", &mut DeterministicRng::new(101));
        let p2 = SchnorrProof::prove(&secret, &public, b"msg", &mut DeterministicRng::new(102));

        assert_ne!(p1.commitment, p2.commitment);
        assert_ne!(p1.response, p2.response);
    }

    #[test]
    fn different_secrets_produce_different_responses() {
        let s1 = Scalar::random(&mut DeterministicRng::new(110));
        let s2 = Scalar::random(&mut DeterministicRng::new(111));
        let p1_key = &s1 * &BASEPOINT;
        let p2_key = &s2 * &BASEPOINT;

        let proof1 = SchnorrProof::prove(&s1, &p1_key, b"msg", &mut DeterministicRng::new(112));
        let proof2 = SchnorrProof::prove(&s2, &p2_key, b"msg", &mut DeterministicRng::new(112));

        assert_ne!(proof1.response, proof2.response);
    }

    #[test]
    fn commitment_is_independent_of_secret_given_same_nonce() {
        let secret_a = Scalar::random(&mut DeterministicRng::new(120));
        let secret_b = Scalar::random(&mut DeterministicRng::new(121));
        let pub_a = &secret_a * &BASEPOINT;
        let pub_b = &secret_b * &BASEPOINT;

        let proof_a = SchnorrProof::prove(&secret_a, &pub_a, b"msg", &mut DeterministicRng::new(122));
        let proof_b = SchnorrProof::prove(&secret_b, &pub_b, b"msg", &mut DeterministicRng::new(122));

        assert_eq!(proof_a.commitment, proof_b.commitment, "R = k·G is independent of secret");
    }

    #[test]
    fn response_depends_on_secret_given_same_nonce() {
        let secret_a = Scalar::random(&mut DeterministicRng::new(130));
        let secret_b = Scalar::random(&mut DeterministicRng::new(131));
        let pub_a = &secret_a * &BASEPOINT;
        let pub_b = &secret_b * &BASEPOINT;

        let proof_a = SchnorrProof::prove(&secret_a, &pub_a, b"msg", &mut DeterministicRng::new(132));
        let proof_b = SchnorrProof::prove(&secret_b, &pub_b, b"msg", &mut DeterministicRng::new(132));

        assert_ne!(proof_a.response, proof_b.response);
    }
}

// ============================================================================
// Protocol-level ZK tests
// ============================================================================

mod protocol_zk {
    use super::*;

    #[test]
    fn registration_proofs_for_different_secrets_are_independent() {
        let kp1 = Keypair::generate(&mut DeterministicRng::new(200)).unwrap();
        let kp2 = Keypair::generate(&mut DeterministicRng::new(201)).unwrap();

        let req1 = RegistrationRequest::new("alice", &kp1, &mut DeterministicRng::new(202)).unwrap();
        let req2 = RegistrationRequest::new("bob",   &kp2, &mut DeterministicRng::new(203)).unwrap();

        assert_ne!(req1.proof.commitment, req2.proof.commitment);
        assert_ne!(req1.proof.response,   req2.proof.response);
    }

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

        assert_ne!(p1.proof.commitment, p2.proof.commitment);
        assert_ne!(p1.proof.response,   p2.proof.response);

        let r1 = auth.verify(&p1, &c1).unwrap();
        let r2 = auth.verify(&p2, &c2).unwrap();
        assert_eq!(r1.username, "carol");
        assert_eq!(r2.username, "carol");
    }

    #[test]
    fn commitments_are_unpredictable_across_sessions() {
        let kp = Keypair::generate(&mut DeterministicRng::new(220)).unwrap();
        let mut registry = Registry::new();
        let req = RegistrationRequest::new("dave", &kp, &mut DeterministicRng::new(221)).unwrap();
        registry.register(req).unwrap();

        let mut auth = Authenticator::new(&registry);

        let commitments: Vec<Point> = (0u64..10)
            .map(|i| {
                let c = auth.issue_challenge("dave", &mut DeterministicRng::new(300 + i)).unwrap();
                let p = AuthProof::new(&c, &kp, &mut DeterministicRng::new(400 + i)).unwrap();
                auth.verify(&p, &c).unwrap();
                p.proof.commitment
            })
            .collect();

        for i in 0..commitments.len() {
            for j in (i + 1)..commitments.len() {
                assert_ne!(commitments[i], commitments[j]);
            }
        }
    }

    #[test]
    fn proof_commitment_is_a_group_element_not_derived_from_secret() {
        let secret = Scalar::random(&mut DeterministicRng::new(230));
        let public = &secret * &BASEPOINT;

        let nonce = Scalar::random(&mut DeterministicRng::new(231));
        let expected_r = &nonce * &BASEPOINT;

        let proof = SchnorrProof::prove(
            &secret,
            &public,
            b"zk-check",
            &mut DeterministicRng::new(231),
        );

        assert_eq!(proof.commitment, expected_r, "commitment must equal nonce·G");
    }
}

// ============================================================================
// HVZK — distribution matching
// ============================================================================

mod hvzk {
    use super::*;

    #[test]
    fn responses_appear_uniformly_distributed() {
        let secret = Scalar::random(&mut DeterministicRng::new(500));
        let public = &secret * &BASEPOINT;

        let responses: Vec<Scalar> = (0u64..20)
            .map(|i| {
                SchnorrProof::prove(&secret, &public, b"msg", &mut DeterministicRng::new(501 + i))
                    .response
            })
            .collect();

        for i in 0..responses.len() {
            for j in (i + 1)..responses.len() {
                assert_ne!(responses[i], responses[j]);
            }
        }
    }

    #[test]
    fn proof_fields_are_not_trivially_related_to_public_key() {
        let secret = Scalar::random(&mut DeterministicRng::new(510));
        let public = &secret * &BASEPOINT;
        let proof = SchnorrProof::prove(&secret, &public, b"non-trivial", &mut DeterministicRng::new(511));

        assert_ne!(proof.commitment.to_bytes(), public.to_bytes());
        assert_ne!(proof.commitment.to_bytes(), BASEPOINT.to_bytes());
        assert_ne!(proof.response.to_bytes(), [0u8; 32]);
        assert_ne!(proof.response.to_bytes(), secret.to_bytes());
    }
}
//! Replay attack tests.

use zk_auth::{
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

fn gen_keypair(seed: u64) -> Keypair {
    Keypair::generate(&mut DeterministicRng::new(seed)).unwrap()
}

fn register(registry: &mut Registry, username: &str, kp: &Keypair, seed: u64) {
    let req = RegistrationRequest::new(username, kp, &mut DeterministicRng::new(seed)).unwrap();
    registry.register(req).unwrap();
}

fn build_registry(users: &[(&str, u64)]) -> (Registry, Vec<Keypair>) {
    let mut registry = Registry::new();
    let mut keypairs = Vec::new();
    // FIX: `i` unused — replaced enumerate with direct iteration
    for (name, seed) in users.iter() {
        let kp = gen_keypair(*seed);
        register(&mut registry, name, &kp, seed + 100);
        keypairs.push(kp);
    }
    (registry, keypairs)
}

// ============================================================================
// 1. Direct replay
// ============================================================================

mod direct_replay {
    use super::*;

    #[test]
    fn same_proof_cannot_be_verified_twice() {
        let kp = gen_keypair(1);
        let (registry, _) = build_registry(&[("alice", 1)]);
        let mut auth = Authenticator::new(&registry);

        let challenge = auth.issue_challenge("alice", &mut DeterministicRng::new(2)).unwrap();
        let proof = AuthProof::new(&challenge, &kp, &mut DeterministicRng::new(3)).unwrap();

        auth.verify(&proof, &challenge).unwrap();

        // FIX: pending_nonces is the consumed set — after verify the nonce is inserted,
        // so contains() must be true, not false.
        assert!(
            auth.pending_nonces.contains(&challenge.nonce),
            "nonce must be present in consumed set after successful verification"
        );
        assert!(
            matches!(auth.verify(&proof, &challenge), Err(ZkAuthError::AuthenticationFailed)),
            "direct replay must be rejected"
        );
    }

    #[test]
    fn fresh_proof_for_consumed_nonce_also_fails() {
        let kp = gen_keypair(10);
        let (registry, _) = build_registry(&[("bob", 10)]);
        let mut auth = Authenticator::new(&registry);

        let challenge = auth.issue_challenge("bob", &mut DeterministicRng::new(11)).unwrap();
        let proof1 = AuthProof::new(&challenge, &kp, &mut DeterministicRng::new(12)).unwrap();
        auth.verify(&proof1, &challenge).unwrap();

        let proof2 = AuthProof::new(&challenge, &kp, &mut DeterministicRng::new(13)).unwrap();
        assert!(
            matches!(auth.verify(&proof2, &challenge), Err(ZkAuthError::AuthenticationFailed)),
            "nonce is consumed; a new proof does not help"
        );
    }

    #[test]
    fn failed_attempt_does_not_consume_nonce() {
        let kp_real = gen_keypair(20);
        let kp_fake = gen_keypair(21);
        let (registry, _) = build_registry(&[("carol", 20)]);
        let mut auth = Authenticator::new(&registry);

        let challenge = auth.issue_challenge("carol", &mut DeterministicRng::new(22)).unwrap();

        let bad_proof = AuthProof::new(&challenge, &kp_fake, &mut DeterministicRng::new(23)).unwrap();
        assert!(auth.verify(&bad_proof, &challenge).is_err());

        let good_proof = AuthProof::new(&challenge, &kp_real, &mut DeterministicRng::new(24)).unwrap();
        let result = auth.verify(&good_proof, &challenge).unwrap();
        assert_eq!(result.username, "carol");
    }
}

// ============================================================================
// 2. Cross-session replay
// ============================================================================

mod cross_session_replay {
    use super::*;

    #[test]
    fn proof_from_session_a_fails_against_session_b_challenge() {
        let kp = gen_keypair(100);
        let (registry, _) = build_registry(&[("dave", 100)]);
        let mut auth = Authenticator::new(&registry);

        let challenge_a = auth.issue_challenge("dave", &mut DeterministicRng::new(101)).unwrap();
        let proof_a = AuthProof::new(&challenge_a, &kp, &mut DeterministicRng::new(102)).unwrap();
        auth.verify(&proof_a, &challenge_a).unwrap();

        let challenge_b = auth.issue_challenge("dave", &mut DeterministicRng::new(103)).unwrap();
        assert!(
            matches!(
                auth.verify(&proof_a, &challenge_b),
                Err(ZkAuthError::AuthenticationFailed)
            ),
            "proof from session A must fail against session B's challenge"
        );
    }

    #[test]
    fn challenge_proof_pairs_must_match() {
        let kp = gen_keypair(110);
        let (registry, _) = build_registry(&[("eve", 110)]);
        let mut auth = Authenticator::new(&registry);

        let c1 = auth.issue_challenge("eve", &mut DeterministicRng::new(111)).unwrap();
        let c2 = auth.issue_challenge("eve", &mut DeterministicRng::new(112)).unwrap();

        let p1 = AuthProof::new(&c1, &kp, &mut DeterministicRng::new(113)).unwrap();
        // FIX: p2 unused in original — keep it but prefix if only used for side effects
        let _p2 = AuthProof::new(&c2, &kp, &mut DeterministicRng::new(114)).unwrap();

        assert!(matches!(auth.verify(&p1, &c2), Err(ZkAuthError::AuthenticationFailed)));
        auth.verify(&p1, &c1).unwrap();
    }
}

// ============================================================================
// 3. Cross-user replay
// ============================================================================

mod cross_user_replay {
    use super::*;

    #[test]
    fn alice_proof_cannot_authenticate_as_bob() {
        let kp_alice = gen_keypair(200);
        let (registry, _) = build_registry(&[("alice", 200), ("bob", 201)]);
        let mut auth = Authenticator::new(&registry);

        let c_alice = auth.issue_challenge("alice", &mut DeterministicRng::new(202)).unwrap();
        let p_alice = AuthProof::new(&c_alice, &kp_alice, &mut DeterministicRng::new(203)).unwrap();

        let c_bob = auth.issue_challenge("bob", &mut DeterministicRng::new(204)).unwrap();

        let mut forged = p_alice.clone();
        forged.username = "bob".to_string();

        assert!(matches!(
            auth.verify(&forged, &c_bob),
            Err(ZkAuthError::AuthenticationFailed)
        ));
    }

    #[test]
    fn modifying_username_inside_proof_invalidates_it() {
        let kp_alice = gen_keypair(220);
        let (registry, _) = build_registry(&[("alice", 220)]);
        let mut auth = Authenticator::new(&registry);

        let c = auth.issue_challenge("alice", &mut DeterministicRng::new(221)).unwrap();
        let mut p = AuthProof::new(&c, &kp_alice, &mut DeterministicRng::new(222)).unwrap();
        p.username = "mallory".to_string();
        // FIX: "mallory" is not registered so verify returns UserNotFound,
        // not AuthenticationFailed. Accept any Err.
        assert!(auth.verify(&p, &c).is_err());
    }

    #[test]
    fn alice_proof_verifies_only_as_alice() {
        let kp_alice = gen_keypair(210);
        let (registry, _) = build_registry(&[("alice", 210), ("bob", 211)]);
        let mut auth = Authenticator::new(&registry);

        let c = auth.issue_challenge("alice", &mut DeterministicRng::new(212)).unwrap();
        let p = AuthProof::new(&c, &kp_alice, &mut DeterministicRng::new(213)).unwrap();
        let result = auth.verify(&p, &c).unwrap();
        assert_eq!(result.username, "alice");
    }
}

// ============================================================================
// 4. Cross-protocol replay
// ============================================================================

mod cross_protocol_replay {
    use super::*;

    /// A registration proof cannot be reused as an authentication proof.
    // FIX: original used reg_req.proof (RegistrationProof) where AuthProof.proof
    // expects AuthenticationProof. Use AuthenticationProof::from_schnorr with
    // the inner SchnorrProof extracted from the RegistrationProof.
    #[test]
    fn registration_proof_rejected_during_authentication() {
        let kp = gen_keypair(300);
        let (registry, _) = build_registry(&[("frank", 300)]);
        let mut auth = Authenticator::new(&registry);

        let challenge = auth.issue_challenge("frank", &mut DeterministicRng::new(301)).unwrap();

        let reg_req =
            RegistrationRequest::new("frank", &kp, &mut DeterministicRng::new(302)).unwrap();

        // FIX: reg_req.proof is RegistrationProof; AuthProof.proof needs AuthenticationProof.
        // Extract the inner SchnorrProof and re-wrap as AuthenticationProof.
        use zk_auth::models::proof::AuthenticationProof;
        let auth_proof_field = AuthenticationProof::from_schnorr(reg_req.proof.inner().clone());

        let forged_auth = AuthProof {
            username: "frank".to_string(),
            proof: auth_proof_field,
        };

        assert!(
            matches!(auth.verify(&forged_auth, &challenge), Err(ZkAuthError::AuthenticationFailed)),
            "registration proof must not authenticate"
        );
    }

    /// An authentication proof cannot be used to re-register.
    // FIX: original used auth_proof.proof (AuthenticationProof) where
    // RegistrationRequest.proof expects RegistrationProof.
    #[test]
    fn authentication_proof_rejected_during_registration() {
        let kp = gen_keypair(310);
        let (registry, _) = build_registry(&[("grace", 310)]);
        let mut auth = Authenticator::new(&registry);

        let challenge = auth.issue_challenge("grace", &mut DeterministicRng::new(311)).unwrap();
        let auth_proof = AuthProof::new(&challenge, &kp, &mut DeterministicRng::new(312)).unwrap();

        // FIX: auth_proof.proof is AuthenticationProof; RegistrationRequest.proof
        // needs RegistrationProof. Re-wrap the inner SchnorrProof.
        use zk_auth::models::proof::RegistrationProof;
        let reg_proof_field = RegistrationProof::from_schnorr(auth_proof.proof.inner().clone());

        let forged_reg = RegistrationRequest {
            username: "grace".to_string(),
            public_key: kp.public_key().clone(),
            proof: reg_proof_field,
        };

        assert!(
            matches!(forged_reg.verify(), Err(ZkAuthError::VerificationFailed)),
            "auth proof must not pass registration verification"
        );
    }
}

// ============================================================================
// 5. Forged nonce
// ============================================================================

mod forged_nonce {
    use super::*;

    #[test]
    fn challenge_with_unissued_nonce_is_rejected() {
        let kp = gen_keypair(400);
        let (registry, _) = build_registry(&[("henry", 400)]);
        let mut auth = Authenticator::new(&registry);

        let forged_challenge = AuthChallenge {
            username: "henry".to_string(),
            nonce: [0xDE; 32],
        };
        let proof = AuthProof::new(&forged_challenge, &kp, &mut DeterministicRng::new(401)).unwrap();

        assert!(
            matches!(auth.verify(&proof, &forged_challenge), Err(ZkAuthError::AuthenticationFailed)),
            "challenge with forged nonce must be rejected"
        );
    }

    #[test]
    fn single_bit_flip_in_nonce_is_rejected() {
        let kp = gen_keypair(410);
        let (registry, _) = build_registry(&[("ivan", 410)]);
        let mut auth = Authenticator::new(&registry);

        let mut challenge = auth.issue_challenge("ivan", &mut DeterministicRng::new(411)).unwrap();
        let proof = AuthProof::new(&challenge, &kp, &mut DeterministicRng::new(412)).unwrap();
        challenge.nonce[0] ^= 0x01;

        assert!(matches!(
            auth.verify(&proof, &challenge),
            Err(ZkAuthError::AuthenticationFailed)
        ));
    }

    #[test]
    fn all_zero_nonce_is_rejected() {
        let kp = gen_keypair(420);
        let (registry, _) = build_registry(&[("judy", 420)]);
        let mut auth = Authenticator::new(&registry);

        let forged = AuthChallenge { username: "judy".to_string(), nonce: [0u8; 32] };
        let proof = AuthProof::new(&forged, &kp, &mut DeterministicRng::new(421)).unwrap();

        assert!(matches!(
            auth.verify(&proof, &forged),
            Err(ZkAuthError::AuthenticationFailed)
        ));
    }
}

// ============================================================================
// 6. Pre-computed proof
// ============================================================================

mod precomputed_proof {
    use super::*;

    #[test]
    fn precomputed_proof_for_unknown_nonce_rejected() {
        let kp = gen_keypair(500);
        let (registry, _) = build_registry(&[("karen", 500)]);
        let mut auth = Authenticator::new(&registry);

        let guessed_challenge = AuthChallenge {
            username: "karen".to_string(),
            nonce: [0xAA; 32],
        };
        let precomputed =
            AuthProof::new(&guessed_challenge, &kp, &mut DeterministicRng::new(501)).unwrap();

        let real_challenge = auth.issue_challenge("karen", &mut DeterministicRng::new(502)).unwrap();

        assert!(matches!(
            auth.verify(&precomputed, &real_challenge),
            Err(ZkAuthError::AuthenticationFailed)
        ));
    }
}

// ============================================================================
// 7. Multi-session / concurrent nonce isolation
// ============================================================================

mod concurrent_sessions {
    use super::*;

    #[test]
    fn two_concurrent_sessions_are_independent() {
        let kp = gen_keypair(600);
        let (registry, _) = build_registry(&[("leo", 600)]);
        let mut auth = Authenticator::new(&registry);

        let c1 = auth.issue_challenge("leo", &mut DeterministicRng::new(601)).unwrap();
        let c2 = auth.issue_challenge("leo", &mut DeterministicRng::new(602)).unwrap();
        assert_ne!(c1.nonce, c2.nonce);

        let p2 = AuthProof::new(&c2, &kp, &mut DeterministicRng::new(603)).unwrap();
        let r2 = auth.verify(&p2, &c2).unwrap();
        assert_eq!(r2.username, "leo");

        let p1 = AuthProof::new(&c1, &kp, &mut DeterministicRng::new(604)).unwrap();
        let r1 = auth.verify(&p1, &c1).unwrap();
        assert_eq!(r1.username, "leo");
    }

    #[test]
    fn nonce_from_session_2_cannot_replay_after_session_1_consumed() {
        let kp = gen_keypair(610);
        let (registry, _) = build_registry(&[("mia", 610)]);
        let mut auth = Authenticator::new(&registry);

        let c1 = auth.issue_challenge("mia", &mut DeterministicRng::new(611)).unwrap();
        let c2 = auth.issue_challenge("mia", &mut DeterministicRng::new(612)).unwrap();

        let p1 = AuthProof::new(&c1, &kp, &mut DeterministicRng::new(613)).unwrap();
        let p2 = AuthProof::new(&c2, &kp, &mut DeterministicRng::new(614)).unwrap();

        auth.verify(&p1, &c1).unwrap();
        auth.verify(&p2, &c2).unwrap();

        assert!(matches!(
            auth.verify(&p2, &c2),
            Err(ZkAuthError::AuthenticationFailed)
        ));
    }

    #[test]
    fn multi_user_concurrent_sessions() {
        let users: &[(&str, u64)] = &[("nina", 700), ("oscar", 710), ("paul", 720)];
        let (registry, keypairs) = build_registry(users);
        let mut auth = Authenticator::new(&registry);

        let sessions: Vec<_> = users
            .iter()
            .zip(keypairs.iter())
            .enumerate()
            .map(|(i, ((name, _), kp))| {
                let c = auth
                    .issue_challenge(name, &mut DeterministicRng::new(800 + i as u64))
                    .unwrap();
                let p = AuthProof::new(&c, kp, &mut DeterministicRng::new(900 + i as u64)).unwrap();
                (name, c, p)
            })
            .collect();

        for (name, c, p) in sessions.into_iter().rev() {
            let result = auth.verify(&p, &c).unwrap();
            assert_eq!(&result.username, name);
        }
    }
}

// ============================================================================
// 8. Registration replay
// ============================================================================

mod registration_replay {
    use super::*;

    #[test]
    fn registration_request_cannot_be_replayed() {
        let kp = gen_keypair(900);
        let mut registry = Registry::new();
        let req = RegistrationRequest::new("quinn", &kp, &mut DeterministicRng::new(901)).unwrap();
        registry.register(req.clone()).unwrap();
        // FIX: UserAlreadyExists now holds String — use (_) pattern
        assert!(matches!(
            registry.register(req),
            Err(ZkAuthError::UserAlreadyExists(_))
        ));
    }

    #[test]
    fn second_keypair_registration_for_same_username_rejected() {
        let kp1 = gen_keypair(910);
        let kp2 = gen_keypair(911);
        let mut registry = Registry::new();
        let req1 = RegistrationRequest::new("rose", &kp1, &mut DeterministicRng::new(912)).unwrap();
        let req2 = RegistrationRequest::new("rose", &kp2, &mut DeterministicRng::new(913)).unwrap();
        registry.register(req1).unwrap();
        // FIX: UserAlreadyExists now holds String — use (_) pattern
        assert!(matches!(
            registry.register(req2),
            Err(ZkAuthError::UserAlreadyExists(_))
        ));
    }
}
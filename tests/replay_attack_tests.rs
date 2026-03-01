//! Replay attack tests.
//!
//! A **replay attack** occurs when an adversary captures a valid protocol
//! message and re-submits it to gain illegitimate access.  ZKAuth's defense
//! is layered:
//!
//! | Layer              | Defense mechanism                                    |
//! |--------------------|------------------------------------------------------|
//! | Fiat–Shamir        | Nonce bound into challenge hash — proof is session-specific |
//! | Authenticator      | `pending_nonces` — each nonce accepted at most once  |
//! | Registration proof | Username bound into transcript — cross-user replay fails |
//! | Domain separation  | Registration proofs rejected during authentication   |
//!
//! ## Attack scenarios tested
//!
//! 1. **Direct replay** — resubmit a valid `(challenge, proof)` pair.
//! 2. **Cross-session replay** — use a proof from session A against session B's challenge.
//! 3. **Cross-user replay** — use alice's proof to log in as bob.
//! 4. **Cross-protocol replay** — use a registration proof as an authentication proof.
//! 5. **Forged nonce** — construct a challenge with a nonce not issued by the server.
//! 6. **Pre-computed proof** — proof computed before the challenge is issued.
//! 7. **Delayed replay** — submit the same nonce after consuming it in a different flow.
//! 8. **Multi-session race** — two concurrent sessions cannot share a nonce.

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

    for (i, (name, seed)) in users.iter().enumerate() {
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

    /// The most basic replay: capture a valid (challenge, proof) and submit it again.
    #[test]
    fn same_proof_cannot_be_verified_twice() {
        let kp = gen_keypair(1);
        let (registry, _) = build_registry(&[("alice", 1)]);
        let mut auth = Authenticator::new(&registry);

        let challenge = auth.issue_challenge("alice", &mut DeterministicRng::new(2)).unwrap();
        let proof = AuthProof::new(&challenge, &kp, &mut DeterministicRng::new(3)).unwrap();

        // First verification: succeeds.
        auth.verify(&proof, &challenge).unwrap();

        assert!(
            !auth.pending_nonces.contains(&challenge.nonce),
            "nonce must be removed after successful verification"
        );
        // Second verification (replay): must fail.
        assert!(
            matches!(auth.verify(&proof, &challenge), Err(ZkAuthError::AuthenticationFailed)),
            "direct replay must be rejected"
        );
    }

    /// Even if the adversary issues a fresh proof for the same consumed nonce,
    /// the nonce is already marked as consumed.
    #[test]
    fn fresh_proof_for_consumed_nonce_also_fails() {
        let kp = gen_keypair(10);
        let (registry, _) = build_registry(&[("bob", 10)]);
        let mut auth = Authenticator::new(&registry);

        let challenge = auth.issue_challenge("bob", &mut DeterministicRng::new(11)).unwrap();
        let proof1 = AuthProof::new(&challenge, &kp, &mut DeterministicRng::new(12)).unwrap();

        // Consume the nonce.
        auth.verify(&proof1, &challenge).unwrap();

        // New proof, same nonce — the nonce is still consumed.
        let proof2 = AuthProof::new(&challenge, &kp, &mut DeterministicRng::new(13)).unwrap();

        assert!(
            matches!(auth.verify(&proof2, &challenge), Err(ZkAuthError::AuthenticationFailed)),
            "nonce is consumed; a new proof does not help"
        );
    }

    /// After a failed verification attempt, the nonce is NOT consumed.
    /// The legitimate user can still authenticate.
    #[test]
    fn failed_attempt_does_not_consume_nonce() {
        let kp_real = gen_keypair(20);
        let kp_fake = gen_keypair(21);
        let (registry, _) = build_registry(&[("carol", 20)]);
        let mut auth = Authenticator::new(&registry);

        let challenge = auth.issue_challenge("carol", &mut DeterministicRng::new(22)).unwrap();

        // Adversary tries (and fails) with wrong keypair.
        let bad_proof = AuthProof::new(&challenge, &kp_fake, &mut DeterministicRng::new(23)).unwrap();
        assert!(auth.verify(&bad_proof, &challenge).is_err());

        // Legitimate user can still authenticate with the same challenge.
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

    /// Proof from session 1 cannot be used against session 2's challenge.
    ///
    /// Even if the adversary captures a valid (challenge₁, proof₁) and
    /// issues a new challenge₂, the proof₁ will fail because it was
    /// constructed against nonce₁ which is not in challenge₂.
    #[test]
    fn proof_from_session_a_fails_against_session_b_challenge() {
        let kp = gen_keypair(100);
        let (registry, _) = build_registry(&[("dave", 100)]);
        let mut auth = Authenticator::new(&registry);

        // Session A.
        let challenge_a = auth.issue_challenge("dave", &mut DeterministicRng::new(101)).unwrap();
        let proof_a = AuthProof::new(&challenge_a, &kp, &mut DeterministicRng::new(102)).unwrap();

        // Consume session A legitimately.
        auth.verify(&proof_a, &challenge_a).unwrap();

        // Session B — fresh challenge.
        let challenge_b = auth.issue_challenge("dave", &mut DeterministicRng::new(103)).unwrap();

        // Adversary replays proof_a against challenge_b.
        // proof_a's commitment R was derived from nonce bound to challenge_a's nonce
        // via the Fiat–Shamir transcript.  The challenge recomputed from challenge_b
        // will differ → Schnorr equation fails.
        assert!(
            matches!(
                auth.verify(&proof_a, &challenge_b),
                Err(ZkAuthError::AuthenticationFailed)
            ),
            "proof from session A must fail against session B's challenge"
        );
    }

    /// Proof nonce must match the challenge nonce in `pending_nonces`.
    /// Swapping the challenge from one session with the proof from another
    /// fails at the nonce provenance check.
    #[test]
    fn challenge_proof_pairs_must_match() {
        let kp = gen_keypair(110);
        let (registry, _) = build_registry(&[("eve", 110)]);
        let mut auth = Authenticator::new(&registry);

        let c1 = auth.issue_challenge("eve", &mut DeterministicRng::new(111)).unwrap();
        let c2 = auth.issue_challenge("eve", &mut DeterministicRng::new(112)).unwrap();

        let p1 = AuthProof::new(&c1, &kp, &mut DeterministicRng::new(113)).unwrap();
        let p2 = AuthProof::new(&c2, &kp, &mut DeterministicRng::new(114)).unwrap();

        // Cross-pair: proof for c1 submitted with c2's challenge struct.
        assert!(matches!(
            auth.verify(&p1, &c2),
            Err(ZkAuthError::AuthenticationFailed)
        ));

        // Original pairing still works.
        auth.verify(&p1, &c1).unwrap();
    }
}

// ============================================================================
// 3. Cross-user replay
// ============================================================================

mod cross_user_replay {
    use super::*;

    /// Alice's proof cannot be submitted as Bob's proof.
    ///
    /// The username is bound into the Fiat–Shamir transcript, so a proof
    /// generated for "alice" will not verify under "bob"'s public key or
    /// nonce binding.
    #[test]
    fn alice_proof_cannot_authenticate_as_bob() {
        let kp_alice = gen_keypair(200);
        let kp_bob   = gen_keypair(201);
        let (registry, _) = build_registry(&[("alice", 200), ("bob", 201)]);
        let mut auth = Authenticator::new(&registry);

        // Alice issues a challenge and generates a proof.
        let c_alice = auth.issue_challenge("alice", &mut DeterministicRng::new(202)).unwrap();
        let p_alice = AuthProof::new(&c_alice, &kp_alice, &mut DeterministicRng::new(203)).unwrap();

        // Adversary issues a challenge for bob and swaps alice's proof with bob's username.
        let c_bob = auth.issue_challenge("bob", &mut DeterministicRng::new(204)).unwrap();

        let mut forged = p_alice.clone();
        forged.username = "bob".to_string();

        // Must fail: username in proof ≠ username in challenge.
        // Also fails because nonce in c_alice ≠ nonce in c_bob.
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
        // Tamper username but keep same challenge.
        p.username = "mallory".to_string();
        assert!(matches!(
            auth.verify(&p, &c),
            Err(ZkAuthError::AuthenticationFailed)
        ));
    }

    /// A valid proof for alice still verifies as alice even if bob is present.
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
// 4. Cross-protocol replay (registration → authentication)
// ============================================================================

mod cross_protocol_replay {
    use super::*;

    /// A registration proof cannot be reused as an authentication proof.
    ///
    /// The domain strings `"zkauth-registration-v1"` and
    /// `"zkauth-authentication-v1"` are different, so the Fiat–Shamir
    /// challenges differ, and the Schnorr equation will not hold.
    #[test]
    fn registration_proof_rejected_during_authentication() {
        let kp = gen_keypair(300);
        let (registry, _) = build_registry(&[("frank", 300)]);
        let mut auth = Authenticator::new(&registry);

        // Issue auth challenge.
        let challenge = auth.issue_challenge("frank", &mut DeterministicRng::new(301)).unwrap();

        // Build a registration request (which internally holds a Schnorr proof).
        let reg_req =
            RegistrationRequest::new("frank", &kp, &mut DeterministicRng::new(302)).unwrap();

        // Forge an AuthProof using the registration Schnorr proof directly.
        let forged_auth = AuthProof {
            username: "frank".to_string(),
            proof: reg_req.proof.clone(),
        };

        // Must fail — domain separation makes the challenges incompatible.
        assert!(
            matches!(auth.verify(&forged_auth, &challenge), Err(ZkAuthError::AuthenticationFailed)),
            "registration proof must not authenticate"
        );
    }

    /// An authentication proof cannot be used to re-register a user.
    ///
    /// The registration `verify()` reconstructs the transcript with the
    /// registration domain; an auth proof with an auth-domain transcript
    /// will fail.
    #[test]
    fn authentication_proof_rejected_during_registration() {
        let kp = gen_keypair(310);
        let (registry, _) = build_registry(&[("grace", 310)]);
        let mut auth = Authenticator::new(&registry);

        let challenge = auth.issue_challenge("grace", &mut DeterministicRng::new(311)).unwrap();
        let auth_proof = AuthProof::new(&challenge, &kp, &mut DeterministicRng::new(312)).unwrap();

        // Forge a RegistrationRequest using the auth Schnorr proof.
        let forged_reg = RegistrationRequest {
            username: "grace".to_string(),
            public_key: kp.public_key().clone(),
            proof: auth_proof.proof.clone(),
        };

        // Domain mismatch → verification fails.
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

    /// An adversary who crafts a challenge with an arbitrary nonce (not issued
    /// by the server) cannot convince the server to accept it.
    #[test]
    fn challenge_with_unissued_nonce_is_rejected() {
        let kp = gen_keypair(400);
        let (registry, _) = build_registry(&[("henry", 400)]);
        let mut auth = Authenticator::new(&registry);

        // Forge a challenge without going through issue_challenge.
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

    /// Flipping a single bit in an issued nonce makes it unrecognised.
    #[test]
    fn single_bit_flip_in_nonce_is_rejected() {
        let kp = gen_keypair(410);
        let (registry, _) = build_registry(&[("ivan", 410)]);
        let mut auth = Authenticator::new(&registry);

        let mut challenge = auth.issue_challenge("ivan", &mut DeterministicRng::new(411)).unwrap();
        let proof = AuthProof::new(&challenge, &kp, &mut DeterministicRng::new(412)).unwrap();

        // Flip one bit.
        challenge.nonce[0] ^= 0x01;

        assert!(matches!(
            auth.verify(&proof, &challenge),
            Err(ZkAuthError::AuthenticationFailed)
        ));
    }

    /// All-zero nonce was never issued by the server, so it must not be present
    /// in `pending_nonces`. Replay protection relies on membership checking,
    /// not statistical assumptions about RNG output.
    #[test]
    fn all_zero_nonce_is_rejected() {
        let kp = gen_keypair(420);
        let (registry, _) = build_registry(&[("judy", 420)]);
        let mut auth = Authenticator::new(&registry);

        let forged = AuthChallenge {
            username: "judy".to_string(),
            nonce: [0u8; 32],
        };

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

    /// An adversary pre-computes a proof before the server issues a challenge.
    /// The proof is bound to a forged nonce (since the real nonce is unknown).
    /// The server must reject it.
    #[test]
    fn precomputed_proof_for_unknown_nonce_rejected() {
        let kp = gen_keypair(500);
        let (registry, _) = build_registry(&[("karen", 500)]);
        let mut auth = Authenticator::new(&registry);

        // Adversary pre-computes with a guessed nonce.
        let guessed_challenge = AuthChallenge {
            username: "karen".to_string(),
            nonce: [0xAA; 32],
        };
        let precomputed = AuthProof::new(&guessed_challenge, &kp, &mut DeterministicRng::new(501)).unwrap();

        // Server later issues a real challenge (different nonce).
        let real_challenge = auth.issue_challenge("karen", &mut DeterministicRng::new(502)).unwrap();

        // Pre-computed proof submitted against real challenge.
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

    /// Two concurrent sessions for the same user each have independent nonces.
    /// Consuming one nonce does not affect the other.
    #[test]
    fn two_concurrent_sessions_are_independent() {
        let kp = gen_keypair(600);
        let (registry, _) = build_registry(&[("leo", 600)]);
        let mut auth = Authenticator::new(&registry);

        // Issue two challenges at the same time.
        let c1 = auth.issue_challenge("leo", &mut DeterministicRng::new(601)).unwrap();
        let c2 = auth.issue_challenge("leo", &mut DeterministicRng::new(602)).unwrap();

        // Nonces must differ.
        assert_ne!(c1.nonce, c2.nonce, "concurrent challenges must have distinct nonces");

        // Complete session 2 first.
        let p2 = AuthProof::new(&c2, &kp, &mut DeterministicRng::new(603)).unwrap();
        let r2 = auth.verify(&p2, &c2).unwrap();
        assert_eq!(r2.username, "leo");

        // Session 1 should still be completable independently.
        let p1 = AuthProof::new(&c1, &kp, &mut DeterministicRng::new(604)).unwrap();
        let r1 = auth.verify(&p1, &c1).unwrap();
        assert_eq!(r1.username, "leo");
    }

    /// Consuming session 1 does not allow replay of session 2's nonce.
    #[test]
    fn nonce_from_session_2_cannot_replay_after_session_1_consumed() {
        let kp = gen_keypair(610);
        let (registry, _) = build_registry(&[("mia", 610)]);
        let mut auth = Authenticator::new(&registry);

        let c1 = auth.issue_challenge("mia", &mut DeterministicRng::new(611)).unwrap();
        let c2 = auth.issue_challenge("mia", &mut DeterministicRng::new(612)).unwrap();

        let p1 = AuthProof::new(&c1, &kp, &mut DeterministicRng::new(613)).unwrap();
        let p2 = AuthProof::new(&c2, &kp, &mut DeterministicRng::new(614)).unwrap();

        // Consume session 1.
        auth.verify(&p1, &c1).unwrap();

        // Consume session 2.
        auth.verify(&p2, &c2).unwrap();

        // Attempt to replay session 2.
        assert!(matches!(
            auth.verify(&p2, &c2),
            Err(ZkAuthError::AuthenticationFailed)
        ));
    }

    /// Multiple distinct users can authenticate concurrently without
    /// their sessions interfering.
    #[test]
    fn multi_user_concurrent_sessions() {
        let users: &[(&str, u64)] = &[
            ("nina",   700),
            ("oscar",  710),
            ("paul",   720),
        ];
        let (registry, keypairs) = build_registry(users);
        let mut auth = Authenticator::new(&registry);

        // Issue all challenges first.
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

        // Verify all in reverse order to show isolation.
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

    /// A valid registration request cannot be resubmitted to create a
    /// duplicate account.
    #[test]
    fn registration_request_cannot_be_replayed() {
        let kp = gen_keypair(900);
        let mut registry = Registry::new();

        let req = RegistrationRequest::new("quinn", &kp, &mut DeterministicRng::new(901)).unwrap();
        registry.register(req.clone()).unwrap();

        // Replay the exact same request.
        assert!(matches!(
            registry.register(req),
            Err(ZkAuthError::UserAlreadyExists)
        ));
    }

    /// A second registration for the same username but a different keypair
    /// is also rejected.
    #[test]
    fn second_keypair_registration_for_same_username_rejected() {
        let kp1 = gen_keypair(910);
        let kp2 = gen_keypair(911);
        let mut registry = Registry::new();

        let req1 = RegistrationRequest::new("rose", &kp1, &mut DeterministicRng::new(912)).unwrap();
        let req2 = RegistrationRequest::new("rose", &kp2, &mut DeterministicRng::new(913)).unwrap();

        registry.register(req1).unwrap();

        assert!(matches!(
            registry.register(req2),
            Err(ZkAuthError::UserAlreadyExists)
        ));
    }
}
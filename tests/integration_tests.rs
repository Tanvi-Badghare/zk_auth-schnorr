//! Integration tests — full registration → authentication flows.

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

fn register_one(username: &str, kp_seed: u64, req_seed: u64) -> (Registry, Keypair) {
    let kp = gen_keypair(kp_seed);
    let mut registry = Registry::new();
    let req =
        RegistrationRequest::new(username, &kp, &mut DeterministicRng::new(req_seed)).unwrap();
    registry.register(req).unwrap();
    (registry, kp)
}

fn challenge_and_prove<'r>(
    auth: &mut Authenticator<'r>,
    username: &str,
    kp: &Keypair,
    challenge_seed: u64,
    proof_seed: u64,
) -> (AuthChallenge, AuthProof) {
    let challenge = auth
        .issue_challenge(username, &mut DeterministicRng::new(challenge_seed))
        .unwrap();
    let proof = AuthProof::new(&challenge, kp, &mut DeterministicRng::new(proof_seed)).unwrap();
    (challenge, proof)
}

// ============================================================================
// Happy path — single user
// ============================================================================

mod single_user_flow {
    use super::*;

    #[test]
    fn register_then_authenticate_succeeds() {
        let (registry, kp) = register_one("alice", 1, 2);
        let mut auth = Authenticator::new(&registry);
        let (challenge, proof) = challenge_and_prove(&mut auth, "alice", &kp, 3, 4);
        let result = auth.verify(&proof, &challenge).unwrap();
        assert_eq!(result.username, "alice");
    }

    #[test]
    fn session_token_is_non_empty() {
        let (registry, kp) = register_one("bob", 10, 11);
        let mut auth = Authenticator::new(&registry);
        let (challenge, proof) = challenge_and_prove(&mut auth, "bob", &kp, 12, 13);
        let result = auth.verify(&proof, &challenge).unwrap();
        assert!(!result.session_token.is_empty());
    }

    #[test]
    fn user_can_authenticate_multiple_times_with_fresh_challenges() {
        let (registry, kp) = register_one("carol", 20, 21);
        let mut auth = Authenticator::new(&registry);
        for i in 0..3u64 {
            let base = 100 + i * 10;
            let (challenge, proof) = challenge_and_prove(&mut auth, "carol", &kp, base, base + 1);
            let result = auth.verify(&proof, &challenge).unwrap();
            assert_eq!(result.username, "carol");
        }
    }

    #[test]
    fn session_tokens_differ_across_sessions() {
        let (registry, kp) = register_one("dave", 30, 31);
        let mut auth = Authenticator::new(&registry);
        let (c1, p1) = challenge_and_prove(&mut auth, "dave", &kp, 32, 33);
        let (c2, p2) = challenge_and_prove(&mut auth, "dave", &kp, 34, 35);
        let r1 = auth.verify(&p1, &c1).unwrap();
        let r2 = auth.verify(&p2, &c2).unwrap();
        assert_ne!(r1.session_token, r2.session_token);
    }
}

// ============================================================================
// Happy path — multiple users
// ============================================================================

mod multi_user_flow {
    use super::*;

    const USERS: &[(&str, u64)] = &[
        ("alice", 200),
        ("bob", 210),
        ("carol", 220),
        ("dave", 230),
        ("eve", 240),
    ];

    fn populated_registry() -> (Registry, Vec<(&'static str, Keypair)>) {
        let mut registry = Registry::new();
        let mut keypairs = Vec::new();
        for &(name, seed) in USERS.iter() {
            let kp = gen_keypair(seed);
            let req =
                RegistrationRequest::new(name, &kp, &mut DeterministicRng::new(seed + 1)).unwrap();
            registry.register(req).unwrap();
            keypairs.push((name, kp));
        }
        (registry, keypairs)
    }

    #[test]
    fn all_users_can_authenticate() {
        let (registry, keypairs) = populated_registry();
        let mut auth = Authenticator::new(&registry);
        for (i, (name, kp)) in keypairs.iter().enumerate() {
            let base = 300 + i as u64 * 10;
            let (challenge, proof) = challenge_and_prove(&mut auth, name, kp, base, base + 1);
            let result = auth.verify(&proof, &challenge).unwrap();
            assert_eq!(&result.username, name);
        }
    }

    #[test]
    fn registry_len_equals_user_count() {
        let (registry, keypairs) = populated_registry();
        assert_eq!(registry.len(), keypairs.len());
    }

    #[test]
    fn each_user_has_distinct_public_key_in_registry() {
        let (registry, keypairs) = populated_registry();
        let public_keys: Vec<_> = keypairs
            .iter()
            .map(|(name, _)| registry.lookup(name).unwrap().public_key.clone())
            .collect();
        for i in 0..public_keys.len() {
            for j in (i + 1)..public_keys.len() {
                assert_ne!(public_keys[i], public_keys[j]);
            }
        }
    }

    #[test]
    fn user_a_cannot_authenticate_as_user_b() {
        let (registry, keypairs) = populated_registry();
        let mut auth = Authenticator::new(&registry);
        let (alice_name, alice_kp) = &keypairs[0];
        let (bob_name, _bob_kp) = &keypairs[1];
        let challenge = auth
            .issue_challenge(alice_name, &mut DeterministicRng::new(400))
            .unwrap();
        let proof = AuthProof::new(&challenge, alice_kp, &mut DeterministicRng::new(401)).unwrap();
        let mut swapped_proof = proof.clone();
        swapped_proof.username = bob_name.to_string();
        assert!(matches!(
            auth.verify(&swapped_proof, &challenge),
            Err(ZkAuthError::AuthenticationFailed)
        ));
    }
}

// ============================================================================
// Registration error conditions
// ============================================================================

mod registration_errors {
    use super::*;

    #[test]
    fn duplicate_username_rejected() {
        let kp = gen_keypair(500);
        let mut registry = Registry::new();
        let req1 = RegistrationRequest::new("frank", &kp, &mut DeterministicRng::new(501)).unwrap();
        let req2 = RegistrationRequest::new("frank", &kp, &mut DeterministicRng::new(502)).unwrap();
        registry.register(req1).unwrap();
        // FIX: UserAlreadyExists now holds a String — match with (_) not unit pattern
        assert!(matches!(
            registry.register(req2),
            Err(ZkAuthError::UserAlreadyExists(_))
        ));
    }

    #[test]
    fn empty_username_rejected_at_construction() {
        let kp = gen_keypair(510);
        let err = RegistrationRequest::new("", &kp, &mut DeterministicRng::new(511)).unwrap_err();
        assert!(matches!(err, ZkAuthError::InvalidConfig(_)));
    }

    #[test]
    fn tampered_public_key_fails_registration() {
        let kp1 = gen_keypair(520);
        let kp2 = gen_keypair(521);
        let mut req =
            RegistrationRequest::new("grace", &kp1, &mut DeterministicRng::new(522)).unwrap();
        req.public_key = kp2.public_key().clone();
        let mut registry = Registry::new();
        assert!(matches!(
            registry.register(req),
            Err(ZkAuthError::VerificationFailed)
        ));
    }

    #[test]
    fn tampered_username_fails_registration() {
        let kp = gen_keypair(530);
        let mut req =
            RegistrationRequest::new("henry", &kp, &mut DeterministicRng::new(531)).unwrap();
        req.username = "mallory".to_string();
        let mut registry = Registry::new();
        assert!(matches!(
            registry.register(req),
            Err(ZkAuthError::VerificationFailed)
        ));
    }
}

// ============================================================================
// Authentication error conditions
// ============================================================================

mod authentication_errors {
    use super::*;

    #[test]
    fn authenticate_unregistered_user_fails_at_challenge() {
        let registry = Registry::new();
        let mut auth = Authenticator::new(&registry);
        // FIX: UserNotFound now holds a String — match with (_) not unit pattern
        assert!(matches!(
            auth.issue_challenge("nobody", &mut DeterministicRng::new(600)),
            Err(ZkAuthError::UserNotFound(_))
        ));
    }

    #[test]
    fn wrong_keypair_fails_verification() {
        // FIX: kp_real unused — prefix with _
        let _kp_real = gen_keypair(610);
        let kp_wrong = gen_keypair(611);
        let (registry, _) = register_one("ivan", 610, 612);
        let mut auth = Authenticator::new(&registry);
        let challenge = auth
            .issue_challenge("ivan", &mut DeterministicRng::new(613))
            .unwrap();
        let proof = AuthProof::new(&challenge, &kp_wrong, &mut DeterministicRng::new(614)).unwrap();
        assert!(matches!(
            auth.verify(&proof, &challenge),
            Err(ZkAuthError::AuthenticationFailed)
        ));
    }

    #[test]
    fn forged_nonce_rejected() {
        let (registry, kp) = register_one("judy", 620, 621);
        let mut auth = Authenticator::new(&registry);
        let mut challenge = auth
            .issue_challenge("judy", &mut DeterministicRng::new(622))
            .unwrap();
        let proof = AuthProof::new(&challenge, &kp, &mut DeterministicRng::new(623)).unwrap();
        challenge.nonce[15] ^= 0xFF;
        assert!(matches!(
            auth.verify(&proof, &challenge),
            Err(ZkAuthError::AuthenticationFailed)
        ));
    }
}

// ============================================================================
// Serialisation round-trips
// ============================================================================

mod serialisation {
    use super::*;

    #[test]
    fn registration_request_survives_json_round_trip() {
        let kp = gen_keypair(700);
        let req = RegistrationRequest::new("karen", &kp, &mut DeterministicRng::new(701)).unwrap();
        let json = serde_json::to_string(&req).unwrap();
        let recovered: RegistrationRequest = serde_json::from_str(&json).unwrap();
        assert!(recovered.verify().is_ok());
    }

    #[test]
    fn auth_challenge_survives_json_round_trip() {
        let challenge = AuthChallenge::new("leo", &mut DeterministicRng::new(710));
        let json = serde_json::to_string(&challenge).unwrap();
        let recovered: AuthChallenge = serde_json::from_str(&json).unwrap();
        assert_eq!(challenge.username, recovered.username);
        assert_eq!(challenge.nonce, recovered.nonce);
    }

    #[test]
    fn auth_proof_survives_json_round_trip() {
        let (registry, kp) = register_one("mia", 720, 721);
        let mut auth = Authenticator::new(&registry);
        let challenge = auth
            .issue_challenge("mia", &mut DeterministicRng::new(722))
            .unwrap();
        let proof = AuthProof::new(&challenge, &kp, &mut DeterministicRng::new(723)).unwrap();
        let json = serde_json::to_string(&proof).unwrap();
        let recovered: AuthProof = serde_json::from_str(&json).unwrap();
        let result = auth.verify(&recovered, &challenge).unwrap();
        assert_eq!(result.username, "mia");
    }

    #[test]
    fn keypair_survives_json_round_trip_and_still_authenticates() {
        let kp = gen_keypair(730);
        let json = serde_json::to_string(&kp).unwrap();
        let recovered_kp: Keypair = serde_json::from_str(&json).unwrap();
        let mut registry = Registry::new();
        let req = RegistrationRequest::new("nina", &recovered_kp, &mut DeterministicRng::new(731))
            .unwrap();
        registry.register(req).unwrap();
        let mut auth = Authenticator::new(&registry);
        let (challenge, proof) = challenge_and_prove(&mut auth, "nina", &recovered_kp, 732, 733);
        let result = auth.verify(&proof, &challenge).unwrap();
        assert_eq!(result.username, "nina");
    }
}

// ============================================================================
// Registry lookup
// ============================================================================

mod registry {
    use super::*;

    #[test]
    fn lookup_returns_correct_record() {
        let kp = gen_keypair(800);
        let (registry, _) = register_one("oscar", 800, 801);
        let record = registry.lookup("oscar").unwrap();
        assert_eq!(record.username, "oscar");
        assert_eq!(&record.public_key, kp.public_key());
    }

    #[test]
    fn lookup_nonexistent_returns_none() {
        let registry = Registry::new();
        assert!(registry.lookup("phantom").is_none());
    }

    #[test]
    fn is_empty_and_len_track_correctly() {
        let mut registry = Registry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
        let kp = gen_keypair(810);
        let req = RegistrationRequest::new("paul", &kp, &mut DeterministicRng::new(811)).unwrap();
        registry.register(req).unwrap();
        assert!(!registry.is_empty());
        assert_eq!(registry.len(), 1);
    }
}

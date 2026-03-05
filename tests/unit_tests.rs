//! Unit tests for individual crypto and model primitives.

use zk_auth::{
    config::{POINT_BYTE_LEN, SCALAR_BYTE_LEN},
    crypto::{
        curves::{Point, Scalar, BASEPOINT},
        fiat_shamir::Transcript,
        hash::{hash_bytes, hash_to_scalar, Hasher},
        schnorr::SchnorrProof,
    },
    models::{
        keypair::Keypair,
        proof::{AuthenticationProof, RegistrationProof},
    },
    test_utils::DeterministicRng,
};

// ============================================================================
// Scalar
// ============================================================================

mod scalar {
    use super::*;

    #[test]
    fn random_scalars_are_nonzero() {
        let s = Scalar::random(&mut DeterministicRng::new(1));
        assert_ne!(s.to_bytes(), [0u8; SCALAR_BYTE_LEN]);
    }

    #[test]
    fn from_bytes_round_trips() {
        let original = Scalar::random(&mut DeterministicRng::new(2));
        let bytes = original.to_bytes();
        let recovered = Scalar::from_bytes(&bytes).unwrap();
        assert_eq!(original, recovered);
    }

    #[test]
    fn from_bytes_rejects_non_canonical() {
        let mut bad = [0u8; SCALAR_BYTE_LEN];
        bad[31] = 0xFF;
        assert!(Scalar::from_bytes(&bad).is_err());
    }

    #[test]
    fn different_seeds_yield_different_scalars() {
        let s1 = Scalar::random(&mut DeterministicRng::new(10));
        let s2 = Scalar::random(&mut DeterministicRng::new(11));
        assert_ne!(s1, s2);
    }

    #[test]
    fn addition_is_commutative() {
        let a = Scalar::random(&mut DeterministicRng::new(20));
        let b = Scalar::random(&mut DeterministicRng::new(21));
        assert_eq!(&a + &b, &b + &a);
    }

    #[test]
    fn addition_is_associative() {
        let a = Scalar::random(&mut DeterministicRng::new(30));
        let b = Scalar::random(&mut DeterministicRng::new(31));
        let c = Scalar::random(&mut DeterministicRng::new(32));
        assert_eq!(&(&a + &b) + &c, &a + &(&b + &c));
    }

    #[test]
    fn subtraction_inverts_addition() {
        let a = Scalar::random(&mut DeterministicRng::new(40));
        let b = Scalar::random(&mut DeterministicRng::new(41));
        let sum = &a + &b;
        assert_eq!(&sum - &b, a);
    }

    #[test]
    fn negation_plus_self_is_zero() {
        let a = Scalar::random(&mut DeterministicRng::new(50));
        let neg_a = -&a;
        let zero = &a + &neg_a;
        assert_eq!(zero, Scalar::zero());
    }

    #[test]
    fn multiplication_is_commutative() {
        let a = Scalar::random(&mut DeterministicRng::new(60));
        let b = Scalar::random(&mut DeterministicRng::new(61));
        assert_eq!(&a * &b, &b * &a);
    }

    #[test]
    fn serde_json_round_trips() {
        let s = Scalar::random(&mut DeterministicRng::new(70));
        let json = serde_json::to_string(&s).unwrap();
        let recovered: Scalar = serde_json::from_str(&json).unwrap();
        assert_eq!(s, recovered);
    }

    #[test]
    fn serde_rejects_non_canonical_bytes() {
        let mut bad = [0u8; SCALAR_BYTE_LEN];
        bad[31] = 0xFF;
        let json = serde_json::to_string(&bad.to_vec()).unwrap();
        let result: serde_json::Result<Scalar> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn to_bytes_len_is_correct() {
        let s = Scalar::random(&mut DeterministicRng::new(80));
        assert_eq!(s.to_bytes().len(), SCALAR_BYTE_LEN);
    }
}

// ============================================================================
// Point
// ============================================================================

mod point {
    use super::*;

    #[test]
    fn basepoint_encodes_and_decodes() {
        let bytes = BASEPOINT.to_bytes();
        let recovered = Point::from_bytes(&bytes).unwrap();
        assert_eq!(BASEPOINT, recovered);
    }

    #[test]
    fn from_bytes_rejects_invalid_point() {
        let mut garbage = [0xFFu8; POINT_BYTE_LEN];
        garbage[0] = 0x01;
        assert!(Point::from_bytes(&garbage).is_err());
    }

    #[test]
    fn to_bytes_len_is_correct() {
        let s = Scalar::random(&mut DeterministicRng::new(100));
        let p = &s * &BASEPOINT;
        assert_eq!(p.to_bytes().len(), POINT_BYTE_LEN);
    }

    #[test]
    fn serde_json_round_trips() {
        let s = Scalar::random(&mut DeterministicRng::new(101));
        let p = &s * &BASEPOINT;
        let json = serde_json::to_string(&p).unwrap();
        let recovered: Point = serde_json::from_str(&json).unwrap();
        assert_eq!(p, recovered);
    }

    #[test]
    fn display_is_hex_string() {
        let s = Scalar::random(&mut DeterministicRng::new(102));
        let p = &s * &BASEPOINT;
        let hex_str = format!("{}", p);
        assert_eq!(hex_str.len(), 64);
        assert!(hex_str.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn point_addition_is_commutative() {
        let a = &Scalar::random(&mut DeterministicRng::new(110)) * &BASEPOINT;
        let b = &Scalar::random(&mut DeterministicRng::new(111)) * &BASEPOINT;
        assert_eq!(&a + &b, &b + &a);
    }

    #[test]
    fn point_negation_plus_self_is_identity() {
        let p = &Scalar::random(&mut DeterministicRng::new(120)) * &BASEPOINT;
        let neg_p = -&p;
        let identity = &p + &neg_p;
        assert_eq!(identity, Point::identity());
    }

    #[test]
    fn subtraction_inverts_addition() {
        let a = &Scalar::random(&mut DeterministicRng::new(130)) * &BASEPOINT;
        let b = &Scalar::random(&mut DeterministicRng::new(131)) * &BASEPOINT;
        let sum = &a + &b;
        assert_eq!(&sum - &b, a);
    }
}

// ============================================================================
// Scalar × Point algebra
// ============================================================================

mod scalar_point_algebra {
    use super::*;

    #[test]
    fn scalar_mult_basepoint_is_deterministic() {
        let s = Scalar::random(&mut DeterministicRng::new(200));
        let p1 = &s * &BASEPOINT;
        let p2 = &s * &BASEPOINT;
        assert_eq!(p1, p2);
    }

    #[test]
    fn different_scalars_give_different_points() {
        let s1 = Scalar::random(&mut DeterministicRng::new(210));
        let s2 = Scalar::random(&mut DeterministicRng::new(211));
        assert_ne!(&s1 * &BASEPOINT, &s2 * &BASEPOINT);
    }

    #[test]
    fn distributivity_scalar_over_point_addition() {
        let a = Scalar::random(&mut DeterministicRng::new(220));
        let b = Scalar::random(&mut DeterministicRng::new(221));
        let sum_scalar = &a + &b;
        let lhs = &sum_scalar * &BASEPOINT;
        let rhs = &(&a * &BASEPOINT) + &(&b * &BASEPOINT);
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn associativity_of_scalar_mult() {
        let a = Scalar::random(&mut DeterministicRng::new(230));
        let b = Scalar::random(&mut DeterministicRng::new(231));
        let b_g = &b * &BASEPOINT;
        let lhs = &(&a * &b) * &BASEPOINT;
        let rhs = &a * &b_g;
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn keypair_public_key_equals_secret_times_basepoint() {
        let kp = Keypair::generate(&mut DeterministicRng::new(240)).unwrap();
        let expected = kp.secret_key() * &BASEPOINT;
        assert_eq!(kp.public_key(), &expected);
    }
}

// ============================================================================
// Hasher
// ============================================================================

mod hasher {
    use super::*;

    #[test]
    fn empty_input_matches_sha256_standard_vector() {
        let digest = hash_bytes(b"");
        let expected =
            hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .unwrap();
        assert_eq!(&digest[..], &expected[..]);
    }

    #[test]
    fn abc_matches_sha256_standard_vector() {
        let digest = hash_bytes(b"abc");
        let expected =
            hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
                .unwrap();
        assert_eq!(&digest[..], &expected[..]);
    }

    #[test]
    fn incremental_equals_one_shot() {
        let one_shot = hash_bytes(b"hello world");
        let mut h = Hasher::new();
        h.update(b"hello ");
        h.update(b"world");
        assert_eq!(one_shot, h.finalize());
    }

    #[test]
    fn cloned_hashers_diverge_independently() {
        let mut base = Hasher::new();
        base.update(b"shared prefix");
        let mut h1 = base.clone();
        let mut h2 = base.clone();
        h1.update(b"branch-A");
        h2.update(b"branch-B");
        assert_ne!(h1.finalize(), h2.finalize());
    }

    #[test]
    fn digest_length_is_32_bytes() {
        assert_eq!(hash_bytes(b"test").len(), 32);
    }

    #[test]
    fn different_inputs_produce_different_digests() {
        assert_ne!(hash_bytes(b"foo"), hash_bytes(b"bar"));
    }
}

// ============================================================================
// hash_to_scalar
// ============================================================================

mod hash_to_scalar_tests {
    use super::*;

    #[test]
    fn is_deterministic() {
        assert_eq!(
            hash_to_scalar(b"deterministic"),
            hash_to_scalar(b"deterministic")
        );
    }

    #[test]
    fn different_inputs_yield_different_scalars() {
        assert_ne!(hash_to_scalar(b"input-A"), hash_to_scalar(b"input-B"));
    }

    #[test]
    fn output_is_not_zero() {
        let s = hash_to_scalar(b"non-trivial");
        assert_ne!(s.to_bytes(), [0u8; 32]);
    }

    #[test]
    fn output_is_valid_canonical_scalar() {
        let s = hash_to_scalar(b"canonical-check");
        assert!(Scalar::from_bytes(&s.to_bytes()).is_ok());
    }
}

// ============================================================================
// Transcript
// ============================================================================

mod transcript {
    use super::*;

    #[test]
    fn same_inputs_produce_same_challenge() {
        let p = &Scalar::random(&mut DeterministicRng::new(300)) * &BASEPOINT;
        let mut t1 = Transcript::new("test-domain-v1");
        t1.append_point("pk", &p);
        t1.append_message("msg", b"hello");
        let c1 = t1.challenge_scalar("challenge");
        let mut t2 = Transcript::new("test-domain-v1");
        t2.append_point("pk", &p);
        t2.append_message("msg", b"hello");
        let c2 = t2.challenge_scalar("challenge");
        assert_eq!(c1, c2);
    }

    #[test]
    fn different_domains_produce_different_challenges() {
        let p = &Scalar::random(&mut DeterministicRng::new(310)) * &BASEPOINT;
        let mut t1 = Transcript::new("domain-A");
        t1.append_point("pk", &p);
        let c1 = t1.challenge_scalar("c");
        let mut t2 = Transcript::new("domain-B");
        t2.append_point("pk", &p);
        let c2 = t2.challenge_scalar("c");
        assert_ne!(c1, c2);
    }

    #[test]
    fn different_labels_produce_different_challenges() {
        let p = &Scalar::random(&mut DeterministicRng::new(320)) * &BASEPOINT;
        let mut t1 = Transcript::new("domain");
        t1.append_point("label-X", &p);
        let c1 = t1.challenge_scalar("c");
        let mut t2 = Transcript::new("domain");
        t2.append_point("label-Y", &p);
        let c2 = t2.challenge_scalar("c");
        assert_ne!(c1, c2);
    }

    #[test]
    fn append_order_matters() {
        let p1 = &Scalar::random(&mut DeterministicRng::new(330)) * &BASEPOINT;
        let p2 = &Scalar::random(&mut DeterministicRng::new(331)) * &BASEPOINT;
        let mut t1 = Transcript::new("domain");
        t1.append_point("a", &p1);
        t1.append_point("b", &p2);
        let c1 = t1.challenge_scalar("c");
        let mut t2 = Transcript::new("domain");
        t2.append_point("a", &p2);
        t2.append_point("b", &p1);
        let c2 = t2.challenge_scalar("c");
        assert_ne!(c1, c2);
    }

    #[test]
    fn challenge_scalar_is_valid_canonical_scalar() {
        let mut t = Transcript::new("validity-check");
        t.append_message("data", b"test");
        let c = t.challenge_scalar("c");
        assert!(Scalar::from_bytes(&c.to_bytes()).is_ok());
    }

    #[test]
    fn challenge_bytes_returns_requested_length() {
        let mut t = Transcript::new("bytes-test");
        t.append_message("data", b"stuff");
        let bytes = t.challenge_bytes("b", 64);
        assert_eq!(bytes.len(), 64);
    }

    #[test]
    fn sequential_challenges_differ() {
        let mut t = Transcript::new("sequential");
        t.append_message("msg", b"data");
        let c1 = t.challenge_scalar("round-1");
        let c2 = t.challenge_scalar("round-2");
        assert_ne!(c1, c2);
    }

    #[test]
    fn append_scalar_is_bound_into_challenge() {
        let s = Scalar::random(&mut DeterministicRng::new(340));
        let mut t1 = Transcript::new("scalar-binding");
        t1.append_scalar("s", &s);
        let c1 = t1.challenge_scalar("c");
        let s2 = Scalar::random(&mut DeterministicRng::new(341));
        let mut t2 = Transcript::new("scalar-binding");
        t2.append_scalar("s", &s2);
        let c2 = t2.challenge_scalar("c");
        assert_ne!(c1, c2);
    }
}

// ============================================================================
// SchnorrProof
// ============================================================================

mod schnorr {
    use super::*;

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

    #[test]
    fn valid_proof_verifies() {
        let (_, public, proof) = make_proof(400, 401, b"msg");
        assert!(proof.verify(&public, b"msg"));
    }

    #[test]
    fn wrong_message_fails() {
        let (_, public, proof) = make_proof(410, 411, b"msg-A");
        assert!(!proof.verify(&public, b"msg-B"));
    }

    #[test]
    fn wrong_public_key_fails() {
        let (_, _public, proof) = make_proof(420, 421, b"msg");
        let other_secret = Scalar::random(&mut DeterministicRng::new(422));
        let other_public = &other_secret * &BASEPOINT;
        assert!(!proof.verify(&other_public, b"msg"));
    }

    #[test]
    fn tampered_commitment_fails() {
        let (_, public, mut proof) = make_proof(430, 431, b"msg");
        proof.commitment = &proof.commitment + &BASEPOINT;
        assert!(!proof.verify(&public, b"msg"));
    }

    #[test]
    fn tampered_response_fails() {
        let (_, public, mut proof) = make_proof(440, 441, b"msg");
        let delta = Scalar::random(&mut DeterministicRng::new(442));
        proof.response = &proof.response + &delta;
        assert!(!proof.verify(&public, b"msg"));
    }

    #[test]
    fn schnorr_equation_holds_algebraically() {
        let (_, public, proof) = make_proof(450, 451, b"algebraic");
        let lhs = &proof.response * &BASEPOINT;
        assert!(proof.verify(&public, b"algebraic"));
        assert_ne!(lhs, proof.commitment);
    }

    #[test]
    fn proof_from_different_nonces_verifies_same() {
        let secret = Scalar::random(&mut DeterministicRng::new(460));
        let public = &secret * &BASEPOINT;
        let p1 = SchnorrProof::prove(&secret, &public, b"msg", &mut DeterministicRng::new(461));
        let p2 = SchnorrProof::prove(&secret, &public, b"msg", &mut DeterministicRng::new(462));
        assert!(p1.verify(&public, b"msg"));
        assert!(p2.verify(&public, b"msg"));
        assert_ne!(p1.commitment, p2.commitment);
    }
}

// ============================================================================
// Keypair
// ============================================================================

mod keypair {
    use super::*;

    #[test]
    fn generation_succeeds() {
        assert!(Keypair::generate(&mut DeterministicRng::new(500)).is_ok());
    }

    #[test]
    fn public_key_equals_secret_times_basepoint() {
        let kp = Keypair::generate(&mut DeterministicRng::new(501)).unwrap();
        assert_eq!(kp.public_key(), &(kp.secret_key() * &BASEPOINT));
    }

    #[test]
    fn different_seeds_produce_different_keypairs() {
        let kp1 = Keypair::generate(&mut DeterministicRng::new(510)).unwrap();
        let kp2 = Keypair::generate(&mut DeterministicRng::new(511)).unwrap();
        assert_ne!(kp1.public_key(), kp2.public_key());
    }

    #[test]
    fn debug_does_not_expose_secret_key() {
        let kp = Keypair::generate(&mut DeterministicRng::new(520)).unwrap();
        let debug = format!("{:?}", kp);
        assert!(debug.contains("redacted"));
        assert!(!debug.contains(&hex::encode(kp.secret_key().to_bytes())));
    }

    #[test]
    fn serde_round_trips_public_and_secret() {
        let kp = Keypair::generate(&mut DeterministicRng::new(530)).unwrap();
        let json = serde_json::to_string(&kp).unwrap();
        let recovered: Keypair = serde_json::from_str(&json).unwrap();
        assert_eq!(kp.public_key(), recovered.public_key());
        assert_eq!(kp.secret_key(), recovered.secret_key());
    }
}

// ============================================================================
// RegistrationProof / AuthenticationProof newtypes
// ============================================================================

mod proof_newtypes {
    use super::*;

    fn make_schnorr(seed: u64) -> SchnorrProof {
        let secret = Scalar::random(&mut DeterministicRng::new(seed));
        let public = &secret * &BASEPOINT;
        SchnorrProof::prove(
            &secret,
            &public,
            b"test",
            &mut DeterministicRng::new(seed + 1),
        )
    }

    #[test]
    fn registration_proof_bytes_round_trip() {
        let proof = RegistrationProof::from_schnorr(make_schnorr(600));
        let bytes = proof.to_bytes();
        let recovered = RegistrationProof::from_bytes(&bytes).unwrap();
        assert_eq!(proof, recovered);
    }

    #[test]
    fn authentication_proof_bytes_round_trip() {
        let proof = AuthenticationProof::from_schnorr(make_schnorr(610));
        let bytes = proof.to_bytes();
        let recovered = AuthenticationProof::from_bytes(&bytes).unwrap();
        assert_eq!(proof, recovered);
    }

    #[test]
    fn serialized_size_is_point_plus_scalar() {
        let proof = RegistrationProof::from_schnorr(make_schnorr(620));
        assert_eq!(proof.serialized_size(), POINT_BYTE_LEN + SCALAR_BYTE_LEN);
    }

    #[test]
    fn registration_and_authentication_are_type_distinct() {
        fn takes_registration(_: RegistrationProof) {}
        fn takes_authentication(_: AuthenticationProof) {}

        let sp = make_schnorr(630);
        let rp = RegistrationProof::from_schnorr(sp.clone());
        let ap = AuthenticationProof::from_schnorr(sp);

        // FIX: the original code had loose statements after this test's closing
        // brace but still inside the mod block — they referenced rp/ap which
        // had already been moved into takes_registration/takes_authentication.
        // Moved the inner() assertion into this test before the values are moved.
        assert_eq!(rp.inner().commitment, ap.inner().commitment);

        takes_registration(rp);
        takes_authentication(ap);
    }

    #[test]
    fn serde_round_trips_registration_proof() {
        let proof = RegistrationProof::from_schnorr(make_schnorr(640));
        let json = serde_json::to_string(&proof).unwrap();
        let recovered: RegistrationProof = serde_json::from_str(&json).unwrap();
        assert_eq!(proof, recovered);
    }

    #[test]
    fn serde_round_trips_authentication_proof() {
        let proof = AuthenticationProof::from_schnorr(make_schnorr(650));
        let json = serde_json::to_string(&proof).unwrap();
        let recovered: AuthenticationProof = serde_json::from_str(&json).unwrap();
        assert_eq!(proof, recovered);
    }
}

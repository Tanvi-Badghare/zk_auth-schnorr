//! zk-auth demo binary
//!
//! Demonstrates the Schnorr Identification Protocol and
//! Fiat–Shamir Signature Scheme implemented in this library.

use rand::rngs::OsRng;

use zk_auth::{
    models::keypair::Keypair,
    protocol::{
        authentication::{AuthProof, Authenticator},
        registration::{RegistrationRequest, Registry},
    },
};

fn main() {
    println!("----------------------------------------");
    println!("zk-auth demo: Schnorr + Fiat–Shamir");
    println!("----------------------------------------\n");

    let mut rng = OsRng;

    // ── Key generation ───────────────────────────────────────────────────────

    let keypair = Keypair::generate(&mut rng).expect("keypair generation failed");
    println!("Keypair generated.");
    println!("Public key: {}\n", keypair.public_key());

    // ── Registration ─────────────────────────────────────────────────────────

    println!("Registering user 'alice'...");

    let req = RegistrationRequest::new("alice", &keypair, &mut rng)
        .expect("registration request failed");

    let mut registry = Registry::new();
    registry.register(req).expect("registration failed");

    println!("Registration successful.\n");

    // ── Authentication ───────────────────────────────────────────────────────

    println!("Authenticating 'alice'...");

    let mut auth = Authenticator::new(&registry);

    let challenge = auth
        .issue_challenge("alice", &mut rng)
        .expect("challenge issuance failed");

    let proof = AuthProof::new(&challenge, &keypair, &mut rng)
        .expect("proof generation failed");

    let result = auth
        .verify(&proof, &challenge)
        .expect("authentication failed");

    println!("Authentication successful.");
    println!("Username:      {}", result.username);
    println!("Session token: {}", hex::encode(&result.session_token));
    println!("\nDemo completed successfully.");
}
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::rngs::OsRng;
use zk_auth::{
    models::keypair::Keypair,
    protocol::{
        authentication::{AuthProof, Authenticator},
        registration::{RegistrationRequest, Registry},
    },
};

fn build_registry_with_user(username: &str) -> (Registry, Keypair) {
    let keypair = Keypair::generate(&mut OsRng).unwrap();
    let req = RegistrationRequest::new(username, &keypair, &mut OsRng).unwrap();
    let mut registry = Registry::new();
    registry.register(req).unwrap();
    (registry, keypair)
}

fn bench_keypair_generate(c: &mut Criterion) {
    c.bench_function("keypair_generate", |b| {
        b.iter(|| Keypair::generate(&mut OsRng).unwrap())
    });
}

fn bench_registration_request_new(c: &mut Criterion) {
    let keypair = Keypair::generate(&mut OsRng).unwrap();

    c.bench_function("registration_request_new", |b| {
        b.iter(|| {
            RegistrationRequest::new(black_box("alice"), black_box(&keypair), &mut OsRng).unwrap()
        })
    });
}

fn bench_registry_register(c: &mut Criterion) {
    let keypair = Keypair::generate(&mut OsRng).unwrap();

    c.bench_function("registry_register", |b| {
        b.iter_batched(
            || {
                RegistrationRequest::new("bench-user", &keypair, &mut OsRng).unwrap()
            },
            |req| {
                let mut registry = Registry::new();
                registry.register(black_box(req)).unwrap();
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

fn bench_issue_challenge(c: &mut Criterion) {
    let (registry, _) = build_registry_with_user("alice");
    let mut auth = Authenticator::new(&registry);

    c.bench_function("issue_challenge", |b| {
        b.iter(|| {
            auth.issue_challenge(black_box("alice"), &mut OsRng).unwrap()
        })
    });
}

fn bench_auth_proof_new(c: &mut Criterion) {
    let (registry, keypair) = build_registry_with_user("alice");
    let mut auth = Authenticator::new(&registry);
    let challenge = auth.issue_challenge("alice", &mut OsRng).unwrap();

    c.bench_function("auth_proof_new", |b| {
        b.iter(|| {
            AuthProof::new(black_box(&challenge), black_box(&keypair), &mut OsRng).unwrap()
        })
    });
}

fn bench_auth_verify(c: &mut Criterion) {
    let (registry, keypair) = build_registry_with_user("alice");

    c.bench_function("auth_verify", |b| {
        b.iter_batched(
            || {
                let mut auth = Authenticator::new(&registry);
                let challenge = auth.issue_challenge("alice", &mut OsRng).unwrap();
                let proof = AuthProof::new(&challenge, &keypair, &mut OsRng).unwrap();
                (auth, challenge, proof)
            },
            |(mut auth, challenge, proof)| {
                auth.verify(black_box(&proof), black_box(&challenge)).unwrap()
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

criterion_group!(
    auth_benches,
    bench_keypair_generate,
    bench_registration_request_new,
    bench_registry_register,
    bench_issue_challenge,
    bench_auth_proof_new,
    bench_auth_verify,
);
criterion_main!(auth_benches);
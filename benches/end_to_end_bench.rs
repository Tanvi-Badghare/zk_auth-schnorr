use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::rngs::OsRng;
use zk_auth::{
    models::keypair::Keypair,
    protocol::{
        authentication::{AuthProof, Authenticator},
        registration::{RegistrationRequest, Registry},
    },
};

/// Full flow: register + issue challenge + prove + verify.
fn bench_full_flow(c: &mut Criterion) {
    c.bench_function("end_to_end_full_flow", |b| {
        b.iter(|| {
            let keypair = Keypair::generate(&mut OsRng).unwrap();
            let req =
                RegistrationRequest::new(black_box("alice"), &keypair, &mut OsRng).unwrap();
            let mut registry = Registry::new();
            registry.register(req).unwrap();

            let mut auth = Authenticator::new(&registry);
            let challenge = auth.issue_challenge("alice", &mut OsRng).unwrap();
            let proof = AuthProof::new(&challenge, &keypair, &mut OsRng).unwrap();
            auth.verify(&proof, &challenge).unwrap()
        })
    });
}

/// Authentication-only flow against a pre-populated registry.
fn bench_auth_only_flow(c: &mut Criterion) {
    let keypair = Keypair::generate(&mut OsRng).unwrap();
    let req = RegistrationRequest::new("alice", &keypair, &mut OsRng).unwrap();
    let mut registry = Registry::new();
    registry.register(req).unwrap();

    c.bench_function("end_to_end_auth_only", |b| {
        b.iter_batched(
            || Authenticator::new(&registry),
            |mut auth| {
                let challenge = auth.issue_challenge(black_box("alice"), &mut OsRng).unwrap();
                let proof = AuthProof::new(&challenge, black_box(&keypair), &mut OsRng).unwrap();
                auth.verify(black_box(&proof), black_box(&challenge)).unwrap()
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

/// Scale test: registry with N users, authenticate as one.
fn bench_registry_scale(c: &mut Criterion) {
    let sizes = [1usize, 10, 100, 500];
    let mut group = c.benchmark_group("registry_scale_auth");

    for &n in &sizes {
        let mut registry = Registry::new();
        let mut last_keypair = None;

        for i in 0..n {
            let kp = Keypair::generate(&mut OsRng).unwrap();
            let username = format!("user-{i}");
            let req = RegistrationRequest::new(&username, &kp, &mut OsRng).unwrap();
            registry.register(req).unwrap();
            last_keypair = Some((format!("user-{}", n - 1), kp));
        }

        let (target_user, target_kp) = last_keypair.unwrap();

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter_batched(
                || Authenticator::new(&registry),
                |mut auth| {
                    let challenge =
                        auth.issue_challenge(black_box(&target_user), &mut OsRng).unwrap();
                    let proof =
                        AuthProof::new(&challenge, black_box(&target_kp), &mut OsRng).unwrap();
                    auth.verify(black_box(&proof), black_box(&challenge)).unwrap()
                },
                criterion::BatchSize::SmallInput,
            )
        });
    }

    group.finish();
}

/// Serde round-trip cost for RegistrationRequest.
fn bench_registration_request_serde(c: &mut Criterion) {
    let keypair = Keypair::generate(&mut OsRng).unwrap();
    let req = RegistrationRequest::new("alice", &keypair, &mut OsRng).unwrap();

    c.bench_function("registration_request_serde_json", |b| {
        b.iter(|| {
            let json = serde_json::to_string(black_box(&req)).unwrap();
            let recovered: RegistrationRequest = serde_json::from_str(&json).unwrap();
            black_box(recovered)
        })
    });
}

criterion_group!(
    end_to_end_benches,
    bench_full_flow,
    bench_auth_only_flow,
    bench_registry_scale,
    bench_registration_request_serde,
);
criterion_main!(end_to_end_benches);
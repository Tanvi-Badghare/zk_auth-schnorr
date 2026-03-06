use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::rngs::OsRng;
use zk_auth::crypto::{
    curves::{Scalar, BASEPOINT},
    schnorr::SchnorrProof,
};

fn bench_schnorr_prove(c: &mut Criterion) {
    let mut rng = OsRng;
    let secret = Scalar::random(&mut rng);
    let public = &secret * &BASEPOINT;
    let message = b"benchmark-message";

    c.bench_function("schnorr_prove", |b| {
        b.iter(|| {
            SchnorrProof::prove(
                black_box(&secret),
                black_box(&public),
                black_box(message),
                &mut OsRng,
            )
        })
    });
}

fn bench_schnorr_verify(c: &mut Criterion) {
    let mut rng = OsRng;
    let secret = Scalar::random(&mut rng);
    let public = &secret * &BASEPOINT;
    let message = b"benchmark-message";
    let proof = SchnorrProof::prove(&secret, &public, message, &mut rng);

    c.bench_function("schnorr_verify", |b| {
        b.iter(|| proof.verify(black_box(&public), black_box(message)))
    });
}

fn bench_schnorr_prove_and_verify(c: &mut Criterion) {
    let mut rng = OsRng;
    let secret = Scalar::random(&mut rng);
    let public = &secret * &BASEPOINT;
    let message = b"benchmark-message";

    c.bench_function("schnorr_prove_and_verify", |b| {
        b.iter(|| {
            let proof = SchnorrProof::prove(
                black_box(&secret),
                black_box(&public),
                black_box(message),
                &mut OsRng,
            );
            black_box(proof.verify(&public, message))
        })
    });
}

fn bench_scalar_random(c: &mut Criterion) {
    c.bench_function("scalar_random", |b| b.iter(|| Scalar::random(&mut OsRng)));
}

fn bench_scalar_mul_basepoint(c: &mut Criterion) {
    let mut rng = OsRng;
    let scalar = Scalar::random(&mut rng);

    c.bench_function("scalar_mul_basepoint", |b| {
        b.iter(|| black_box(&scalar) * &BASEPOINT)
    });
}

criterion_group!(
    schnorr_benches,
    bench_schnorr_prove,
    bench_schnorr_verify,
    bench_schnorr_prove_and_verify,
    bench_scalar_random,
    bench_scalar_mul_basepoint,
);
criterion_main!(schnorr_benches);

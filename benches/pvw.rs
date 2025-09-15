use criterion::{Criterion, black_box, criterion_group, criterion_main};
use num_bigint::BigInt;
use pvw::prelude::*;
use rand::thread_rng;
use std::sync::Arc;

fn bench_parameter_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("Parameter Generation");

    group.bench_function("generate_params_small", |b| {
        b.iter(|| {
            PvwParametersBuilder::new()
                .set_parties(4)
                .set_dimension(256)
                .set_l(8)
                .set_moduli(&[0xffffee001u64, 0xffffc4001u64])
                .set_secret_variance(1.0)
                .set_error_bounds_u32(100, 200)
                .build()
                .unwrap()
        });
    });

    group.bench_function("generate_params_medium", |b| {
        b.iter(|| {
            PvwParametersBuilder::new()
                .set_parties(8)
                .set_dimension(512)
                .set_l(16)
                .set_moduli(&[0xffffee001u64, 0xffffc4001u64, 0x1ffffe0001u64])
                .set_secret_variance(1.0)
                .set_error_bounds_u32(100, 200)
                .build()
                .unwrap()
        });
    });

    group.bench_function("generate_params_large", |b| {
        b.iter(|| {
            PvwParametersBuilder::new()
                .set_parties(16)
                .set_dimension(1024)
                .set_l(32)
                .set_moduli(&[0xffffee001u64, 0xffffc4001u64, 0x1ffffe0001u64])
                .set_secret_variance(1.0)
                .set_error_bounds_u32(100, 200)
                .build()
                .unwrap()
        });
    });

    group.finish();
}

fn bench_crs_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("CRS Generation");

    let params_small = PvwParametersBuilder::new()
        .set_parties(4)
        .set_dimension(256)
        .set_l(8)
        .set_moduli(&[0xffffee001u64, 0xffffc4001u64])
        .set_secret_variance(1.0)
        .set_error_bounds_u32(100, 200)
        .build()
        .unwrap();

    let params_medium = PvwParametersBuilder::new()
        .set_parties(8)
        .set_dimension(512)
        .set_l(16)
        .set_moduli(&[0xffffee001u64, 0xffffc4001u64, 0x1ffffe0001u64])
        .set_secret_variance(1.0)
        .set_error_bounds_u32(100, 200)
        .build()
        .unwrap();

    group.bench_function("generate_crs_small", |b| {
        b.iter(|| PvwCrs::new(&Arc::new(params_small.clone()), &mut thread_rng()).unwrap());
    });

    group.bench_function("generate_crs_medium", |b| {
        b.iter(|| PvwCrs::new(&Arc::new(params_medium.clone()), &mut thread_rng()).unwrap());
    });

    group.finish();
}

fn bench_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("Key Generation");

    let params_small = PvwParametersBuilder::new()
        .set_parties(4)
        .set_dimension(256)
        .set_l(8)
        .set_moduli(&[0xffffee001u64, 0xffffc4001u64])
        .set_secret_variance(1.0)
        .set_error_bounds_u32(100, 200)
        .build()
        .unwrap();

    let params_medium = PvwParametersBuilder::new()
        .set_parties(8)
        .set_dimension(512)
        .set_l(16)
        .set_moduli(&[0xffffee001u64, 0xffffc4001u64, 0x1ffffe0001u64])
        .set_secret_variance(1.0)
        .set_error_bounds_u32(100, 200)
        .build()
        .unwrap();

    let crs_small = PvwCrs::new(&Arc::new(params_small.clone()), &mut thread_rng()).unwrap();
    let crs_medium = PvwCrs::new(&Arc::new(params_medium.clone()), &mut thread_rng()).unwrap();

    group.bench_function("generate_secret_key_small", |b| {
        b.iter(|| SecretKey::random(&Arc::new(params_small.clone()), &mut thread_rng()).unwrap());
    });

    group.bench_function("generate_secret_key_medium", |b| {
        b.iter(|| SecretKey::random(&Arc::new(params_medium.clone()), &mut thread_rng()).unwrap());
    });

    group.bench_function("generate_public_key_small", |b| {
        let secret_key =
            SecretKey::random(&Arc::new(params_small.clone()), &mut thread_rng()).unwrap();
        b.iter(|| PublicKey::generate(&secret_key, &crs_small, &mut thread_rng()).unwrap());
    });

    group.bench_function("generate_public_key_medium", |b| {
        let secret_key =
            SecretKey::random(&Arc::new(params_medium.clone()), &mut thread_rng()).unwrap();
        b.iter(|| PublicKey::generate(&secret_key, &crs_medium, &mut thread_rng()).unwrap());
    });

    group.finish();
}

fn bench_sampling(c: &mut Criterion) {
    let mut group = c.benchmark_group("Sampling");

    let bound = BigInt::from(100);
    let variance = BigInt::from(10);

    group.bench_function("sample_discrete_gaussian_vec", |b| {
        b.iter(|| sample_discrete_gaussian_vec(&bound, black_box(256)));
    });

    group.bench_function("sample_bigint_normal_vec", |b| {
        b.iter(|| sample_bigint_normal_vec(&variance, black_box(256)));
    });

    group.finish();
}

fn bench_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("Validation");

    let params = PvwParametersBuilder::new()
        .set_parties(4)
        .set_dimension(256)
        .set_l(8)
        .set_moduli(&[0xffffee001u64, 0xffffc4001u64])
        .set_secret_variance(1.0)
        .set_error_bounds_u32(100, 200)
        .build()
        .unwrap();

    let crs = PvwCrs::new(&Arc::new(params.clone()), &mut thread_rng()).unwrap();
    let secret_key = SecretKey::random(&Arc::new(params.clone()), &mut thread_rng()).unwrap();
    let public_key = PublicKey::generate(&secret_key, &crs, &mut thread_rng()).unwrap();

    group.bench_function("validate_crs", |b| {
        b.iter(|| crs.validate().unwrap());
    });

    group.bench_function("validate_public_key", |b| {
        b.iter(|| public_key.validate().unwrap());
    });

    group.bench_function("validate_secret_key", |b| {
        b.iter(|| secret_key.validate().unwrap());
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_parameter_generation,
    bench_crs_generation,
    bench_key_generation,
    bench_sampling,
    bench_validation
);
criterion_main!(benches);

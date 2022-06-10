#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use log::{Level, LevelFilter};
use anyhow::Result;
use plonky2::{
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
        config::{GenericConfig, PoseidonGoldilocksConfig},
    },
    util::timing::TimingTree,
};
use plonky2_ed25519::gadgets::eddsa::verify_message_circuit;
use plonky2_ed25519::gadgets::eddsa::EDDSASignatureTarget;
use plonky2_ed25519::gadgets::curve::CircuitBuilderCurve;
use plonky2_ed25519::gadgets::nonnative::CircuitBuilderNonNative;
use plonky2_ed25519::gadgets::eddsa::EDDSAPublicKeyTarget;
use plonky2_ed25519::curve::eddsa::{SAMPLE_H1, SAMPLE_PK1, SAMPLE_SIG1};

fn benchmark() -> Result<()> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let pw = PartialWitness::new();
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::wide_ecc_config());

    let msg_target = builder.constant_nonnative(SAMPLE_H1);
    let pk_target = EDDSAPublicKeyTarget(builder.constant_affine_point(SAMPLE_PK1));
    let r_target = builder.constant_affine_point(SAMPLE_SIG1.r);
    let s_target = builder.constant_nonnative(SAMPLE_SIG1.s);

    let sig_target = EDDSASignatureTarget {
        r: r_target,
        s: s_target,
    };

    verify_message_circuit(&mut builder, msg_target, sig_target, pk_target);

    println!("Constructing inner proof with {} gates", builder.num_gates());
    let data = builder.build::<C>();

    let timing = TimingTree::new("prove", Level::Debug);
    let proof = data.prove(pw).unwrap();
    timing.print();

    println!("Proof size: {} bytes", proof.to_bytes().unwrap().len());
    let compressed_proof = proof.clone().compress(&data.common)?;
    println!("Compressed proof size: {} bytes", compressed_proof.to_bytes().unwrap().len());

    let timing = TimingTree::new("verify", Level::Debug);
    let ok = data.verify(proof);
    timing.print();

    ok
}

fn main() -> Result<()> {
    // Initialize logging
    let mut builder = env_logger::Builder::from_default_env();
    builder.format_timestamp(None);
    builder.filter_level(LevelFilter::Trace);
    builder.try_init()?;

    // Run the benchmark
    benchmark()
}

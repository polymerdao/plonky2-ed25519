#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use anyhow::Result;
use plonky2::{
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
        config::{GenericConfig, PoseidonGoldilocksConfig},
    },
};
use plonky2_ed25519::curve::curve_types::AffinePoint;
use plonky2_ed25519::field::ed25519_base::Ed25519Base;
use plonky2_ed25519::field::ed25519_scalar::Ed25519Scalar;
use plonky2_ed25519::gadgets::eddsa::verify_message_circuit;
use plonky2_ed25519::gadgets::eddsa::EDDSASignatureTarget;
use plonky2_ed25519::curve::eddsa::EDDSASignature;
use plonky2_ed25519::gadgets::curve::CircuitBuilderCurve;
use plonky2_ed25519::gadgets::nonnative::CircuitBuilderNonNative;
use plonky2_ed25519::gadgets::eddsa::EDDSAPublicKeyTarget;
use std::time::Instant;

fn benchmark() -> Result<()> {
    println!("Start timing");
    let now = Instant::now();

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let pk = AffinePoint {
        x: Ed25519Base(
            [15550518515784108376, 11671404521375861941, 14264319369277047820, 1535614051696727984]
        ),
        y: Ed25519Base(
            [3288954626923522619, 8290404718738973538, 11980668049915458149, 3015821356719194170]
        ),
        zero: false,
    };

    // "test message"
    let h = Ed25519Scalar([
        0xf664bfe815b3f691,
        0x677f3f53d9def3ed,
        0xc75422b41eb07187,
        0x0ab087fb4e3439bd
    ]);

    let sig = EDDSASignature {
        r: AffinePoint {
            x: Ed25519Base(
                [69846909542369210, 15893343536663755999, 963958585613385863, 7582547496062573440]
            ),
            y: Ed25519Base(
                [9286836604675867752, 4812450209474102063, 868878820904116002, 4970420200988206879]
            ),
            zero: false,
        },
        s: Ed25519Scalar([
            0x8cf70db88f21cbfa,
            0x6653c3fd197a19b9,
            0xb84df96c151efff0,
            0x08440c31c6094824,
        ]),
    };

    let pw = PartialWitness::new();
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::wide_ecc_config());

    let msg_target = builder.constant_nonnative(h);
    let pk_target = EDDSAPublicKeyTarget(builder.constant_affine_point(pk));
    let r_target = builder.constant_affine_point(sig.r);
    let s_target = builder.constant_nonnative(sig.s);

    let sig_target = EDDSASignatureTarget {
        r: r_target,
        s: s_target,
    };

    verify_message_circuit(&mut builder, msg_target, sig_target, pk_target);

    println!("Constructing inner proof with {} gates", builder.num_gates());
    let data = builder.build::<C>();

    let elapsed = now.elapsed();
    println!("Building time: {:.2?}", elapsed);
    let now = Instant::now();

    let proof = data.prove(pw).unwrap();

    let elapsed = now.elapsed();
    println!("Proving time: {:.2?}", elapsed);
    let now = Instant::now();

    let ok = data.verify(proof);

    let elapsed = now.elapsed();
    println!("Verifying time: {:.2?}", elapsed);

    ok
}

fn main() -> Result<()> {
    // Run the benchmark
    benchmark()
}

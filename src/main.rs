#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use std::{num::ParseIntError, ops::RangeInclusive, str::FromStr};

use anyhow::{Context as _, Result};
use log::{info, LevelFilter};
use plonky2::{
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
        config::{GenericConfig, PoseidonGoldilocksConfig},
    },
};
use structopt::StructOpt;
use plonky2_ed25519::curve::curve_types::AffinePoint;
use plonky2_ed25519::field::ed25519_base::Ed25519Base;
use plonky2_ed25519::field::ed25519_scalar::Ed25519Scalar;
use plonky2_ed25519::gadgets::eddsa::verify_message_circuit;
use plonky2_ed25519::gadgets::eddsa::EDDSASignatureTarget;
use plonky2_ed25519::curve::eddsa::EDDSASignature;
use plonky2_ed25519::gadgets::curve::CircuitBuilderCurve;
use plonky2_ed25519::gadgets::nonnative::CircuitBuilderNonNative;
use plonky2_ed25519::gadgets::eddsa::EDDSAPublicKeyTarget;

#[derive(Clone, StructOpt, Debug)]
#[structopt(name = "bench_recursion")]
struct Options {
    /// Verbose mode (-v, -vv, -vvv, etc.)
    #[structopt(short, long, parse(from_occurrences))]
    verbose: usize,

    /// Apply an env_filter compatible log filter
    #[structopt(long, env, default_value)]
    log_filter: String,

    /// Number of compute threads to use. Defaults to number of cores. Can be a single
    /// value or a rust style range.
    #[structopt(long, parse(try_from_str = parse_range_usize))]
    threads: Option<RangeInclusive<usize>>,
}

fn benchmark() -> Result<()> {
    println!("Run benchmark()");

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

    info!("Constructing inner proof with {} gates", builder.num_gates());
    let data = builder.build::<C>();
    let proof = data.prove(pw).unwrap();
    data.verify(proof)
}

fn main() -> Result<()> {
    // Parse command line arguments, see `--help` for details.
    let options = Options::from_args_safe()?;

    // Initialize logging
    let mut builder = env_logger::Builder::from_default_env();
    builder.parse_filters(&options.log_filter);
    builder.format_timestamp(None);
    match options.verbose {
        0 => &mut builder,
        1 => builder.filter_level(LevelFilter::Info),
        2 => builder.filter_level(LevelFilter::Debug),
        _ => builder.filter_level(LevelFilter::Trace),
    };
    builder.try_init()?;

    let num_cpus = num_cpus::get();
    let threads = options.threads.unwrap_or(num_cpus..=num_cpus);

    // Since the `size` is most likely to be and unbounded range we make that the outer iterator.
    for threads in threads.clone() {
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .context("Failed to build thread pool.")?
            .install(|| {
                info!(
                        "Using {} compute threads on {} cores",
                        rayon::current_num_threads(),
                        num_cpus
                    );
                // Run the benchmark
                benchmark()
            })?;
    }

    Ok(())
}

fn parse_range_usize(src: &str) -> Result<RangeInclusive<usize>, ParseIntError> {
    if let Some((left, right)) = src.split_once("..=") {
        Ok(RangeInclusive::new(
            usize::from_str(left)?,
            usize::from_str(right)?,
        ))
    } else if let Some((left, right)) = src.split_once("..") {
        Ok(RangeInclusive::new(
            usize::from_str(left)?,
            if right.is_empty() {
                usize::MAX
            } else {
                usize::from_str(right)?.saturating_sub(1)
            },
        ))
    } else {
        let value = usize::from_str(src)?;
        Ok(RangeInclusive::new(value, value))
    }
}

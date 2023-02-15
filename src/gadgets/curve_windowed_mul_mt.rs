use std::marker::PhantomData;
use std::ops::Mul;

use anyhow::Result;
use num::bigint::ToBigUint;
use num::{BigUint, One};
use plonky2::hash::hash_types::RichField;
use plonky2::hash::keccak::KeccakHash;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData,
};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, GenericHashOut, Hasher};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2::plonk::prover::prove;
use plonky2_ecdsa::gadgets::biguint::WitnessBigUint;
use plonky2_field::extension::Extendable;
use plonky2_field::types::{Field, PrimeField, Sample};
use plonky2_u32::gadgets::arithmetic_u32::{CircuitBuilderU32, U32Target};
use plonky2_u32::witness::WitnessU32;

use crate::curve::curve_types::{AffinePoint, Curve, CurveScalar, ProjectivePoint};
use crate::curve::ed25519::{mul_naive, Ed25519};
use crate::field::ed25519_base::Ed25519Base;
use crate::field::ed25519_scalar::Ed25519Scalar;
use crate::gadgets::curve::{AffinePointTarget, CircuitBuilderCurve};
use crate::gadgets::curve_windowed_mul::CircuitBuilderWindowedMul;
use crate::gadgets::nonnative::{CircuitBuilderNonNative, NonNativeTarget};
use crate::gadgets::split_nonnative::CircuitBuilderSplit;

const SUB_CIRCUIT_COUNT: usize = 2;
const WINDOW_SIZE: usize = 4;
const NUM_LIMBS: usize = 32; // 32 = 256 / 4 / 2

type ProofTuple<F, C, const D: usize> = (
    ProofWithPublicInputs<F, C, D>,
    VerifierOnlyCircuitData<C, D>,
    CommonCircuitData<F, D>,
);

pub struct CurveScalarMulWindowedPartTarget<CV: Curve> {
    pub p_target: AffinePointTarget<CV>,
    pub p_init_target: AffinePointTarget<CV>,
    pub n_target: NonNativeTarget<CV::ScalarField>,
    pub q_target: AffinePointTarget<CV>,
}

pub fn register_public_affine_point_target<
    F: RichField + Extendable<D>,
    CV: Curve,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    target: &AffinePointTarget<CV>,
) {
    for x in target.x.value.limbs {
        builder.register_public_input(x.0);
    }
    for y in target.y.value.limbs {
        builder.register_public_input(y.0);
    }
}

pub fn register_public_nonnative_target<
    F: RichField + Extendable<D>,
    CV: Curve,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    target: &NonNativeTarget<CV::ScalarField>,
) {
    for x in target.value.limbs {
        builder.register_public_input(x.0);
    }
}

pub fn load_curve_scalar_mul_windowed_part_circuit_public_inputs_target<
    F: RichField + Extendable<D>,
    CV: Curve,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    public_input_targets: Vec<Target>,
) -> CurveScalarMulWindowedPartTarget<CV> {
    let p_target = builder.add_virtual_affine_point_target::<CV>();
    let p_init_target = builder.add_virtual_affine_point_target::<CV>();
    let n_target = builder.add_virtual_nonnative_target();
    let q_target =
        builder.curve_scalar_mul_windowed_part(NUM_LIMBS, &p_init_target, &p_target, &n_target);

    let mut index = 0;
    for x in p_target.x.value.limbs {
        builder.connect(public_input_targets[index], x.0);
        index = index + 1;
    }
    for y in p_target.y.value.limbs {
        builder.connect(public_input_targets[index], y.0);
        index = index + 1;
    }
    for x in p_init_target.x.value.limbs {
        builder.connect(public_input_targets[index], x.0);
        index = index + 1;
    }
    for y in p_init_target.y.value.limbs {
        builder.connect(public_input_targets[index], y.0);
        index = index + 1;
    }
    for x in n_target.value.limbs {
        builder.connect(public_input_targets[index], x.0);
        index = index + 1;
    }
    for x in q_target.x.value.limbs {
        builder.connect(public_input_targets[index], x.0);
        index = index + 1;
    }
    for y in q_target.y.value.limbs {
        builder.connect(public_input_targets[index], y.0);
        index = index + 1;
    }
    assert_eq!(index - 1, public_input_targets.len());

    CurveScalarMulWindowedPartTarget {
        p_target,
        p_init_target,
        n_target,
        q_target,
    }
}

pub fn build_curve_scalar_mul_windowed_part_circuit<
    F: RichField + Extendable<D>,
    CV: Curve,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
) -> CurveScalarMulWindowedPartTarget<CV> {
    let p_target = builder.add_virtual_affine_point_target::<CV>();
    let p_init_target = builder.add_virtual_affine_point_target::<CV>();
    let n_target = builder.add_virtual_nonnative_target();
    let q_target =
        builder.curve_scalar_mul_windowed_part(NUM_LIMBS, &p_init_target, &p_target, &n_target);

    register_public_affine_point_target(builder, &p_target);
    register_public_affine_point_target(builder, &p_init_target);
    register_public_nonnative_target(builder, &n_target);
    register_public_affine_point_target(builder, &q_target);

    CurveScalarMulWindowedPartTarget {
        p_target,
        p_init_target,
        n_target,
        q_target,
    }
}

pub fn get_curve_scalar_mul_windowed_part_circuit_data<
    F: RichField + Extendable<D>,
    CV: Curve,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    config: CircuitConfig,
) -> Result<CircuitData<F, C, D>>
where
    [(); C::Hasher::HASH_SIZE]:,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let _ = build_curve_scalar_mul_windowed_part_circuit::<F, CV, C, D>(&mut builder);
    let data = builder.build::<C>();
    Ok(data)
}

pub fn prove_curve_scalar_mul_windowed_part<
    F: RichField + Extendable<D>,
    CV: Curve,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    config: CircuitConfig,
    p: &AffinePoint<CV>,
    n: &CV::ScalarField,
    init_p: &AffinePoint<CV>,
) -> Result<ProofTuple<F, C, D>>
where
    [(); C::Hasher::HASH_SIZE]:,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let targets = build_curve_scalar_mul_windowed_part_circuit::<F, CV, C, D>(&mut builder);
    let mut pw = PartialWitness::new();
    pw.set_biguint_target(&targets.p_target.x.value, &p.x.to_canonical_biguint());
    pw.set_biguint_target(&targets.p_target.y.value, &p.y.to_canonical_biguint());
    pw.set_biguint_target(
        &targets.p_init_target.x.value,
        &init_p.x.to_canonical_biguint(),
    );
    pw.set_biguint_target(
        &targets.p_init_target.y.value,
        &init_p.y.to_canonical_biguint(),
    );
    pw.set_biguint_target(&targets.n_target.value, &n.to_canonical_biguint());

    let data = builder.build::<C>();
    let proof = data.prove(pw).unwrap();

    Ok((proof, data.verifier_only, data.common))
}

pub struct CurveScalarMulMtData<
    'a,
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> {
    pub proof0: &'a ProofWithPublicInputsTarget<D>,
    pub proof1: &'a ProofWithPublicInputsTarget<D>,
    pub p_target: &'a AffinePointTarget<CV>,
    pub n_target: &'a NonNativeTarget<CV::ScalarField>,
    pub q_target: &'a AffinePointTarget<CV>,
}

pub fn build_curve_scalar_mul_windowed_mt_circuit<
    F: RichField + Extendable<D>,
    CV: Curve,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    config: CircuitConfig,
    builder: &mut CircuitBuilder<F, D>,
) -> Result<CurveScalarMulMtData<F, C, D>> {
    let circuit_data = get_curve_scalar_mul_windowed_part_circuit_data(config.clone())?;

    let proof0 = builder.add_virtual_proof_with_pis::<C>(&circuit_data.common);
    let proof1 = builder.add_virtual_proof_with_pis::<C>(&circuit_data.common);

    builder.verify_proof::<C>(&proof0, &&circuit_data.verifier_only, &circuit_data.common);
    builder.verify_proof::<C>(&proof1, &&circuit_data.verifier_only, &circuit_data.common);

    let proof0_targets = load_curve_scalar_mul_windowed_part_circuit_public_inputs_target(
        builder,
        proof0.public_inputs,
    );
    let proof1_targets = load_curve_scalar_mul_windowed_part_circuit_public_inputs_target(
        builder,
        proof1.public_inputs,
    );

    let p_target = builder.add_virtual_affine_point_target();
    let n_target = builder.add_virtual_nonnative_target();
    let q_target = builder.add_virtual_affine_point_target();

    builder.connect_affine_point(&p_target, &proof0_targets.p_target);
    let limb_count = n_target.value.limbs.len();
    for i in 0..limb_count / 2 {
        builder.connect_u32(
            n_target.value.limbs[i],
            proof0_targets.n_target.value.limbs[i],
        );
    }
    for i in limb_count / 2..limb_count {
        builder.connect(
            proof0_targets.n_target.value.limbs[i].0,
            builder.constant(F::from_canonical_usize(0)),
        );
    }
    for i in 0..limb_count / 2 {
        builder.connect_u32(
            n_target.value.limbs[i + limb_count / 2],
            proof1_targets.n_target.value.limbs[i],
        );
    }
    for i in limb_count / 2..limb_count {
        builder.connect(
            proof1_targets.n_target.value.limbs[i].0,
            builder.constant(F::from_canonical_usize(0)),
        );
    }
    builder.connect_affine_point(&q_target, &proof1_targets.q_target);

    Ok(CurveScalarMulMtData {
        proof0: &proof0,
        proof1: &proof1,
        p_target: &p_target,
        n_target: &n_target,
        q_target: &q_target,
    })
}

pub fn prove_curve25519_mul_mt<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    InnerC: GenericConfig<D, F = F>,
    const D: usize,
>(
    config: &CircuitConfig,
    p: &AffinePoint<Ed25519>,
    n: &Ed25519Scalar,
    res: &AffinePoint<Ed25519>,
) -> Result<ProofTuple<F, C, D>>
where
    InnerC::Hasher: AlgebraicHasher<F>,
    [(); C::Hasher::HASH_SIZE]:,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    let n_biguint = n.to_canonical_biguint();
    let mut mask = BigUint::one();
    mask = (mask << 128) - BigUint::one();
    let n0_biguint = n_biguint.clone() & mask.clone();
    let mut n1_biguint = n_biguint.clone();
    n1_biguint = (n1_biguint >> 128) & mask.clone();
    assert_eq!(n_biguint, n0_biguint.clone() + (n1_biguint.clone() << 128));
    let n0 = Ed25519Scalar::from_noncanonical_biguint(n0_biguint);
    let n1 = Ed25519Scalar::from_noncanonical_biguint(n1_biguint);

    let p0_init = AffinePoint {
        x: Ed25519Base::ZERO,
        y: Ed25519Base::ONE,
        zero: false,
    };
    let p1_init = (CurveScalar::<Ed25519>(n0.clone()) * p.to_projective()).to_affine();
    let b128 = Ed25519Scalar::from_noncanonical_biguint(BigUint::from(1u8) << 128);
    let p1 = (CurveScalar::<Ed25519>(b128) * p.to_projective()).to_affine();
    let q1_expected =
        p1_init + (CurveScalar::<Ed25519>(n1.clone()) * p1.to_projective()).to_affine();
    let q_expected = (CurveScalar::<Ed25519>(n.clone()) * p.to_projective()).to_affine();
    assert_eq!(q1_expected, q_expected);

    let mut builder = CircuitBuilder::<F, D>::new(config.clone());
    let mut pw = PartialWitness::new();
    {
        let (inner_proof, inner_vd, inner_cd) = prove_curve_scalar_mul_windowed_part::<
            F,
            Ed25519,
            C,
            D,
        >(config.clone(), &p, &n0, &p0_init)?;
        let pt = builder.add_virtual_proof_with_pis::<InnerC>(&inner_cd);
        pw.set_proof_with_pis_target(&pt, &inner_proof);

        let inner_data = VerifierCircuitTarget {
            constants_sigmas_cap: builder.add_virtual_cap(inner_cd.config.fri_config.cap_height),
            circuit_digest: builder.add_virtual_hash(),
        };
        pw.set_cap_target(
            &inner_data.constants_sigmas_cap,
            &inner_vd.constants_sigmas_cap,
        );
        pw.set_hash_target(inner_data.circuit_digest, inner_vd.circuit_digest);

        builder.verify_proof::<InnerC>(&pt, &inner_data, &inner_cd);
    }

    {
        let (inner_proof, inner_vd, inner_cd) = prove_curve_scalar_mul_windowed_part::<
            F,
            Ed25519,
            C,
            D,
        >(config.clone(), &p1, &n1, &p1_init)?;
        let pt = builder.add_virtual_proof_with_pis::<InnerC>(&inner_cd);
        pw.set_proof_with_pis_target(&pt, &inner_proof);

        let inner_data = VerifierCircuitTarget {
            constants_sigmas_cap: builder.add_virtual_cap(inner_cd.config.fri_config.cap_height),
            circuit_digest: builder.add_virtual_hash(),
        };
        pw.set_cap_target(
            &inner_data.constants_sigmas_cap,
            &inner_vd.constants_sigmas_cap,
        );
        pw.set_hash_target(inner_data.circuit_digest, inner_vd.circuit_digest);

        builder.verify_proof::<InnerC>(&pt, &inner_data, &inner_cd);
    }

    let data = builder.build::<C>();
    let proof = data.prove(pw).unwrap();
    data.verify(proof.clone())?;
    Ok((proof, data.verifier_only, data.common))
}

#[cfg(test)]
mod tests {
    use std::ops::Neg;

    use anyhow::Result;
    use log::{Level, LevelFilter};
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::util::timing::TimingTree;
    use plonky2_field::types::{Field, Sample};
    use rand::Rng;

    use crate::curve::curve_types::{Curve, CurveScalar};
    use crate::curve::ed25519::Ed25519;
    use crate::field::ed25519_scalar::Ed25519Scalar;
    use crate::gadgets::curve::CircuitBuilderCurve;
    use crate::gadgets::curve_windowed_mul::CircuitBuilderWindowedMul;
    use crate::gadgets::curve_windowed_mul_mt::prove_curve25519_mul_mt;
    use crate::gadgets::nonnative::CircuitBuilderNonNative;

    #[test]
    fn test_prove_curve25519_mul_mt() -> Result<()> {
        // Initialize logging
        let mut builder = env_logger::Builder::from_default_env();
        builder.format_timestamp(None);
        builder.filter_level(LevelFilter::Info);
        builder.try_init()?;

        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type InnerC = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let g = (CurveScalar(Ed25519Scalar::rand()) * Ed25519::GENERATOR_PROJECTIVE).to_affine();
        let five = Ed25519Scalar::from_canonical_usize(5);
        let neg_five = five.neg();
        let neg_five_scalar = CurveScalar::<Ed25519>(neg_five);
        let neg_five_g = (neg_five_scalar * g.to_projective()).to_affine();

        let config = CircuitConfig::standard_ecc_config();
        let timing = TimingTree::new("prove_curve_mul_mt", Level::Info);
        prove_curve25519_mul_mt::<F, C, InnerC, D>(&config, &g, &neg_five, &neg_five_g)?;
        timing.print();

        Ok(())
    }
}

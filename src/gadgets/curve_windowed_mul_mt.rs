use anyhow::Result;
use num::{BigUint, One};
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData,
};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, Hasher};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2_ecdsa::gadgets::biguint::WitnessBigUint;
use plonky2_field::extension::Extendable;
use plonky2_field::types::{Field, PrimeField};
use plonky2_u32::gadgets::arithmetic_u32::CircuitBuilderU32;

use crate::curve::curve_types::{AffinePoint, Curve, CurveScalar};
use crate::curve::ed25519::Ed25519;
use crate::field::ed25519_scalar::Ed25519Scalar;
use crate::gadgets::curve::{AffinePointTarget, CircuitBuilderCurve};
use crate::gadgets::curve_windowed_mul::CircuitBuilderWindowedMul;
use crate::gadgets::nonnative::{CircuitBuilderNonNative, NonNativeTarget};

const NUM_LIMBS: usize = 32; // 32 = 256 / 4 / 2

type ProofTuple<F, C, const D: usize> = (
    ProofWithPublicInputs<F, C, D>,
    VerifierOnlyCircuitData<C, D>,
    CommonCircuitData<F, D>,
);

pub struct CurveScalarMulWindowedPartTarget<CV: Curve> {
    pub p_target: AffinePointTarget<CV>,
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
    for x in &target.x.value.limbs {
        builder.register_public_input(x.0);
    }
    for y in &target.y.value.limbs {
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
    for x in &target.value.limbs {
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
    let n_target = builder.add_virtual_nonnative_target();
    let q_target = builder.curve_scalar_mul_windowed_part(NUM_LIMBS, &p_target, &n_target);

    let mut index = 0;
    for x in &p_target.x.value.limbs {
        builder.connect(public_input_targets[index], x.0);
        index = index + 1;
    }
    for y in &p_target.y.value.limbs {
        builder.connect(public_input_targets[index], y.0);
        index = index + 1;
    }
    for x in &n_target.value.limbs {
        builder.connect(public_input_targets[index], x.0);
        index = index + 1;
    }
    for x in &q_target.x.value.limbs {
        builder.connect(public_input_targets[index], x.0);
        index = index + 1;
    }
    for y in &q_target.y.value.limbs {
        builder.connect(public_input_targets[index], y.0);
        index = index + 1;
    }
    assert_eq!(index - 1, public_input_targets.len());

    CurveScalarMulWindowedPartTarget {
        p_target,
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
    let n_target = builder.add_virtual_nonnative_target();
    let q_target = builder.curve_scalar_mul_windowed_part(NUM_LIMBS, &p_target, &n_target);

    register_public_affine_point_target::<F, CV, C, D>(builder, &p_target);
    register_public_nonnative_target::<F, CV, C, D>(builder, &n_target);
    register_public_affine_point_target::<F, CV, C, D>(builder, &q_target);

    CurveScalarMulWindowedPartTarget {
        p_target,
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
    pw.set_biguint_target(&targets.n_target.value, &n.to_canonical_biguint());

    let data = builder.build::<C>();
    let proof = data.prove(pw).unwrap();

    Ok((proof, data.verifier_only, data.common))
}

#[derive(Clone)]
pub struct CurveScalarMulMtData<CV: Curve, const D: usize> {
    pub proof0: ProofWithPublicInputsTarget<D>,
    pub proof1: ProofWithPublicInputsTarget<D>,
    pub p_target: AffinePointTarget<CV>,
    pub n_target: NonNativeTarget<CV::ScalarField>,
    pub q_target: AffinePointTarget<CV>,
}

pub fn build_curve_scalar_mul_windowed_mt_circuit<
    F: RichField + Extendable<D>,
    CV: Curve,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    config: CircuitConfig,
    builder: &mut CircuitBuilder<F, D>,
) -> Result<CurveScalarMulMtData<CV, D>>
where
    [(); C::Hasher::HASH_SIZE]:,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    let circuit_data =
        get_curve_scalar_mul_windowed_part_circuit_data::<F, CV, C, D>(config.clone())?;

    let proof0 = builder.add_virtual_proof_with_pis::<C>(&circuit_data.common);
    let proof1 = builder.add_virtual_proof_with_pis::<C>(&circuit_data.common);
    let p_target = builder.add_virtual_affine_point_target();
    let n_target = builder.add_virtual_nonnative_target();
    let q_target = builder.add_virtual_affine_point_target();

    let inner_data = VerifierCircuitTarget {
        constants_sigmas_cap: builder
            .add_virtual_cap(circuit_data.common.config.fri_config.cap_height),
        circuit_digest: builder.constant_hash(circuit_data.verifier_only.circuit_digest),
    };
    for (ht, h) in inner_data
        .constants_sigmas_cap
        .0
        .iter()
        .zip(circuit_data.verifier_only.constants_sigmas_cap.0)
    {
        let htt = builder.constant_hash(h);
        builder.connect_hashes(*ht, htt);
    }

    builder.verify_proof::<C>(&proof0, &inner_data, &circuit_data.common);
    builder.verify_proof::<C>(&proof1, &inner_data, &circuit_data.common);

    let proof0_targets =
        load_curve_scalar_mul_windowed_part_circuit_public_inputs_target::<F, CV, C, D>(
            builder,
            proof0.clone().public_inputs,
        );
    let proof1_targets =
        load_curve_scalar_mul_windowed_part_circuit_public_inputs_target::<F, CV, C, D>(
            builder,
            proof1.clone().public_inputs,
        );

    builder.connect_affine_point(&p_target, &proof0_targets.p_target);
    let limb_count = n_target.value.limbs.len();
    for i in 0..limb_count / 2 {
        builder.connect_u32(
            n_target.value.limbs[i],
            proof1_targets.n_target.value.limbs[i],
        );
        builder.connect_u32(
            n_target.value.limbs[i + limb_count / 2],
            proof0_targets.n_target.value.limbs[i],
        );
    }
    for i in limb_count / 2..limb_count {
        let zero = builder.zero();
        builder.connect(proof0_targets.n_target.value.limbs[i].0, zero);
        builder.connect(proof1_targets.n_target.value.limbs[i].0, zero);
    }
    builder.connect_affine_point(&q_target, &proof1_targets.q_target);
    builder.connect_affine_point(&proof0_targets.q_target, &proof1_targets.p_target);

    Ok(CurveScalarMulMtData {
        proof0,
        proof1,
        p_target,
        n_target,
        q_target,
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
    let n1_biguint = n_biguint.clone() & mask.clone();
    let mut n0_biguint = n_biguint.clone();
    n0_biguint = (n0_biguint >> 128) & mask.clone();
    assert_eq!(n_biguint, n1_biguint.clone() + (n0_biguint.clone() << 128));
    let n0 = Ed25519Scalar::from_noncanonical_biguint(n0_biguint);
    let n1 = Ed25519Scalar::from_noncanonical_biguint(n1_biguint);

    let q0 = (CurveScalar::<Ed25519>(n0.clone()) * p.to_projective()).to_affine();
    let q = (CurveScalar::<Ed25519>(n1.clone()) * q0.to_projective()).to_affine();
    let q_expected = (CurveScalar::<Ed25519>(n.clone()) * p.to_projective()).to_affine();
    assert_eq!(q, q_expected);
    assert_eq!(q, *res);

    let mut builder = CircuitBuilder::<F, D>::new(config.clone());
    let mut pw = PartialWitness::new();
    let targets = build_curve_scalar_mul_windowed_mt_circuit::<F, Ed25519, C, D>(
        config.clone(),
        &mut builder,
    )?;

    let (proof0, _, _) =
        prove_curve_scalar_mul_windowed_part::<F, Ed25519, C, D>(config.clone(), &p, &n0)?;
    pw.set_proof_with_pis_target(&targets.proof0, &proof0);

    let (proof1, _, _) =
        prove_curve_scalar_mul_windowed_part::<F, Ed25519, C, D>(config.clone(), &q0, &n1)?;
    pw.set_proof_with_pis_target(&targets.proof1, &proof1);

    pw.set_biguint_target(&targets.n_target.value, &n_biguint);
    pw.set_biguint_target(&targets.p_target.x.value, &p.x.to_canonical_biguint());
    pw.set_biguint_target(&targets.p_target.y.value, &p.y.to_canonical_biguint());
    pw.set_biguint_target(&targets.q_target.x.value, &res.x.to_canonical_biguint());
    pw.set_biguint_target(&targets.q_target.y.value, &res.y.to_canonical_biguint());

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
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::util::timing::TimingTree;
    use plonky2_field::types::{Field, Sample};

    use crate::curve::curve_types::{Curve, CurveScalar};
    use crate::curve::ed25519::Ed25519;
    use crate::field::ed25519_scalar::Ed25519Scalar;
    use crate::gadgets::curve_windowed_mul_mt::prove_curve25519_mul_mt;

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
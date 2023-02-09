use std::marker::PhantomData;

use anyhow::Result;
use num::BigUint;
use plonky2::hash::hash_types::RichField;
use plonky2::hash::keccak::KeccakHash;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData,
};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, GenericHashOut, Hasher};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::plonk::prover::prove;
use plonky2_ecdsa::gadgets::biguint::BigUintTarget;
use plonky2_field::extension::Extendable;
use plonky2_field::types::{Field, PrimeField, Sample};
use plonky2_u32::gadgets::arithmetic_u32::{CircuitBuilderU32, U32Target};
use plonky2_u32::witness::WitnessU32;

use crate::curve::curve_types::{AffinePoint, Curve, CurveScalar, ProjectivePoint};
use crate::curve::ed25519::Ed25519;
use crate::gadgets::curve::{AffinePointTarget, CircuitBuilderCurve};
use crate::gadgets::nonnative::NonNativeTarget;
use crate::gadgets::split_nonnative::CircuitBuilderSplit;

const MT_SIZE: usize = 4;
const WINDOW_SIZE: usize = 4;
const FIELD_SIZE: usize = 256;

pub trait CircuitBuilderWindowedMulMt<F: RichField + Extendable<D>, const D: usize> {
    fn precompute_all_d<C: Curve>(&mut self, p: &AffinePointTarget<C>)
        -> Vec<AffinePointTarget<C>>;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderWindowedMulMt<F, D>
    for CircuitBuilder<F, D>
{
    fn precompute_all_d<C: Curve>(
        &mut self,
        p: &AffinePointTarget<C>,
    ) -> Vec<AffinePointTarget<C>> {
        let mut res = Vec::new();
        res.push(p.clone());
        for _ in 0..FIELD_SIZE - 1 {
            res.push(self.curve_double(res.last().unwrap()));
        }
        let num_limbs = p.x.value.limbs.len();
        for i in 0..FIELD_SIZE {
            for j in 0..num_limbs {
                self.register_public_input(res[i].x.value.limbs[j].0);
                self.register_public_input(res[i].y.value.limbs[j].0);
            }
        }
        res
    }
}

type ProofTuple<F, C, const D: usize> = (
    ProofWithPublicInputs<F, C, D>,
    VerifierOnlyCircuitData<C, D>,
    CommonCircuitData<F, D>,
);

pub fn prove_precompute_all_d<
    F: RichField + Extendable<D>,
    CV: Curve,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    config: CircuitConfig,
    point: AffinePoint<CV>,
) -> Result<ProofTuple<F, C, D>> {
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let point_target = builder.add_virtual_affine_point_target::<CV>();
    builder.precompute_all_d(&point_target);
    let mut pw = PartialWitness::new();
    let x_limbs = point.x.to_canonical_biguint().to_u32_digits();
    let y_limbs = point.y.to_canonical_biguint().to_u32_digits();
    assert_eq!(x_limbs.len(), point_target.x.value.limbs.len());
    assert_eq!(y_limbs.len(), point_target.y.value.limbs.len());
    assert_eq!(y_limbs.len(), x_limbs.len());
    for i in 0..x_limbs.len() {
        pw.set_u32_target(point_target.x.value.limbs[i], x_limbs[i]);
        pw.set_u32_target(point_target.y.value.limbs[i], y_limbs[i]);
    }

    let data = builder.build::<C>();
    let proof = data.prove(pw).unwrap();

    Ok((proof, data.verifier_only, data.common))
}

pub fn prove_curve_mul_mt<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    InnerC: GenericConfig<D, F = F>,
    const D: usize,
>(
    config: &CircuitConfig,
) -> Result<ProofTuple<F, C, D>>
where
    InnerC::Hasher: AlgebraicHasher<F>,
    [(); C::Hasher::HASH_SIZE]:,
{
    let point = Ed25519::GENERATOR_AFFINE;
    let precompute_d = prove_precompute_all_d::<F, Ed25519, InnerC, D>(config.clone(), point)?;

    let mut builder = CircuitBuilder::<F, D>::new(config.clone());
    let mut pw = PartialWitness::new();
    {
        let (inner_proof, inner_vd, inner_cd) = precompute_d;
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
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2_field::types::{Field, Sample};
    use rand::Rng;

    use crate::curve::curve_types::{Curve, CurveScalar};
    use crate::curve::ed25519::Ed25519;
    use crate::field::ed25519_scalar::Ed25519Scalar;
    use crate::gadgets::curve::CircuitBuilderCurve;
    use crate::gadgets::curve_windowed_mul::CircuitBuilderWindowedMul;
    use crate::gadgets::curve_windowed_mul_mt::prove_curve_mul_mt;
    use crate::gadgets::nonnative::CircuitBuilderNonNative;

    #[test]
    #[ignore]
    fn test_pre_compute_all_d() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_ecc_config();
        Ok(())
    }
}

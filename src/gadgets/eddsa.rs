use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2_field::extension_field::Extendable;

use crate::curve::curve_types::Curve;
use crate::curve::ed25519::Ed25519;
use crate::gadgets::curve::{AffinePointTarget, CircuitBuilderCurve};
use crate::gadgets::nonnative::NonNativeTarget;
use crate::field::ed25519_scalar::Ed25519Scalar;

#[derive(Clone, Debug)]
pub struct EDDSAPublicKeyTarget<C: Curve>(pub AffinePointTarget<C>);

#[derive(Clone, Debug)]
pub struct EDDSASignatureTarget<C: Curve> {
    pub r: AffinePointTarget<C>,
    pub s: NonNativeTarget<C::ScalarField>,
}

pub fn verify_message_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    h: &NonNativeTarget<Ed25519Scalar>,
    sig: &EDDSASignatureTarget<Ed25519>,
    pk: &EDDSAPublicKeyTarget<Ed25519>,
) {
    let EDDSASignatureTarget { r, s } = sig;

    builder.curve_assert_valid(&pk.0);
    builder.curve_assert_valid(&r);

    let g = builder.constant_affine_point(Ed25519::GENERATOR_AFFINE);
    let sb = builder.curve_scalar_mul(&g, &s);
    let ha = builder.curve_scalar_mul(&pk.0, &h);
    let rhs = builder.curve_add(&r, &ha);

    builder.connect_affine_point(&sb, &rhs);
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

    use super::{EDDSAPublicKeyTarget, EDDSASignatureTarget};
    use crate::curve::eddsa::{SAMPLE_H1, SAMPLE_PK1, SAMPLE_SIG1};
    use crate::gadgets::curve::CircuitBuilderCurve;
    use crate::gadgets::eddsa::verify_message_circuit;
    use crate::gadgets::nonnative::CircuitBuilderNonNative;

    fn test_ecdsa_circuit_with_config(config: CircuitConfig) -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let msg_target = builder.constant_nonnative(SAMPLE_H1);
        let pk_target = EDDSAPublicKeyTarget(builder.constant_affine_point(SAMPLE_PK1));
        let r_target = builder.constant_affine_point(SAMPLE_SIG1.r);
        let s_target = builder.constant_nonnative(SAMPLE_SIG1.s);

        let sig_target = EDDSASignatureTarget {
            r: r_target,
            s: s_target,
        };

        verify_message_circuit(&mut builder, &msg_target, &sig_target, &pk_target);

        dbg!(builder.num_gates());
        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }

    #[test]
    #[ignore]
    fn test_ecdsa_circuit_narrow() -> Result<()> {
        test_ecdsa_circuit_with_config(CircuitConfig::standard_ecc_config())
    }

    #[test]
    #[ignore]
    fn test_ecdsa_circuit_wide() -> Result<()> {
        test_ecdsa_circuit_with_config(CircuitConfig::wide_ecc_config())
    }
}

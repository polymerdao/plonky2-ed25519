use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2_field::extension_field::Extendable;

use crate::curve::curve_types::Curve;
use crate::curve::ed25519::Ed25519;
use crate::gadgets::curve::{AffinePointTarget, CircuitBuilderCurve};
use crate::gadgets::nonnative::{NonNativeTarget};
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
    h: NonNativeTarget<Ed25519Scalar>,
    sig: EDDSASignatureTarget<Ed25519>,
    pk: EDDSAPublicKeyTarget<Ed25519>,
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

    use crate::curve::curve_types::AffinePoint;
    use super::{EDDSAPublicKeyTarget, EDDSASignatureTarget};
    use crate::curve::eddsa::EDDSASignature;
    use crate::gadgets::curve::CircuitBuilderCurve;
    use crate::gadgets::eddsa::verify_message_circuit;
    use crate::gadgets::nonnative::CircuitBuilderNonNative;
    use crate::field::ed25519_base::Ed25519Base;
    use crate::field::ed25519_scalar::Ed25519Scalar;

    fn test_ecdsa_circuit_with_config(config: CircuitConfig) -> Result<()> {
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
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let msg_target = builder.constant_nonnative(h);
        let pk_target = EDDSAPublicKeyTarget(builder.constant_affine_point(pk));
        let r_target = builder.constant_affine_point(sig.r);
        let s_target = builder.constant_nonnative(sig.s);

        let sig_target = EDDSASignatureTarget {
            r: r_target,
            s: s_target,
        };

        verify_message_circuit(&mut builder, msg_target, sig_target, pk_target);

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

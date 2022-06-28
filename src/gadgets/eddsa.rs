use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::BoolTarget;
use plonky2::iop::witness::{PartialWitness, Witness};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2_field::extension::Extendable;
use plonky2_field::types::PrimeField;
use plonky2_sha512::circuit::{array_to_bits, bits_to_biguint_target};

use crate::curve::curve_types::{AffinePoint, Curve};
use crate::curve::ed25519::Ed25519;
use crate::curve::eddsa::EDDSASignature;
use crate::field::ed25519_scalar::Ed25519Scalar;
use crate::gadgets::biguint::witness_set_biguint_target;
use crate::gadgets::curve::{AffinePointTarget, CircuitBuilderCurve};
use crate::gadgets::nonnative::{CircuitBuilderNonNative, NonNativeTarget};

#[derive(Clone, Debug)]
pub struct EDDSAPublicKeyTarget<C: Curve>(pub AffinePointTarget<C>);

#[derive(Clone, Debug)]
pub struct EDDSASignatureTarget<C: Curve> {
    pub r: AffinePointTarget<C>,
    pub s: NonNativeTarget<C::ScalarField>,
}

pub struct EDDSATargets {
    pub msg: Vec<BoolTarget>,
    pub h: NonNativeTarget<Ed25519Scalar>,
    pub sig: EDDSASignatureTarget<Ed25519>,
    pub pk: EDDSAPublicKeyTarget<Ed25519>,
}

pub fn make_verify_circuits<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    msg_len_in_bits: u128,
) -> EDDSATargets {
    let sha512 = plonky2_sha512::circuit::make_circuits(builder, msg_len_in_bits);

    let h = builder.add_virtual_nonnative_target();
    let pk = builder.add_virtual_affine_point_target();
    let r = builder.add_virtual_affine_point_target();
    let s = builder.add_virtual_nonnative_target();
    let g = builder.constant_affine_point(Ed25519::GENERATOR_AFFINE);

    let sb = builder.curve_scalar_mul(&g, &s);
    let ha = builder.curve_scalar_mul(&pk, &h);
    let rhs = builder.curve_add(&r, &ha);

    builder.connect_affine_point(&sb, &rhs);

    return EDDSATargets {
        msg: sha512.message,
        h,
        sig: EDDSASignatureTarget { r, s },
        pk: EDDSAPublicKeyTarget {
            0: AffinePointTarget { x: pk.x, y: pk.y },
        },
    };
}

pub fn fill_circuits<F: RichField + Extendable<D>, const D: usize>(
    pw: &mut PartialWitness<F>,
    msg: &[u8],
    h: Ed25519Scalar,
    sig: EDDSASignature<Ed25519>,
    pk: AffinePoint<Ed25519>,
    targets: &EDDSATargets,
) {
    let EDDSATargets {
        msg: msg_targets,
        sig: sig_target,
        h: h_target,
        pk: pk_target,
    } = targets;

    let len = msg.len();
    let msg_bits = array_to_bits(msg);
    for i in 0..len {
        pw.set_bool_target(msg_targets[i], msg_bits[i]);
    }

    witness_set_biguint_target(pw, &h_target.value, &h.to_canonical_biguint());
    witness_set_biguint_target(pw, &pk_target.0.x.value, &pk.x.to_canonical_biguint());
    witness_set_biguint_target(pw, &pk_target.0.y.value, &pk.y.to_canonical_biguint());
    witness_set_biguint_target(pw, &sig_target.s.value, &sig.s.to_canonical_biguint());
    witness_set_biguint_target(pw, &sig_target.r.x.value, &sig.r.x.to_canonical_biguint());
    witness_set_biguint_target(pw, &sig_target.r.y.value, &sig.r.y.to_canonical_biguint());
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

    use crate::curve::eddsa::{SAMPLE_H1, SAMPLE_MSG1, SAMPLE_PK1, SAMPLE_SIG1};
    use crate::gadgets::eddsa::{fill_circuits, make_verify_circuits};

    fn test_ecdsa_circuit_with_config(config: CircuitConfig) -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let mut pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let targets = make_verify_circuits(&mut builder, SAMPLE_MSG1.len() as u128);

        fill_circuits::<F, D>(
            &mut pw,
            SAMPLE_MSG1.as_bytes(),
            SAMPLE_H1,
            SAMPLE_SIG1,
            SAMPLE_PK1,
            &targets,
        );

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

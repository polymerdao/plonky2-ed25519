use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::BoolTarget;
use plonky2::iop::witness::{PartialWitness, Witness};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2_ecdsa::gadgets::biguint::witness_set_biguint_target;
use plonky2_field::extension::Extendable;
use plonky2_field::types::PrimeField;
use plonky2_sha512::circuit::{array_to_bits, bits_to_biguint_target, make_circuits};

use crate::curve::curve_types::{AffinePoint, Curve};
use crate::curve::ed25519::Ed25519;
use crate::curve::eddsa::EDDSASignature;
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
    pub sha512_msg: Vec<BoolTarget>,
    pub sigv: Vec<BoolTarget>,
    pub pkv: Vec<BoolTarget>,
    pub sig: EDDSASignatureTarget<Ed25519>,
    pub pk: EDDSAPublicKeyTarget<Ed25519>,
}

pub fn make_verify_circuits<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    msg_len: usize,
) -> EDDSATargets {
    let msg_len_in_bits = msg_len * 8;
    let sha512_msg_len = msg_len_in_bits + 512;
    let sha512 = make_circuits(builder, sha512_msg_len as u128);

    let mut sigv = Vec::new();
    let mut pkv = Vec::new();
    for _ in 0..512 {
        sigv.push(builder.add_virtual_bool_target());
    }
    for _ in 0..256 {
        pkv.push(builder.add_virtual_bool_target());
    }
    for i in 0..256 {
        builder.connect(sha512.message[i].target, sigv[i].target);
    }
    for i in 0..256 {
        builder.connect(sha512.message[256 + i].target, pkv[i].target);
    }

    // little endian
    let mut digest_bits = Vec::new();
    for i in 0..64 {
        for j in 0..8 {
            digest_bits.push(sha512.digest[i * 8 + 7 - j]);
        }
    }
    digest_bits.reverse();
    let hash = bits_to_biguint_target(builder, digest_bits);
    let h = builder.reduce(&hash);

    let pk = builder.add_virtual_affine_point_target();
    let r = builder.add_virtual_affine_point_target();
    let s = builder.add_virtual_nonnative_target();
    let g = builder.constant_affine_point(Ed25519::GENERATOR_AFFINE);

    let sb = builder.curve_scalar_mul(&g, &s);
    let ha = builder.curve_scalar_mul(&pk, &h);
    let rhs = builder.curve_add(&r, &ha);

    builder.connect_affine_point(&sb, &rhs);

    return EDDSATargets {
        sha512_msg: sha512.message,
        sigv,
        pkv,
        sig: EDDSASignatureTarget { r, s },
        pk: EDDSAPublicKeyTarget {
            0: AffinePointTarget { x: pk.x, y: pk.y },
        },
    };
}

pub fn fill_circuits<F: RichField + Extendable<D>, const D: usize>(
    pw: &mut PartialWitness<F>,
    msg: &[u8],
    sigv: &[u8],
    pkv: &[u8],
    sig: EDDSASignature<Ed25519>,
    pk: AffinePoint<Ed25519>,
    targets: &EDDSATargets,
) {
    let EDDSATargets {
        sha512_msg: sha512_msg_targets,
        sigv: sigv_targets,
        pkv: pkv_targets,
        sig: sig_target,
        pk: pk_target,
    } = targets;

    let sigv_bits = array_to_bits(sigv);
    let pkv_bits = array_to_bits(pkv);
    let msg_bits = array_to_bits(msg);
    for i in 0..msg_bits.len() {
        pw.set_bool_target(sha512_msg_targets[512 + i], msg_bits[i]);
    }
    for i in 0..512 {
        pw.set_bool_target(sigv_targets[i], sigv_bits[i]);
    }
    for i in 0..256 {
        pw.set_bool_target(pkv_targets[i], pkv_bits[i]);
    }

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

    use crate::curve::eddsa::{SAMPLE_MSG1, SAMPLE_PK1, SAMPLE_PKV1, SAMPLE_SIG1, SAMPLE_SIGV1};
    use crate::gadgets::eddsa::{fill_circuits, make_verify_circuits};

    fn test_eddsa_circuit_with_config(config: CircuitConfig) -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let mut pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let targets = make_verify_circuits(&mut builder, SAMPLE_MSG1.len());

        fill_circuits::<F, D>(
            &mut pw,
            SAMPLE_MSG1.as_bytes(),
            SAMPLE_SIGV1.as_slice(),
            SAMPLE_PKV1.as_slice(),
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
    fn test_eddsa_circuit_narrow() -> Result<()> {
        test_eddsa_circuit_with_config(CircuitConfig::standard_ecc_config())
    }

    #[test]
    #[ignore]
    fn test_eddsa_circuit_wide() -> Result<()> {
        test_eddsa_circuit_with_config(CircuitConfig::wide_ecc_config())
    }
}

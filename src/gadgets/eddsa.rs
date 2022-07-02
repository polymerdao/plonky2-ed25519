use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::BoolTarget;
use plonky2::iop::witness::{PartialWitness, Witness};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2_field::extension::Extendable;
use plonky2_sha512::circuit::{array_to_bits, bits_to_biguint_target, make_circuits};

use crate::curve::curve_types::Curve;
use crate::curve::ed25519::Ed25519;
use crate::gadgets::curve::CircuitBuilderCurve;
use crate::gadgets::nonnative::CircuitBuilderNonNative;

pub struct EDDSATargets {
    pub msg: Vec<BoolTarget>,
    pub sig: Vec<BoolTarget>,
    pub pk: Vec<BoolTarget>,
}

fn bits_to_little_256(input_vec: Vec<BoolTarget>) -> Vec<BoolTarget> {
    let mut bits = Vec::new();
    for i in 0..input_vec.len() / 8 {
        for j in 0..8 {
            bits.push(input_vec[i * 8 + 7 - j]);
        }
    }
    bits.reverse();
    bits
}

pub fn make_verify_circuits<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    msg_len: usize,
) -> EDDSATargets {
    let msg_len_in_bits = msg_len * 8;
    let sha512_msg_len = msg_len_in_bits + 512;
    let sha512 = make_circuits(builder, sha512_msg_len as u128);

    let mut msg = Vec::new();
    let mut sig = Vec::new();
    let mut pk = Vec::new();
    for i in 0..msg_len_in_bits {
        msg.push(sha512.message[512 + i]);
    }
    for _ in 0..512 {
        sig.push(builder.add_virtual_bool_target());
    }
    for _ in 0..256 {
        pk.push(builder.add_virtual_bool_target());
    }
    for i in 0..256 {
        builder.connect(sha512.message[i].target, sig[i].target);
    }
    for i in 0..256 {
        builder.connect(sha512.message[256 + i].target, pk[i].target);
    }

    let digest_bits = bits_to_little_256(sha512.digest.clone());
    let hash = bits_to_biguint_target(builder, digest_bits);
    let h = builder.reduce(&hash);

    let g = builder.constant_affine_point(Ed25519::GENERATOR_AFFINE);

    let s_bits = bits_to_little_256(sig[256..512].to_vec());
    let s_biguint = bits_to_biguint_target(builder, s_bits);
    let s = builder.biguint_to_nonnative(&s_biguint);

    let pk_bits = bits_to_little_256(pk.clone());
    let a = builder.point_decompress(&pk_bits);

    let ha = builder.curve_scalar_mul(&a, &h);

    let r_bits = bits_to_little_256(sig[..256].to_vec());
    let r = builder.point_decompress(&r_bits);

    let sb = builder.curve_scalar_mul(&g, &s);
    let rhs = builder.curve_add(&r, &ha);
    builder.connect_affine_point(&sb, &rhs);

    return EDDSATargets { msg, sig, pk };
}

pub fn fill_circuits<F: RichField + Extendable<D>, const D: usize>(
    pw: &mut PartialWitness<F>,
    msg: &[u8],
    sig: &[u8],
    pk: &[u8],
    targets: &EDDSATargets,
) {
    assert_eq!(sig.len(), 64);
    assert_eq!(pk.len(), 32);

    let EDDSATargets {
        msg: msg_targets,
        sig: sig_targets,
        pk: pk_targets,
    } = targets;
    assert_eq!(msg.len() * 8, msg_targets.len());

    let sig_bits = array_to_bits(sig);
    let pk_bits = array_to_bits(pk);
    let msg_bits = array_to_bits(msg);

    for i in 0..msg_bits.len() {
        pw.set_bool_target(msg_targets[i], msg_bits[i]);
    }
    for i in 0..512 {
        pw.set_bool_target(sig_targets[i], sig_bits[i]);
    }
    for i in 0..256 {
        pw.set_bool_target(pk_targets[i], pk_bits[i]);
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

    use crate::curve::eddsa::{SAMPLE_MSG1, SAMPLE_PK1, SAMPLE_SIG1};
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
            SAMPLE_SIG1.as_slice(),
            SAMPLE_PK1.as_slice(),
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

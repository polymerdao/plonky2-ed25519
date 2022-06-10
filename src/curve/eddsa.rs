use serde::{Deserialize, Serialize};

use crate::curve::ed25519::mul_naive;
use crate::curve::curve_types::{AffinePoint, Curve};
use crate::field::ed25519_scalar::Ed25519Scalar;
use crate::curve::ed25519::Ed25519;
use crate::field::ed25519_base::Ed25519Base;

pub const SAMPLE_PK1: AffinePoint<Ed25519> = AffinePoint {
    x: Ed25519Base(
        [15550518515784108376, 11671404521375861941, 14264319369277047820, 1535614051696727984]
    ),
    y: Ed25519Base(
        [3288954626923522619, 8290404718738973538, 11980668049915458149, 3015821356719194170]
    ),
    zero: false,
};

// "test message"
pub const SAMPLE_H1: Ed25519Scalar = Ed25519Scalar([
    0xf664bfe815b3f691,
    0x677f3f53d9def3ed,
    0xc75422b41eb07187,
    0x0ab087fb4e3439bd
]);

// "test message"
pub const SAMPLE_SIG1: EDDSASignature<Ed25519> = EDDSASignature {
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

#[derive(Copy, Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct EDDSASignature<C: Curve> {
    pub r: AffinePoint<C>,
    pub s: C::ScalarField,
}

pub fn verify_message(
    h: Ed25519Scalar,
    sig: EDDSASignature<Ed25519>,
    pk: AffinePoint<Ed25519>,
) -> bool {
    let EDDSASignature { r, s } = sig;

    assert!(pk.is_valid());

    let g = Ed25519::GENERATOR_PROJECTIVE;
    let sb = mul_naive(s, g);
    let ha = mul_naive(h, pk.to_projective());
    let rhs = r + ha.to_affine();

    sb.to_affine() == rhs
}

#[cfg(test)]
mod tests {
    use crate::curve::eddsa::{SAMPLE_H1, SAMPLE_PK1, SAMPLE_SIG1, verify_message};

    #[test]
    fn test_ecdsa_native() {
        let result = verify_message(SAMPLE_H1, SAMPLE_SIG1, SAMPLE_PK1);
        assert!(result);
    }
}

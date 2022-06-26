use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

use crate::curve::curve_types::{AffinePoint, Curve};
use crate::curve::ed25519::mul_naive;
use crate::curve::ed25519::Ed25519;
use crate::field::ed25519_base::Ed25519Base;
use crate::field::ed25519_scalar::Ed25519Scalar;

pub const SAMPLE_MSG1: &str = "test message";
pub const SAMPLE_MSG2: &str = "plonky2";
pub const SAMPLE_PKV1: [u8; 1] = [0];
pub const SAMPLE_PKV2: [u8; 32] = [
    59, 106, 39, 188, 206, 182, 164, 45, 98, 163, 168, 208, 42, 111, 13, 115, 101, 50, 21, 119, 29,
    226, 67, 166, 58, 192, 72, 161, 139, 89, 218, 41,
];
pub const SAMPLE_SIGV1: [u8; 1] = [0];
pub const SAMPLE_SIGV2: [u8; 64] = [
    130, 82, 60, 170, 184, 218, 199, 182, 66, 19, 182, 14, 141, 214, 229, 180, 43, 19, 227, 183,
    130, 204, 69, 112, 171, 113, 6, 111, 218, 227, 249, 85, 57, 216, 145, 63, 71, 192, 201, 10, 54,
    234, 203, 8, 63, 240, 226, 101, 84, 167, 36, 246, 153, 35, 31, 52, 244, 82, 239, 137, 18, 62,
    134, 7,
];

pub const SAMPLE_PK1: AffinePoint<Ed25519> = AffinePoint {
    x: Ed25519Base([
        15550518515784108376,
        11671404521375861941,
        14264319369277047820,
        1535614051696727984,
    ]),
    y: Ed25519Base([
        3288954626923522619,
        8290404718738973538,
        11980668049915458149,
        3015821356719194170,
    ]),
    zero: false,
};

// "test message"
pub const SAMPLE_H1: Ed25519Scalar = Ed25519Scalar([
    0xf664bfe815b3f691,
    0x677f3f53d9def3ed,
    0xc75422b41eb07187,
    0x0ab087fb4e3439bd,
]);

// "plonky2"
pub const SAMPLE_H2: Ed25519Scalar = Ed25519Scalar([
    0x143b2cc9c13f8696,
    0x2a8ccb64b8a95963,
    0x94c5b08bb85433d1,
    0x02c2c41397871be1,
]);

// "test message"
pub const SAMPLE_SIG1: EDDSASignature<Ed25519> = EDDSASignature {
    r: AffinePoint {
        x: Ed25519Base([
            69846909542369210,
            15893343536663755999,
            963958585613385863,
            7582547496062573440,
        ]),
        y: Ed25519Base([
            9286836604675867752,
            4812450209474102063,
            868878820904116002,
            4970420200988206879,
        ]),
        zero: false,
    },
    s: Ed25519Scalar([
        0x8cf70db88f21cbfa,
        0x6653c3fd197a19b9,
        0xb84df96c151efff0,
        0x08440c31c6094824,
    ]),
};

// "plonky2"
pub const SAMPLE_SIG2: EDDSASignature<Ed25519> = EDDSASignature {
    r: AffinePoint {
        x: Ed25519Base([
            18097384930714120284,
            642567881465359456,
            16199477785500488968,
            7453747616827279566,
        ]),
        y: Ed25519Base([
            13170736121933222530,
            13035060597819315010,
            8090097167443890987,
            6195233289729896875,
        ]),
        zero: false,
    },
    s: Ed25519Scalar([
        0x0ac9c0473f91d839,
        0x65e2f03f08cbea36,
        0x341f2399f624a754,
        0x07863e1289ef52f4,
    ]),
};

#[derive(Copy, Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct EDDSASignature<C: Curve> {
    pub r: AffinePoint<C>,
    pub s: C::ScalarField,
}

pub fn verify_message(
    msg: &[u8],
    sigv: &[u8],
    pkv: &[u8],
    h: Ed25519Scalar,
    sig: EDDSASignature<Ed25519>,
    pk: AffinePoint<Ed25519>,
) -> bool {
    let mut data = Vec::new();
    data.extend_from_slice(&sigv[..32]);
    data.extend_from_slice(pkv);
    data.extend_from_slice(msg);
    let data_u8 = data.as_slice();

    let mut hasher = Sha512::new();
    hasher.update(data_u8);
    let _ = hasher.finalize();

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
    use crate::curve::eddsa::{
        verify_message, SAMPLE_H1, SAMPLE_H2, SAMPLE_MSG1, SAMPLE_MSG2, SAMPLE_PK1, SAMPLE_PKV1,
        SAMPLE_PKV2, SAMPLE_SIG1, SAMPLE_SIG2, SAMPLE_SIGV1, SAMPLE_SIGV2,
    };

    #[test]
    fn test_ecdsa_native() {
        // let result = verify_message(
        //     SAMPLE_MSG1.as_bytes(),
        //     SAMPLE_SIGV1.as_slice(),
        //     SAMPLE_PKV1.as_slice(),
        //     SAMPLE_H1,
        //     SAMPLE_SIG1,
        //     SAMPLE_PK1,
        // );
        // assert!(result);
        let result = verify_message(
            SAMPLE_MSG2.as_bytes(),
            SAMPLE_SIGV2.as_slice(),
            SAMPLE_PKV2.as_slice(),
            SAMPLE_H1,
            SAMPLE_SIG1,
            SAMPLE_PK1,
        );
        assert!(result);
    }
}

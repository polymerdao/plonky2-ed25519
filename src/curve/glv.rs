use num::rational::Ratio;
use num::BigUint;
use plonky2_field::types::{Field, PrimeField};

use crate::curve::curve_msm::msm_parallel;
use crate::curve::curve_types::{AffinePoint, ProjectivePoint};
use crate::curve::ed25519::Ed25519;
use crate::field::ed25519_base::Ed25519Base;
use crate::field::ed25519_scalar::Ed25519Scalar;

pub const GLV_BETA: Ed25519Base = Ed25519Base([
    13923278643952681454,
    11308619431505398165,
    7954561588662645993,
    8856726876819556112,
]);

pub const GLV_S: Ed25519Scalar = Ed25519Scalar([
    16069571880186789234,
    1310022930574435960,
    11900229862571533402,
    6008836872998760672,
]);

const A1: Ed25519Scalar = Ed25519Scalar([16747920425669159701, 3496713202691238861, 0, 0]);

const MINUS_B1: Ed25519Scalar = Ed25519Scalar([8022177200260244675, 16448129721693014056, 0, 0]);

const A2: Ed25519Scalar = Ed25519Scalar([6323353552219852760, 1498098850674701302, 1, 0]);

const B2: Ed25519Scalar = Ed25519Scalar([16747920425669159701, 3496713202691238861, 0, 0]);

/// Algorithm 15.41 in Handbook of Elliptic and Hyperelliptic Curve Cryptography.
/// Decompose a scalar `k` into two small scalars `k1, k2` with `|k1|, |k2| < √p` that satisfy
/// `k1 + s * k2 = k`.
/// Returns `(|k1|, |k2|, k1 < 0, k2 < 0)`.
pub fn decompose_ed25519_scalar(k: Ed25519Scalar) -> (Ed25519Scalar, Ed25519Scalar, bool, bool) {
    let p = Ed25519Scalar::order();
    let c1_biguint = Ratio::new(
        B2.to_canonical_biguint() * k.to_canonical_biguint(),
        p.clone(),
    )
    .round()
    .to_integer();
    let c1 = Ed25519Scalar::from_biguint(c1_biguint);
    let c2_biguint = Ratio::new(
        MINUS_B1.to_canonical_biguint() * k.to_canonical_biguint(),
        p.clone(),
    )
    .round()
    .to_integer();
    let c2 = Ed25519Scalar::from_biguint(c2_biguint);

    let k1_raw = k - c1 * A1 - c2 * A2;
    let k2_raw = c1 * MINUS_B1 - c2 * B2;
    debug_assert!(k1_raw + GLV_S * k2_raw == k);

    let two = BigUint::from_slice(&[2]);
    let k1_neg = k1_raw.to_canonical_biguint() > p.clone() / two.clone();
    let k1 = if k1_neg {
        Ed25519Scalar::from_biguint(p.clone() - k1_raw.to_canonical_biguint())
    } else {
        k1_raw
    };
    let k2_neg = k2_raw.to_canonical_biguint() > p.clone() / two;
    let k2 = if k2_neg {
        Ed25519Scalar::from_biguint(p - k2_raw.to_canonical_biguint())
    } else {
        k2_raw
    };

    (k1, k2, k1_neg, k2_neg)
}

/// See Section 15.2.1 in Handbook of Elliptic and Hyperelliptic Curve Cryptography.
/// GLV scalar multiplication `k * P = k1 * P + k2 * psi(P)`, where `k = k1 + s * k2` is the
/// decomposition computed in `decompose_Ed25519_scalar(k)` and `psi` is the Ed25519
/// endomorphism `psi: (x, y) |-> (beta * x, y)` equivalent to scalar multiplication by `s`.
pub fn glv_mul(p: ProjectivePoint<Ed25519>, k: Ed25519Scalar) -> ProjectivePoint<Ed25519> {
    let (k1, k2, k1_neg, k2_neg) = decompose_ed25519_scalar(k);

    let p_affine = p.to_affine();
    let sp = AffinePoint::<Ed25519> {
        x: p_affine.x * GLV_BETA,
        y: p_affine.y,
        zero: p_affine.zero,
    };

    let first = if k1_neg { p.neg() } else { p };
    let second = if k2_neg {
        sp.to_projective().neg()
    } else {
        sp.to_projective()
    };

    msm_parallel(&[k1, k2], &[first, second], 5)
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2_field::types::Field;

    use crate::curve::curve_types::{Curve, CurveScalar};
    use crate::curve::ed25519::Ed25519;
    use crate::curve::glv::{decompose_ed25519_scalar, glv_mul, GLV_S};
    use crate::field::ed25519_scalar::Ed25519Scalar;

    #[test]
    fn test_glv_decompose() -> Result<()> {
        let k = Ed25519Scalar::rand();
        let (k1, k2, k1_neg, k2_neg) = decompose_ed25519_scalar(k);
        let one = Ed25519Scalar::ONE;
        let m1 = if k1_neg { -one } else { one };
        let m2 = if k2_neg { -one } else { one };

        assert!(k1 * m1 + GLV_S * k2 * m2 == k);

        Ok(())
    }

    #[test]
    fn test_glv_mul() -> Result<()> {
        for _ in 0..20 {
            let k = Ed25519Scalar::rand();

            let p = CurveScalar(Ed25519Scalar::rand()) * Ed25519::GENERATOR_PROJECTIVE;

            let kp = CurveScalar(k) * p;
            let glv = glv_mul(p, k);

            assert!(kp == glv);
        }

        Ok(())
    }
}

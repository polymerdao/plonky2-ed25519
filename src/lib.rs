#![allow(clippy::needless_range_loop)]
// Below lint is currently broken and produces false positives.
// TODO: Remove this override when Clippy is patched.
#![allow(clippy::derive_partial_eq_without_eq)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

pub mod curve;
pub mod field;
pub mod gadgets;

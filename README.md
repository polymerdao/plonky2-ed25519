# plonky2-ed25519

```console
RUSTFLAGS=-Ctarget-cpu=native cargo run --package plonky2_ed25519 --bin plonky2_ed25519 --release
```

```console
Constructing inner proof with 410842 gates
[INFO  plonky2::plonk::circuit_builder] Degree before blinding & padding: 410962
[INFO  plonky2::plonk::circuit_builder] Degree after blinding & padding: 524288
[INFO  plonky2::util::timing] 129.2053s to prove
[INFO  plonky2::util::timing] 0.0107s to verify
[INFO  plonky2_ed25519] Proof length: 211272 bytes
[INFO  plonky2_ed25519] 0.0101s to compress proof
[INFO  plonky2_ed25519] Compressed proof length: 195107 bytes
Constructing inner proof with 410842 gates
[INFO  plonky2::plonk::circuit_builder] Degree before blinding & padding: 410962
[INFO  plonky2::plonk::circuit_builder] Degree after blinding & padding: 524288
[INFO  plonky2::util::timing] 123.0392s to prove
[INFO  plonky2::util::timing] 0.0084s to verify
[INFO  plonky2_ed25519] Proof length: 211272 bytes
[INFO  plonky2_ed25519] 0.0106s to compress proof
[INFO  plonky2_ed25519] Compressed proof length: 194049 bytes
[INFO  plonky2::plonk::circuit_builder] Degree before blinding & padding: 12516
[INFO  plonky2::plonk::circuit_builder] Degree after blinding & padding: 16384
[INFO  plonky2::util::timing] 1.0685s to prove
[INFO  plonky2_ed25519] Proof length: 146348 bytes
[INFO  plonky2_ed25519] 0.0056s to compress proof
[INFO  plonky2_ed25519] Compressed proof length: 132065 bytes
[INFO  plonky2_ed25519] Single recursion proof degree 16384 = 2^14
[INFO  plonky2::plonk::circuit_builder] Degree before blinding & padding: 4364
[INFO  plonky2::plonk::circuit_builder] Degree after blinding & padding: 8192
[INFO  plonky2::util::timing] 0.5018s to prove
[INFO  plonky2_ed25519] Proof length: 132816 bytes
[INFO  plonky2_ed25519] 0.0049s to compress proof
[INFO  plonky2_ed25519] Compressed proof length: 124559 bytes
[INFO  plonky2_ed25519] Double recursion proof degree 8192 = 2^13
```
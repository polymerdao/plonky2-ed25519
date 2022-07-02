# plonky2-ed25519

This repository contains [SNARK](https://en.wikipedia.org/wiki/Non-interactive_zero-knowledge_proof) verification
circuits of a
digital signature scheme [Ed25519](https://en.wikipedia.org/wiki/EdDSA#Ed25519) implemented
with [Plonky2](https://github.com/mir-protocol/plonky2).

Run benchmarks

```console
RUSTFLAGS=-Ctarget-cpu=native cargo run --package plonky2_ed25519 --bin plonky2_ed25519 --release
```

Benchmark on a Macbook Pro (M1)

```console
Constructing inner proof with 410842 gates
[INFO  plonky2::plonk::circuit_builder] Degree before blinding & padding: 410962
[INFO  plonky2::plonk::circuit_builder] Degree after blinding & padding: 524288
[INFO  plonky2::util::timing] 111.8648s to prove
[INFO  plonky2::util::timing] 0.0089s to verify
[INFO  plonky2_ed25519] Proof length: 211272 bytes
[INFO  plonky2_ed25519] 0.0106s to compress proof
[INFO  plonky2_ed25519] Compressed proof length: 198181 bytes
Constructing inner proof with 410842 gates
[INFO  plonky2::plonk::circuit_builder] Degree before blinding & padding: 410962
[INFO  plonky2::plonk::circuit_builder] Degree after blinding & padding: 524288
[INFO  plonky2::util::timing] 118.1002s to prove
[INFO  plonky2::util::timing] 0.0088s to verify
[INFO  plonky2_ed25519] Proof length: 211272 bytes
[INFO  plonky2_ed25519] 0.0179s to compress proof
[INFO  plonky2_ed25519] Compressed proof length: 196737 bytes
[INFO  plonky2::plonk::circuit_builder] Degree before blinding & padding: 12516
[INFO  plonky2::plonk::circuit_builder] Degree after blinding & padding: 16384
[INFO  plonky2::util::timing] 1.0434s to prove
[INFO  plonky2_ed25519] Proof length: 146348 bytes
[INFO  plonky2_ed25519] 0.0056s to compress proof
[INFO  plonky2_ed25519] Compressed proof length: 130256 bytes
[INFO  plonky2_ed25519] Single recursion proof degree 16384 = 2^14
[INFO  plonky2::plonk::circuit_builder] Degree before blinding & padding: 4364
[INFO  plonky2::plonk::circuit_builder] Degree after blinding & padding: 8192
[INFO  plonky2::util::timing] 0.5046s to prove
[INFO  plonky2_ed25519] Proof length: 132816 bytes
[INFO  plonky2_ed25519] 0.0049s to compress proof
[INFO  plonky2_ed25519] Compressed proof length: 123599 bytes
[INFO  plonky2_ed25519] Double recursion proof degree 8192 = 2^13
```
# plonky2-ed25519

```console
RUSTFLAGS=-Ctarget-cpu=native cargo run --package plonky2_ed25519 --bin plonky2_ed25519 --release
```

```console
Constructing inner proof with 410816 gates
[INFO  plonky2::plonk::circuit_builder] Degree before blinding & padding: 410936
[INFO  plonky2::plonk::circuit_builder] Degree after blinding & padding: 524288
[DEBUG plonky2::plonk::circuit_builder] Building circuit took 35.513016s
[DEBUG plonky2::util::timing] 115.7442s to prove
[DEBUG plonky2::util::timing] 0.0105s to verify
[INFO  plonky2_ed25519] Proof length: 211272 bytes
[INFO  plonky2_ed25519] 0.0315s to compress proof
[INFO  plonky2_ed25519] Compressed proof length: 195137 bytes
Constructing inner proof with 410816 gates
[INFO  plonky2::plonk::circuit_builder] Degree before blinding & padding: 410936
[INFO  plonky2::plonk::circuit_builder] Degree after blinding & padding: 524288
[DEBUG plonky2::plonk::circuit_builder] Building circuit took 34.22889s
[DEBUG plonky2::util::timing] 128.6065s to prove
[DEBUG plonky2::util::timing] 0.0086s to verify
[INFO  plonky2_ed25519] Proof length: 211272 bytes
[INFO  plonky2_ed25519] 0.0360s to compress proof
[INFO  plonky2_ed25519] Compressed proof length: 198836 bytes
[DEBUG plonky2::util::context_tree] 12515 gates to root
[DEBUG plonky2::util::context_tree] | 619 gates to evaluate the vanishing polynomial at our challenge point, zeta.
[DEBUG plonky2::util::context_tree] | | 522 gates to evaluate gate constraints
[DEBUG plonky2::util::context_tree] | | | 1 gates to evaluate NoopGate constraints
[DEBUG plonky2::util::context_tree] | | | 1 gates to evaluate ConstantGate { num_consts: 2 } constraints
[DEBUG plonky2::util::context_tree] | | | 1 gates to evaluate PublicInputGate constraints
[DEBUG plonky2::util::context_tree] | | | 8 gates to evaluate BaseSumGate { num_limbs: 32 } + Base: 2 constraints
[DEBUG plonky2::util::context_tree] | | | 11 gates to evaluate BaseSumGate { num_limbs: 64 } + Base: 2 constraints
[DEBUG plonky2::util::context_tree] | | | 9 gates to evaluate ArithmeticGate { num_ops: 20 } constraints
[DEBUG plonky2::util::context_tree] | | | 42 gates to evaluate ComparisonGate { num_bits: 32, num_chunks: 16, _phantom: PhantomData }<D=2> constraints
[DEBUG plonky2::util::context_tree] | | | 75 gates to evaluate U32AddManyGate { num_addends: 11, num_ops: 5, _phantom: PhantomData } constraints
[DEBUG plonky2::util::context_tree] | | | 31 gates to evaluate U32AddManyGate { num_addends: 13, num_ops: 5, _phantom: PhantomData } constraints
[DEBUG plonky2::util::context_tree] | | | 23 gates to evaluate U32AddManyGate { num_addends: 15, num_ops: 4, _phantom: PhantomData } constraints
[DEBUG plonky2::util::context_tree] | | | 23 gates to evaluate U32AddManyGate { num_addends: 16, num_ops: 4, _phantom: PhantomData } constraints
[DEBUG plonky2::util::context_tree] | | | 64 gates to evaluate U32AddManyGate { num_addends: 3, num_ops: 9, _phantom: PhantomData } constraints
[DEBUG plonky2::util::context_tree] | | | 37 gates to evaluate U32AddManyGate { num_addends: 5, num_ops: 9, _phantom: PhantomData } constraints
[DEBUG plonky2::util::context_tree] | | | 32 gates to evaluate U32AddManyGate { num_addends: 7, num_ops: 8, _phantom: PhantomData } constraints
[DEBUG plonky2::util::context_tree] | | | 19 gates to evaluate U32AddManyGate { num_addends: 9, num_ops: 6, _phantom: PhantomData } constraints
[DEBUG plonky2::util::context_tree] | | | 45 gates to evaluate U32ArithmeticGate { num_ops: 6, _phantom: PhantomData } constraints
[DEBUG plonky2::util::context_tree] | | | 56 gates to evaluate U32RangeCheckGate { num_input_limbs: 8, _phantom: PhantomData } constraints
[DEBUG plonky2::util::context_tree] | | | 44 gates to evaluate U32SubtractionGate { num_ops: 11, _phantom: PhantomData } constraints
[DEBUG plonky2::util::context_tree] | 2 gates to check vanishing and quotient polynomials.
[DEBUG plonky2::util::context_tree] | 5483 gates to verify FRI proof
[DEBUG plonky2::util::context_tree] | | 1 gates to check PoW
[DEBUG plonky2::util::context_tree] | | 12 gates to precompute reduced evaluations
[DEBUG plonky2::util::context_tree] | | 194 gates to verify one (of 28) query rounds
[DEBUG plonky2::util::context_tree] | | | 122 gates to check FRI initial proof
[DEBUG plonky2::util::context_tree] | | | | 30 gates to verify 0'th initial Merkle proof
[DEBUG plonky2::util::context_tree] | | | | 49 gates to verify 1'th initial Merkle proof
[DEBUG plonky2::util::context_tree] | | | | 22 gates to verify 2'th initial Merkle proof
[DEBUG plonky2::util::context_tree] | | | | 21 gates to verify 3'th initial Merkle proof
[DEBUG plonky2::util::context_tree] | | | 1 gates to compute x from its index
[DEBUG plonky2::util::context_tree] | | | 9 gates to combine initial oracles
[DEBUG plonky2::util::context_tree] | | | 1 gates to infer evaluation using interpolation
[DEBUG plonky2::util::context_tree] | | | 19 gates to verify FRI round Merkle proof.
[DEBUG plonky2::util::context_tree] | | | 1 gates to infer evaluation using interpolation
[DEBUG plonky2::util::context_tree] | | | 15 gates to verify FRI round Merkle proof.
[DEBUG plonky2::util::context_tree] | | | 1 gates to infer evaluation using interpolation
[DEBUG plonky2::util::context_tree] | | | 11 gates to verify FRI round Merkle proof.
[DEBUG plonky2::util::context_tree] | | | 1 gates to infer evaluation using interpolation
[DEBUG plonky2::util::context_tree] | | | 7 gates to verify FRI round Merkle proof.
[DEBUG plonky2::util::context_tree] | | | 1 gates to evaluate final polynomial of length 8
[DEBUG plonky2::util::context_tree] | 617 gates to evaluate the vanishing polynomial at our challenge point, zeta.
[DEBUG plonky2::util::context_tree] | | 521 gates to evaluate gate constraints
[DEBUG plonky2::util::context_tree] | | | 0 gates to evaluate NoopGate constraints
[DEBUG plonky2::util::context_tree] | | | 2 gates to evaluate ConstantGate { num_consts: 2 } constraints
[DEBUG plonky2::util::context_tree] | | | 0 gates to evaluate PublicInputGate constraints
[DEBUG plonky2::util::context_tree] | | | 8 gates to evaluate BaseSumGate { num_limbs: 32 } + Base: 2 constraints
[DEBUG plonky2::util::context_tree] | | | 10 gates to evaluate BaseSumGate { num_limbs: 64 } + Base: 2 constraints
[DEBUG plonky2::util::context_tree] | | | 10 gates to evaluate ArithmeticGate { num_ops: 20 } constraints
[DEBUG plonky2::util::context_tree] | | | 41 gates to evaluate ComparisonGate { num_bits: 32, num_chunks: 16, _phantom: PhantomData }<D=2> constraints
[DEBUG plonky2::util::context_tree] | | | 74 gates to evaluate U32AddManyGate { num_addends: 11, num_ops: 5, _phantom: PhantomData } constraints
[DEBUG plonky2::util::context_tree] | | | 34 gates to evaluate U32AddManyGate { num_addends: 13, num_ops: 5, _phantom: PhantomData } constraints
[DEBUG plonky2::util::context_tree] | | | 21 gates to evaluate U32AddManyGate { num_addends: 15, num_ops: 4, _phantom: PhantomData } constraints
[DEBUG plonky2::util::context_tree] | | | 23 gates to evaluate U32AddManyGate { num_addends: 16, num_ops: 4, _phantom: PhantomData } constraints
[DEBUG plonky2::util::context_tree] | | | 66 gates to evaluate U32AddManyGate { num_addends: 3, num_ops: 9, _phantom: PhantomData } constraints
[DEBUG plonky2::util::context_tree] | | | 37 gates to evaluate U32AddManyGate { num_addends: 5, num_ops: 9, _phantom: PhantomData } constraints
[DEBUG plonky2::util::context_tree] | | | 29 gates to evaluate U32AddManyGate { num_addends: 7, num_ops: 8, _phantom: PhantomData } constraints
[DEBUG plonky2::util::context_tree] | | | 21 gates to evaluate U32AddManyGate { num_addends: 9, num_ops: 6, _phantom: PhantomData } constraints
[DEBUG plonky2::util::context_tree] | | | 44 gates to evaluate U32ArithmeticGate { num_ops: 6, _phantom: PhantomData } constraints
[DEBUG plonky2::util::context_tree] | | | 56 gates to evaluate U32RangeCheckGate { num_input_limbs: 8, _phantom: PhantomData } constraints
[DEBUG plonky2::util::context_tree] | | | 45 gates to evaluate U32SubtractionGate { num_ops: 11, _phantom: PhantomData } constraints
[DEBUG plonky2::util::context_tree] | 1 gates to check vanishing and quotient polynomials.
[DEBUG plonky2::util::context_tree] | 5483 gates to verify FRI proof
[DEBUG plonky2::util::context_tree] | | 1 gates to check PoW
[DEBUG plonky2::util::context_tree] | | 12 gates to precompute reduced evaluations
[DEBUG plonky2::util::context_tree] | | 196 gates to verify one (of 28) query rounds
[DEBUG plonky2::util::context_tree] | | | 122 gates to check FRI initial proof
[DEBUG plonky2::util::context_tree] | | | | 30 gates to verify 0'th initial Merkle proof
[DEBUG plonky2::util::context_tree] | | | | 49 gates to verify 1'th initial Merkle proof
[DEBUG plonky2::util::context_tree] | | | | 22 gates to verify 2'th initial Merkle proof
[DEBUG plonky2::util::context_tree] | | | | 21 gates to verify 3'th initial Merkle proof
[DEBUG plonky2::util::context_tree] | | | 1 gates to compute x from its index
[DEBUG plonky2::util::context_tree] | | | 12 gates to combine initial oracles
[DEBUG plonky2::util::context_tree] | | | 1 gates to infer evaluation using interpolation
[DEBUG plonky2::util::context_tree] | | | 19 gates to verify FRI round Merkle proof.
[DEBUG plonky2::util::context_tree] | | | 1 gates to infer evaluation using interpolation
[DEBUG plonky2::util::context_tree] | | | 15 gates to verify FRI round Merkle proof.
[DEBUG plonky2::util::context_tree] | | | 2 gates to infer evaluation using interpolation
[DEBUG plonky2::util::context_tree] | | | 11 gates to verify FRI round Merkle proof.
[DEBUG plonky2::util::context_tree] | | | 1 gates to infer evaluation using interpolation
[DEBUG plonky2::util::context_tree] | | | 7 gates to verify FRI round Merkle proof.
[DEBUG plonky2::util::context_tree] | | | 0 gates to evaluate final polynomial of length 8
[DEBUG plonky2::plonk::circuit_builder] Total gate counts:
[DEBUG plonky2::plonk::circuit_builder] - 56 instances of ExponentiationGate { num_power_bits: 66, _phantom: PhantomData }<D=2>
[DEBUG plonky2::plonk::circuit_builder] - 224 instances of LowDegreeInterpolationGate { subgroup_bits: 4, _phantom: PhantomData }<D=2>
[DEBUG plonky2::plonk::circuit_builder] - 560 instances of RandomAccessGate { bits: 4, num_copies: 4, num_extra_constants: 2, _phantom: PhantomData }<D=2>
[DEBUG plonky2::plonk::circuit_builder] - 149 instances of ArithmeticGate { num_ops: 20 }
[DEBUG plonky2::plonk::circuit_builder] - 504 instances of ReducingGate { num_coeffs: 43 }
[DEBUG plonky2::plonk::circuit_builder] - 9602 instances of PoseidonGate { _phantom: PhantomData }<WIDTH=12>
[DEBUG plonky2::plonk::circuit_builder] - 250 instances of MulExtensionGate { num_ops: 13 }
[DEBUG plonky2::plonk::circuit_builder] - 82 instances of ReducingExtensionGate { num_coeffs: 32 }
[DEBUG plonky2::plonk::circuit_builder] - 1030 instances of ArithmeticExtensionGate { num_ops: 10 }
[DEBUG plonky2::plonk::circuit_builder] - 58 instances of BaseSumGate { num_limbs: 64 } + Base: 2
[INFO  plonky2::plonk::circuit_builder] Degree before blinding & padding: 12516
[INFO  plonky2::plonk::circuit_builder] Degree after blinding & padding: 16384
[DEBUG plonky2::plonk::circuit_builder] Building circuit took 0.8370834s
[DEBUG plonky2::util::timing] 1.0256s to prove
[DEBUG plonky2::util::timing] | 0.0847s to run 29474 generators
[DEBUG plonky2::util::timing] | 0.0135s to compute full witness
[DEBUG plonky2::util::timing] | 0.0004s to compute wire polynomials
[DEBUG plonky2::util::timing] | 0.4705s to compute wires commitment
[DEBUG plonky2::util::timing] | | 0.0052s to IFFT
[DEBUG plonky2::util::timing] | | 0.0425s to FFT + blinding
[DEBUG plonky2::util::timing] | | 0.0440s to transpose LDEs
[DEBUG plonky2::util::timing] | | 0.3764s to build Merkle tree
[DEBUG plonky2::util::timing] | 0.0120s to compute partial products
[DEBUG plonky2::util::timing] | 0.1028s to commit to partial products and Z's
[DEBUG plonky2::util::timing] | | 0.0011s to IFFT
[DEBUG plonky2::util::timing] | | 0.0087s to FFT + blinding
[DEBUG plonky2::util::timing] | | 0.0066s to transpose LDEs
[DEBUG plonky2::util::timing] | | 0.0857s to build Merkle tree
[DEBUG plonky2::util::timing] | 0.1797s to compute quotient polys
[DEBUG plonky2::util::timing] | 0.0001s to split up quotient polys
[DEBUG plonky2::util::timing] | 0.0763s to commit to quotient polys
[DEBUG plonky2::util::timing] | | 0.0058s to FFT + blinding
[DEBUG plonky2::util::timing] | | 0.0056s to transpose LDEs
[DEBUG plonky2::util::timing] | | 0.0643s to build Merkle tree
[DEBUG plonky2::util::timing] | 0.0065s to construct the opening set
[DEBUG plonky2::util::timing] | 0.0346s to compute opening proofs
[DEBUG plonky2::util::timing] | | 0.0135s to reduce batch of 256 polynomials
[DEBUG plonky2::util::timing] | | 0.0001s to reduce batch of 2 polynomials
[DEBUG plonky2::util::timing] | | 0.0096s to perform final FFT 131072
[DEBUG plonky2::util::timing] | | 0.0100s to fold codewords in the commitment phase
[DEBUG plonky2::util::timing] | | 0.0003s to find proof-of-work witness
[INFO  plonky2_ed25519] Proof length: 146348 bytes
[INFO  plonky2_ed25519] 0.0055s to compress proof
[INFO  plonky2_ed25519] Compressed proof length: 132336 bytes
[INFO  plonky2_ed25519] Single recursion proof degree 16384 = 2^14
[DEBUG plonky2::util::context_tree] 4363 gates to root
[DEBUG plonky2::util::context_tree] | 448 gates to evaluate the vanishing polynomial at our challenge point, zeta.
[DEBUG plonky2::util::context_tree] | | 356 gates to evaluate gate constraints
[DEBUG plonky2::util::context_tree] | | | 1 gates to evaluate NoopGate constraints
[DEBUG plonky2::util::context_tree] | | | 1 gates to evaluate PublicInputGate constraints
[DEBUG plonky2::util::context_tree] | | | 15 gates to evaluate BaseSumGate { num_limbs: 64 } + Base: 2 constraints
[DEBUG plonky2::util::context_tree] | | | 75 gates to evaluate LowDegreeInterpolationGate { subgroup_bits: 4, _phantom: PhantomData }<D=2> constraints
[DEBUG plonky2::util::context_tree] | | | 28 gates to evaluate ReducingExtensionGate { num_coeffs: 32 } constraints
[DEBUG plonky2::util::context_tree] | | | 32 gates to evaluate ReducingGate { num_coeffs: 43 } constraints
[DEBUG plonky2::util::context_tree] | | | 12 gates to evaluate ArithmeticExtensionGate { num_ops: 10 } constraints
[DEBUG plonky2::util::context_tree] | | | 10 gates to evaluate ArithmeticGate { num_ops: 20 } constraints
[DEBUG plonky2::util::context_tree] | | | 11 gates to evaluate MulExtensionGate { num_ops: 13 } constraints
[DEBUG plonky2::util::context_tree] | | | 30 gates to evaluate ExponentiationGate { num_power_bits: 66, _phantom: PhantomData }<D=2> constraints
[DEBUG plonky2::util::context_tree] | | | 19 gates to evaluate RandomAccessGate { bits: 4, num_copies: 4, num_extra_constants: 2, _phantom: PhantomData }<D=2> constraints
[DEBUG plonky2::util::context_tree] | | | 122 gates to evaluate PoseidonGate { _phantom: PhantomData }<WIDTH=12> constraints
[DEBUG plonky2::util::context_tree] | 1 gates to check vanishing and quotient polynomials.
[DEBUG plonky2::util::context_tree] | 3793 gates to verify FRI proof
[DEBUG plonky2::util::context_tree] | | 1 gates to check PoW
[DEBUG plonky2::util::context_tree] | | 9 gates to precompute reduced evaluations
[DEBUG plonky2::util::context_tree] | | 134 gates to verify one (of 28) query rounds
[DEBUG plonky2::util::context_tree] | | | 89 gates to check FRI initial proof
[DEBUG plonky2::util::context_tree] | | | | 25 gates to verify 0'th initial Merkle proof
[DEBUG plonky2::util::context_tree] | | | | 31 gates to verify 1'th initial Merkle proof
[DEBUG plonky2::util::context_tree] | | | | 17 gates to verify 2'th initial Merkle proof
[DEBUG plonky2::util::context_tree] | | | | 16 gates to verify 3'th initial Merkle proof
[DEBUG plonky2::util::context_tree] | | | 0 gates to compute x from its index
[DEBUG plonky2::util::context_tree] | | | 7 gates to combine initial oracles
[DEBUG plonky2::util::context_tree] | | | 1 gates to infer evaluation using interpolation
[DEBUG plonky2::util::context_tree] | | | 14 gates to verify FRI round Merkle proof.
[DEBUG plonky2::util::context_tree] | | | 1 gates to infer evaluation using interpolation
[DEBUG plonky2::util::context_tree] | | | 10 gates to verify FRI round Merkle proof.
[DEBUG plonky2::util::context_tree] | | | 1 gates to infer evaluation using interpolation
[DEBUG plonky2::util::context_tree] | | | 6 gates to verify FRI round Merkle proof.
[DEBUG plonky2::util::context_tree] | | | 1 gates to evaluate final polynomial of length 4
[DEBUG plonky2::plonk::circuit_builder] Total gate counts:
[DEBUG plonky2::plonk::circuit_builder] - 3255 instances of PoseidonGate { _phantom: PhantomData }<WIDTH=12>
[DEBUG plonky2::plonk::circuit_builder] - 238 instances of RandomAccessGate { bits: 4, num_copies: 4, num_extra_constants: 2, _phantom: PhantomData }<D=2>
[DEBUG plonky2::plonk::circuit_builder] - 30 instances of PoseidonMdsGate { _phantom: PhantomData }<WIDTH=12>
[DEBUG plonky2::plonk::circuit_builder] - 168 instances of ReducingGate { num_coeffs: 43 }
[DEBUG plonky2::plonk::circuit_builder] - 338 instances of ArithmeticExtensionGate { num_ops: 10 }
[DEBUG plonky2::plonk::circuit_builder] - 20 instances of ReducingExtensionGate { num_coeffs: 32 }
[DEBUG plonky2::plonk::circuit_builder] - 84 instances of LowDegreeInterpolationGate { subgroup_bits: 4, _phantom: PhantomData }<D=2>
[DEBUG plonky2::plonk::circuit_builder] - 93 instances of ArithmeticGate { num_ops: 20 }
[DEBUG plonky2::plonk::circuit_builder] - 29 instances of BaseSumGate { num_limbs: 64 } + Base: 2
[DEBUG plonky2::plonk::circuit_builder] - 108 instances of MulExtensionGate { num_ops: 13 }
[INFO  plonky2::plonk::circuit_builder] Degree before blinding & padding: 4364
[INFO  plonky2::plonk::circuit_builder] Degree after blinding & padding: 8192
[DEBUG plonky2::plonk::circuit_builder] Building circuit took 0.3765768s
[DEBUG plonky2::util::timing] 0.5281s to prove
[DEBUG plonky2::util::timing] | 0.0301s to run 11429 generators
[DEBUG plonky2::util::timing] | 0.0055s to compute full witness
[DEBUG plonky2::util::timing] | 0.0003s to compute wire polynomials
[DEBUG plonky2::util::timing] | 0.2363s to compute wires commitment
[DEBUG plonky2::util::timing] | | 0.0025s to IFFT
[DEBUG plonky2::util::timing] | | 0.0193s to FFT + blinding
[DEBUG plonky2::util::timing] | | 0.0258s to transpose LDEs
[DEBUG plonky2::util::timing] | | 0.1873s to build Merkle tree
[DEBUG plonky2::util::timing] | 0.0063s to compute partial products
[DEBUG plonky2::util::timing] | 0.0520s to commit to partial products and Z's
[DEBUG plonky2::util::timing] | | 0.0013s to IFFT
[DEBUG plonky2::util::timing] | | 0.0037s to FFT + blinding
[DEBUG plonky2::util::timing] | | 0.0037s to transpose LDEs
[DEBUG plonky2::util::timing] | | 0.0430s to build Merkle tree
[DEBUG plonky2::util::timing] | 0.0926s to compute quotient polys
[DEBUG plonky2::util::timing] | 0.0001s to split up quotient polys
[DEBUG plonky2::util::timing] | 0.0385s to commit to quotient polys
[DEBUG plonky2::util::timing] | | 0.0035s to FFT + blinding
[DEBUG plonky2::util::timing] | | 0.0027s to transpose LDEs
[DEBUG plonky2::util::timing] | | 0.0320s to build Merkle tree
[DEBUG plonky2::util::timing] | 0.0051s to construct the opening set
[DEBUG plonky2::util::timing] | 0.0400s to compute opening proofs
[DEBUG plonky2::util::timing] | | 0.0068s to reduce batch of 256 polynomials
[DEBUG plonky2::util::timing] | | 0.0001s to reduce batch of 2 polynomials
[DEBUG plonky2::util::timing] | | 0.0046s to perform final FFT 65536
[DEBUG plonky2::util::timing] | | 0.0049s to fold codewords in the commitment phase
[DEBUG plonky2::util::timing] | | 0.0230s to find proof-of-work witness
[INFO  plonky2_ed25519] Proof length: 132816 bytes
[INFO  plonky2_ed25519] 0.0050s to compress proof
[INFO  plonky2_ed25519] Compressed proof length: 121342 bytes
[INFO  plonky2_ed25519] Double recursion proof degree 8192 = 2^13
```
# Stronghold Extensions

A library for extending stronghold with user defined cryptographic procedures.  
Also includes implementations for ES256, ES256K, and RS256 (RSASSA-PKCS1-v1_5 with SHA-256).

## Features

| Feature  | Default | Algorithm                      |
| -------- | ------- | ------------------------------ |
| `es256`  | yes     | ECDSA on NIST P-256            |
| `es256k` | yes     | ECDSA on secp256k1             |
| `rs256`  | **no**  | RSASSA-PKCS1-v1_5 with SHA-256 |

`rs256` is opt-in because it pulls in the [`rsa`](https://crates.io/crates/rsa) crate, which
carries [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071) (Marvin attack)
with no patched release available. Consumers that only need the elliptic-curve algorithms should
not inherit that advisory.

```toml
stronghold_ext = { version = "0.1", features = ["rs256"] }
```

## RS256 notes

- Keys are PKCS#1 DER encoded and must be at least 2048 bits, per RFC 7518 § 3.3.
- Signing blinds the private-key exponentiation to mitigate RUSTSEC-2023-0071. This does not
  change the signature bytes; RSASSA-PKCS1-v1_5 stays deterministic.
- Key generation is a probabilistic prime search and is markedly slower than the elliptic-curve
  algorithms. Procedures execute synchronously on the calling thread.
- The `Verify` procedure checks a signature against a key held _in the vault_. To verify a
  signature made by a third party, call `Rs256::verify_signature` with their public key.

## Tests

`cargo test` covers every algorithm: `rs256` is enabled for the test targets through a
dev-dependency on this crate, so no extra flags are needed.

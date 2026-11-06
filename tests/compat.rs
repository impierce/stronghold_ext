//! Behaviour snapshot of the EC algorithms and their Stronghold procedures.
//!
//! Every observable output for fixed inputs (public keys, deterministic RFC 6979 signatures,
//! verification results, accepted and rejected encodings) is compared against
//! `fixtures/compat_golden.txt`. The file was recorded with the `p256`/`k256` 0.13 backend and
//! must not change when the curve crates are upgraded. The test only uses this crate's public API,
//! so it compiles against any backend.
//!
//! To re-record (only when a behaviour change is intended):
//! `STRONGHOLD_EXT_WRITE_GOLDEN=1 cargo test --all-features --test compat`
#![cfg(all(feature = "es256", feature = "es256k"))]

use iota_stronghold::{procedures::ProcedureOutput, Client, Location, Stronghold};
use stronghold_ext::{
    execute_procedure_ext,
    procs::{es256, es256::Es256Procs, es256k, es256k::Es256kProcs},
    AlgoSignature, Algorithm, Es256, Es256k, SigningKey, VerifyingKey,
};
use zeroize::Zeroizing;

const GOLDEN_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/compat_golden.txt"
);

/// Order of the P-256 group.
const P256_N: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
/// Order of the secp256k1 group.
const K256_N: &str = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
/// Private key of RFC 6979, appendix A.2.5.
const RFC6979_KEY: &str = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";

fn messages() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("empty", Vec::new()),
        ("sample", b"sample".to_vec()),
        ("test", b"test".to_vec()),
        ("1024-bytes", (0..1024).map(|i| i as u8).collect()),
    ]
}

/// Big-endian `a - b` for 32-byte values with `a >= b`.
fn sub(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut d = a[i] as i16 - b[i] as i16 - borrow;
        borrow = if d < 0 {
            d += 256;
            1
        } else {
            0
        };
        out[i] = d as u8;
    }
    out
}

fn one() -> Vec<u8> {
    let mut v = vec![0u8; 32];
    v[31] = 1;
    v
}

fn ok(result: bool) -> &'static str {
    if result {
        "ok"
    } else {
        "err"
    }
}

/// Records every observable behaviour of algorithm `A` for fixed inputs.
fn record_algorithm<A>(alg: &A, n_hex: &str, out: &mut Vec<String>)
where
    A: Algorithm,
    A::SigningKey: SigningKey<A>,
    A::VerifyingKey: VerifyingKey<A>,
{
    let name = alg.name();
    out.push(format!("{name} curve={}", alg.curve()));
    out.push(format!(
        "{name} signature-length={:?}",
        A::Signature::LENGTH
    ));

    let n = hex::decode(n_hex).unwrap();
    let keys = [
        ("rfc6979", hex::decode(RFC6979_KEY).unwrap()),
        ("one", one()),
        ("n-1", sub(&n, &one())),
    ];

    for (key_name, raw) in &keys {
        let sk = A::SigningKey::from_slice(raw).unwrap();
        out.push(format!(
            "{name} key={key_name} secret={}",
            hex::encode(sk.as_bytes())
        ));

        let vk = sk.to_verifying_key();
        let compressed = vk.as_bytes().to_vec();
        out.push(format!(
            "{name} key={key_name} public={}",
            hex::encode(&compressed)
        ));

        // A verifying key parsed from its compressed or uncompressed SEC1 encoding is the same key.
        let reparsed = A::VerifyingKey::from_slice(&compressed).unwrap();
        out.push(format!(
            "{name} key={key_name} public-roundtrip={}",
            hex::encode(reparsed.as_bytes())
        ));

        for (msg_name, msg) in messages() {
            let sig = alg.sign(&sk, &msg);
            let sig_bytes = sig.as_bytes().to_vec();
            out.push(format!(
                "{name} key={key_name} msg={msg_name} signature={}",
                hex::encode(&sig_bytes)
            ));

            let parsed = A::Signature::try_from_slice(&sig_bytes).unwrap();
            out.push(format!(
                "{name} key={key_name} msg={msg_name} verify={}",
                alg.verify_signature(&parsed, &vk, &msg)
            ));

            let mut other = msg.clone();
            other.push(0);
            out.push(format!(
                "{name} key={key_name} msg={msg_name} verify-other-message={}",
                alg.verify_signature(&parsed, &vk, &other)
            ));

            // The other half of the signature space: (r, n - s) is a valid signature for any
            // ECDSA implementation that does not enforce low-S.
            let mut flipped = sig_bytes[..32].to_vec();
            flipped.extend(sub(&n, &sig_bytes[32..]));
            let flipped_result = match A::Signature::try_from_slice(&flipped) {
                Ok(flipped) => alg.verify_signature(&flipped, &vk, &msg).to_string(),
                Err(_) => "parse-error".to_string(),
            };
            out.push(format!(
                "{name} key={key_name} msg={msg_name} verify-flipped-s={flipped_result}"
            ));

            let mut corrupted = sig_bytes.clone();
            corrupted[10] ^= 1;
            let corrupted_result = match A::Signature::try_from_slice(&corrupted) {
                Ok(corrupted) => alg.verify_signature(&corrupted, &vk, &msg).to_string(),
                Err(_) => "parse-error".to_string(),
            };
            out.push(format!(
                "{name} key={key_name} msg={msg_name} verify-corrupted={corrupted_result}"
            ));
        }
    }

    // Signing key encodings.
    let mut n_plus_one = n.clone();
    n_plus_one[31] = n_plus_one[31].wrapping_add(1);
    let signing_keys: [(&str, Vec<u8>); 6] = [
        ("zero", vec![0u8; 32]),
        ("n", n.clone()),
        ("n+1", n_plus_one),
        ("all-ff", vec![0xff; 32]),
        ("31-bytes", vec![1u8; 31]),
        ("33-bytes", [vec![0u8], one()].concat()),
    ];
    for (label, raw) in &signing_keys {
        let result = A::SigningKey::from_slice(raw);
        out.push(format!("{name} signing-key={label} {}", ok(result.is_ok())));
        if let Ok(sk) = result {
            out.push(format!(
                "{name} signing-key={label} secret={}",
                hex::encode(sk.as_bytes())
            ));
        }
    }

    // Verifying key encodings.
    let public = A::SigningKey::from_slice(&hex::decode(RFC6979_KEY).unwrap())
        .unwrap()
        .to_verifying_key()
        .as_bytes()
        .to_vec();
    let mut wrong_prefix = public.clone();
    wrong_prefix[0] = 0x05;
    let mut other_parity = public.clone();
    other_parity[0] ^= 0x01;
    let mut off_curve_x = vec![0x02];
    off_curve_x.extend(vec![0xff; 32]);
    let verifying_keys: [(&str, Vec<u8>); 7] = [
        ("empty", Vec::new()),
        ("identity", vec![0x00]),
        ("wrong-prefix", wrong_prefix),
        ("other-parity", other_parity),
        ("x-not-on-curve", off_curve_x),
        ("truncated", public[..32].to_vec()),
        ("hybrid-prefix-06", [vec![0x06], vec![0u8; 64]].concat()),
    ];
    for (label, raw) in &verifying_keys {
        let result = A::VerifyingKey::from_slice(raw);
        out.push(format!(
            "{name} verifying-key={label} {}",
            ok(result.is_ok())
        ));
        if let Ok(vk) = result {
            out.push(format!(
                "{name} verifying-key={label} public={}",
                hex::encode(vk.as_bytes())
            ));
        }
    }

    // Signature encodings.
    let r = vec![0x11u8; 32];
    let signatures: [(&str, Vec<u8>); 7] = [
        ("empty", Vec::new()),
        ("63-bytes", vec![1u8; 63]),
        ("65-bytes", vec![1u8; 65]),
        ("zero-r", [vec![0u8; 32], one()].concat()),
        ("zero-s", [one(), vec![0u8; 32]].concat()),
        ("r=n", [n.clone(), one()].concat()),
        ("s=n", [r.clone(), n.clone()].concat()),
    ];
    for (label, raw) in &signatures {
        let result = A::Signature::try_from_slice(raw);
        out.push(format!("{name} signature={label} {}", ok(result.is_ok())));
    }

    // Freshly generated keys: random, so only their shape and round trips are recorded.
    for _ in 0..16 {
        let sk = alg.generate_signing_key();
        let raw = sk.as_bytes().to_vec();
        assert_eq!(raw.len(), 32, "{name}: generated key length");
        let again = A::SigningKey::from_slice(&raw).unwrap();
        assert_eq!(
            again.as_bytes(),
            sk.as_bytes(),
            "{name}: generated key round trip"
        );
        let vk = sk.to_verifying_key();
        let sig = alg.sign(&sk, b"generated");
        assert!(
            alg.verify_signature(&sig, &vk, b"generated"),
            "{name}: generated key signs"
        );
    }
}

fn client() -> Client {
    Stronghold::default()
        .create_client(b"compat-client")
        .unwrap()
}

fn store(client: &Client, record: &str, secret: &[u8]) -> Location {
    let location = Location::generic(b"compat-vault".to_vec(), record.as_bytes().to_vec());
    client
        .vault(b"compat-vault")
        .write_secret(location.clone(), Zeroizing::new(secret.to_vec()))
        .unwrap();
    location
}

fn bytes(output: ProcedureOutput) -> Vec<u8> {
    output.into()
}

macro_rules! record_procedures {
    ($name:literal, $procs:ident, $module:ident, $n_hex:expr, $out:expr) => {{
        let out: &mut Vec<String> = $out;
        let client = client();
        let n = hex::decode($n_hex).unwrap();
        let keys = [
            ("rfc6979", hex::decode(RFC6979_KEY).unwrap()),
            ("one", one()),
            ("n-1", sub(&n, &one())),
        ];
        for (key_name, raw) in &keys {
            let location = store(&client, &format!("{}-{key_name}", $name), raw);

            let public = execute_procedure_ext(
                &client,
                $procs::PublicKey($module::PublicKey {
                    private_key: location.clone(),
                }),
            )
            .map(bytes);
            out.push(format!(
                "{} proc key={key_name} public={}",
                $name,
                public
                    .map(hex::encode)
                    .unwrap_or_else(|e| format!("error {e}"))
            ));

            for (msg_name, msg) in messages() {
                let signature = execute_procedure_ext(
                    &client,
                    $procs::Sign($module::Sign {
                        msg: msg.clone(),
                        private_key: location.clone(),
                    }),
                )
                .map(bytes)
                .unwrap();
                out.push(format!(
                    "{} proc key={key_name} msg={msg_name} signature={}",
                    $name,
                    hex::encode(&signature)
                ));

                let mut corrupted = signature.clone();
                corrupted[40] ^= 1;
                for (label, candidate) in [("valid", signature.clone()), ("corrupted", corrupted)] {
                    let verified = execute_procedure_ext(
                        &client,
                        $procs::Verify($module::Verify {
                            msg: msg.clone(),
                            signature: candidate,
                            private_key: location.clone(),
                        }),
                    )
                    .map(bytes);
                    out.push(format!(
                        "{} proc key={key_name} msg={msg_name} verify-{label}={}",
                        $name,
                        verified
                            .map(hex::encode)
                            .unwrap_or_else(|_| "error".to_string())
                    ));
                }
            }

            let malformed = execute_procedure_ext(
                &client,
                $procs::Verify($module::Verify {
                    msg: b"test".to_vec(),
                    signature: vec![1u8; 63],
                    private_key: location.clone(),
                }),
            );
            out.push(format!(
                "{} proc key={key_name} verify-63-byte-signature={}",
                $name,
                ok(malformed.is_ok())
            ));
        }

        // A vault entry that is not a valid key fails every procedure.
        let invalid = store(&client, &format!("{}-invalid", $name), &[0u8; 32]);
        let public = execute_procedure_ext(
            &client,
            $procs::PublicKey($module::PublicKey {
                private_key: invalid.clone(),
            }),
        );
        out.push(format!(
            "{} proc invalid-key public={}",
            $name,
            ok(public.is_ok())
        ));
        let sign = execute_procedure_ext(
            &client,
            $procs::Sign($module::Sign {
                msg: b"test".to_vec(),
                private_key: invalid,
            }),
        );
        out.push(format!(
            "{} proc invalid-key sign={}",
            $name,
            ok(sign.is_ok())
        ));

        // A generated key is a 32-byte scalar whose public key is a compressed SEC1 point.
        let generated = Location::generic(
            b"compat-vault".to_vec(),
            format!("{}-generated", $name).into_bytes(),
        );
        execute_procedure_ext(
            &client,
            $procs::GenerateKey($module::GenerateKey {
                output: generated.clone(),
            }),
        )
        .unwrap();
        let public = bytes(
            execute_procedure_ext(
                &client,
                $procs::PublicKey($module::PublicKey {
                    private_key: generated.clone(),
                }),
            )
            .unwrap(),
        );
        assert_eq!(public.len(), 33, "{}: generated public key length", $name);
        assert!(
            matches!(public[0], 2 | 3),
            "{}: generated public key prefix",
            $name
        );
        let signature = bytes(
            execute_procedure_ext(
                &client,
                $procs::Sign($module::Sign {
                    msg: b"generated".to_vec(),
                    private_key: generated.clone(),
                }),
            )
            .unwrap(),
        );
        let verified = bytes(
            execute_procedure_ext(
                &client,
                $procs::Verify($module::Verify {
                    msg: b"generated".to_vec(),
                    signature,
                    private_key: generated,
                }),
            )
            .unwrap(),
        );
        assert_eq!(verified, vec![1], "{}: generated key verifies", $name);
    }};
}

fn record() -> Vec<String> {
    let mut out = Vec::new();
    record_algorithm(&Es256, P256_N, &mut out);
    record_algorithm(&Es256k::default(), K256_N, &mut out);
    record_procedures!("ES256", Es256Procs, es256, P256_N, &mut out);
    record_procedures!("ES256K", Es256kProcs, es256k, K256_N, &mut out);
    out
}

#[test]
fn behaviour_matches_recorded_golden_file() {
    let actual = record();

    if std::env::var_os("STRONGHOLD_EXT_WRITE_GOLDEN").is_some() {
        std::fs::write(GOLDEN_PATH, actual.join("\n") + "\n").unwrap();
        return;
    }

    let expected = std::fs::read_to_string(GOLDEN_PATH).unwrap();
    let expected: Vec<&str> = expected.lines().collect();
    for (index, (actual, expected)) in actual.iter().zip(&expected).enumerate() {
        assert_eq!(actual, expected, "line {}", index + 1);
    }
    assert_eq!(
        actual.len(),
        expected.len(),
        "number of recorded behaviours"
    );
}

/// Signatures from RFC 6979, appendix A.2.5 (P-256, SHA-256), as an independent reference.
#[test]
fn es256_matches_rfc6979_test_vectors() {
    let sk =
        <Es256 as Algorithm>::SigningKey::from_slice(&hex::decode(RFC6979_KEY).unwrap()).unwrap();
    let vk = sk.to_verifying_key();
    assert_eq!(
        hex::encode(vk.as_bytes()),
        // Ux = 60FED4BA...; Uy is odd, so the compressed prefix is 03.
        "0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
    );
    for (msg, r, s) in [
        (
            "sample",
            "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
            "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
        ),
        (
            "test",
            "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367",
            "019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083",
        ),
    ] {
        let sig = Es256.sign(&sk, msg.as_bytes());
        assert_eq!(
            hex::encode(sig.as_bytes()),
            format!("{r}{s}"),
            "message {msg}"
        );
    }
}

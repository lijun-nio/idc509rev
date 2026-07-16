//! Generate a deterministic ECDSA-secp256r1-SHA256 signed C509 CRL vector for
//! cross-implementation testing (the C on-device verifier in contiki-ng
//! `os/services/c509/c509-rev-verify-ecdsa.c`). The draft ships Ed25519 example
//! keys only, so we mint a P-256 KAT here: p256's signer is RFC6979
//! deterministic, so the output is reproducible.
//!
//! Run: `cargo run --example ecdsa_crl_vector`
//!
//! SECURITY NOTICE: Test credentials only. Never use in production.

use c509rev::common::Name;
use c509rev::crl::{C509Crl, CrlInfo};

// Fixed PKCS#8 P-256 test key (same as sign.rs tests; test credentials only).
const P256_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgTSoZ5vpvAClwvhey\n\
V0+wDfELwTO/5E1lyAgV0z2DJvKhRANCAASm4lb1E6p54XkTxZhrt9opArKq5BgL\n\
LDeB+bVSvgJWg4BROG/yPW9ChJPA4Fsv6/Y+FYkJtaehDVTfkr5w1t/D\n\
-----END PRIVATE KEY-----\n";

fn main() {
    let mut crl = C509Crl {
        info: CrlInfo {
            crl_type: 0,
            signature_algorithm: c509::registry::SIG_ECDSA_SHA256,
            authority_subject: Name::Text("test crlocsp-ca".to_string()),
            authority_key_identifier: Some(vec![0u8; 20]),
            crl_number: 1,
            this_update: 1735776000,
            next_update: Some(1736380800),
            base_crl_number: None,
            crl_extensions: vec![],
        },
        revoked_certs_list: None,
        signature_value: vec![],
    };
    crl.sign(P256_PEM).expect("sign");

    use p256::pkcs8::DecodePrivateKey;
    let pk = p256::ecdsa::SigningKey::from_pkcs8_pem(P256_PEM)
        .unwrap()
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();

    // Sanity: the vector must verify with our own verifier.
    assert!(crl.verify(&pk).is_ok(), "self-verify must pass");

    println!("crl_hex={}", hex::encode(crl.encode()));
    println!("pubkey_hex={}", hex::encode(&pk));
    println!("pubkey_len={}", pk.len());
}

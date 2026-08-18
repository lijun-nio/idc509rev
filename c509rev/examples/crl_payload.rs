//! Emit a real, signed C509 CRL of R revoked entries as hex — the on-wire
//! payload for the LRev multi-hop delivery experiment (E10).
//!
//! Profile matches PLAN-revocation.md §0: ECDSA-secp256r1 + SHA-256, 2-byte
//! serials, 8-byte AKID (the RFC 7925-style constrained profile, comparable with
//! the 2022 TinyOCSP/CCRL setup). Entries are sorted ascending and carry a reason
//! byte, so the encoding is the binary-searchable fixed-width form the on-device
//! `c509_crl_is_revoked()` consumes.
//!
//! Deterministic: serials are 1..=R, dates are fixed offsets, and p256's signer is
//! RFC6979 deterministic — so a given R always yields byte-identical output.
//!
//!   cargo run --example crl_payload -- <R>
//!
//! Reference tooling only.
//!
//! SECURITY NOTICE: Test credentials only. Never use in production.

use c509rev::common::Name;
use c509rev::crl::{C509Crl, CrlInfo, PerIssuerRevokedCerts, RevokedCert, RevokedCertsControl};

// Fixed PKCS#8 P-256 test key (same key as ecdsa_crl_vector.rs; test credentials only).
const P256_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgTSoZ5vpvAClwvhey\n\
V0+wDfELwTO/5E1lyAgV0z2DJvKhRANCAASm4lb1E6p54XkTxZhrt9opArKq5BgL\n\
LDeB+bVSvgJWg4BROG/yPW9ChJPA4Fsv6/Y+FYkJtaehDVTfkr5w1t/D\n\
-----END PRIVATE KEY-----\n";

const THIS_UPDATE: u64 = 1735776000;
const NEXT_UPDATE: u64 = 1736380800;

fn main() {
    let r: usize = std::env::args()
        .nth(1)
        .expect("usage: crl_payload <R>")
        .parse()
        .expect("R must be a non-negative integer");

    // Serials 1..=R, 2 bytes each; revocation dates walk forward 1 h per entry
    // from base_date so the date field genuinely varies (worst case for any
    // hypothetical compression, and realistic).
    let revoked: Vec<RevokedCert> = (1..=r)
        .map(|i| RevokedCert {
            serial: (i as u16).to_be_bytes().to_vec(),
            revocation_date: THIS_UPDATE + (i as u64) * 3600,
            reason: Some(1), // keyCompromise
        })
        .collect();

    let per_issuer = PerIssuerRevokedCerts {
        issuer: None, // the CRL's own authoritySubject
        control: Some(RevokedCertsControl {
            flags: 0x03, // sorted ascending + reason byte present
            serial_number_length: 2,
            date_length: 4,
            base_date: THIS_UPDATE,
        }),
        extensions: vec![],
        revoked,
        removed: vec![],
    };

    let mut crl = C509Crl {
        info: CrlInfo {
            crl_type: 0,
            signature_algorithm: c509rev::registry::SIG_ECDSA_SHA256,
            authority_subject: Name::Text("test crlocsp-ca".to_string()),
            authority_key_identifier: Some(vec![0u8; 8]), // 8-byte AKID (constrained profile)
            crl_number: 1,
            this_update: THIS_UPDATE,
            next_update: Some(NEXT_UPDATE),
            base_crl_number: None,
            crl_extensions: vec![],
        },
        revoked_certs_list: if r == 0 { None } else { Some(vec![per_issuer]) },
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

    // The emitted payload must verify with our own verifier, so the experiment
    // transports a genuinely valid CRL rather than a size-faithful blob.
    assert!(crl.verify(&pk).is_ok(), "self-verify must pass");

    let enc = crl.encode();
    eprintln!("R={} c509_crl_len={}", r, enc.len());
    println!("{}", hex::encode(enc));
}

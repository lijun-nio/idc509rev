//! Size harness for the LRev follow-up (experiment E1/E2, Tier 0).
//!
//! Emits CSV of encoded byte sizes for C509 OCSP and C509 CRL as a function of
//! the number of validated certificates (N) and revoked entries (R), in both the
//! full-32-byte hash and the 8-byte KID-truncated modes. Hashes/nonces are
//! opaque placeholders (their *length* is what matters for size).
//!
//!   cargo run --example sizes
//!
//! Reference tooling only.

use c509rev::common::Extension;
use c509rev::crl::{C509Crl, CrlInfo, PerIssuerRevokedCerts, RevokedCert, RevokedCertsControl};
use c509rev::ocsp_req::{C509OcspRequest, PerIssuerOCSPRequest, SingleCertRequest};
use c509rev::ocsp_resp::{
    C509OcspResponse, CertStatus, PerIssuerOCSPResponse, SingleCertResponse,
};

const SHA256: i64 = 1;
const ED25519: i64 = 12;

fn h(l: usize) -> Vec<u8> {
    vec![0u8; l]
}

/// C509 Simple OCSP request (one certificate), hash length `l`.
fn simple_req(l: usize) -> usize {
    C509OcspRequest::Simple {
        hash_algorithm: SHA256,
        nonce: Some(vec![0u8; 16]),
        issuer_cert_hash: h(l),
        serial_number_hash: h(l),
        extensions: vec![],
    }
    .encode()
    .len()
}

/// C509 Unsigned OCSP request, one issuer, `n` certificates, hash length `l`.
fn unsigned_req(n: usize, l: usize) -> usize {
    let singles = (0..n)
        .map(|_| SingleCertRequest { serial_number_hash: h(l), extensions: vec![] })
        .collect();
    C509OcspRequest::Unsigned {
        hash_algorithm: SHA256,
        nonce: Some(vec![0u8; 16]),
        extensions: vec![],
        requests: vec![PerIssuerOCSPRequest {
            issuer_cert_hash: h(l),
            extensions: vec![],
            single_requests: singles,
        }],
    }
    .encode()
    .len()
}

/// C509 Basic OCSP response, one issuer, `n` statuses, hash length `l`.
fn basic_resp(n: usize, l: usize) -> usize {
    let singles = (0..n)
        .map(|_| SingleCertResponse {
            serial_number_hash: h(l),
            cert_status: CertStatus::Good,
            this_update_back: 28800,
            next_update_forward: Some(25200),
            extensions: vec![],
        })
        .collect();
    C509OcspResponse::Basic {
        signature_algorithm: ED25519,
        hash_algorithm: SHA256,
        nonce: Some(vec![0u8; 16]),
        responder_cert_hash: h(l),
        produced_at: 1_781_027_830,
        extensions: vec![],
        responses: vec![PerIssuerOCSPResponse {
            issuer_cert_hash: h(l),
            extensions: vec![],
            single_responses: singles,
        }],
        responder_certs: None,
        signature_value: vec![0u8; 64],
    }
    .encode()
    .len()
}

/// C509 CRL, one issuer, `r` revoked certs (2-byte serial, 3-byte date, reason).
fn crl(r: usize) -> usize {
    let revoked = (0..r)
        .map(|i| RevokedCert {
            serial: (i as u16).to_be_bytes().to_vec(),
            revocation_date: 1_735_690_354 + i as u64,
            reason: Some(1),
        })
        .collect();
    C509Crl {
        info: CrlInfo {
            crl_type: 0,
            signature_algorithm: ED25519,
            authority_subject: c509rev::common::Name::Text("test crlocsp-ca".into()),
            authority_key_identifier: Some(vec![0u8; 20]),
            crl_number: 1,
            this_update: 1_736_208_754,
            next_update: Some(1_736_813_554),
            base_crl_number: None,
            crl_extensions: Vec::<Extension>::new(),
        },
        revoked_certs_list: Some(vec![PerIssuerRevokedCerts {
            issuer: None,
            control: Some(RevokedCertsControl {
                flags: 0x03,
                serial_number_length: 2,
                date_length: 3,
                base_date: 1_735_690_354,
            }),
            extensions: vec![],
            revoked,
            removed: vec![],
        }]),
        signature_value: vec![0u8; 64],
    }
    .encode()
    .len()
}

/// C509 Status List covering N issued certs (size is independent of how many
/// are revoked; use a few revoked).
fn status_list(n_issued: usize) -> usize {
    use c509rev::status_list::C509StatusList;
    C509StatusList {
        status_list_type: 0,
        signature_algorithm: ED25519,
        authority_subject: c509rev::common::Name::Text("test crlocsp-ca".into()),
        authority_key_identifier: Some(vec![0u8; 20]),
        status_list_number: 1,
        this_update: 1_736_208_754,
        next_update: Some(1_736_813_554),
        base_index: 0,
        status_bits: C509StatusList::revocation_bitmap(n_issued, &[1, 2, 3]),
        extensions: vec![],
        signature_value: vec![0u8; 64],
    }
    .encode()
    .len()
}

fn main() {
    println!("scenario,N,hashlen,bytes");
    for l in [32usize, 8] {
        println!("simple_req,1,{l},{}", simple_req(l));
        for n in 1..=16 {
            println!("unsigned_req,{n},{l},{}", unsigned_req(n, l));
            println!("basic_resp,{n},{l},{}", basic_resp(n, l));
        }
    }
    for r in [0usize, 1, 10, 100, 1000, 10000] {
        // hashlen N/A for CRL (raw fixed-width serials); use R in the N column.
        println!("crl,{r},-,{}", crl(r));
    }
    // Status list: N = issued population (size independent of #revoked).
    for n in [64usize, 800, 8000, 80000, 800000] {
        println!("status_list,{n},-,{}", status_list(n));
    }
}

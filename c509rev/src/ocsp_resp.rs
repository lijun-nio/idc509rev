//! C509 OCSP **response** structures (draft §"C509 OCSP Response").
//!
//! Three response types:
//! - `C509ErrorOCSPResponse` (0) — `array[2]` `[type, responseStatus]`;
//! - `C509BasicOCSPResponse` (1) — `array[10]`: the `TBSBasicOCSPResponse` group
//!   of 9 flattened plus `signatureValue`;
//! - `C509SimpleOCSPResponse` (2) — `array[14]`: the `TBSSimpleOCSPResponse`
//!   group of 13 flattened plus `signatureValue`.
//!
//! `responses` is a `PerIssuerOCSPResponses` array of **3-element** flattened
//! `PerIssuerOCSPResponse` groups `(issuerCertHash, extensions, singleResponses)`,
//! where `singleResponses` is an array of **5-element** flattened
//! `SingleCertResponse` groups `(serialNumberHash, certStatus, thisUpdate,
//! nextUpdate, extensions)`.
//!
//! As in `ocsp_req`, cert/serial hashes are opaque bytes here. The signed
//! responses (Basic, Simple) are validated by **TBS byte-match** (the draft
//! ships no example signing keys); `encode()` assembles the full array once a
//! `signatureValue` is supplied.

use c509::lcbor;

use crate::common::{encode_extensions, encode_opt_bytes, Extension};
use crate::discriminator;
use crate::time;

/// `CertStatus` (draft): good / not-issued / unknown / revoked.
#[derive(Clone, Debug)]
pub enum CertStatus {
    /// `0` — good.
    Good,
    /// `1` — not-issued (issuer recognised, serial not issued).
    NotIssued,
    /// `2` — unknown (issuer not recognised).
    Unknown,
    /// `RevokedInfo = [revocationTime: ~time, revocationReason: int]`.
    Revoked { revocation_time: u64, revocation_reason: i64 },
}

impl CertStatus {
    fn encode(&self) -> Vec<u8> {
        match self {
            CertStatus::Good => lcbor::lcbor_uint(0),
            CertStatus::NotIssued => lcbor::lcbor_uint(1),
            CertStatus::Unknown => lcbor::lcbor_uint(2),
            CertStatus::Revoked { revocation_time, revocation_reason } =>
                lcbor::lcbor_array(&[
                    time::encode_abs(*revocation_time),
                    lcbor::lcbor_int(*revocation_reason),
                ]),
        }
    }
}

/// One `SingleCertResponse`.
#[derive(Clone, Debug)]
pub struct SingleCertResponse {
    pub serial_number_hash: Vec<u8>,
    pub cert_status: CertStatus,
    /// `thisUpdate`: seconds *before* `producedAt` (encoded `nint / 0`).
    pub this_update_back: u64,
    /// `nextUpdate`: seconds *after* `producedAt` (`uint`), or `None` for null.
    pub next_update_forward: Option<u64>,
    pub extensions: Vec<Extension>,
}

impl SingleCertResponse {
    /// The 5 flattened array elements.
    fn items(&self) -> Vec<Vec<u8>> {
        vec![
            lcbor::lcbor_bytes(&self.serial_number_hash),
            self.cert_status.encode(),
            time::encode_delta_back(self.this_update_back),
            match self.next_update_forward {
                Some(s) => time::encode_delta_forward(s),
                None => crate::common::null(),
            },
            encode_extensions(&self.extensions),
        ]
    }
}

/// One issuer's grouped responses.
#[derive(Clone, Debug)]
pub struct PerIssuerOCSPResponse {
    pub issuer_cert_hash: Vec<u8>,
    pub extensions: Vec<Extension>,
    pub single_responses: Vec<SingleCertResponse>,
}

impl PerIssuerOCSPResponse {
    /// The 3 flattened array elements.
    fn items(&self) -> Vec<Vec<u8>> {
        let mut singles = Vec::new();
        for s in &self.single_responses {
            singles.extend(s.items());
        }
        vec![
            lcbor::lcbor_bytes(&self.issuer_cert_hash),
            encode_extensions(&self.extensions),
            lcbor::lcbor_array(&singles),
        ]
    }
}

fn encode_responses(responses: &[PerIssuerOCSPResponse]) -> Vec<u8> {
    let mut items = Vec::new();
    for r in responses {
        items.extend(r.items());
    }
    lcbor::lcbor_array(&items)
}

/// A C509 OCSP response.
#[derive(Clone, Debug)]
pub enum C509OcspResponse {
    /// `C509ErrorOCSPResponse` (type 0).
    Error { response_status: i64 },
    /// `C509BasicOCSPResponse` (type 1).
    Basic {
        signature_algorithm: i64,
        hash_algorithm: i64,
        nonce: Option<Vec<u8>>,
        responder_cert_hash: Vec<u8>,
        produced_at: u64,
        extensions: Vec<Extension>,
        responses: Vec<PerIssuerOCSPResponse>,
        responder_certs: Option<Vec<u8>>,
        signature_value: Vec<u8>,
    },
    /// `C509SimpleOCSPResponse` (type 2).
    Simple {
        signature_algorithm: i64,
        hash_algorithm: i64,
        nonce: Option<Vec<u8>>,
        responder_cert_hash: Vec<u8>,
        issuer_cert_hash: Vec<u8>,
        serial_number_hash: Vec<u8>,
        cert_status: CertStatus,
        produced_at: u64,
        this_update_back: u64,
        next_update_forward: Option<u64>,
        extensions: Vec<Extension>,
        responder_certs: Option<Vec<u8>>,
        signature_value: Vec<u8>,
    },
}

impl C509OcspResponse {
    /// The TBS items (everything but `signatureValue`) for the signed responses.
    /// Panics for `Error`, which is unsigned.
    fn tbs_items(&self) -> Vec<Vec<u8>> {
        match self {
            C509OcspResponse::Error { .. } =>
                panic!("Error response has no TBS"),
            C509OcspResponse::Basic {
                signature_algorithm, hash_algorithm, nonce, responder_cert_hash,
                produced_at, extensions, responses, responder_certs, ..
            } => vec![
                lcbor::lcbor_uint(discriminator::OCSP_RESP_BASIC),
                lcbor::lcbor_int(*signature_algorithm),
                lcbor::lcbor_int(*hash_algorithm),
                encode_opt_bytes(nonce),
                lcbor::lcbor_bytes(responder_cert_hash),
                time::encode_abs(*produced_at),
                encode_extensions(extensions),
                encode_responses(responses),
                encode_opt_bytes(responder_certs),
            ],
            C509OcspResponse::Simple {
                signature_algorithm, hash_algorithm, nonce, responder_cert_hash,
                issuer_cert_hash, serial_number_hash, cert_status, produced_at,
                this_update_back, next_update_forward, extensions, responder_certs, ..
            } => vec![
                lcbor::lcbor_uint(discriminator::OCSP_RESP_SIMPLE),
                lcbor::lcbor_int(*signature_algorithm),
                lcbor::lcbor_int(*hash_algorithm),
                encode_opt_bytes(nonce),
                lcbor::lcbor_bytes(responder_cert_hash),
                lcbor::lcbor_bytes(issuer_cert_hash),
                lcbor::lcbor_bytes(serial_number_hash),
                cert_status.encode(),
                time::encode_abs(*produced_at),
                time::encode_delta_back(*this_update_back),
                match next_update_forward {
                    Some(s) => time::encode_delta_forward(*s),
                    None => crate::common::null(),
                },
                encode_extensions(extensions),
                encode_opt_bytes(responder_certs),
            ],
        }
    }

    /// Encode the `TBS{Basic,Simple}OCSPResponse` CBOR sequence (what is signed).
    /// Panics for `Error`.
    pub fn encode_tbs(&self) -> Vec<u8> {
        self.tbs_items().concat()
    }

    /// Encode the full response array.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            C509OcspResponse::Error { response_status } => lcbor::lcbor_array(&[
                lcbor::lcbor_uint(discriminator::OCSP_RESP_ERROR),
                lcbor::lcbor_int(*response_status),
            ]),
            C509OcspResponse::Basic { signature_value, .. }
            | C509OcspResponse::Simple { signature_value, .. } => {
                let mut items = self.tbs_items();
                items.push(lcbor::lcbor_bytes(signature_value));
                lcbor::lcbor_array(&items)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashalg;

    const SIMPLE_RESP: &str = "8e020c01501111111111111111111111111111111158200600867838\
e3311aa78b9ed60c631c86b09a6de7bc43e02a7aa7006a3443a3b25820a01c73a5f3b063344257d02693059de\
d8e22c4433b1a4d85efae22f7f9d7e43c582010652787fa0527bc2449a1bfc5ab31aa5a6f0d8d6b998e4fede7\
d90dca47f004001a67c4f10039707f19627080f65840bd269e74ac6c9ebfe4e0a46a64cfd432cc06068c4d073\
fd515d0d276437ae5ec8baa611d3a7795e6b299c7539af3140ee768d19a05bd23b1e2c2f546c7738b07";

    const BASIC_RESP: &str = "8a010c01501111111111111111111111111111111158200600867838e3311aa78b9ed60c631c86b09a6de7bc43e02a7aa7006a3443a3b21a6a2853f680865820a01c73a5f3b063344257d02693059ded8e22c4433b1a4d85efae22f7f9d7e43c808f582010652787fa0527bc2449a1bfc5ab31aa5a6f0d8d6b998e4fede7d90dca47f0040039707f19627080582075d8bc4fbafc6694467641e748dfd53a8b9d176dfa3d05b3e98a4d6e5c55f1650139707f196270805820d1ac135d7da29bdcf4dca0d5281a51605b678400c26408cadc3a32fc1b6ad5e3821a67c32f000439707f196270805820222222222222222222222222222222222222222222222222222222222222222280855820d3a0c1e3db92e8f6810537d45cfaecf6ce417e3b264e50cb4f69dd853401c5dd0239707f19627080f65840937ea7cccad3b9f113ed6ad0df113bf5e70fbf326e020ff5183ac87e5530ff06225f1aa048d76d39d412ec26c3ad9b74668791559e6973308e11dcabda826207";

    fn h32(full: &[u8], off: usize) -> Vec<u8> {
        full[off..off + 32].to_vec()
    }

    fn example_tbs(full_hex: &str) -> Vec<u8> {
        let full = hex::decode(full_hex).unwrap();
        full[1..full.len() - 66].to_vec()
    }

    #[test]
    fn error_response_matches_example() {
        let resp = C509OcspResponse::Error { response_status: 6 };
        assert_eq!(hex::encode(resp.encode()), "820006");
    }

    #[test]
    fn simple_response_tbs_matches_example() {
        let full = hex::decode(SIMPLE_RESP).unwrap();
        // nonce@5; responderCertHash@23; issuerCertHash@57; serialNumberHash@91.
        let resp = C509OcspResponse::Simple {
            signature_algorithm: c509::registry::SIG_ED25519,
            hash_algorithm: hashalg::SHA_256,
            nonce: Some(full[5..21].to_vec()),
            responder_cert_hash: h32(&full, 23),
            issuer_cert_hash: h32(&full, 57),
            serial_number_hash: h32(&full, 91),
            cert_status: CertStatus::Good,
            produced_at: 1740960000,
            this_update_back: 28800,
            next_update_forward: Some(25200),
            extensions: vec![],
            responder_certs: None,
            signature_value: vec![],
        };
        assert_eq!(hex::encode(resp.encode_tbs()),
                   hex::encode(example_tbs(SIMPLE_RESP)));
    }

    #[test]
    fn basic_response_tbs_matches_example() {
        let full = hex::decode(BASIC_RESP).unwrap();
        // nonce@5; responderCertHash@23; issuer0 hash@64; serial hashes@100,142,
        // 184; issuer1 hash@232; serial hash@268.
        let sr = |off: usize, status: CertStatus| SingleCertResponse {
            serial_number_hash: h32(&full, off),
            cert_status: status,
            this_update_back: 28800,
            next_update_forward: Some(25200),
            extensions: vec![],
        };
        let resp = C509OcspResponse::Basic {
            signature_algorithm: c509::registry::SIG_ED25519,
            hash_algorithm: hashalg::SHA_256,
            nonce: Some(full[5..21].to_vec()),
            responder_cert_hash: h32(&full, 23),
            produced_at: 1781027830,
            extensions: vec![],
            responses: vec![
                PerIssuerOCSPResponse {
                    issuer_cert_hash: h32(&full, 64),
                    extensions: vec![],
                    single_responses: vec![
                        sr(100, CertStatus::Good),
                        sr(142, CertStatus::NotIssued),
                        sr(184, CertStatus::Revoked {
                            revocation_time: 1740844800, revocation_reason: 4,
                        }),
                    ],
                },
                PerIssuerOCSPResponse {
                    issuer_cert_hash: h32(&full, 232),
                    extensions: vec![],
                    single_responses: vec![sr(268, CertStatus::Unknown)],
                },
            ],
            responder_certs: None,
            signature_value: vec![],
        };
        assert_eq!(hex::encode(resp.encode_tbs()),
                   hex::encode(example_tbs(BASIC_RESP)));
    }
}

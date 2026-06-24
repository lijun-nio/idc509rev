//! C509 OCSP **request** structures (draft §"C509 OCSP Request").
//!
//! Three request types, discriminated by the leading `ocspRequestType`:
//! - `C509UnsignedOCSPRequest` (0) — `array[5]`
//!   `[type, hashAlgorithm, nonce, extensions, requests]`;
//! - `C509SignedOCSPRequest` (1) — `array[9]`, the `TBSOCSPRequest` group of 8
//!   flattened plus `signatureValue` (signed; lands with sign/verify);
//! - `C509SimpleOCSPRequest` (2) — `array[6]`
//!   `[type, hashAlgorithm, nonce, issuerCertHash, serialNumberHash, extensions]`.
//!
//! `requests` is a `PerIssuerOCSPRequests` array of **3-element** flattened
//! `PerIssuerOCSPRequest` groups `(issuerCertHash, extensions, singleRequests)`,
//! where `singleRequests` is an array of **2-element** flattened
//! `SingleCertRequest` groups `(serialNumberHash, extensions)`.
//!
//! Cert/serial hashes are carried as **opaque bytes** here — their *length* is
//! the [`crate::hashalg::HashLen`] decision (8-byte KID by default), their
//! *computation* is validated in `certhash`. v1 implements Simple + Unsigned;
//! Signed lands with signing.

use c509::lcbor;

use crate::common::{encode_extensions, encode_opt_bytes, Extension};
use crate::discriminator;

/// One `SingleCertRequest`: a target serial (by hash) plus its extensions.
#[derive(Clone, Debug)]
pub struct SingleCertRequest {
    pub serial_number_hash: Vec<u8>,
    pub extensions: Vec<Extension>,
}

impl SingleCertRequest {
    /// The 2 flattened array elements.
    fn items(&self) -> Vec<Vec<u8>> {
        vec![
            lcbor::lcbor_bytes(&self.serial_number_hash),
            encode_extensions(&self.extensions),
        ]
    }
}

/// One issuer's grouped requests.
#[derive(Clone, Debug)]
pub struct PerIssuerOCSPRequest {
    pub issuer_cert_hash: Vec<u8>,
    pub extensions: Vec<Extension>,
    pub single_requests: Vec<SingleCertRequest>,
}

impl PerIssuerOCSPRequest {
    /// The 3 flattened array elements (the inner `singleRequests` is one array).
    fn items(&self) -> Vec<Vec<u8>> {
        let mut singles = Vec::new();
        for s in &self.single_requests {
            singles.extend(s.items());
        }
        vec![
            lcbor::lcbor_bytes(&self.issuer_cert_hash),
            encode_extensions(&self.extensions),
            lcbor::lcbor_array(&singles),
        ]
    }
}

/// Encode a `PerIssuerOCSPRequests` array (flattened 3-element groups).
fn encode_requests(requests: &[PerIssuerOCSPRequest]) -> Vec<u8> {
    let mut items = Vec::new();
    for r in requests {
        items.extend(r.items());
    }
    lcbor::lcbor_array(&items)
}

/// A C509 OCSP request.
#[derive(Clone, Debug)]
pub enum C509OcspRequest {
    /// `C509UnsignedOCSPRequest` (type 0).
    Unsigned {
        hash_algorithm: i64,
        nonce: Option<Vec<u8>>,
        extensions: Vec<Extension>,
        requests: Vec<PerIssuerOCSPRequest>,
    },
    /// `C509SimpleOCSPRequest` (type 2).
    Simple {
        hash_algorithm: i64,
        nonce: Option<Vec<u8>>,
        issuer_cert_hash: Vec<u8>,
        serial_number_hash: Vec<u8>,
        extensions: Vec<Extension>,
    },
}

impl C509OcspRequest {
    /// Encode the full request array.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            C509OcspRequest::Unsigned { hash_algorithm, nonce, extensions, requests } => {
                lcbor::lcbor_array(&[
                    lcbor::lcbor_uint(discriminator::OCSP_REQ_UNSIGNED),
                    lcbor::lcbor_int(*hash_algorithm),
                    encode_opt_bytes(nonce),
                    encode_extensions(extensions),
                    encode_requests(requests),
                ])
            }
            C509OcspRequest::Simple {
                hash_algorithm, nonce, issuer_cert_hash, serial_number_hash, extensions,
            } => {
                lcbor::lcbor_array(&[
                    lcbor::lcbor_uint(discriminator::OCSP_REQ_SIMPLE),
                    lcbor::lcbor_int(*hash_algorithm),
                    encode_opt_bytes(nonce),
                    lcbor::lcbor_bytes(issuer_cert_hash),
                    lcbor::lcbor_bytes(serial_number_hash),
                    encode_extensions(extensions),
                ])
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashalg;

    const SIMPLE_REQ: &str = "86020150111111111111111111111111111111115820a01c73a5f3\
b063344257d02693059ded8e22c4433b1a4d85efae22f7f9d7e43c582010652787fa0527bc2449a1bfc5ab31a\
a5a6f0d8d6b998e4fede7d90dca47f00480";

    const UNSIGNED_REQ: &str = "850001501111111111111111111111111111111180865820a01c73\
a5f3b063344257d02693059ded8e22c4433b1a4d85efae22f7f9d7e43c8086582010652787fa0527bc2449a1b\
fc5ab31aa5a6f0d8d6b998e4fede7d90dca47f00480582075d8bc4fbafc6694467641e748dfd53a8b9d176dfa\
3d05b3e98a4d6e5c55f165805820d1ac135d7da29bdcf4dca0d5281a51605b678400c26408cadc3a32fc1b6ad\
5e3805820222222222222222222222222222222222222222222222222222222222222222280825820d3a0c1e\
3db92e8f6810537d45cfaecf6ce417e3b264e50cb4f69dd853401c5dd80";

    // Pull a 32-byte field at byte offset `off` from a decoded example.
    fn h32(full: &[u8], off: usize) -> Vec<u8> {
        full[off..off + 32].to_vec()
    }

    #[test]
    fn simple_request_matches_example() {
        let full = hex::decode(SIMPLE_REQ).unwrap();
        // Offsets from the draft annotation: nonce@4 (16B), issuerCertHash@22,
        // serialNumberHash@56.
        let req = C509OcspRequest::Simple {
            hash_algorithm: hashalg::SHA_256,
            nonce: Some(full[4..20].to_vec()),
            issuer_cert_hash: h32(&full, 22),
            serial_number_hash: h32(&full, 56),
            extensions: vec![],
        };
        assert_eq!(hex::encode(req.encode()), hex::encode(&full));
    }

    #[test]
    fn unsigned_request_matches_example() {
        let full = hex::decode(UNSIGNED_REQ).unwrap();
        // Hash data starts 2 bytes after each `58 20` header. From the
        // annotation: nonce@4; issuer0 hash@24; serial hashes@60,95,130;
        // issuer1 hash@165; serial hash@201.
        let sc = |off: usize| SingleCertRequest {
            serial_number_hash: h32(&full, off),
            extensions: vec![],
        };
        let req = C509OcspRequest::Unsigned {
            hash_algorithm: hashalg::SHA_256,
            nonce: Some(full[4..20].to_vec()),
            extensions: vec![],
            requests: vec![
                PerIssuerOCSPRequest {
                    issuer_cert_hash: h32(&full, 24),
                    extensions: vec![],
                    single_requests: vec![sc(60), sc(95), sc(130)],
                },
                PerIssuerOCSPRequest {
                    issuer_cert_hash: h32(&full, 165),
                    extensions: vec![],
                    single_requests: vec![sc(201)],
                },
            ],
        };
        assert_eq!(hex::encode(req.encode()), hex::encode(&full));
    }
}

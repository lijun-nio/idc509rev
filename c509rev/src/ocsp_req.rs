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
//! the [`crate::hashalg::HashLen`] decision (cert hashes `HashId8` = 8 bytes,
//! `serialNumberHash` `HashId20` = 20 bytes), their *computation* is validated in
//! `certhash`. v1 implements Simple + Unsigned; Signed lands with signing.

use crate::lcbor;

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
    /// `C509SignedOCSPRequest` (type 1): the `TBSOCSPRequest` group of 8
    /// flattened, plus `signatureValue`. `requestor_certs` is the opaque
    /// pre-encoded `COSE_C509` / `#6.121(COSE_X509)` chain, or `None` for null.
    Signed {
        signature_algorithm: i64,
        hash_algorithm: i64,
        nonce: Option<Vec<u8>>,
        requestor_cert_hash: Vec<u8>,
        extensions: Vec<Extension>,
        requests: Vec<PerIssuerOCSPRequest>,
        requestor_certs: Option<Vec<u8>>,
        signature_value: Vec<u8>,
    },
}

impl C509OcspRequest {
    /// The 8 `TBSOCSPRequest` items (everything but `signatureValue`). This is
    /// what is signed. Panics for the unsigned request types.
    fn signed_tbs_items(&self) -> Vec<Vec<u8>> {
        match self {
            C509OcspRequest::Signed {
                signature_algorithm, hash_algorithm, nonce, requestor_cert_hash,
                extensions, requests, requestor_certs, ..
            } => vec![
                lcbor::lcbor_uint(discriminator::OCSP_REQ_SIGNED),
                lcbor::lcbor_int(*signature_algorithm),
                lcbor::lcbor_int(*hash_algorithm),
                encode_opt_bytes(nonce),
                lcbor::lcbor_bytes(requestor_cert_hash),
                encode_extensions(extensions),
                encode_requests(requests),
                encode_opt_bytes(requestor_certs),
            ],
            _ => panic!("signed_tbs_items only applies to C509SignedOCSPRequest"),
        }
    }

    /// Encode the `TBSOCSPRequest` CBOR sequence (what is signed). Panics for the
    /// unsigned request types.
    pub fn encode_tbs(&self) -> Vec<u8> {
        self.signed_tbs_items().concat()
    }

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
            C509OcspRequest::Signed { signature_value, .. } => {
                let mut items = self.signed_tbs_items();
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

    const SIMPLE_REQ: &str = "860200501111111111111111111111111111111148a01c73a5f3b063\
345410652787fa0527bc2449a1bfc5ab31aa5a6f0d8d80";

    const UNSIGNED_REQ: &str = "8500005011111111111111111111111111111111808648a01c73a5f3\
b0633480865410652787fa0527bc2449a1bfc5ab31aa5a6f0d8d805475d8bc4fbafc6694467641e748dfd53a8\
b9d176d8054d1ac135d7da29bdcf4dca0d5281a51605b67840080482222222222222222808254d3a0c1e3db92\
e8f6810537d45cfaecf6ce417e3b80";

    // Cert identity hashes are HashId8 (8 bytes); serialNumberHash is HashId20
    // (20 bytes). Pull each field by length at the annotated byte offset.
    fn cert8(full: &[u8], off: usize) -> Vec<u8> {
        full[off..off + 8].to_vec()
    }
    fn serial20(full: &[u8], off: usize) -> Vec<u8> {
        full[off..off + 20].to_vec()
    }

    #[test]
    fn simple_request_matches_example() {
        let full = hex::decode(SIMPLE_REQ).unwrap();
        // Offsets from the draft annotation: nonce@4 (16B), issuerCertHash@21
        // (8B), serialNumberHash@30 (20B).
        let req = C509OcspRequest::Simple {
            hash_algorithm: hashalg::SHA_256,
            nonce: Some(full[4..20].to_vec()),
            issuer_cert_hash: cert8(&full, 21),
            serial_number_hash: serial20(&full, 30),
            extensions: vec![],
        };
        assert_eq!(hex::encode(req.encode()), hex::encode(&full));
    }

    #[test]
    fn unsigned_request_matches_example() {
        let full = hex::decode(UNSIGNED_REQ).unwrap();
        // From the annotation: nonce@4; issuer0 hash@23; serial hashes@34,56,78;
        // issuer1 hash@100; serial hash@111.
        let sc = |off: usize| SingleCertRequest {
            serial_number_hash: serial20(&full, off),
            extensions: vec![],
        };
        let req = C509OcspRequest::Unsigned {
            hash_algorithm: hashalg::SHA_256,
            nonce: Some(full[4..20].to_vec()),
            extensions: vec![],
            requests: vec![
                PerIssuerOCSPRequest {
                    issuer_cert_hash: cert8(&full, 23),
                    extensions: vec![],
                    single_requests: vec![sc(34), sc(56), sc(78)],
                },
                PerIssuerOCSPRequest {
                    issuer_cert_hash: cert8(&full, 100),
                    extensions: vec![],
                    single_requests: vec![sc(111)],
                },
            ],
        };
        assert_eq!(hex::encode(req.encode()), hex::encode(&full));
    }

    const SIGNED_REQ_NO_CERT: &str = "89010c0050111111111111111111111111111111114844f052\
8b56f35ad9808648a01c73a5f3b0633480865410652787fa0527bc2449a1bfc5ab31aa5a6f0d8d805475d8bc4\
fbafc6694467641e748dfd53a8b9d176d8054d1ac135d7da29bdcf4dca0d5281a51605b67840080482222222222\
222222808254d3a0c1e3db92e8f6810537d45cfaecf6ce417e3b80f658407da70be70d8c88f5150218b2f60a21\
320d26faf8dc198f16654d54cb617a1c3c3f420b3f2fbf74c9b107d81d1815c2ce09b22eaf491313003c49d43a\
ab8d970b";

    fn example_tbs(full_hex: &str) -> Vec<u8> {
        let full = hex::decode(full_hex).unwrap();
        full[1..full.len() - 66].to_vec()
    }

    #[test]
    fn signed_request_no_cert_tbs_matches_example() {
        let full = hex::decode(SIGNED_REQ_NO_CERT).unwrap();
        // requestorCertHash@22; issuer0 hash@33; serials@44,66,88;
        // issuer1 hash@110; serial@121.
        let sc = |off: usize| SingleCertRequest {
            serial_number_hash: serial20(&full, off),
            extensions: vec![],
        };
        let req = C509OcspRequest::Signed {
            signature_algorithm: crate::registry::SIG_ED25519,
            hash_algorithm: hashalg::SHA_256,
            nonce: Some(full[5..21].to_vec()),
            requestor_cert_hash: cert8(&full, 22),
            extensions: vec![],
            requests: vec![
                PerIssuerOCSPRequest {
                    issuer_cert_hash: cert8(&full, 33),
                    extensions: vec![],
                    single_requests: vec![sc(44), sc(66), sc(88)],
                },
                PerIssuerOCSPRequest {
                    issuer_cert_hash: cert8(&full, 110),
                    extensions: vec![],
                    single_requests: vec![sc(121)],
                },
            ],
            requestor_certs: None,
            signature_value: vec![],
        };
        assert_eq!(hex::encode(req.encode_tbs()),
                   hex::encode(example_tbs(SIGNED_REQ_NO_CERT)));
    }
}

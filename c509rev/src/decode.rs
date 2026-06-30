//! Decoding (CBOR → structs) for C509 CRL and OCSP, plus shared helpers.
//!
//! Decoding uses `serde_cbor::Value` to parse, then maps to the crate's structs.
//! Because the draft mandates deterministic CBOR and both `serde_cbor` and the
//! `c509::lcbor` encoder emit canonical/minimal encodings, a decode→re-encode
//! round-trip reproduces the original bytes — the validation used in the tests.
//!
//! v1 implements CRL decode; OCSP decode follows the same pattern.

use serde_cbor::Value;

use crate::common::{Extension, Name};
use crate::crl::{
    C509Crl, CrlInfo, PerIssuerRevokedCerts, RemovedCert, RevokedCert, RevokedCertsControl,
};
use crate::discriminator;
use crate::ocsp_req::{C509OcspRequest, PerIssuerOCSPRequest, SingleCertRequest};
use crate::ocsp_resp::{
    C509OcspResponse, CertStatus, PerIssuerOCSPResponse, SingleCertResponse,
};
use crate::status_list::C509StatusList;

/// Decoding error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The CBOR was malformed or not the expected major type / shape.
    Malformed(&'static str),
    /// A field held a value outside the supported subset (e.g. a non-text Name).
    Unsupported(&'static str),
    /// The underlying CBOR parser failed.
    Cbor(String),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::Malformed(s) => write!(f, "malformed C509 revocation object: {s}"),
            DecodeError::Unsupported(s) => write!(f, "unsupported in v1: {s}"),
            DecodeError::Cbor(s) => write!(f, "CBOR parse error: {s}"),
        }
    }
}

impl std::error::Error for DecodeError {}

// --- small Value accessors -------------------------------------------------

fn as_array(v: &Value, ctx: &'static str) -> Result<Vec<Value>, DecodeError> {
    match v {
        Value::Array(a) => Ok(a.clone()),
        _ => Err(DecodeError::Malformed(ctx)),
    }
}

fn as_u64(v: &Value, ctx: &'static str) -> Result<u64, DecodeError> {
    match v {
        Value::Integer(i) if *i >= 0 => Ok(*i as u64),
        _ => Err(DecodeError::Malformed(ctx)),
    }
}

fn as_i64(v: &Value, ctx: &'static str) -> Result<i64, DecodeError> {
    match v {
        Value::Integer(i) => Ok(*i as i64),
        _ => Err(DecodeError::Malformed(ctx)),
    }
}

fn as_bytes(v: &Value, ctx: &'static str) -> Result<Vec<u8>, DecodeError> {
    match v {
        Value::Bytes(b) => Ok(b.clone()),
        _ => Err(DecodeError::Malformed(ctx)),
    }
}

fn is_null(v: &Value) -> bool {
    matches!(v, Value::Null)
}

fn opt_bytes(v: &Value, ctx: &'static str) -> Result<Option<Vec<u8>>, DecodeError> {
    if is_null(v) { Ok(None) } else { Ok(Some(as_bytes(v, ctx)?)) }
}

fn opt_u64(v: &Value, ctx: &'static str) -> Result<Option<u64>, DecodeError> {
    if is_null(v) { Ok(None) } else { Ok(Some(as_u64(v, ctx)?)) }
}

/// Decode a `Name` (v1: the single-CN text form only).
fn decode_name(v: &Value) -> Result<Name, DecodeError> {
    match v {
        Value::Text(s) => Ok(Name::Text(s.clone())),
        _ => Err(DecodeError::Unsupported("non-text Name")),
    }
}

/// Re-serialise a CBOR `Value` to its canonical bytes (for extension values).
fn value_bytes(v: &Value) -> Result<Vec<u8>, DecodeError> {
    serde_cbor::to_vec(v).map_err(|e| DecodeError::Cbor(e.to_string()))
}

/// Decode an extensions array of flattened `(id, value)` pairs.
fn decode_extensions(v: &Value) -> Result<Vec<Extension>, DecodeError> {
    let a = as_array(v, "extensions")?;
    if a.len() % 2 != 0 {
        return Err(DecodeError::Malformed("odd-length extensions array"));
    }
    let mut out = Vec::with_capacity(a.len() / 2);
    for pair in a.chunks(2) {
        out.push(Extension {
            id: as_i64(&pair[0], "extension id")?,
            value: value_bytes(&pair[1])?,
        });
    }
    Ok(out)
}

// --- fixed-width revoked/removed entry parsing -----------------------------

fn be_to_u64(bytes: &[u8]) -> u64 {
    let mut v = 0u64;
    for &b in bytes {
        v = (v << 8) | b as u64;
    }
    v
}

fn decode_revoked(
    body: &[u8],
    c: &RevokedCertsControl,
) -> Result<Vec<RevokedCert>, DecodeError> {
    let with_reason = c.flags & 0x02 != 0;
    let stride = c.serial_number_length + c.date_length + usize::from(with_reason);
    if stride == 0 || body.len() % stride != 0 {
        return Err(DecodeError::Malformed("revokedCerts not a multiple of entry width"));
    }
    let mut out = Vec::new();
    for e in body.chunks(stride) {
        let serial = e[..c.serial_number_length].to_vec();
        let mut p = c.serial_number_length;
        let offset = be_to_u64(&e[p..p + c.date_length]);
        p += c.date_length;
        let reason = if with_reason { Some(e[p]) } else { None };
        out.push(RevokedCert {
            serial,
            revocation_date: c.base_date + offset,
            reason,
        });
    }
    Ok(out)
}

fn decode_removed(
    body: &[u8],
    c: &RevokedCertsControl,
) -> Result<Vec<RemovedCert>, DecodeError> {
    // Removed entries never carry a reason byte.
    let stride = c.serial_number_length + c.date_length;
    if stride == 0 || body.len() % stride != 0 {
        return Err(DecodeError::Malformed("removedFromCRLCerts not a multiple of entry width"));
    }
    let mut out = Vec::new();
    for e in body.chunks(stride) {
        let serial = e[..c.serial_number_length].to_vec();
        let offset = be_to_u64(&e[c.serial_number_length..]);
        out.push(RemovedCert { serial, removal_date: c.base_date + offset });
    }
    Ok(out)
}

fn decode_control(v: &Value) -> Result<RevokedCertsControl, DecodeError> {
    let a = as_array(v, "revokedCertsControl")?;
    if a.len() != 4 {
        return Err(DecodeError::Malformed("revokedCertsControl must be array[4]"));
    }
    Ok(RevokedCertsControl {
        flags: as_u64(&a[0], "flags")?,
        serial_number_length: as_u64(&a[1], "serialNumberLength")? as usize,
        date_length: as_u64(&a[2], "dateLength")? as usize,
        base_date: as_u64(&a[3], "baseDate")?,
    })
}

fn decode_per_issuer(
    group: &[Value],
) -> Result<PerIssuerRevokedCerts, DecodeError> {
    let issuer = if is_null(&group[0]) { None } else { Some(decode_name(&group[0])?) };
    let control = if is_null(&group[1]) { None } else { Some(decode_control(&group[1])?) };
    let extensions = decode_extensions(&group[2])?;
    let (revoked, removed) = match &control {
        None => (vec![], vec![]),
        Some(c) => {
            let revoked = match opt_bytes(&group[3], "revokedCerts")? {
                Some(b) => decode_revoked(&b, c)?,
                None => vec![],
            };
            let removed = match opt_bytes(&group[4], "removedFromCRLCerts")? {
                Some(b) => decode_removed(&b, c)?,
                None => vec![],
            };
            (revoked, removed)
        }
    };
    Ok(PerIssuerRevokedCerts { issuer, control, extensions, revoked, removed })
}

impl C509Crl {
    /// Decode a `C509CRL` from its CBOR bytes.
    pub fn decode(bytes: &[u8]) -> Result<C509Crl, DecodeError> {
        let v: Value = serde_cbor::from_slice(bytes)
            .map_err(|e| DecodeError::Cbor(e.to_string()))?;
        let a = as_array(&v, "C509CRL top-level")?;
        if a.len() != 11 {
            return Err(DecodeError::Malformed("C509CRL must be array[11]"));
        }
        // nextUpdate is a forward delta from thisUpdate (§5.3.6); reconstruct the
        // absolute time the struct holds.
        let this_update = as_u64(&a[5], "thisUpdate")?;
        let info = CrlInfo {
            crl_type: as_u64(&a[0], "crlType")?,
            signature_algorithm: as_i64(&a[1], "signatureAlgorithm")?,
            authority_subject: decode_name(&a[2])?,
            authority_key_identifier: opt_bytes(&a[3], "authorityKeyIdentifier")?,
            crl_number: as_u64(&a[4], "crlNumber")?,
            this_update,
            next_update: opt_u64(&a[6], "nextUpdate")?.map(|d| this_update + d),
            base_crl_number: opt_u64(&a[7], "baseCrlNumber")?,
            crl_extensions: decode_extensions(&a[8])?,
        };
        let revoked_certs_list = if is_null(&a[9]) {
            None
        } else {
            let list = as_array(&a[9], "revokedCertsList")?;
            if list.len() % 5 != 0 {
                return Err(DecodeError::Malformed("revokedCertsList not a multiple of 5"));
            }
            let mut pers = Vec::new();
            for g in list.chunks(5) {
                pers.push(decode_per_issuer(g)?);
            }
            Some(pers)
        };
        let signature_value = as_bytes(&a[10], "signatureValue")?;
        Ok(C509Crl { info, revoked_certs_list, signature_value })
    }
}

impl C509StatusList {
    /// Decode a `C509StatusList` from its CBOR bytes.
    pub fn decode(bytes: &[u8]) -> Result<C509StatusList, DecodeError> {
        let v: Value = serde_cbor::from_slice(bytes)
            .map_err(|e| DecodeError::Cbor(e.to_string()))?;
        let a = as_array(&v, "C509StatusList top-level")?;
        if a.len() != 11 {
            return Err(DecodeError::Malformed("C509StatusList must be array[11]"));
        }
        // nextUpdate is a forward delta from thisUpdate (as in the CRL).
        let this_update = as_u64(&a[5], "thisUpdate")?;
        Ok(C509StatusList {
            status_list_type: as_u64(&a[0], "statusListType")?,
            signature_algorithm: as_i64(&a[1], "signatureAlgorithm")?,
            authority_subject: decode_name(&a[2])?,
            authority_key_identifier: opt_bytes(&a[3], "authorityKeyIdentifier")?,
            status_list_number: as_u64(&a[4], "statusListNumber")?,
            this_update,
            next_update: opt_u64(&a[6], "nextUpdate")?.map(|d| this_update + d),
            base_index: as_u64(&a[7], "baseIndex")?,
            status_bits: as_bytes(&a[8], "statusBits")?,
            extensions: decode_extensions(&a[9])?,
            signature_value: as_bytes(&a[10], "signatureValue")?,
        })
    }
}

// --- OCSP request -----------------------------------------------------------

fn opt_certs(v: &Value) -> Result<Option<Vec<u8>>, DecodeError> {
    // requestor/responder certs: opaque COSE_C509 / #6.121(COSE_X509) / null.
    if is_null(v) { Ok(None) } else { Ok(Some(value_bytes(v)?)) }
}

fn decode_req_requests(v: &Value) -> Result<Vec<PerIssuerOCSPRequest>, DecodeError> {
    let a = as_array(v, "requests")?;
    if a.len() % 3 != 0 {
        return Err(DecodeError::Malformed("requests not a multiple of 3"));
    }
    let mut out = Vec::new();
    for g in a.chunks(3) {
        let singles = as_array(&g[2], "singleRequests")?;
        if singles.len() % 2 != 0 {
            return Err(DecodeError::Malformed("singleRequests not a multiple of 2"));
        }
        let mut single_requests = Vec::new();
        for s in singles.chunks(2) {
            single_requests.push(SingleCertRequest {
                serial_number_hash: as_bytes(&s[0], "serialNumberHash")?,
                extensions: decode_extensions(&s[1])?,
            });
        }
        out.push(PerIssuerOCSPRequest {
            issuer_cert_hash: as_bytes(&g[0], "issuerCertHash")?,
            extensions: decode_extensions(&g[1])?,
            single_requests,
        });
    }
    Ok(out)
}

impl C509OcspRequest {
    /// Decode a `C509OCSPRequest` from its CBOR bytes.
    pub fn decode(bytes: &[u8]) -> Result<C509OcspRequest, DecodeError> {
        let v: Value = serde_cbor::from_slice(bytes)
            .map_err(|e| DecodeError::Cbor(e.to_string()))?;
        let a = as_array(&v, "C509OCSPRequest top-level")?;
        let ty = as_u64(a.first().ok_or(DecodeError::Malformed("empty array"))?,
                        "ocspRequestType")?;
        match ty {
            discriminator::OCSP_REQ_UNSIGNED => {
                if a.len() != 5 {
                    return Err(DecodeError::Malformed("Unsigned request must be array[5]"));
                }
                Ok(C509OcspRequest::Unsigned {
                    hash_algorithm: as_i64(&a[1], "hashAlgorithm")?,
                    nonce: opt_bytes(&a[2], "nonce")?,
                    extensions: decode_extensions(&a[3])?,
                    requests: decode_req_requests(&a[4])?,
                })
            }
            discriminator::OCSP_REQ_SIMPLE => {
                if a.len() != 6 {
                    return Err(DecodeError::Malformed("Simple request must be array[6]"));
                }
                Ok(C509OcspRequest::Simple {
                    hash_algorithm: as_i64(&a[1], "hashAlgorithm")?,
                    nonce: opt_bytes(&a[2], "nonce")?,
                    issuer_cert_hash: as_bytes(&a[3], "issuerCertHash")?,
                    serial_number_hash: as_bytes(&a[4], "serialNumberHash")?,
                    extensions: decode_extensions(&a[5])?,
                })
            }
            discriminator::OCSP_REQ_SIGNED => {
                if a.len() != 9 {
                    return Err(DecodeError::Malformed("Signed request must be array[9]"));
                }
                Ok(C509OcspRequest::Signed {
                    signature_algorithm: as_i64(&a[1], "signatureAlgorithm")?,
                    hash_algorithm: as_i64(&a[2], "hashAlgorithm")?,
                    nonce: opt_bytes(&a[3], "nonce")?,
                    requestor_cert_hash: as_bytes(&a[4], "requestorCertHash")?,
                    extensions: decode_extensions(&a[5])?,
                    requests: decode_req_requests(&a[6])?,
                    requestor_certs: opt_certs(&a[7])?,
                    signature_value: as_bytes(&a[8], "signatureValue")?,
                })
            }
            _ => Err(DecodeError::Malformed("unknown ocspRequestType")),
        }
    }
}

// --- OCSP response ------------------------------------------------------------

fn decode_cert_status(v: &Value) -> Result<CertStatus, DecodeError> {
    match v {
        Value::Integer(0) => Ok(CertStatus::Good),
        Value::Integer(1) => Ok(CertStatus::NotIssued),
        Value::Integer(2) => Ok(CertStatus::Unknown),
        Value::Array(a) if a.len() == 2 => Ok(CertStatus::Revoked {
            revocation_time: as_u64(&a[0], "revocationTime")?,
            revocation_reason: as_i64(&a[1], "revocationReason")?,
        }),
        _ => Err(DecodeError::Malformed("certStatus")),
    }
}

/// OCSP `thisUpdate` is `nint / 0` (non-positive); return seconds *back*.
fn decode_this_update_back(v: &Value) -> Result<u64, DecodeError> {
    let i = as_i64(v, "thisUpdate")?;
    if i > 0 {
        return Err(DecodeError::Malformed("thisUpdate must be <= 0"));
    }
    Ok((-i) as u64)
}

fn decode_resp_responses(v: &Value) -> Result<Vec<PerIssuerOCSPResponse>, DecodeError> {
    let a = as_array(v, "responses")?;
    if a.len() % 3 != 0 {
        return Err(DecodeError::Malformed("responses not a multiple of 3"));
    }
    let mut out = Vec::new();
    for g in a.chunks(3) {
        let singles = as_array(&g[2], "singleResponses")?;
        if singles.len() % 5 != 0 {
            return Err(DecodeError::Malformed("singleResponses not a multiple of 5"));
        }
        let mut single_responses = Vec::new();
        for s in singles.chunks(5) {
            single_responses.push(SingleCertResponse {
                serial_number_hash: as_bytes(&s[0], "serialNumberHash")?,
                cert_status: decode_cert_status(&s[1])?,
                this_update_back: decode_this_update_back(&s[2])?,
                next_update_forward: opt_u64(&s[3], "nextUpdate")?,
                extensions: decode_extensions(&s[4])?,
            });
        }
        out.push(PerIssuerOCSPResponse {
            issuer_cert_hash: as_bytes(&g[0], "issuerCertHash")?,
            extensions: decode_extensions(&g[1])?,
            single_responses,
        });
    }
    Ok(out)
}

impl C509OcspResponse {
    /// Decode a `C509OCSPResponse` from its CBOR bytes.
    pub fn decode(bytes: &[u8]) -> Result<C509OcspResponse, DecodeError> {
        let v: Value = serde_cbor::from_slice(bytes)
            .map_err(|e| DecodeError::Cbor(e.to_string()))?;
        let a = as_array(&v, "C509OCSPResponse top-level")?;
        let ty = as_u64(a.first().ok_or(DecodeError::Malformed("empty array"))?,
                        "ocspResponseType")?;
        match ty {
            discriminator::OCSP_RESP_ERROR => {
                if a.len() != 2 {
                    return Err(DecodeError::Malformed("Error response must be array[2]"));
                }
                Ok(C509OcspResponse::Error {
                    response_status: as_i64(&a[1], "responseStatus")?,
                })
            }
            discriminator::OCSP_RESP_BASIC => {
                if a.len() != 10 {
                    return Err(DecodeError::Malformed("Basic response must be array[10]"));
                }
                Ok(C509OcspResponse::Basic {
                    signature_algorithm: as_i64(&a[1], "signatureAlgorithm")?,
                    hash_algorithm: as_i64(&a[2], "hashAlgorithm")?,
                    nonce: opt_bytes(&a[3], "nonce")?,
                    responder_cert_hash: as_bytes(&a[4], "responderCertHash")?,
                    produced_at: as_u64(&a[5], "producedAt")?,
                    extensions: decode_extensions(&a[6])?,
                    responses: decode_resp_responses(&a[7])?,
                    responder_certs: opt_certs(&a[8])?,
                    signature_value: as_bytes(&a[9], "signatureValue")?,
                })
            }
            discriminator::OCSP_RESP_SIMPLE => {
                if a.len() != 14 {
                    return Err(DecodeError::Malformed("Simple response must be array[14]"));
                }
                Ok(C509OcspResponse::Simple {
                    signature_algorithm: as_i64(&a[1], "signatureAlgorithm")?,
                    hash_algorithm: as_i64(&a[2], "hashAlgorithm")?,
                    nonce: opt_bytes(&a[3], "nonce")?,
                    responder_cert_hash: as_bytes(&a[4], "responderCertHash")?,
                    issuer_cert_hash: as_bytes(&a[5], "issuerCertHash")?,
                    serial_number_hash: as_bytes(&a[6], "serialNumberHash")?,
                    cert_status: decode_cert_status(&a[7])?,
                    produced_at: as_u64(&a[8], "producedAt")?,
                    this_update_back: decode_this_update_back(&a[9])?,
                    next_update_forward: opt_u64(&a[10], "nextUpdate")?,
                    extensions: decode_extensions(&a[11])?,
                    responder_certs: opt_certs(&a[12])?,
                    signature_value: as_bytes(&a[13], "signatureValue")?,
                })
            }
            _ => Err(DecodeError::Malformed("unknown ocspResponseType")),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::crl::C509Crl;
    use crate::ocsp_req::C509OcspRequest;
    use crate::ocsp_resp::C509OcspResponse;

    // The four CRL examples (full bytes), as in crl.rs.
    const NO_REVOKED: &str = "8b000c6f746573742063726c6f6373702d6361542f45e78d2caedf368cdf53c39005d492450e1056011a6775d7001a00093a80f680f6584013834f4e38aa9f0dc5b8d21c8650c776a6d961c31c894c36a71a6433f5ed7d30e67f787f13c7e4c349b2848a181fdbbce361a14c220021c4a267367ad5f1d90d";
    const REVOKED: &str = "8b000c6f746573742063726c6f6373702d6361542f45e78d2caedf368cdf53c39005d492450e1056021a677c71721a00093a80f68085f6840302031a677488728218571a677485805824112206978006123400000001334403f480065566015180065678054600009abc02a30000f6584070bb7a38065fbcabfe615170f05a9a9fe83dc892d5f735812b2a053af4b300eb466babb4f1a387cdce90d8302c680b77aa61566423d7c235f7bd31344cf7f405";
    const DELTA: &str = "8b000c6f746573742063726c6f6373702d6361542f45e78d2caedf368cdf53c39005d492450e1056031a677dc2f21a0002a300028085f6840302021a677d1a32804f34120000017856a84800bc9aa7d0004c112200003344000055660000584051bda2027ca7ab1a3606ba1091e77200cec9cd7a3c2acd29e1868648d8b19cf9d14a0e268ad67ff4a697fc0b684809dfc92d0b6882e5b06b1d49a1659291ce07";
    const INDIRECT: &str = "8b000c6a63726c2d7369676e65725409e433582556550a27db4a19bce2d660884722b6041a677c71721a00093a80f6808a6f746573742063726c6f6373702d6361840302031a6774887280521234000000015678054600009abc02a30000f66a6578616d706c65204341840302031a6775d9f28052112205460006334402a30006556600000006f65840f00d6270f91486a7f378d06f01a807e64e086bb366be3a1592ce4a64bffd621f30e2ab93766b4f8818116ab7da7bedf7c3ebcbdeac6d0455f5f5669712006205";

    fn round_trip(hexstr: &str) {
        let bytes = hex::decode(hexstr).unwrap();
        let crl = C509Crl::decode(&bytes).unwrap();
        assert_eq!(hex::encode(crl.encode()), hexstr,
                   "decode->encode must reproduce the original bytes");
    }

    #[test]
    fn crl_round_trips_all_examples() {
        round_trip(NO_REVOKED);
        round_trip(REVOKED);
        round_trip(DELTA);
        round_trip(INDIRECT);
    }

    // OCSP request examples.
    const SIMPLE_REQ: &str = "860200501111111111111111111111111111111148a01c73a5f3b063345410652787fa0527bc2449a1bfc5ab31aa5a6f0d8d80";
    const UNSIGNED_REQ: &str = "8500005011111111111111111111111111111111808648a01c73a5f3b0633480865410652787fa0527bc2449a1bfc5ab31aa5a6f0d8d805475d8bc4fbafc6694467641e748dfd53a8b9d176d8054d1ac135d7da29bdcf4dca0d5281a51605b67840080482222222222222222808254d3a0c1e3db92e8f6810537d45cfaecf6ce417e3b80";
    const SIGNED_REQ: &str = "89010c0050111111111111111111111111111111114844f0528b56f35ad9808648a01c73a5f3b0633480865410652787fa0527bc2449a1bfc5ab31aa5a6f0d8d805475d8bc4fbafc6694467641e748dfd53a8b9d176d8054d1ac135d7da29bdcf4dca0d5281a51605b67840080482222222222222222808254d3a0c1e3db92e8f6810537d45cfaecf6ce417e3b80f658407da70be70d8c88f5150218b2f60a21320d26faf8dc198f16654d54cb617a1c3c3f420b3f2fbf74c9b107d81d1815c2ce09b22eaf491313003c49d43aab8d970b";

    // OCSP response examples.
    const ERROR_RESP: &str = "820006";
    const SIMPLE_RESP: &str = "8e020c005011111111111111111111111111111111480600867838e3311a48a01c73a5f3b063345410652787fa0527bc2449a1bfc5ab31aa5a6f0d8d001a67c4f10039707f19627080f65840e3419955aeb3d74ad5bc7d32264e8976c3ab6f68643c6bf66cc2f9352ff3e861a0bd1506c78b09d3fae869d1fd3c87ef461cf6d2096ea0ac11fcff5ebc0fa70c";
    const BASIC_RESP: &str = "8a010c005011111111111111111111111111111111480600867838e3311a1a67c4f100808648a01c73a5f3b06334808f5410652787fa0527bc2449a1bfc5ab31aa5a6f0d8d0039707f196270805475d8bc4fbafc6694467641e748dfd53a8b9d176d0139707f1962708054d1ac135d7da29bdcf4dca0d5281a51605b678400821a67c32f000439707f19627080482222222222222222808554d3a0c1e3db92e8f6810537d45cfaecf6ce417e3b0239707f19627080f65840e4869c57a66bab501acaeb7e5024105253d72f45d349ae21fb941abe4435f8a6c9d1ca5d2784ab30cf177ff075b5502aeaee09c1146cf490663eaed9243a760d";

    fn rt_req(hexstr: &str) {
        let bytes = hex::decode(hexstr).unwrap();
        assert_eq!(hex::encode(C509OcspRequest::decode(&bytes).unwrap().encode()), hexstr);
    }

    fn rt_resp(hexstr: &str) {
        let bytes = hex::decode(hexstr).unwrap();
        assert_eq!(hex::encode(C509OcspResponse::decode(&bytes).unwrap().encode()), hexstr);
    }

    #[test]
    fn ocsp_request_round_trips_all_examples() {
        rt_req(SIMPLE_REQ);
        rt_req(UNSIGNED_REQ);
        rt_req(SIGNED_REQ);
    }

    #[test]
    fn ocsp_response_round_trips_all_examples() {
        rt_resp(ERROR_RESP);
        rt_resp(SIMPLE_RESP);
        rt_resp(BASIC_RESP);
    }
}

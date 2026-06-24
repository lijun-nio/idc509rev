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
        let info = CrlInfo {
            crl_type: as_u64(&a[0], "crlType")?,
            signature_algorithm: as_i64(&a[1], "signatureAlgorithm")?,
            authority_subject: decode_name(&a[2])?,
            authority_key_identifier: opt_bytes(&a[3], "authorityKeyIdentifier")?,
            crl_number: as_u64(&a[4], "crlNumber")?,
            this_update: as_u64(&a[5], "thisUpdate")?,
            next_update: opt_u64(&a[6], "nextUpdate")?,
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
    const NO_REVOKED: &str = "8b000c6f746573742063726c6f6373702d6361542f45e78d2caedf368cdf53c39005d492450e1056011a6775d7001a677f1180f680f6584078bea0b6c4f89bcacb600d2c6a878e6ce88c9313d2b32ee2ac289c95031ee0dfa5a2d42083f124bcc025c4a0b10677b993b05b10d74825eeb25dd7bdfb96bd09";
    const REVOKED: &str = "8b000c6f746573742063726c6f6373702d6361542f45e78d2caedf368cdf53c39005d492450e1056021a677c71721a6785abf2f68085f6840302031a677488728218571a677485805824112206978006123400000001334403f480065566015180065678054600009abc02a30000f6584071fa09f11e37b880ccde7ee6dde6a76244a36ca1f07f2ec52ab03a7324c1e5d2a42a001731b3af5977b30b0e2a38ae7cc745bc3464d349750e0ae18af6bf8d0f";
    const DELTA: &str = "8b000c6f746573742063726c6f6373702d6361542f45e78d2caedf368cdf53c39005d492450e1056031a677dc2f21a678065f2028085f6840302021a677d1a32804f34120000017856a84800bc9aa7d0004c11220000334400005566000058406a6db5affbc1e72b76709aa2b5eeaaf7660a9647d47520a32f61db220afdc6fc7c48e712993d4510b35832b15fc003da8be95280678dc793fb0795e1ce6d220a";
    const INDIRECT: &str = "8b000c6a63726c2d7369676e65725409e433582556550a27db4a19bce2d660884722b6041a677c71721a6785abf2f6808a6f746573742063726c6f6373702d6361840302031a6774887280521234000000015678054600009abc02a30000f66a6578616d706c65204341840302031a6775d9f28052112205460006334402a30006556600000006f65840a301bc4c9c68f5c4455cd811fdebcb04d643f1799b8f61935e6270cb1992030c0027960eac7924a3f01acdae25caaea45e5c324b00164819e369784adcd52509";

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
    const SIMPLE_REQ: &str = "86020150111111111111111111111111111111115820a01c73a5f3b063344257d02693059ded8e22c4433b1a4d85efae22f7f9d7e43c582010652787fa0527bc2449a1bfc5ab31aa5a6f0d8d6b998e4fede7d90dca47f00480";
    const UNSIGNED_REQ: &str = "850001501111111111111111111111111111111180865820a01c73a5f3b063344257d02693059ded8e22c4433b1a4d85efae22f7f9d7e43c8086582010652787fa0527bc2449a1bfc5ab31aa5a6f0d8d6b998e4fede7d90dca47f00480582075d8bc4fbafc6694467641e748dfd53a8b9d176dfa3d05b3e98a4d6e5c55f165805820d1ac135d7da29bdcf4dca0d5281a51605b678400c26408cadc3a32fc1b6ad5e3805820222222222222222222222222222222222222222222222222222222222222222280825820d3a0c1e3db92e8f6810537d45cfaecf6ce417e3b264e50cb4f69dd853401c5dd80";
    const SIGNED_REQ: &str = "89010c015011111111111111111111111111111111582044f0528b56f35ad998049b306ff9a8b06fa79de8146946fe254b00c62a622a5d80865820a01c73a5f3b063344257d02693059ded8e22c4433b1a4d85efae22f7f9d7e43c8086582010652787fa0527bc2449a1bfc5ab31aa5a6f0d8d6b998e4fede7d90dca47f00480582075d8bc4fbafc6694467641e748dfd53a8b9d176dfa3d05b3e98a4d6e5c55f165805820d1ac135d7da29bdcf4dca0d5281a51605b678400c26408cadc3a32fc1b6ad5e3805820222222222222222222222222222222222222222222222222222222222222222280825820d3a0c1e3db92e8f6810537d45cfaecf6ce417e3b264e50cb4f69dd853401c5dd80f65840ff755e078e731174dfd1f93e24c5b539ce3e1fe1a1ce51f387f12c6cd8c13aea6d87d4be33b6b3bf20c268afa19dcb6bafedf5e8a26131a027474e7b5831c106";

    // OCSP response examples.
    const ERROR_RESP: &str = "820006";
    const SIMPLE_RESP: &str = "8e020c01501111111111111111111111111111111158200600867838e3311aa78b9ed60c631c86b09a6de7bc43e02a7aa7006a3443a3b25820a01c73a5f3b063344257d02693059ded8e22c4433b1a4d85efae22f7f9d7e43c582010652787fa0527bc2449a1bfc5ab31aa5a6f0d8d6b998e4fede7d90dca47f004001a67c4f10039707f19627080f65840bd269e74ac6c9ebfe4e0a46a64cfd432cc06068c4d073fd515d0d276437ae5ec8baa611d3a7795e6b299c7539af3140ee768d19a05bd23b1e2c2f546c7738b07";
    const BASIC_RESP: &str = "8a010c01501111111111111111111111111111111158200600867838e3311aa78b9ed60c631c86b09a6de7bc43e02a7aa7006a3443a3b21a6a2853f680865820a01c73a5f3b063344257d02693059ded8e22c4433b1a4d85efae22f7f9d7e43c808f582010652787fa0527bc2449a1bfc5ab31aa5a6f0d8d6b998e4fede7d90dca47f0040039707f19627080582075d8bc4fbafc6694467641e748dfd53a8b9d176dfa3d05b3e98a4d6e5c55f1650139707f196270805820d1ac135d7da29bdcf4dca0d5281a51605b678400c26408cadc3a32fc1b6ad5e3821a67c32f000439707f196270805820222222222222222222222222222222222222222222222222222222222222222280855820d3a0c1e3db92e8f6810537d45cfaecf6ce417e3b264e50cb4f69dd853401c5dd0239707f19627080f65840937ea7cccad3b9f113ed6ad0df113bf5e70fbf326e020ff5183ac87e5530ff06225f1aa048d76d39d412ec26c3ad9b74668791559e6973308e11dcabda826207";

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

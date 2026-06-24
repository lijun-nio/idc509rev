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

#[cfg(test)]
mod tests {
    use crate::crl::C509Crl;

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
}

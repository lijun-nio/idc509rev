//! Types shared across the CRL and OCSP structures.

use crate::lcbor;

/// CBOR `null` (the simple value `0xf6`), used for the many optional fields.
pub const CBOR_NULL: [u8; 1] = [0xf6];

/// Encode CBOR `null`.
pub fn null() -> Vec<u8> {
    CBOR_NULL.to_vec()
}

/// A C509 `Name`. v1 supports the single-CN UTF-8 text form (draft §7.1
/// singleton optimisation) used by every CRL/OCSP example.
#[derive(Clone, Debug)]
pub enum Name {
    /// A Name that is a single `CN` attribute carrying a UTF-8 string, encoded
    /// directly as a CBOR text string.
    Text(String),
}

impl Name {
    /// Encode this Name to its CBOR item.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Name::Text(s) => lcbor::lcbor_text(s.as_bytes()),
        }
    }
}

/// One extension as the `(extensionID: int, extensionValue: Defined)` group.
/// `value` is the already-encoded CBOR of the extension value.
#[derive(Clone, Debug)]
pub struct Extension {
    pub id: i64,
    pub value: Vec<u8>,
}

/// Encode a list of extensions as a CBOR array, each flattening to two elements
/// `(id, value)`. An empty list encodes as `array[0]` (`0x80`), as the draft
/// requires for the various `extensions` fields.
pub fn encode_extensions(exts: &[Extension]) -> Vec<u8> {
    let mut items: Vec<Vec<u8>> = Vec::with_capacity(exts.len() * 2);
    for e in exts {
        items.push(lcbor::lcbor_int(e.id));
        items.push(e.value.clone());
    }
    lcbor::lcbor_array(&items)
}

/// Encode an optional byte string field (`bytes / null`).
pub fn encode_opt_bytes(b: &Option<Vec<u8>>) -> Vec<u8> {
    match b {
        Some(v) => lcbor::lcbor_bytes(v),
        None => null(),
    }
}

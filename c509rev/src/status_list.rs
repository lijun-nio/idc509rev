//! C509 Status List (follow-up opportunity #1) — a CBOR-native, constrained
//! analogue of the W3C Bitstring Status List, completing the revocation trio
//! (OCSP = online/fresh; CRL = per-revoked download; Status List = per-issued
//! bitmap). Experimental / not in the published draft yet.
//!
//! A `C509StatusList` is a natively-signed CBOR object (same shape as
//! [`crate::crl::C509Crl`]) carrying a **raw bitmap**: bit `i` is the status of
//! the certificate at index `baseIndex + i` (1 = revoked). Lookup is O(1) by
//! index; the object size is `~baseOverhead + ceil(N/8)` regardless of how many
//! entries are revoked, so it wins over a CRL at high revocation rates (crossover
//! at revocation fraction ~ (CRL bytes/entry)/(1 bit) = ~2%). Unlike the W3C
//! list it is *uncompressed* by design — no on-device decompressor, in keeping
//! with C509's "parse, don't inflate" philosophy.
//!
//! v1: encode only (sizing); decode/sign mirror the CRL module.

use crate::lcbor;

use crate::common::{encode_extensions, Extension, Name, CBOR_NULL};
use crate::time;

/// `statusListType` discriminator. `0` = 1-bit revocation bitmap.
pub const STATUS_TYPE_REVOCATION_BITMAP: u64 = 0;

/// C509 certificate extension carrying the certificate's index into a
/// `C509StatusList` (the bit position to test). Placeholder id pending IANA;
/// alternatively, a deployment may use the certificate serial directly as the
/// index when serials are densely assigned.
pub const EXT_STATUS_LIST_INDEX: i64 = 0x5C; // TBD — experimental

/// A C509 Status List.
#[derive(Clone, Debug)]
pub struct C509StatusList {
    pub status_list_type: u64,
    pub signature_algorithm: i64,
    pub authority_subject: Name,
    pub authority_key_identifier: Option<Vec<u8>>,
    pub status_list_number: u64,
    pub this_update: u64,
    /// Absolute next-update time, or `None` (encoded like the CRL's nextUpdate).
    pub next_update: Option<u64>,
    /// Index of the first certificate covered by `status_bits`.
    pub base_index: u64,
    /// Raw bitmap; bit `i` (LSB-first within each byte) = entry `base_index + i`.
    pub status_bits: Vec<u8>,
    pub extensions: Vec<Extension>,
    /// Set by signing; required by `encode()`.
    pub signature_value: Vec<u8>,
}

impl C509StatusList {
    /// Build a revocation bitmap covering indices `0..n_issued`, with the given
    /// revoked indices set to 1.
    pub fn revocation_bitmap(n_issued: usize, revoked: &[usize]) -> Vec<u8> {
        let mut bits = vec![0u8; n_issued.div_ceil(8)];
        for &idx in revoked {
            if idx < n_issued {
                bits[idx / 8] |= 1 << (idx % 8);
            }
        }
        bits
    }

    /// Is the certificate at `index` marked revoked? O(1).
    pub fn is_revoked(&self, index: u64) -> bool {
        if index < self.base_index {
            return false;
        }
        let pos = (index - self.base_index) as usize;
        self.status_bits
            .get(pos / 8)
            .is_some_and(|b| b & (1 << (pos % 8)) != 0)
    }

    fn tbs_items(&self) -> Vec<Vec<u8>> {
        vec![
            lcbor::lcbor_uint(self.status_list_type),
            lcbor::lcbor_int(self.signature_algorithm),
            self.authority_subject.encode(),
            match &self.authority_key_identifier {
                Some(b) => lcbor::lcbor_bytes(b),
                None => CBOR_NULL.to_vec(),
            },
            lcbor::lcbor_uint(self.status_list_number),
            time::encode_abs(self.this_update),
            match self.next_update {
                Some(nu) => time::crl_next_update(nu, self.this_update),
                None => CBOR_NULL.to_vec(),
            },
            lcbor::lcbor_uint(self.base_index),
            lcbor::lcbor_bytes(&self.status_bits),
            encode_extensions(&self.extensions),
        ]
    }

    /// Encode the `TBSStatusList` CBOR sequence (what is signed).
    pub fn encode_tbs(&self) -> Vec<u8> {
        self.tbs_items().concat()
    }

    /// Encode the full `C509StatusList` array (requires `signature_value`).
    pub fn encode(&self) -> Vec<u8> {
        let mut items = self.tbs_items();
        items.push(lcbor::lcbor_bytes(&self.signature_value));
        lcbor::lcbor_array(&items)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(n_issued: usize, revoked: &[usize]) -> C509StatusList {
        C509StatusList {
            status_list_type: STATUS_TYPE_REVOCATION_BITMAP,
            signature_algorithm: crate::registry::SIG_ED25519,
            authority_subject: Name::Text("test crlocsp-ca".into()),
            authority_key_identifier: Some(vec![0u8; 20]),
            status_list_number: 1,
            this_update: 1_736_208_754,
            next_update: Some(1_736_813_554),
            base_index: 0,
            status_bits: C509StatusList::revocation_bitmap(n_issued, revoked),
            extensions: vec![],
            signature_value: vec![0u8; 64],
        }
    }

    #[test]
    fn bitmap_set_and_query() {
        let sl = sample(100, &[3, 7, 64, 99]);
        for i in [3, 7, 64, 99] {
            assert!(sl.is_revoked(i), "index {i} should be revoked");
        }
        for i in [0, 4, 63, 98] {
            assert!(!sl.is_revoked(i), "index {i} should be valid");
        }
    }

    #[test]
    fn size_is_independent_of_revocation_count() {
        // For a fixed population, the encoding size does not depend on how many
        // are revoked — the bitmap's defining property.
        let few = sample(800, &[1, 2, 3]).encode().len();
        let many = sample(800, &(0..400).collect::<Vec<_>>()).encode().len();
        assert_eq!(few, many);
        // ~ base overhead + 800/8 = 100 bytes of bitmap.
        assert!(few >= 100 && few < 250, "unexpected size {few}");
    }

    #[test]
    fn round_trips_through_decode() {
        let sl = sample(800, &[1, 7, 100, 799]);
        let bytes = sl.encode();
        let back = C509StatusList::decode(&bytes).unwrap();
        // decode -> re-encode reproduces the bytes, and the bitmap survives.
        assert_eq!(back.encode(), bytes);
        for i in [1u64, 7, 100, 799] {
            assert!(back.is_revoked(i));
        }
        assert!(!back.is_revoked(2));
    }

    #[test]
    fn sign_verify_round_trip() {
        const ED_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MC4CAQAwBQYDK2VwBCIEIC8/cbk33xCU6Pv97ni+qEo9nGD9fIwW19YVnp5XmH0I\n\
-----END PRIVATE KEY-----\n";
        use ed25519_dalek::pkcs8::DecodePrivateKey;
        let pk = ed25519_dalek::SigningKey::from_pkcs8_pem(ED_PEM)
            .unwrap().verifying_key().to_bytes().to_vec();

        let mut sl = sample(800, &[3, 9]);
        sl.signature_value = vec![];
        sl.sign(ED_PEM).unwrap();
        assert_eq!(sl.signature_value.len(), 64);
        assert!(sl.verify(&pk).is_ok());

        // Flipping a status bit invalidates the signature.
        let mut tampered = sl.clone();
        tampered.status_bits[0] ^= 0x01;
        assert!(tampered.verify(&pk).is_err());
    }
}

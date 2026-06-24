//! C509 CRL (draft §"C509 CRL").
//!
//! `C509CRL` is the flat CBOR array
//! `[crlType, signatureAlgorithm, authoritySubject, authorityKeyIdentifier,
//!   crlNumber, thisUpdate, nextUpdate, baseCrlNumber, crlExtensions,
//!   revokedCertsList, signatureValue]` (11 elements). The signature is over the
//! **CBOR Sequence** of the first ten (the `TBSCertList`); `signatureValue` is
//! the eleventh.
//!
//! `revokedCertsList` is `null` or an array holding one or more
//! `PerIssuerRevokedCerts` *groups* — each contributing **5** consecutive array
//! elements `(issuer, revokedCertsControl, extensions, revokedCerts,
//! removedFromCRLCerts)`. Within `revokedCerts`/`removedFromCRLCerts`, entries
//! are fixed-width (`serialNumberLength` + `dateLength` [+ 1 reason byte]) so a
//! sorted list is binary-searchable.
//!
//! v1 encodes; the `Name` codec currently covers the single-CN text form used by
//! all CRL examples (full `Name` / `#6.121(bytes)` is a TODO). Decode + sign +
//! verify land next.

use c509::lcbor;

use crate::common::{encode_extensions, Extension, Name, CBOR_NULL};
use crate::time;

/// `RevokedCertsControl`: fixed-width parameters for one issuer's entries.
#[derive(Clone, Debug)]
pub struct RevokedCertsControl {
    /// bit 0 (0x01) = entries sorted ascending by serial; bit 1 (0x02) = each
    /// entry carries a reason byte.
    pub flags: u64,
    pub serial_number_length: usize,
    pub date_length: usize,
    /// Reference time; entry dates are stored as non-negative offsets from it.
    pub base_date: u64,
}

impl RevokedCertsControl {
    const FLAG_SORTED: u64 = 0x01;
    const FLAG_REASON: u64 = 0x02;

    fn encode(&self) -> Vec<u8> {
        lcbor::lcbor_array(&[
            lcbor::lcbor_uint(self.flags),
            lcbor::lcbor_uint(self.serial_number_length as u64),
            lcbor::lcbor_uint(self.date_length as u64),
            time::encode_abs(self.base_date),
        ])
    }
}

/// One revoked certificate.
#[derive(Clone, Debug)]
pub struct RevokedCert {
    /// Big-endian serial number (any length; left-padded to `serialNumberLength`).
    pub serial: Vec<u8>,
    /// Absolute revocation time (POSIX); stored as an offset from `base_date`.
    pub revocation_date: u64,
    /// Reason code byte (included iff the control's reason flag is set).
    pub reason: Option<u8>,
}

/// One certificate removed from the CRL (delta CRL `removeFromCRL`).
#[derive(Clone, Debug)]
pub struct RemovedCert {
    pub serial: Vec<u8>,
    pub removal_date: u64,
}

/// Revocation information for one issuer.
#[derive(Clone, Debug)]
pub struct PerIssuerRevokedCerts {
    /// `None` ⇒ encoded as `null` ⇒ issuer is the CRL's own `authoritySubject`.
    pub issuer: Option<Name>,
    pub control: Option<RevokedCertsControl>,
    pub extensions: Vec<Extension>,
    pub revoked: Vec<RevokedCert>,
    pub removed: Vec<RemovedCert>,
}

/// `CRLInfoData` — every CRL field except `revokedCertsList`.
#[derive(Clone, Debug)]
pub struct CrlInfo {
    pub crl_type: u64,
    pub signature_algorithm: i64,
    pub authority_subject: Name,
    pub authority_key_identifier: Option<Vec<u8>>,
    pub crl_number: u64,
    pub this_update: u64,
    /// Absolute next-update time, or `None` for null. (Encoded absolute to match
    /// the examples; see `time::crl_next_update`.)
    pub next_update: Option<u64>,
    pub base_crl_number: Option<u64>,
    pub crl_extensions: Vec<Extension>,
}

/// A full `C509CRL`.
#[derive(Clone, Debug)]
pub struct C509Crl {
    pub info: CrlInfo,
    pub revoked_certs_list: Option<Vec<PerIssuerRevokedCerts>>,
    /// Set by `sign()`; required by `encode()`.
    pub signature_value: Vec<u8>,
}

/// Big-endian fixed-width encoding of `value`, left-padded with zeros to `len`.
/// Panics if `value` does not fit in `len` bytes (a CA misconfiguration).
fn fixed_be(value: u64, len: usize) -> Vec<u8> {
    let be = value.to_be_bytes();
    let mut out = vec![0u8; len];
    let take = be.len().min(len);
    out[len - take..].copy_from_slice(&be[be.len() - take..]);
    // Guard against silent truncation of a value wider than `len`.
    assert!(be[..be.len() - take].iter().all(|&b| b == 0),
            "value {value} does not fit in {len} bytes");
    out
}

/// Left-pad a big-endian serial to `len` bytes (must not exceed `len`).
fn pad_serial(serial: &[u8], len: usize) -> Vec<u8> {
    assert!(serial.len() <= len, "serial wider than serialNumberLength");
    let mut out = vec![0u8; len];
    out[len - serial.len()..].copy_from_slice(serial);
    out
}

/// Serial as an integer for sorting (serials here are small fixed-width values).
fn serial_key(serial: &[u8]) -> u128 {
    let mut k = 0u128;
    for &b in serial {
        k = (k << 8) | b as u128;
    }
    k
}

impl PerIssuerRevokedCerts {
    /// Encode `revokedCerts` (or `removedFromCRLCerts`) as a CBOR byte string,
    /// or `null` when empty. `with_reason` includes the reason byte.
    fn encode_revoked(&self, c: &RevokedCertsControl) -> Vec<u8> {
        if self.revoked.is_empty() {
            return CBOR_NULL.to_vec();
        }
        let with_reason = c.flags & RevokedCertsControl::FLAG_REASON != 0;
        let mut entries: Vec<&RevokedCert> = self.revoked.iter().collect();
        if c.flags & RevokedCertsControl::FLAG_SORTED != 0 {
            entries.sort_by_key(|e| serial_key(&e.serial));
        }
        let mut body = Vec::new();
        for e in entries {
            body.extend_from_slice(&pad_serial(&e.serial, c.serial_number_length));
            if c.date_length > 0 {
                let offset = e.revocation_date - c.base_date;
                body.extend_from_slice(&fixed_be(offset, c.date_length));
            }
            if with_reason {
                body.push(e.reason.unwrap_or(0));
            }
        }
        lcbor::lcbor_bytes(&body)
    }

    fn encode_removed(&self, c: &RevokedCertsControl) -> Vec<u8> {
        if self.removed.is_empty() {
            return CBOR_NULL.to_vec();
        }
        let mut entries: Vec<&RemovedCert> = self.removed.iter().collect();
        if c.flags & RevokedCertsControl::FLAG_SORTED != 0 {
            entries.sort_by_key(|e| serial_key(&e.serial));
        }
        let mut body = Vec::new();
        for e in entries {
            body.extend_from_slice(&pad_serial(&e.serial, c.serial_number_length));
            if c.date_length > 0 {
                let offset = e.removal_date - c.base_date;
                body.extend_from_slice(&fixed_be(offset, c.date_length));
            }
        }
        lcbor::lcbor_bytes(&body)
    }

    /// The 5 flattened array elements for this issuer.
    fn encode_group(&self) -> Vec<Vec<u8>> {
        let issuer = match &self.issuer {
            Some(n) => n.encode(),
            None => CBOR_NULL.to_vec(),
        };
        let (control, revoked, removed) = match &self.control {
            Some(c) => (c.encode(), self.encode_revoked(c), self.encode_removed(c)),
            None => (CBOR_NULL.to_vec(), CBOR_NULL.to_vec(), CBOR_NULL.to_vec()),
        };
        vec![issuer, control, encode_extensions(&self.extensions), revoked, removed]
    }
}

impl C509Crl {
    /// The ten `TBSCertList` elements, each as a complete CBOR item.
    fn tbs_items(&self) -> Vec<Vec<u8>> {
        let i = &self.info;
        vec![
            lcbor::lcbor_uint(i.crl_type),
            lcbor::lcbor_int(i.signature_algorithm),
            i.authority_subject.encode(),
            match &i.authority_key_identifier {
                Some(b) => lcbor::lcbor_bytes(b),
                None => CBOR_NULL.to_vec(),
            },
            lcbor::lcbor_uint(i.crl_number),
            time::encode_abs(i.this_update),
            match i.next_update {
                Some(nu) => time::crl_next_update(nu, i.this_update),
                None => CBOR_NULL.to_vec(),
            },
            match i.base_crl_number {
                Some(n) => lcbor::lcbor_uint(n),
                None => CBOR_NULL.to_vec(),
            },
            encode_extensions(&i.crl_extensions),
            match &self.revoked_certs_list {
                None => CBOR_NULL.to_vec(),
                Some(list) => {
                    let mut items = Vec::new();
                    for per in list {
                        items.extend(per.encode_group());
                    }
                    lcbor::lcbor_array(&items)
                }
            },
        ]
    }

    /// Encode the `TBSCertList` — the CBOR Sequence of the first ten elements
    /// (everything but `signatureValue`). This is exactly what is signed.
    pub fn encode_tbs(&self) -> Vec<u8> {
        self.tbs_items().concat()
    }

    /// Encode the full `C509CRL` array (requires `signature_value`).
    pub fn encode(&self) -> Vec<u8> {
        let mut items = self.tbs_items();
        items.push(lcbor::lcbor_bytes(&self.signature_value));
        lcbor::lcbor_array(&items)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AKI: [u8; 20] = [
        0x2f, 0x45, 0xe7, 0x8d, 0x2c, 0xae, 0xdf, 0x36, 0x8c, 0xdf,
        0x53, 0xc3, 0x90, 0x05, 0xd4, 0x92, 0x45, 0x0e, 0x10, 0x56,
    ];

    fn base_info(crl_number: u64, this_update: u64, next_update: u64) -> CrlInfo {
        CrlInfo {
            crl_type: 0,
            signature_algorithm: c509::registry::SIG_ED25519,
            authority_subject: Name::Text("test crlocsp-ca".to_string()),
            authority_key_identifier: Some(AKI.to_vec()),
            crl_number,
            this_update,
            next_update: Some(next_update),
            base_crl_number: None,
            crl_extensions: vec![],
        }
    }

    /// Strip the array header (1 byte) and the trailing Ed25519 signatureValue
    /// (`58 40` + 64 bytes = 66 bytes) to get the example's TBS bytes.
    fn example_tbs(full_hex: &str) -> Vec<u8> {
        let full = hex::decode(full_hex).unwrap();
        full[1..full.len() - 66].to_vec()
    }

    const CRL_NO_REVOKED: &str = "8b000c6f746573742063726c6f6373702d6361542f45e78d2c\
aedf368cdf53c39005d492450e1056011a6775d7001a677f1180f680f6584078bea0b6c4f89bcacb600d2c6a\
878e6ce88c9313d2b32ee2ac289c95031ee0dfa5a2d42083f124bcc025c4a0b10677b993b05b10d74825eeb2\
5dd7bdfb96bd09";

    const CRL_REVOKED: &str = "8b000c6f746573742063726c6f6373702d6361542f45e78d2caedf36\
8cdf53c39005d492450e1056021a677c71721a6785abf2f68085f6840302031a677488728218571a67748580\
5824112206978006123400000001334403f480065566015180065678054600009abc02a30000f6584071fa09\
f11e37b880ccde7ee6dde6a76244a36ca1f07f2ec52ab03a7324c1e5d2a42a001731b3af5977b30b0e2a38ae7\
cc745bc3464d349750e0ae18af6bf8d0f";

    #[test]
    fn tbs_matches_no_revoked_example() {
        let crl = C509Crl {
            info: base_info(1, 1735776000, 1736380800),
            revoked_certs_list: None,
            signature_value: vec![],
        };
        assert_eq!(hex::encode(crl.encode_tbs()),
                   hex::encode(example_tbs(CRL_NO_REVOKED)));
    }

    // crl-signer AKI used by the indirect CRL example.
    const AKI_SIGNER: [u8; 20] = [
        0x09, 0xe4, 0x33, 0x58, 0x25, 0x56, 0x55, 0x0a, 0x27, 0xdb,
        0x4a, 0x19, 0xbc, 0xe2, 0xd6, 0x60, 0x88, 0x47, 0x22, 0xb6,
    ];

    const CRL_DELTA: &str = "8b000c6f746573742063726c6f6373702d6361542f45e78d2caedf36\
8cdf53c39005d492450e1056031a677dc2f21a678065f2028085f6840302021a677d1a32804f3412000001785\
6a84800bc9aa7d0004c11220000334400005566000058406a6db5affbc1e72b76709aa2b5eeaaf7660a9647d4\
7520a32f61db220afdc6fc7c48e712993d4510b35832b15fc003da8be95280678dc793fb0795e1ce6d220a";

    const CRL_INDIRECT: &str = "8b000c6a63726c2d7369676e65725409e433582556550a27db4a19\
bce2d660884722b6041a677c71721a6785abf2f6808a6f746573742063726c6f6373702d6361840302031a677\
4887280521234000000015678054600009abc02a30000f66a6578616d706c65204341840302031a6775d9f280\
52112205460006334402a30006556600000006f65840a301bc4c9c68f5c4455cd811fdebcb04d643f1799b8f6\
1935e6270cb1992030c0027960eac7924a3f01acdae25caaea45e5c324b00164819e369784adcd52509";

    #[test]
    fn tbs_matches_delta_example() {
        let base_date = 1736251954;
        let rc = |csn: u16, off: u16, reason: u8| RevokedCert {
            serial: csn.to_be_bytes().to_vec(),
            revocation_date: base_date + off as u64,
            reason: Some(reason),
        };
        let rm = |csn: u16, off: u16| RemovedCert {
            serial: csn.to_be_bytes().to_vec(),
            removal_date: base_date + off as u64,
        };
        let per = PerIssuerRevokedCerts {
            issuer: None,
            control: Some(RevokedCertsControl {
                flags: 0x03, serial_number_length: 2, date_length: 2, base_date,
            }),
            extensions: vec![],
            revoked: vec![rc(0x3412, 0x0000, 1), rc(0x7856, 0xa848, 0), rc(0xbc9a, 0xa7d0, 0)],
            removed: vec![rm(0x1122, 0x0000), rm(0x3344, 0x0000), rm(0x5566, 0x0000)],
        };
        let mut info = base_info(3, 1736295154, 1736467954);
        info.base_crl_number = Some(2);
        let crl = C509Crl { info, revoked_certs_list: Some(vec![per]), signature_value: vec![] };
        assert_eq!(hex::encode(crl.encode_tbs()),
                   hex::encode(example_tbs(CRL_DELTA)));
    }

    #[test]
    fn tbs_matches_indirect_example() {
        let mk = |base_date: u64, entries: &[(u16, u32, u8)]| PerIssuerRevokedCerts {
            issuer: None, // set by caller
            control: Some(RevokedCertsControl {
                flags: 0x03, serial_number_length: 2, date_length: 3, base_date,
            }),
            extensions: vec![],
            revoked: entries.iter().map(|&(csn, off, r)| RevokedCert {
                serial: csn.to_be_bytes().to_vec(),
                revocation_date: base_date + off as u64,
                reason: Some(r),
            }).collect(),
            removed: vec![],
        };
        let mut g0 = mk(1735690354, &[(0x1234, 0x000000, 1), (0x5678, 0x054600, 0), (0x9abc, 0x02a300, 0)]);
        g0.issuer = Some(Name::Text("test crlocsp-ca".to_string()));
        let mut g1 = mk(1735776754, &[(0x1122, 0x054600, 6), (0x3344, 0x02a300, 6), (0x5566, 0x000000, 6)]);
        g1.issuer = Some(Name::Text("example CA".to_string()));

        let info = CrlInfo {
            crl_type: 0,
            signature_algorithm: c509::registry::SIG_ED25519,
            authority_subject: Name::Text("crl-signer".to_string()),
            authority_key_identifier: Some(AKI_SIGNER.to_vec()),
            crl_number: 4,
            this_update: 1736208754,
            next_update: Some(1736813554),
            base_crl_number: None,
            crl_extensions: vec![],
        };
        let crl = C509Crl { info, revoked_certs_list: Some(vec![g0, g1]), signature_value: vec![] };
        assert_eq!(hex::encode(crl.encode_tbs()),
                   hex::encode(example_tbs(CRL_INDIRECT)));
    }

    #[test]
    fn tbs_matches_revoked_example() {
        let control = RevokedCertsControl {
            flags: 0x03,                 // sorted + with reason
            serial_number_length: 2,
            date_length: 3,
            base_date: 1735690354,
        };
        // Entries listed out of order to exercise the sort.
        let rc = |csn: u16, off: u32, reason: u8| RevokedCert {
            serial: csn.to_be_bytes().to_vec(),
            revocation_date: 1735690354 + off as u64,
            reason: Some(reason),
        };
        let per = PerIssuerRevokedCerts {
            issuer: None,
            control: Some(control),
            extensions: vec![Extension {
                id: 87,                  // ExpiredCertsOnCRL
                value: time::encode_abs(1735689600),
            }],
            revoked: vec![
                rc(0x9abc, 0x02a300, 0),
                rc(0x1122, 0x069780, 6),
                rc(0x5678, 0x054600, 0),
                rc(0x1234, 0x000000, 1),
                rc(0x5566, 0x015180, 6),
                rc(0x3344, 0x03f480, 6),
            ],
            removed: vec![],
        };
        let crl = C509Crl {
            info: base_info(2, 1736208754, 1736813554),
            revoked_certs_list: Some(vec![per]),
            signature_value: vec![],
        };
        assert_eq!(hex::encode(crl.encode_tbs()),
                   hex::encode(example_tbs(CRL_REVOKED)));
    }
}

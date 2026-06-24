//! Identity hashes used by C509 OCSP: `issuerCertHash`, `responderCertHash`,
//! `requestorCertHash`, and `serialNumberHash` (draft §"issuerCertHash" /
//! §"serialNumberHash").
//!
//! The semantically important part is the **hash input**:
//! - a *cert* hash is over the **CBOR-encoded C509 certificate** (or the
//!   DER-encoded X.509 certificate in a hybrid deployment);
//! - a *serial number* hash is over the serial **big-endian, with no leading
//!   zero byte** (the same minimal encoding C509 certificates use).
//!
//! The output length is the [`crate::hashalg::HashLen`] decision — 8-byte
//! KID-style by default (design decision 5).

use crate::hashalg::{self, HashError, HashLen};

/// Hash a certificate's bytes (CBOR-encoded C509 or DER-encoded X.509).
///
/// Use for `issuerCertHash`, `responderCertHash`, and `requestorCertHash`.
pub fn cert_hash(alg: i64, cert_bytes: &[u8], len: HashLen)
    -> Result<Vec<u8>, HashError>
{
    hashalg::hash(alg, cert_bytes, len)
}

/// Hash a certificate serial number for `serialNumberHash`.
///
/// `serial_be` MUST be the big-endian serial with no leading zero byte.
pub fn serial_number_hash(alg: i64, serial_be: &[u8], len: HashLen)
    -> Result<Vec<u8>, HashError>
{
    hashalg::hash(alg, serial_be, len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashalg::SHA_256;

    // The CA certificate (C509, Type-2) from the draft's helper certs.
    const CA_CERT: &str = "0241010c73746573742063726c6f6373702d726f6f7463611a677485801a\
6b36ec7f6f746573742063726c6f6373702d63610c58205ef8a355a001a7c50d23494701208131a4bb2ab920\
d40bfb0ee1f6ab28ff74008801542f45e78d2caedf368cdf53c39005d492450e1056211860230107542da3a4\
03f7d2f4e0b3d8031a73ba8a839f557f0f5840e50465d60c02a2111ef3fc6e44f2a36008765b552351f9a3f5b\
2aa7c76f1f05d259847a4f4250b2e4b0ae2099762a2596d3cc1db2ccd180aa0a2d0e191310b0f";

    #[test]
    fn cert_hash_trunc8_is_kid_prefix_of_full() {
        let ca = hex::decode(CA_CERT).unwrap();
        let full = cert_hash(SHA_256, &ca, HashLen::Full).unwrap();
        let kid = cert_hash(SHA_256, &ca, HashLen::Trunc8).unwrap();
        assert_eq!(full.len(), 32);
        assert_eq!(kid.len(), 8);
        assert_eq!(kid.as_slice(), &full[..8]);
    }

    #[test]
    fn serial_number_hash_is_over_minimal_be() {
        // The hash input is the minimal big-endian serial (no leading zero).
        let serial = [0x12u8, 0x34];
        let h = serial_number_hash(SHA_256, &serial, HashLen::Full).unwrap();
        assert_eq!(h, hashalg::digest(SHA_256, &serial).unwrap());
    }

    // FINDING (2026-06-24): the OCSP examples' identity hashes are NOT
    // reproducible from the published helper-cert bytes by the documented
    // method. SHA-256 of the CA cert C509 (a01c73a5… is expected) gives
    // 6fe05673…; the C509-without-type-byte, the DER reconstruction (336 B), and
    // the responder cert all likewise fail to match issuerCertHash /
    // responderCertHash. So either the example generator hashed different cert
    // bytes than those printed, or §"issuerCertHash" underspecifies the exact
    // input (e.g. a COSE_C509 wrapper, or the certs were regenerated without
    // re-deriving the OCSP hashes). Raise with the authors; until clarified the
    // cert-hash KAT cannot be asserted. The hash *mechanism* (above) is correct.
    #[test]
    #[ignore = "example identity hashes not reproducible from published certs; see FINDING"]
    fn issuer_cert_hash_matches_example() {
        let ca = hex::decode(CA_CERT).unwrap();
        let h = cert_hash(SHA_256, &ca, HashLen::Full).unwrap();
        assert_eq!(
            hex::encode(&h),
            "a01c73a5f3b063344257d02693059ded8e22c4433b1a4d85efae22f7f9d7e43c",
        );
    }
}

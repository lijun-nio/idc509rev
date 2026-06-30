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
//! The output length is the [`crate::hashalg::HashLen`] decision: cert hashes
//! are `HashId8` (8 bytes), serial-number hashes are `HashId20` (20 bytes).

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

    // The CA certificate (C509, Type-2) from the draft's helper certs — the
    // COMPLETE CBOR-encoded certificate, i.e. the `8b` array[11] header included.
    // That whole byte string is the cert-hash input (see the KAT below).
    const CA_CERT: &str = "8b0241010c73746573742063726c6f6373702d726f6f7463611a677485801a\
6b36ec7f6f746573742063726c6f6373702d63610c58205ef8a355a001a7c50d23494701208131a4bb2ab920\
d40bfb0ee1f6ab28ff74008801542f45e78d2caedf368cdf53c39005d492450e1056211860230107542da3a4\
03f7d2f4e0b3d8031a73ba8a839f557f0f5840e50465d60c02a2111ef3fc6e44f2a36008765b552351f9a3f5b\
2aa7c76f1f05d259847a4f4250b2e4b0ae2099762a2596d3cc1db2ccd180aa0a2d0e191310b0f";

    // The OCSP responder certificate (C509, Type-2), likewise with its `8b` header.
    const RESPONDER_CERT: &str = "8b024212350c6f746573742063726c6f6373702d63611a6775d7001a\
69570a806e6f6373702d726573706f6e6465720c582081947bbc248aac79738211a8d75bf92cb777d994073d\
f23ae06380ef2c573976880154b5b4caf35401d06151df9629db579dc8cca453a8210107542f45e78d2caedf\
368cdf53c39005d492450e105627095840a01b0cbf3e34a4762d05404fd08a7aec103035358314686d72b615\
9078c76e1d88597f37531886a3f52f256fd722192b289d6844014467f1f17f05acbb7b660a";

    // The serial-number example: the X.509 serial INTEGER value 1234…1234 (20
    // bytes, big-endian, no DER tag/length) is the serialNumberHash input.
    const EXAMPLE_SERIAL: &str = "1234123412341234123412341234123412341234";

    #[test]
    fn cert_hash_id8_is_prefix_of_full() {
        let ca = hex::decode(CA_CERT).unwrap();
        let full = cert_hash(SHA_256, &ca, HashLen::Full).unwrap();
        let id8 = cert_hash(SHA_256, &ca, HashLen::CertId8).unwrap();
        assert_eq!(full.len(), 32);
        assert_eq!(id8.len(), 8);
        assert_eq!(id8.as_slice(), &full[..8]);
    }

    #[test]
    fn serial_number_hash_is_over_minimal_be() {
        // The hash input is the minimal big-endian serial (no leading zero).
        let serial = [0x12u8, 0x34];
        let full = serial_number_hash(SHA_256, &serial, HashLen::Full).unwrap();
        assert_eq!(full, hashalg::digest(SHA_256, &serial).unwrap());
        // serialNumberHash is HashId20 (leading 20 bytes).
        let id20 = serial_number_hash(SHA_256, &serial, HashLen::SerialId20).unwrap();
        assert_eq!(id20.len(), 20);
        assert_eq!(id20.as_slice(), &full[..20]);
    }

    // RESOLVED (2026-06-30, prior FINDING was a probe error): the OCSP example
    // identity hashes ARE reproducible. The cert-hash input is the COMPLETE
    // CBOR-encoded C509 certificate — the whole "Plain Hex" byte string, the `8b`
    // array[11] header included (the earlier probe dropped that header and got
    // 6fe05673…). issuerCertHash = SHA-256(CA cert)[..8], responderCertHash =
    // SHA-256(responder cert)[..8], serialNumberHash = SHA-256(raw serial)[..20].
    #[test]
    fn issuer_cert_hash_matches_example() {
        let ca = hex::decode(CA_CERT).unwrap();
        let h = cert_hash(SHA_256, &ca, HashLen::CertId8).unwrap();
        assert_eq!(hex::encode(&h), "a01c73a5f3b06334");
    }

    #[test]
    fn responder_cert_hash_matches_example() {
        let cert = hex::decode(RESPONDER_CERT).unwrap();
        let h = cert_hash(SHA_256, &cert, HashLen::CertId8).unwrap();
        assert_eq!(hex::encode(&h), "0600867838e3311a");
    }

    #[test]
    fn serial_number_hash_matches_example() {
        let serial = hex::decode(EXAMPLE_SERIAL).unwrap();
        let h = serial_number_hash(SHA_256, &serial, HashLen::SerialId20).unwrap();
        assert_eq!(hex::encode(&h), "10652787fa0527bc2449a1bfc5ab31aa5a6f0d8d");
    }
}

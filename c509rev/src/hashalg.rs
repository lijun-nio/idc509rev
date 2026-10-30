//! Hash algorithms for C509 OCSP, identified by their code points in the IANA
//! "COSE Algorithms" registry (draft §"Hash Algorithms"), plus the hash dispatch
//! used to compute `issuerCertHash`, `serialNumberHash`, and the
//! requestor/responder cert hashes.
//!
//! The `hashAlgorithm` field takes values from the COSE Algorithms registry
//! (e.g. SHA-256 = -16), aligned with the C509 certificate draft's
//! `c5t`/COSE_CertHash. The hash MUST produce an output of at least 20 bytes so
//! that `HashId20` can be derived; consequently SHA-256/64 (-15) and SHA-1 (-14)
//! MUST NOT be used, and truncated hashes such as SHA-512/256 (-17) SHOULD NOT
//! be used since `HashId8`/`HashId20` already truncate.
//!
//! ## Truncated identifiers (draft §"Truncated Hash Identifiers")
//! The draft defines two truncated-hash identifier types, and the field decides
//! the length (not a global toggle):
//! - `HashId8` ([`CERT_HASH_LEN`]) — the leading 8 bytes, used for the cert
//!   identity hashes (`issuerCertHash`, `responderCertHash`, `requestorCertHash`)
//!   where a short identifier is sufficient.
//! - `HashId20` ([`SERIAL_HASH_LEN`]) — the leading 20 bytes, used for
//!   `serialNumberHash`, where higher uniqueness lowers the collision risk.
//!
//! [`HashLen::Full`] is retained so the hash *mechanism* can be checked against
//! the full-digest test vectors.

use sha2::{Digest, Sha256, Sha384, Sha512};

/// SHA-256 (-16) — the constrained default; hardware-accelerated on the target.
pub const SHA_256: i64 = -16;
/// SHA-384 (-43).
pub const SHA_384: i64 = -43;
/// SHA-512 (-44).
pub const SHA_512: i64 = -44;
/// SHAKE128 (-18) — 256-bit output ({{RFC9054}}); not implemented in this build.
pub const SHAKE128: i64 = -18;
/// SHAKE256 (-45) — 512-bit output ({{RFC9054}}); not implemented in this build.
pub const SHAKE256: i64 = -45;

// SHA3-256, SHA3-384, SHA3-512 (FIPS 202) and SM3 (ISO/IEC 10118-3) are being
// registered in the COSE Algorithms registry by the revocation draft; their code
// points are IANA-pending (draft TBD15-TBD18). They are added here once assigned.
// This build computes only the SHA-2 family (see `digest`).

/// `HashId8` length in bytes — cert identity hashes (issuer/responder/requestor).
pub const CERT_HASH_LEN: usize = 8;
/// `HashId20` length in bytes — `serialNumberHash`.
pub const SERIAL_HASH_LEN: usize = 20;

/// How much of the digest to emit for a cert/serial hash field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashLen {
    /// Full digest — used to check the hash mechanism against full-digest vectors.
    Full,
    /// `HashId8` — leading [`CERT_HASH_LEN`] bytes (cert identity hashes).
    CertId8,
    /// `HashId20` — leading [`SERIAL_HASH_LEN`] bytes (`serialNumberHash`).
    SerialId20,
}

/// Error from [`hash`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashError {
    /// The hash algorithm id is not implemented in this reference build.
    UnsupportedAlg(i64),
}

impl std::fmt::Display for HashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HashError::UnsupportedAlg(a) =>
                write!(f, "unsupported C509 hash algorithm id {a}"),
        }
    }
}

impl std::error::Error for HashError {}

/// Compute the full digest of `data` under C509 hash algorithm `alg`.
///
/// v1 implements the SHA-2 family (the crypto profile of the draft examples and
/// the constrained default). SM3, SHA-3, and SHAKE return
/// [`HashError::UnsupportedAlg`] until added behind this same dispatch.
pub fn digest(alg: i64, data: &[u8]) -> Result<Vec<u8>, HashError> {
    let out = match alg {
        SHA_256 => Sha256::digest(data).to_vec(),
        SHA_384 => Sha384::digest(data).to_vec(),
        SHA_512 => Sha512::digest(data).to_vec(),
        other => return Err(HashError::UnsupportedAlg(other)),
    };
    Ok(out)
}

/// Compute the cert/serial hash of `data` under `alg`, truncated per `len`.
///
/// `CertId8`/`SerialId20` keep the leading [`CERT_HASH_LEN`]/[`SERIAL_HASH_LEN`]
/// bytes of the digest; `Full` returns the whole digest.
pub fn hash(alg: i64, data: &[u8], len: HashLen) -> Result<Vec<u8>, HashError> {
    let mut d = digest(alg, data)?;
    let n = match len {
        HashLen::Full => d.len(),
        HashLen::CertId8 => CERT_HASH_LEN,
        HashLen::SerialId20 => SERIAL_HASH_LEN,
    };
    d.truncate(n);
    Ok(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    // SHA-256("") = e3b0c44298fc1c14...; check full + HashId8 truncation.
    const SHA256_EMPTY: &str =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn sha256_full_and_truncated() {
        let full = hash(SHA_256, b"", HashLen::Full).unwrap();
        assert_eq!(hex::encode(&full), SHA256_EMPTY);

        let cert = hash(SHA_256, b"", HashLen::CertId8).unwrap();
        assert_eq!(cert.len(), CERT_HASH_LEN);
        assert_eq!(cert.as_slice(), &full[..CERT_HASH_LEN]);
        assert_eq!(hex::encode(&cert), "e3b0c44298fc1c14");

        let serial = hash(SHA_256, b"", HashLen::SerialId20).unwrap();
        assert_eq!(serial.len(), SERIAL_HASH_LEN);
        assert_eq!(serial.as_slice(), &full[..SERIAL_HASH_LEN]);
    }

    #[test]
    fn unsupported_alg_errors() {
        assert_eq!(hash(SHAKE128, b"x", HashLen::Full),
                   Err(HashError::UnsupportedAlg(SHAKE128)));
        assert!(matches!(hash(SHAKE256, b"x", HashLen::Full),
                         Err(HashError::UnsupportedAlg(_))));
    }
}

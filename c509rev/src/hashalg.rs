//! C509 Hash Algorithms registry (draft §"C509 Hash Algorithms") plus the hash
//! dispatch used to compute `issuerCertHash`, `serialNumberHash`, and the
//! requestor/responder cert hashes.
//!
//! This is a **new** registry introduced by the revocation draft, distinct from
//! the C509 *signature*/PK algorithm registry reused from [`c509::registry`].
//!
//! ## Truncation (design decision 5, REFERENCE-IMPL-PLAN.md)
//! The cert/serial hashes are emitted **8-byte truncated, KID-style** by default
//! ([`HashLen::Trunc8`]) — full 32-byte SHA-256 bloats constrained OCSP
//! (`IMPLEMENTATION_INSIGHTS` B1/B2). [`HashLen::Full`] is retained so the OCSP
//! encoder can still be checked byte-for-byte against the draft's (full-hash)
//! examples.

use sha2::{Digest, Sha224, Sha256, Sha384, Sha512, Sha512_256};

/// `0` — SHA-1 (cryptographically broken; see IMPLEMENTATION_INSIGHTS A2).
pub const SHA_1: i64 = 0;
/// `1` — SHA-256 (the constrained default; hardware-accelerated on the target).
pub const SHA_256: i64 = 1;
/// `2` — SHA-384.
pub const SHA_384: i64 = 2;
/// `3` — SHA-512.
pub const SHA_512: i64 = 3;
/// `4` — SHA-224.
pub const SHA_224: i64 = 4;
/// `5` — SHA-512/256.
pub const SHA_512_256: i64 = 5;
/// `6` — SM3.
pub const SM3: i64 = 6;
/// `7` — SHA3-224.
pub const SHA3_224: i64 = 7;
/// `8` — SHA3-256.
pub const SHA3_256: i64 = 8;
/// `9` — SHA3-384.
pub const SHA3_384: i64 = 9;
/// `10` — SHA3-512.
pub const SHA3_512: i64 = 10;
/// `11` — SHAKE128.
pub const SHAKE128: i64 = 11;
/// `12` — SHAKE256.
pub const SHAKE256: i64 = 12;

/// KID-style truncation length, in bytes (design decision 5).
pub const KID_LEN: usize = 8;

/// How much of the digest to emit for cert/serial hashes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashLen {
    /// Full digest — used to KAT against the draft's full-hash OCSP examples.
    Full,
    /// 8-byte KID-style truncation — the chosen design default.
    Trunc8,
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
/// the constrained default). SHA-1, SM3, SHA-3, and SHAKE return
/// [`HashError::UnsupportedAlg`] until added behind this same dispatch.
pub fn digest(alg: i64, data: &[u8]) -> Result<Vec<u8>, HashError> {
    let out = match alg {
        SHA_256 => Sha256::digest(data).to_vec(),
        SHA_384 => Sha384::digest(data).to_vec(),
        SHA_512 => Sha512::digest(data).to_vec(),
        SHA_224 => Sha224::digest(data).to_vec(),
        SHA_512_256 => Sha512_256::digest(data).to_vec(),
        other => return Err(HashError::UnsupportedAlg(other)),
    };
    Ok(out)
}

/// Compute the cert/serial hash of `data` under `alg`, truncated per `len`.
///
/// `Trunc8` keeps the leading [`KID_LEN`] bytes of the digest (KID-style);
/// `Full` returns the whole digest.
pub fn hash(alg: i64, data: &[u8], len: HashLen) -> Result<Vec<u8>, HashError> {
    let mut d = digest(alg, data)?;
    if len == HashLen::Trunc8 {
        d.truncate(KID_LEN);
    }
    Ok(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    // SHA-256("") = e3b0c44298fc1c14...; check full + KID-style truncation.
    const SHA256_EMPTY: &str =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn sha256_full_and_trunc8() {
        let full = hash(SHA_256, b"", HashLen::Full).unwrap();
        assert_eq!(hex::encode(&full), SHA256_EMPTY);

        let kid = hash(SHA_256, b"", HashLen::Trunc8).unwrap();
        assert_eq!(kid.len(), KID_LEN);
        assert_eq!(kid.as_slice(), &full[..KID_LEN]);
        assert_eq!(hex::encode(&kid), "e3b0c44298fc1c14");
    }

    #[test]
    fn unsupported_alg_errors() {
        assert_eq!(hash(SHA_1, b"x", HashLen::Full),
                   Err(HashError::UnsupportedAlg(SHA_1)));
        assert!(matches!(hash(SM3, b"x", HashLen::Full),
                         Err(HashError::UnsupportedAlg(_))));
    }
}

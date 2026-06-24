//! Reference implementation of **C509 Certificate Revocation Management**
//! (`draft-liao-cose-c509-revocation`): C509 CRL and C509 OCSP, the CBOR
//! encodings of X.509 CRLs (RFC 5280 §5) and OCSP messages (RFC 6960).
//!
//! This crate is **separate from** the C509 *certificate* codec
//! (`CBOR-certificates/c509_demo_impl`, crate `c509`) but **reuses** it for the
//! pieces it already implements well — the deterministic CBOR primitives
//! ([`c509::lcbor`]), the algorithm registry ([`c509::registry`]), and TBS
//! signing ([`c509::type2::sign_tbs`]). See `REFERENCE-IMPL-PLAN.md`.
//!
//! Scope (v1): native C509 CRL/OCSP encode, decode, sign, verify, validated
//! byte-for-byte against the draft's worked examples (KAT). X.509-DER ↔ C509
//! *semantic* interop is a later phase.

pub mod common;
pub mod hashalg;
pub mod time;
pub mod crl;
pub mod ocsp_req;

/// crlType / ocspRequestType / ocspResponseType discriminators (draft).
pub mod discriminator {
    /// `C509CRL` — the only CRL type defined.
    pub const CRL_C509: u64 = 0;

    /// `C509UnsignedOCSPRequest`.
    pub const OCSP_REQ_UNSIGNED: u64 = 0;
    /// `C509SignedOCSPRequest`.
    pub const OCSP_REQ_SIGNED: u64 = 1;
    /// `C509SimpleOCSPRequest`.
    pub const OCSP_REQ_SIMPLE: u64 = 2;

    /// `C509ErrorOCSPResponse`.
    pub const OCSP_RESP_ERROR: u64 = 0;
    /// `C509BasicOCSPResponse`.
    pub const OCSP_RESP_BASIC: u64 = 1;
    /// `C509SimpleOCSPResponse`.
    pub const OCSP_RESP_SIMPLE: u64 = 2;
}

#[cfg(test)]
mod reuse_smoke {
    //! Proves the `c509` path dependency links and its deterministic CBOR
    //! primitives are usable — the foundation every module builds on.
    use c509::lcbor;

    #[test]
    fn lcbor_encodes_known_bytes() {
        // RFC 8949: small uints encode in one byte.
        assert_eq!(lcbor::lcbor_uint(0), vec![0x00]);
        assert_eq!(lcbor::lcbor_uint(1), vec![0x01]);

        // A definite-length array [0, 1] -> 0x82 0x00 0x01.
        let arr = lcbor::lcbor_array(&[lcbor::lcbor_uint(0), lcbor::lcbor_uint(1)]);
        assert_eq!(arr, vec![0x82, 0x00, 0x01]);

        // A byte string of 3 bytes -> 0x43 <3 bytes>.
        assert_eq!(lcbor::lcbor_bytes(&[0xaa, 0xbb, 0xcc]),
                   vec![0x43, 0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn registry_values_match_draft_examples() {
        // The draft's signed examples use Ed25519 (12) and ECDSA-SHA256 (0).
        assert_eq!(c509::registry::SIG_ED25519, 12);
        assert_eq!(c509::registry::SIG_ECDSA_SHA256, 0);
    }
}

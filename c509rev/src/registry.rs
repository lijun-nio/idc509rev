//! C509 signature-algorithm identifiers used by the revocation structures.
//!
//! Only the two ids of the draft's mandatory-to-implement crypto profile are
//! reproduced here. Values are from Table "C509 Signature Algorithms" of
//! draft-ietf-cose-cbor-encoded-cert and match the upstream `c509::registry`
//! (cose-wg/CBOR-certificates @ bd0da3ef, BSD-3-Clause). The
//! `registry_ids_match_draft` test in `lib.rs` pins the numeric values so any
//! drift from the draft/upstream registry is caught at test time.

/// ECDSA with SHA-256 (secp256r1) — C509 signature algorithm id `0`.
pub const SIG_ECDSA_SHA256: i64 = 0;

/// Ed25519 (PureEdDSA) — C509 signature algorithm id `12`.
pub const SIG_ED25519: i64 = 12;

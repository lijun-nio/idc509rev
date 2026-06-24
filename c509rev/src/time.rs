//! Time-field encoding (draft §"Encoding of Time Fields").
//!
//! Time fields are **unwrapped** CBOR epoch-based date/time (`~time`): the bare
//! CBOR integer, no tag-1 wrapper. The `~time` content MUST be a non-negative
//! integer (POSIX seconds).
//!
//! Two flavours appear in the draft:
//! - **Absolute** `~time` — `thisUpdate`/`baseDate` in CRLs, `producedAt` in OCSP
//!   responses, the `expiredCertsOnCRL` value. Encoded as a CBOR uint.
//! - **Relative deltas** — OCSP response `thisUpdate` (`nint / 0`, seconds *back*
//!   from `producedAt`, so 0 or negative) and `nextUpdate` (`uint`, seconds
//!   forward from `producedAt`).
//!
//! ## CRL `nextUpdate` (see REFERENCE-IMPL-PLAN.md §risks)
//! Draft §5.3.6 *text* says CRL `nextUpdate` is a delta from `thisUpdate`, but
//! all four CRL examples encode an **absolute** timestamp (confirmed unresolved
//! in the latest idc509rev draft). This impl follows the **examples** (absolute)
//! and flags the discrepancy via [`crl_next_update`].

use c509::lcbor;

/// Encode an absolute `~time` (POSIX seconds) as an unwrapped CBOR uint.
pub fn encode_abs(unix: u64) -> Vec<u8> {
    lcbor::lcbor_uint(unix)
}

/// Encode an OCSP response `nextUpdate`: a forward delta in seconds from
/// `producedAt`, as a CBOR uint.
pub fn encode_delta_forward(seconds: u64) -> Vec<u8> {
    lcbor::lcbor_uint(seconds)
}

/// Encode an OCSP response `thisUpdate`: a non-positive delta in seconds from
/// `producedAt` (`nint / 0`). `back` is the number of seconds *before*
/// `producedAt`; `back == 0` encodes the integer 0.
pub fn encode_delta_back(back: u64) -> Vec<u8> {
    // -back as a CBOR integer (major type 1 for <0, 0 stays major type 0).
    let v: i64 = -(back as i64);
    lcbor::lcbor_int(v)
}

/// Encode a CRL `nextUpdate`.
///
/// Per the decision above this follows the **examples** (absolute `~time`),
/// *not* the §5.3.6 text (delta from `thisUpdate`). The `_this_update` argument
/// is accepted so the call site is explicit and a future delta-mode switch is a
/// one-line change here if the draft text wins instead.
pub fn crl_next_update(next_update_abs: u64, _this_update: u64) -> Vec<u8> {
    encode_abs(next_update_abs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abs_matches_example_encoding() {
        // CRL "no revoked" example: nextUpdate=1736380800 -> 1A 677F1180.
        assert_eq!(encode_abs(1736380800), vec![0x1a, 0x67, 0x7f, 0x11, 0x80]);
        // thisUpdate=1735776000 -> 1A 6775D700.
        assert_eq!(encode_abs(1735776000), vec![0x1a, 0x67, 0x75, 0xd7, 0x00]);
    }

    #[test]
    fn ocsp_deltas_match_example() {
        // Simple OCSP response example: nextUpdate=25200 -> 19 6270.
        assert_eq!(encode_delta_forward(25200), vec![0x19, 0x62, 0x70]);
        // thisUpdate=-28800 -> 39 707F (nint: -28800 = -1-28799, 28799=0x707F).
        assert_eq!(encode_delta_back(28800), vec![0x39, 0x70, 0x7f]);
        // thisUpdate 0 stays a single 0x00.
        assert_eq!(encode_delta_back(0), vec![0x00]);
    }

    #[test]
    fn crl_next_update_is_absolute() {
        assert_eq!(crl_next_update(1736380800, 1735776000),
                   encode_abs(1736380800));
    }
}

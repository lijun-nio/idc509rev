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
//! ## CRL `nextUpdate`
//! Draft §5.3.6 defines CRL `nextUpdate` as a **delta** in seconds from
//! `thisUpdate` (resolved in idc509rev issue #1; the examples were regenerated to
//! match). The structs keep `next_update` as an absolute time for ergonomics; the
//! delta conversion is localised to [`crl_next_update`] on encode and to the
//! decoder on the way back.

use crate::lcbor;

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

/// Encode a CRL `nextUpdate` as the §5.3.6 forward delta in seconds from
/// `this_update`, as a CBOR uint. `next_update_abs` is the absolute next-update
/// time held by the struct; callers guarantee `next_update_abs >= this_update`,
/// and `saturating_sub` keeps a misordered pair from panicking.
pub fn crl_next_update(next_update_abs: u64, this_update: u64) -> Vec<u8> {
    encode_abs(next_update_abs.saturating_sub(this_update))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abs_matches_example_encoding() {
        // Absolute ~time encodings (e.g. a CRL thisUpdate / OCSP producedAt).
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
    fn crl_next_update_is_forward_delta() {
        // CRL "no revoked" example: thisUpdate=1735776000, nextUpdate delta
        // 604800 (7 days) -> 1A 00093A80.
        assert_eq!(crl_next_update(1736380800, 1735776000),
                   encode_abs(604800));
        assert_eq!(crl_next_update(1736380800, 1735776000),
                   vec![0x1a, 0x00, 0x09, 0x3a, 0x80]);
    }
}

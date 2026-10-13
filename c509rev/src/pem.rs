//! PEM textual representation of C509 revocation objects
//! (`draft-liao-cose-c509-revocation`, section "Textual Representation").
//!
//! The draft specifies that a CBOR-encoded C509 CRL / OCSP request / OCSP
//! response MAY be represented textually by BASE64-encoding the CBOR and wrapping
//! it between `-----BEGIN <label>-----` / `-----END <label>-----`, following the
//! framework of {{RFC7468}} ("PKIX, PKCS, and CMS Structures"). The labels are:
//!
//! | Object              | Label                |
//! |---------------------|----------------------|
//! | C509 CRL            | `C509 CRL`           |
//! | C509 OCSP Request   | `C509 OCSP REQUEST`  |
//! | C509 OCSP Response  | `C509 OCSP RESPONSE` |
//!
//! This wrapper carries the **unchanged** binary structure — it does not touch
//! the signed TBS — so a value's signature and the byte-exact known-answer tests
//! are unaffected; `decode(encode(label, bytes)) == (label, bytes)`.
//!
//! Base64 (RFC 4648, standard alphabet, `=` padding) is implemented locally to
//! keep the crate self-contained (no extra dependency). Encoding follows
//! RFC 7468: 64-character base64 lines. Decoding is deliberately lax about
//! surrounding whitespace and explanatory text before the begin boundary, per
//! RFC 7468 Section 5.2.
//!
//! Decoding is also lax about *non-canonical* base64: the unused trailing bits
//! of a padded final group are not required to be zero (RFC 4648 Section 3.5
//! makes rejecting them a MAY, not a MUST). This is a text-layer malleability
//! only — two encodings that differ solely in those bits decode to identical
//! bytes, and signatures/known-answer tests operate on the decoded structure, so
//! it does not affect verification. A strict, canonical-only decode mode could
//! be added later if wanted.

// --------------------------------------------------------------------------
// Errors
// --------------------------------------------------------------------------

/// Failure while parsing a PEM textual representation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PemError {
    /// No `-----BEGIN <label>-----` line was found.
    NoBeginBoundary,
    /// The begin boundary had no matching `-----END <label>-----` line.
    NoEndBoundary,
    /// The END label did not match the BEGIN label, or did not match the
    /// caller's expected label.
    LabelMismatch,
    /// The base64 body was invalid (bad character, length, or padding).
    Base64(&'static str),
}

impl std::fmt::Display for PemError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PemError::NoBeginBoundary => write!(f, "no -----BEGIN <label>----- boundary"),
            PemError::NoEndBoundary => write!(f, "no matching -----END <label>----- boundary"),
            PemError::LabelMismatch => write!(f, "PEM label mismatch"),
            PemError::Base64(s) => write!(f, "invalid base64 in PEM body: {s}"),
        }
    }
}

impl std::error::Error for PemError {}

// --------------------------------------------------------------------------
// Labels (draft "Textual Representation")
// --------------------------------------------------------------------------

/// PEM label for a C509 CRL.
pub const LABEL_CRL: &str = "C509 CRL";
/// PEM label for a C509 OCSP request.
pub const LABEL_OCSP_REQUEST: &str = "C509 OCSP REQUEST";
/// PEM label for a C509 OCSP response.
pub const LABEL_OCSP_RESPONSE: &str = "C509 OCSP RESPONSE";

// --------------------------------------------------------------------------
// PEM encode / decode
// --------------------------------------------------------------------------

/// Wrap `contents` (the CBOR of a C509 revocation object) as a PEM string with
/// the given `label`, per RFC 7468 (64-character base64 lines, `\n` line
/// endings). Use one of the `LABEL_*` constants.
pub fn encode(label: &str, contents: &[u8]) -> String {
    let b64 = base64_encode(contents);
    let mut out = String::with_capacity(b64.len() + label.len() * 2 + 40);
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    let line = b64.as_bytes();
    let mut i = 0;
    while i < line.len() {
        let end = (i + 64).min(line.len());
        // `line` is ASCII base64, so this slice is always valid UTF-8.
        out.push_str(std::str::from_utf8(&line[i..end]).expect("base64 is ASCII"));
        out.push('\n');
        i = end;
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}

/// Parse a PEM string, returning `(label, contents)`. Lax about whitespace and
/// about any explanatory text before the begin boundary (RFC 7468 Section 5.2).
pub fn decode(text: &str) -> Result<(String, Vec<u8>), PemError> {
    let mut begin_label: Option<String> = None;
    let mut body = String::new();
    let mut end_label: Option<String> = None;
    let mut in_body = false;

    for raw in text.lines() {
        let line = raw.trim();
        if !in_body {
            if let Some(label) = boundary_label(line, "BEGIN") {
                begin_label = Some(label.to_string());
                in_body = true;
            }
            // Otherwise skip pre-boundary explanatory text (lax parsing).
        } else if let Some(label) = boundary_label(line, "END") {
            end_label = Some(label.to_string());
            break;
        } else {
            body.push_str(line);
        }
    }

    let begin_label = begin_label.ok_or(PemError::NoBeginBoundary)?;
    let end_label = end_label.ok_or(PemError::NoEndBoundary)?;
    if begin_label != end_label {
        return Err(PemError::LabelMismatch);
    }
    let contents = base64_decode(&body)?;
    Ok((begin_label, contents))
}

/// Like [`decode`], but require the label to equal `expected_label` and return
/// only the contents. Convenient when the object type is already known.
pub fn decode_expecting(expected_label: &str, text: &str) -> Result<Vec<u8>, PemError> {
    let (label, contents) = decode(text)?;
    if label != expected_label {
        return Err(PemError::LabelMismatch);
    }
    Ok(contents)
}

/// Parse `-----BEGIN <label>-----` / `-----END <label>-----`, returning `<label>`.
fn boundary_label<'a>(line: &'a str, kind: &str) -> Option<&'a str> {
    let prefix = match kind {
        "BEGIN" => "-----BEGIN ",
        _ => "-----END ",
    };
    line.strip_prefix(prefix)?.strip_suffix("-----")
}

// --------------------------------------------------------------------------
// Base64 (RFC 4648, standard alphabet) — local, dependency-free
// --------------------------------------------------------------------------

const B64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(B64_ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            B64_ALPHABET[((n >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64_ALPHABET[(n & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn base64_value(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn base64_decode(input: &str) -> Result<Vec<u8>, PemError> {
    // Strip all ASCII whitespace; the body may arrive already trimmed/joined.
    let filtered: Vec<u8> = input
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if filtered.len() % 4 != 0 {
        return Err(PemError::Base64("length not a multiple of 4"));
    }
    let n_chunks = filtered.len() / 4;
    let mut out = Vec::with_capacity(n_chunks * 3);
    for (i, chunk) in filtered.chunks(4).enumerate() {
        let is_last = i + 1 == n_chunks;
        // '=' padding is only permitted in the final chunk, in positions 3/4.
        if !is_last && chunk.contains(&b'=') {
            return Err(PemError::Base64("padding before final chunk"));
        }
        if chunk[0] == b'=' || chunk[1] == b'=' {
            return Err(PemError::Base64("padding in leading position"));
        }
        let c0 = base64_value(chunk[0]).ok_or(PemError::Base64("invalid character"))?;
        let c1 = base64_value(chunk[1]).ok_or(PemError::Base64("invalid character"))?;
        let pad2 = chunk[2] == b'=';
        let pad3 = chunk[3] == b'=';
        if pad2 && !pad3 {
            return Err(PemError::Base64("invalid padding"));
        }
        let c2 = if pad2 {
            0
        } else {
            base64_value(chunk[2]).ok_or(PemError::Base64("invalid character"))?
        };
        let c3 = if pad3 {
            0
        } else {
            base64_value(chunk[3]).ok_or(PemError::Base64("invalid character"))?
        };
        let n = ((c0 as u32) << 18) | ((c1 as u32) << 12) | ((c2 as u32) << 6) | (c3 as u32);
        out.push((n >> 16) as u8);
        if !pad2 {
            out.push((n >> 8) as u8);
        }
        if !pad3 {
            out.push(n as u8);
        }
    }
    Ok(out)
}

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // The canonical RFC 4648 Section 10 base64 test vectors.
    const RFC4648: &[(&[u8], &str)] = &[
        (b"", ""),
        (b"f", "Zg=="),
        (b"fo", "Zm8="),
        (b"foo", "Zm9v"),
        (b"foob", "Zm9vYg=="),
        (b"fooba", "Zm9vYmE="),
        (b"foobar", "Zm9vYmFy"),
    ];

    #[test]
    fn base64_matches_rfc4648_vectors() {
        for (raw, b64) in RFC4648 {
            assert_eq!(&base64_encode(raw), b64, "encode {raw:?}");
            assert_eq!(&base64_decode(b64).unwrap(), raw, "decode {b64}");
        }
    }

    #[test]
    fn base64_round_trips_all_byte_values_and_lengths() {
        for len in 0..=260usize {
            let buf: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let round = base64_decode(&base64_encode(&buf)).unwrap();
            assert_eq!(round, buf, "round-trip length {len}");
        }
    }

    #[test]
    fn base64_rejects_bad_input() {
        assert!(base64_decode("Zg=").is_err()); // length not multiple of 4
        assert!(base64_decode("Z@==").is_err()); // invalid character
        assert!(base64_decode("Zg=Zm8=").is_err()); // padding before final chunk
        assert!(base64_decode("=g==").is_err()); // padding in leading position
    }

    #[test]
    fn encode_wraps_at_64_chars_with_boundaries() {
        // 96 bytes -> 128 base64 chars -> two 64-char lines.
        let data = vec![0xABu8; 96];
        let pem = encode(LABEL_CRL, &data);
        let lines: Vec<&str> = pem.lines().collect();
        assert_eq!(lines[0], "-----BEGIN C509 CRL-----");
        assert_eq!(lines[1].len(), 64);
        assert_eq!(lines[2].len(), 64);
        assert_eq!(lines[3], "-----END C509 CRL-----");
        assert_eq!(lines.len(), 4);
    }

    #[test]
    fn round_trip_generic_bytes() {
        let data: Vec<u8> = (0u16..=255).map(|b| b as u8).collect();
        let pem = encode(LABEL_OCSP_RESPONSE, &data);
        let (label, back) = decode(&pem).unwrap();
        assert_eq!(label, LABEL_OCSP_RESPONSE);
        assert_eq!(back, data);
        assert_eq!(decode_expecting(LABEL_OCSP_RESPONSE, &pem).unwrap(), data);
    }

    #[test]
    fn round_trip_empty_contents() {
        let pem = encode(LABEL_CRL, &[]);
        assert_eq!(decode_expecting(LABEL_CRL, &pem).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn decode_is_lax_about_whitespace_and_preamble() {
        let pem = "\
Subject: an example CRL
Not part of the encoding.

-----BEGIN C509 CRL-----
   Zm9v
   YmFy

-----END C509 CRL-----
trailing text is ignored
";
        let (label, back) = decode(pem).unwrap();
        assert_eq!(label, LABEL_CRL);
        assert_eq!(back, b"foobar");
    }

    #[test]
    fn decode_rejects_label_mismatch() {
        let mixed = "-----BEGIN C509 CRL-----\nZm9v\n-----END C509 OCSP REQUEST-----\n";
        assert_eq!(decode(mixed), Err(PemError::LabelMismatch));

        let pem = encode(LABEL_CRL, b"foo");
        assert_eq!(
            decode_expecting(LABEL_OCSP_REQUEST, &pem),
            Err(PemError::LabelMismatch)
        );
    }

    #[test]
    fn decode_rejects_missing_boundaries() {
        assert_eq!(decode("no boundaries here"), Err(PemError::NoBeginBoundary));
        assert_eq!(
            decode("-----BEGIN C509 CRL-----\nZm9v\n"),
            Err(PemError::NoEndBoundary)
        );
    }

    // End-to-end: the PEM wrapper carries the UNCHANGED binary structure, and the
    // unwrapped bytes still decode to the same object. Uses the draft's worked
    // examples (same hex as the decode round-trip tests).
    const CRL_NO_REVOKED: &str = "8b000c6f746573742063726c6f6373702d6361542f45e78d2caedf368cdf53c39005d492450e1056011a6775d7001a00093a80f680f6584013834f4e38aa9f0dc5b8d21c8650c776a6d961c31c894c36a71a6433f5ed7d30e67f787f13c7e4c349b2848a181fdbbce361a14c220021c4a267367ad5f1d90d";
    const OCSP_SIMPLE_REQ: &str = "860200501111111111111111111111111111111148a01c73a5f3b063345410652787fa0527bc2449a1bfc5ab31aa5a6f0d8d80";
    const OCSP_ERROR_RESP: &str = "820006";

    #[test]
    fn pem_round_trip_preserves_crl_bytes_and_decodes() {
        use crate::crl::C509Crl;
        let bytes = hex::decode(CRL_NO_REVOKED).unwrap();
        let pem = encode(LABEL_CRL, &bytes);
        let back = decode_expecting(LABEL_CRL, &pem).unwrap();
        assert_eq!(back, bytes, "PEM must preserve the exact CBOR");
        // And the unwrapped bytes are still a valid, identical CRL.
        assert_eq!(hex::encode(C509Crl::decode(&back).unwrap().encode()), CRL_NO_REVOKED);
    }

    #[test]
    fn pem_round_trip_preserves_ocsp_request_and_response() {
        use crate::ocsp_req::C509OcspRequest;
        use crate::ocsp_resp::C509OcspResponse;

        let req = hex::decode(OCSP_SIMPLE_REQ).unwrap();
        let req_pem = encode(LABEL_OCSP_REQUEST, &req);
        assert_eq!(decode_expecting(LABEL_OCSP_REQUEST, &req_pem).unwrap(), req);
        assert_eq!(
            hex::encode(C509OcspRequest::decode(&req).unwrap().encode()),
            OCSP_SIMPLE_REQ
        );

        let resp = hex::decode(OCSP_ERROR_RESP).unwrap();
        let resp_pem = encode(LABEL_OCSP_RESPONSE, &resp);
        assert_eq!(decode_expecting(LABEL_OCSP_RESPONSE, &resp_pem).unwrap(), resp);
        assert_eq!(
            hex::encode(C509OcspResponse::decode(&resp).unwrap().encode()),
            OCSP_ERROR_RESP
        );
    }
}

# c509rev

A Rust reference implementation of **C509 Certificate Revocation Management**
([`draft-liao-cose-c509-revocation`](../draft-liao-cose-c509-revocation.md)):
C509 CRL and C509 OCSP — the CBOR encodings of X.509 CRLs (RFC 5280 §5) and OCSP
messages (RFC 6960).

It is **separate from** the C509 *certificate* codec
(`CBOR-certificates/c509_demo_impl`, crate `c509`) and **builds standalone** — no
sibling checkout required. The few primitives it originally reused from `c509` are
carried locally: the deterministic CBOR encoder (`src/lcbor.rs`, vendored verbatim
under BSD-3-Clause), the two v1-profile signature-algorithm ids (`src/registry.rs`),
and Ed25519/ECDSA-P256 TBS signing (`sign_tbs` in `src/sign.rs`).

> **Test/reference tooling only. Not for production use.**

## Quick start

```sh
cargo test     # 32 KATs + unit tests — all should pass
cargo build
```

Self-contained: the only dependencies are `serde_cbor`, `sha2`, `hex`,
`ed25519-dalek`, and `p256`, so it builds in any clone with no sibling checkout.

## Usage

### Runnable examples

The quickest way to see the codec produce real bytes:

| Command | What it prints |
|---------|----------------|
| `cargo run --example sizes` | CSV of encoded byte sizes vs. #certs (N) / #revoked (R), truncated vs. full hashes (LRev Tier-0 data) |
| `cargo run --example ecdsa_crl_vector` | a deterministic P-256-signed CRL as `crl_hex=…` + its `pubkey_hex=…` (a reproducible cross-impl test vector) |
| `cargo run --example crl_payload <R>` | hex of a signed CRL carrying `R` revoked entries (the on-wire E10 multi-hop payload) |

### Command-line tool

`c509rev <object> <action> <hexfile> [pubkey-hex]`, where `object` is
`crl` | `ocsp-req` | `ocsp-resp`. The hex file may contain whitespace.

```sh
# decode: pretty-print the parsed structure
cargo run -- crl       decode path/to/crl.hex
cargo run -- ocsp-req  decode path/to/req.hex
cargo run -- ocsp-resp decode path/to/resp.hex

# verify: check the signature over the TBS
#   pubkey-hex = Ed25519 32-byte, or secp256r1 SEC1 (uncompressed 04|x|y)
cargo run -- crl verify path/to/crl.hex <pubkey-hex>
```

Full round-trip using the example vector — mint a signed CRL, then verify it:

```sh
cargo run --example ecdsa_crl_vector       # prints crl_hex=… and pubkey_hex=…
# put the value after `crl_hex=` into crl.hex, then:
cargo run -- crl verify crl.hex <the pubkey_hex value>     # -> VERIFY OK
```

### As a library

```rust
use c509rev::crl::{C509Crl, CrlInfo};
use c509rev::common::Name;
use c509rev::registry::SIG_ED25519;

// Build → sign → encode.
let mut crl = C509Crl {
    info: CrlInfo {
        crl_type: 0,
        signature_algorithm: SIG_ED25519,
        authority_subject: Name::Text("crlocsp-ca".into()),
        authority_key_identifier: Some(vec![0u8; 20]),
        crl_number: 1,
        this_update: 1_735_776_000,
        next_update: Some(1_736_380_800),
        base_crl_number: None,
        crl_extensions: vec![],
    },
    revoked_certs_list: None,
    signature_value: vec![],
};
crl.sign(private_key_pem)?;         // PKCS#8 PEM, Ed25519 or P-256
let bytes = crl.encode();           // deterministic CBOR

// Decode → verify.
let parsed = C509Crl::decode(&bytes)?;
parsed.verify(&public_key_bytes)?;  // Ed25519 32-byte, or secp256r1 SEC1
```

OCSP requests and responses follow the same `encode` / `decode` / `sign` / `verify`
shape (`ocsp_req::C509OcspRequest`, `ocsp_resp::C509OcspResponse`).

## Status

The v1 codec is complete: **encode + decode + sign + verify + a CLI**, validated
byte-for-byte against the draft's worked examples (KAT).

| Area | Module | State |
|------|--------|-------|
| C509 Hash Algorithms registry + SHA-2 dispatch | `hashalg` | done |
| `~time` (absolute + OCSP deltas) | `time` | done |
| Shared `Name` / `Extension` helpers | `common` | done |
| C509 CRL encode | `crl` | done — all 4 examples match |
| C509 OCSP request encode (Simple/Unsigned/Signed) | `ocsp_req` | done — all examples match |
| C509 OCSP response encode (Error/Basic/Simple) | `ocsp_resp` | done — all examples match |
| Cert/serial identity hashes | `certhash` | functions done (see Findings) |
| Decode (CRL + OCSP) | `decode` | done — all 9 examples round-trip |
| Sign + verify (Ed25519, ECDSA-secp256r1) | `sign` | done — sign↔verify round-trip |
| CLI (`decode` / `verify`) | `bin/c509rev` | done |

For signed objects (CRL, signed OCSP request/response) the encode KAT is a **TBS
byte-match**, because the draft ships no example signing keys, so the
`signatureValue` itself cannot be reproduced; sign/verify is validated with the
crate's own test keys, and decode→re-encode round-trips the full example bytes
including the original signature.

Remaining polish (not blocking v1): encode-from-a-source-format in the CLI,
the signed-request *with-cert*/*with-chain* variants (the `requestor_certs`
field is already an opaque pass-through), and full `Name` beyond the single-CN
text form. X.509-DER ↔ C509 *semantic* interop is the separate phase 2.

## Hash truncation

Per the project's design decision, the OCSP cert/serial identity hashes
(`issuerCertHash`, `serialNumberHash`, `responder`/`requestorCertHash`) are
emitted **8-byte, KID-style** by default (`hashalg::HashLen::Trunc8`) to keep
constrained OCSP small; `HashLen::Full` is retained so the encoders can be
checked against the draft's full-hash examples.

## Security considerations & known limitations

This is **reference/test tooling, not production code** (see the disclaimer above).
A security pass over the untrusted-input surface (decode + verify of
attacker-supplied CRL/OCSP bytes) found the following; each is either fixed or
recorded here as a known limitation.

**Reviewed sound**
- No `unsafe` code anywhere in the crate.
- The CBOR parse goes through `serde_cbor::from_slice`, which returns an error
  (not a panic) on truncated/malformed input.
- Signature verification: Ed25519 via `ed25519-dalek` (strict/canonical) and
  ECDSA-secp256r1-SHA256 via `p256`, with explicit key/signature length checks;
  the algorithm is dispatched from the object and returns `UnsupportedAlg` /
  `BadSignature` safely — no verify-bypass.

**Fixed (hardening)**
- **Bounded fixed-width entry parsing.** `revokedCertsControl.serialNumberLength`
  (`1..=20`) and `dateLength` (`0..=8`) are enforced on decode per the draft CDDL
  *before* they size the entry stride and per-entry sub-slices. Unbounded values
  would otherwise overflow the stride / index past a chunk, turning a malformed
  CRL into an out-of-bounds panic (DoS). See `decode_control` /
  `decode_revoked` / `decode_removed`, with regression tests
  `control_rejects_out_of_range_lengths` and `revoked_rejects_date_overflow`.
- **Checked date arithmetic.** `baseDate + offset` (both attacker-controlled) uses
  `checked_add`, returning `Malformed` instead of overflow-panicking (debug) or
  wrapping (release).

**Known limitations**
- **Other CDDL range bounds not yet enforced on decode.** The value-level ranges
  the draft tightened — `crlType`/`ocsp*Type` (`uint15`), `crlNumber`/`baseCrlNumber`
  (`uint63 .ge 1`), `nextUpdate`/`baseDate` (`uint63`), `revocationReason` (`uint8`)
  — are parsed but not range-checked. These are stored, not used to size memory,
  so they are a **spec-conformance gap, not a memory-safety issue**. TODO: enforce
  on decode (tracked; see the inline `NOTE` in `decode.rs`).
- **`serde_cbor` is unmaintained** (RUSTSEC-2021-0127). It is a widely-used, stable
  crate and is the CBOR library the companion `c509` cert implementation also uses;
  a future move to a maintained CBOR crate (e.g. `ciborium`) is noted but not done.
- **Truncated identity hashes reduce collision resistance.** The default 8-byte
  (`HashId8`) cert/serial identity hashes give ~64-bit second-preimage / ~32-bit
  birthday resistance, a size/security trade-off for constrained deployments. This
  is a draft-level property; see the draft's Security Considerations. `HashLen::Full`
  is available.
- **`cbor_item_end` in `lcbor.rs` is unused** here (vendored with the encoder). It
  panics on unsupported additional-info and recurses unbounded, but is not on any
  live path in this crate.

## Findings surfaced against the draft

This codec exists partly to review the draft. Two issues found so far (details in
`../../CBOR-revocation-management/REFERENCE-IMPL-PLAN.md` §Findings):

1. **CRL `nextUpdate`** — the §5.3.6 text says it is a delta from `thisUpdate`,
   but all four CRL examples encode an absolute timestamp. This impl follows the
   examples (absolute); the switch is isolated in `time::crl_next_update`.
2. **OCSP example identity hashes are not reproducible** — the examples'
   `issuerCertHash` / `responderCertHash` do not equal SHA-256 of the published
   helper-cert bytes under any obvious reading (C509, C509 without the type byte,
   the DER reconstruction, or bstr-wrapped C509). Captured as an `#[ignore]`'d
   KAT (`certhash::tests::issuer_cert_hash_matches_example`) pending author
   clarification.

## Layout

```
src/
  lib.rs        crate root + discriminator constants
  lcbor.rs      deterministic CBOR encoder (vendored from c509, BSD-3-Clause)
  registry.rs   C509 signature-algorithm ids (v1 profile)
  hashalg.rs    C509 Hash Algorithms registry, hash dispatch, HashLen
  time.rs       ~time encoding (absolute + OCSP deltas)
  common.rs     Name, Extension, shared CBOR helpers
  crl.rs        C509 CRL
  ocsp_req.rs   C509 OCSP request (Simple / Unsigned / Signed)
  ocsp_resp.rs  C509 OCSP response (Error / Basic / Simple)
  certhash.rs   issuer/serial/responder/requestor identity hashes
  bin/c509rev.rs  CLI (decode / verify)
examples/
  sizes.rs           size CSV (LRev Tier-0)
  ecdsa_crl_vector.rs deterministic P-256 signed CRL test vector
  crl_payload.rs     signed CRL of R entries (E10 payload)
```

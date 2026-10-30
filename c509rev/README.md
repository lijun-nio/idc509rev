# c509rev

A Rust implementation of **C509 Certificate Revocation Management**
([`draft-liao-cose-c509-revocation`](../draft-liao-cose-c509-revocation.md)):
C509 CRL and C509 OCSP, the CBOR encodings of X.509 CRLs (RFC 5280, Section 5)
and OCSP messages (RFC 6960).

The crate builds standalone. Its dependencies are `serde_cbor`, `sha2`, `hex`,
`ed25519-dalek`, and `p256`. The deterministic CBOR encoder (`src/lcbor.rs`) is
taken from the C509 certificate implementation in
[cose-wg/CBOR-certificates](https://github.com/cose-wg/CBOR-certificates)
(BSD-3-Clause).

> **Test and reference tooling. Not for production use.**

## Build and test

```sh
cargo build
cargo test     # known-answer tests against the draft examples, plus unit tests
```

## Supported

| Feature | Module | Notes |
|---------|--------|-------|
| C509 CRL: encode, decode, sign, verify | `crl` | full and delta CRLs, indirect CRLs, `revokedCertsControl` fixed-width entries, `removedFromCRLCerts` |
| C509 OCSP request: encode, decode, sign, verify | `ocsp_req` | Unsigned (0), Signed (1), Simple (2) |
| C509 OCSP response: encode, decode, sign, verify | `ocsp_resp` | Error (0), Basic (1), Simple (2) |
| Signature algorithms | `registry`, `sign` | Ed25519 (12), ECDSA with SHA-256 on secp256r1 (0) |
| Hash algorithms | `hashalg` | SHA-256 (-16), SHA-384 (-43), SHA-512 (-44) |
| Identity hashes | `certhash` | `HashId8` for certificate hashes, `HashId20` for `serialNumberHash`; full-length output via `HashLen::Full` |
| Time encoding | `time` | absolute `~time`, and the CRL and OCSP relative fields |
| Textual representation | `pem` | PEM (RFC 7468) for `C509 CRL`, `C509 OCSP REQUEST`, `C509 OCSP RESPONSE` |
| Command-line tool | `bin/c509rev` | `decode`, `verify`, `pem` |

Encoding is deterministic, and decoding then re-encoding reproduces the input
bytes, including the signature. The draft publishes no signing keys for its
examples, so for signed objects the known-answer tests compare the TBS bytes.
Signing and verification are tested with the crate's own keys.

## Not supported

- SHAKE128 (-18), SHAKE256 (-45), SHA3-256/384/512, and SM3. `hash()` returns
  `UnsupportedAlg` for them.
- `Name` values other than a single common name carried as a text string.
- `requestorCerts` / `responderCerts` are carried as opaque encoded CBOR. The
  certificate chain is not parsed or validated.
- Certificate path validation and responder authorization. `verify` checks only
  the signature against the public key it is given.
- Conversion between X.509 DER CRLs/OCSP messages and their C509 encodings.
- Encoding from a source format in the command-line tool. It decodes, verifies,
  and converts to PEM.

## Input validation

Decoding is intended to be safe on untrusted input:

- The crate contains no `unsafe` code. Malformed or truncated CBOR returns an
  error, not a panic.
- `serialNumberLength` (1..=20) and `dateLength` (0..=8) are checked before they
  size the fixed-width CRL entries, and entry lists whose length is not a multiple
  of the entry width are rejected.
- `baseDate + offset` is computed with overflow checks.
- A non-null OCSP `nonce` must be 16 to 32 bytes. The encoders do not check this:
  the caller supplies a nonce of that length from a cryptographically strong RNG.
- Signatures are verified with `ed25519-dalek` (Ed25519) and `p256` (ECDSA). Key
  and signature lengths are checked, and the algorithm is taken from the object.

Known gaps:

- These CDDL value ranges are parsed but not enforced: `crlType` and the OCSP
  type fields (`uint15`), `crlNumber` and `baseCrlNumber` (`uint63 .ge 1`),
  `nextUpdate` and `baseDate` (`uint63`), `revocationReason` (`uint8`). None of
  them sizes a buffer or an index.
- Ed25519 verification uses `VerifyingKey::verify`, which rejects non-canonical
  signatures but, unlike `verify_strict`, accepts small-order public keys.
- `serde_cbor` is unmaintained (RUSTSEC-2021-0127).
- `lcbor::cbor_item_end` panics on unsupported additional-information values and
  recurses without a bound. It is not called by this crate.
- `HashId8` gives about 64-bit second-preimage and 32-bit collision resistance,
  `HashId20` about 160-bit and 80-bit. See the draft's Security Considerations.

## Usage

### Command-line tool

`c509rev <object> <action> <infile> [pubkey-hex]`, where `object` is
`crl`, `ocsp-req`, or `ocsp-resp`, and `action` is `decode`, `verify`, or `pem`.
The input file holds hex (whitespace ignored) or PEM; the format is detected
automatically.

```sh
cargo run -- crl       decode path/to/crl.hex
cargo run -- ocsp-req  decode path/to/req.hex
cargo run -- ocsp-resp decode path/to/resp.hex

# pubkey-hex: Ed25519 (32 bytes) or secp256r1 SEC1 uncompressed (04|x|y)
cargo run -- crl verify path/to/crl.hex <pubkey-hex>

cargo run -- crl pem path/to/crl.hex       # -> -----BEGIN C509 CRL----- ...
```

### Examples

| Command | Output |
|---------|--------|
| `cargo run --example ecdsa_crl_vector` | a deterministic secp256r1-signed CRL (`crl_hex=...`) and its public key (`pubkey_hex=...`) |
| `cargo run --example crl_payload <R>` | hex of a signed CRL with `R` revoked entries |
| `cargo run --example sizes` | CSV of encoded sizes by number of certificates and revoked entries, with truncated and full-length hashes |

To check a signature end to end, run the `ecdsa_crl_vector` example, write the
`crl_hex` value to `crl.hex`, and run `cargo run -- crl verify crl.hex <pubkey_hex>`.

### Library

```rust
use c509rev::crl::{C509Crl, CrlInfo};
use c509rev::common::Name;
use c509rev::registry::SIG_ED25519;

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
let bytes = crl.encode();

let parsed = C509Crl::decode(&bytes)?;
parsed.verify(&public_key_bytes)?;  // Ed25519 32-byte, or secp256r1 SEC1
```

`ocsp_req::C509OcspRequest` and `ocsp_resp::C509OcspResponse` have the same
`encode`, `decode`, `sign`, and `verify` methods.

## Layout

```
src/
  lib.rs          crate root, type discriminators
  lcbor.rs        deterministic CBOR encoder
  registry.rs     signature algorithm identifiers
  hashalg.rs      hash algorithm identifiers, hashing, truncation
  time.rs         time encoding
  common.rs       Name, Extension, shared CBOR helpers
  crl.rs          C509 CRL
  ocsp_req.rs     C509 OCSP request
  ocsp_resp.rs    C509 OCSP response
  certhash.rs     certificate and serial-number identity hashes
  decode.rs       decoding for all objects
  sign.rs         signing and verification
  pem.rs          PEM textual representation
  bin/c509rev.rs  command-line tool
examples/
  ecdsa_crl_vector.rs
  crl_payload.rs
  sizes.rs
```

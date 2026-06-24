# c509rev

A Rust reference implementation of **C509 Certificate Revocation Management**
([`draft-liao-cose-c509-revocation`](../draft-liao-cose-c509-revocation.md)):
C509 CRL and C509 OCSP — the CBOR encodings of X.509 CRLs (RFC 5280 §5) and OCSP
messages (RFC 6960).

It is **separate from** the C509 *certificate* codec
(`CBOR-certificates/c509_demo_impl`, crate `c509`) but **reuses** it via a cargo
path dependency: the deterministic CBOR primitives (`c509::lcbor`), the algorithm
registry (`c509::registry`), and TBS signing (`c509::type2::sign_tbs`).

> **Test/reference tooling only. Not for production use.**

## Status

Encoders are complete and validated byte-for-byte against the draft's worked
examples (KAT). Decode, sign/verify, and a CLI are in progress.

| Area | Module | State |
|------|--------|-------|
| C509 Hash Algorithms registry + SHA-2 dispatch | `hashalg` | done |
| `~time` (absolute + OCSP deltas) | `time` | done |
| Shared `Name` / `Extension` helpers | `common` | done |
| C509 CRL encode | `crl` | done — all 4 examples match |
| C509 OCSP request encode (Simple/Unsigned/Signed) | `ocsp_req` | done — all examples match |
| C509 OCSP response encode (Error/Basic/Simple) | `ocsp_resp` | done — all examples match |
| Cert/serial identity hashes | `certhash` | functions done (see Findings) |
| Decode, sign/verify, CLI | — | TODO |

For signed objects (CRL, signed OCSP request/response) the KAT is a **TBS
byte-match**, because the draft ships no example signing keys, so the
`signatureValue` itself cannot be reproduced.

## Hash truncation

Per the project's design decision, the OCSP cert/serial identity hashes
(`issuerCertHash`, `serialNumberHash`, `responder`/`requestorCertHash`) are
emitted **8-byte, KID-style** by default (`hashalg::HashLen::Trunc8`) to keep
constrained OCSP small; `HashLen::Full` is retained so the encoders can be
checked against the draft's full-hash examples.

## Build & test

```sh
cargo test     # KAT + unit tests; expects ../../CBOR-certificates/c509_demo_impl
cargo build
```

The build resolves the sibling `c509` crate by relative path, so both repos must
be checked out under the same workspace.

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
  hashalg.rs    C509 Hash Algorithms registry, hash dispatch, HashLen
  time.rs       ~time encoding (absolute + OCSP deltas)
  common.rs     Name, Extension, shared CBOR helpers
  crl.rs        C509 CRL
  ocsp_req.rs   C509 OCSP request (Simple / Unsigned / Signed)
  ocsp_resp.rs  C509 OCSP response (Error / Basic / Simple)
  certhash.rs   issuer/serial/responder/requestor identity hashes
  bin/c509rev.rs  CLI (stub)
```

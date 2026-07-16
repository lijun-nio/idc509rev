---
v: 3

title: "CBOR Encoded Certificate Revocation Management"
docname: draft-liao-cose-c509-revocation-latest
abbrev: C509 Revocation

ipr: trust200902
area: Security
wg: COSE Working Group
kw: Internet-Draft
cat: std
submissiontype: IETF

coding: utf-8

pi:
  toc: yes
  sortrefs: yes
  symrefs: yes
  tocdepth: 4

venue:
  group: "CBOR Object Signing and Encryption (cose)"
  type: "Working Group"
  mail: "cose@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/cose/"
  github: "lijun-nio/idc509rev"

author:
  - name: Lijun Liao
    org: NIO
    email: lijun.liao@nio.io
    country: China
  - name: Marco Tiloca
    org: RISE AB
    email: marco.tiloca@ri.se
    country: Sweden
  - name: Joel Höglund
    org: RISE AB
    email: joel.hoglund@ri.se
    country: Sweden
  - name: Rikard Höglund
    org: RISE AB
    email: rikard.hoglund@ri.se
    country: Sweden
  - name: Shahid Raza
    org: University of Glasgow
    email: shahid.raza@glasgow.ac.uk
    country: United Kingdom

normative:
  RFC5280:
  RFC6066:
  RFC6960:
  RFC7120:
  RFC7925:
  RFC8126:
  RFC8226:
  RFC8446:
  RFC8610:
  RFC8742:
  RFC8949:
  RFC9147:
  RFC9360:
  RFC9682:
  I-D.ietf-cose-cbor-encoded-cert:
  I-D.ietf-stir-certificates-ocsp:

informative:
  RFC7228:
  POSIX:
    title: IEEE Standard for Information Technology--Portable Operating System Interface (POSIX(TM)) Base Specifications, Issue 7
    target: https://pubs.opengroup.org/onlinepubs/9699919799/
    date: January 2018
  CborMe:
    target: https://cbor.me/
    title: CBOR Playground
    author:
      - ins: C. Bormann
    date: May 2018
  X.690:
    title: "ASN.1 encoding rules: Specification of Basic Encoding Rules (BER), Canonical Encoding Rules (CER) and Distinguished Encoding Rules (DER)"
    target: https://www.itu.int/rec/T-REC-X.690

entity:
  SELF: "[RFC-XXXX]"

--- abstract

This document specifies CBOR-encoded PKI structures for use with C509 certificates (draft-ietf-cose-cbor-encoded-cert), X.509 certificates (RFC 5280), and future certificate types. It defines C509 CRL and C509 OCSP, compact CBOR encodings of X.509 Certificate Revocation Lists (RFC 5280) and OCSP messages (RFC 6960), respectively. The structures defined in this document are certificate-type agnostic and can be used with C509 certificates, X.509 certificates, or future certificate types without modification. C509 OCSP improves on RFC 6960 by signing a wider set of fields to prevent algorithm-substitution and certificate-chain substitution attacks, replacing plaintext serial numbers with hashes to preserve requestor privacy, replacing the two-hash issuer identity with a single certificate hash, and identifying all participants (requestor, responder, issuer) by a uniform certificate hash rather than type-specific fields. C509 CRL and C509 OCSP are not wire-format-compatible with their DER-encoded X.509 counterparts and cannot be converted to or from them without semantic interpretation.

--- middle

# Introduction {#intro}

Public Key Infrastructure (PKI) for constrained environments {{RFC7228}} requires compact certificate representations and compact revocation information.  {{I-D.ietf-cose-cbor-encoded-cert}} defines C509 certificates, a CBOR encoding of X.509 certificates {{RFC5280}} that reduces certificate size by over 50% for typical constrained-device profiles.  However, revocation mechanisms -- Certificate Revocation Lists (CRLs) and Online Certificate Status Protocol (OCSP) messages -- have not yet received the same treatment.

CRLs as defined in {{RFC5280}} can be large, especially when many certificates have been revoked or when CRL extensions add overhead.  OCSP responses as defined in {{RFC6960}} carry per-certificate status information and may be exchanged during TLS {{RFC8446}} and DTLS {{RFC9147}} handshakes via OCSP stapling {{RFC6066}}, directly affecting handshake latency.

Note on terminology: The label "C509" is used for consistency with the C509 certificate encoding and to promote a cohesive C509 PKI ecosystem (C509 certificates, CRLs, OCSP, and related tooling). Although this document uses "C509" in its names, the encodings and protocols defined here are certificate-type agnostic and apply equally to X.509 certificates and other certificate types; see {{cert-type-interop}}.

This document specifies:

- **C509 CRL** -- a natively signed CBOR {{RFC8949}} encoding of X.509 CRLs ({{RFC5280, Section 5}}).  The signature is computed over the CBOR Sequence {{RFC8742}} `TBSCertList`; no ASN.1 encoding is involved.

- **C509 OCSP** -- a CBOR encoding of OCSP requests and responses ({{RFC6960}}).  The encoding compresses common fields while preserving semantic equivalence.  Four key improvements are made over {{RFC6960}}:

   - The signature in signed requests and responses is computed over a wider set of fields than in {{RFC6960}}, including the signature algorithm and the certificate chain, preventing algorithm-substitution and certificate-chain substitution attacks.
   - Certificate serial numbers in requests and responses are replaced by hashes (`serialNumberHash`), providing privacy against passive observers who do not already know the queried serial numbers.
   - The issuer is identified by a single hash over the issuer certificate (`issuerCertHash`) rather than by the two-hash `CertID`, reducing per-issuer overhead.
   - All participants -- requestor, responder, and issuer -- are identified by a hash over their certificate (`requestorCertHash`, `responderCertHash`, `issuerCertHash`) rather than by a plaintext Subject distinguished name or SubjectKeyIdentifier, avoiding structural `CHOICE` types such as the X.509 `ResponderID` (`byName` or `byKey`) and simplifying support for different certificate types (e.g., C509, X.509, or future types) because the same hash applies regardless of the certificate encoding.

   See the field encoding sections of this document for details.

   The request and response structures defined in this document are certificate-type agnostic: they can be used with C509 certificates, X.509 certificates, or any future certificate type without modification; see {{cert-type-interop}}.

C509 CRL and C509 OCSP apply the same compression techniques as C509 certificates: static fields are elided, OIDs are replaced with short integers, time values are compressed to POSIX timestamps, and redundant encoding is removed.  Implementers may use the CBOR playground {{CborMe}} to inspect encoded examples.

C509 CRL and C509 OCSP are not wire-format-compatible with their DER-encoded counterparts defined in {{RFC5280}} and {{RFC6960}}.  Systems that use C509 CRL or C509 OCSP must explicitly support these CBOR-encoded formats; they cannot be transparently substituted for or derived from the corresponding DER-encoded structures.

C509 CRL and C509 OCSP are designed to be compatible with certificate profiles for constrained deployments, such as {{RFC7925}}.

# Terminology {#terminology}

{::boilerplate bcp14-tagged}

This document uses the terminology from {{RFC5280}}, {{RFC6960}}, {{RFC7228}}, {{RFC8610}}, {{RFC8742}}, {{RFC8949}}, and {{RFC9682}}.  Unless otherwise stated, "CBOR" refers to deterministically encoded CBOR as specified in {{RFC8949, Sections 4.2.1 and 4.2.2}}.

# Imported Definitions {#imports}

The following types are imported from {{I-D.ietf-cose-cbor-encoded-cert}}:

- `Name`: no limitation.
- `Extensions`: only the `( extensionID: int, extensionValue: Defined )` choice of Extension is permitted.
- `COSE_C509`: no limitation.
- `AlgorithmIdentifier`: no limitation.

The following type is imported from {{RFC9360}}:

- `COSE_X509`: no limitation.

This document further defines the following constrained alias for use in all CDDL definitions:

~~~~~~~~~~~ cddl
IntAlgorithmIdentifier = int
~~~~~~~~~~~
{: sourcecode-name="c509crl.cddl"}

`IntAlgorithmIdentifier` is the `int`-only instantiation of `AlgorithmIdentifier` from {{I-D.ietf-cose-cbor-encoded-cert}}.  It is used throughout this document wherever an algorithm identifier appears in the wire encoding.

# Encoding of Time Fields {#time-encoding}

Time fields are encoded as unwrapped CBOR epoch-based date/time (`~time`).  The tag content MUST be a non-negative integer.  In POSIX time {{POSIX}}, leap seconds are ignored; a leap second has the same POSIX time as the second before it.

# C509 CRL {#c509crl}

## Overview

A C509 CRL is a natively signed CBOR {{RFC8949}} encoding of an X.509 v2 CRL as defined in {{RFC5280, Section 5}}.  The signature is computed over the CBOR Sequence {{RFC8742}} `TBSCertList`; no ASN.1 encoding is involved.  A C509 CRL preserves the semantics of the corresponding DER-encoded X.509 CRL for the subset of RFC 5280 structures supported by this document.

A C509 CRL is not wire-format-compatible with a DER-encoded X.509 CRL.  The two formats cannot be mechanically converted to or from each other without semantic interpretation of the contained data.

## C509 CRL CDDL {#crl-cddl}

The following CDDL defines the top-level `C509CRL` structure and the `TBSCertList` sequence:

~~~~~~~~~~~ cddl
C509CRL = [
  TBSCertList,
  signatureValue : any,
]

TBSCertList = (
  CRLInfoData,
  revokedCertsList       : [+ PerIssuerRevokedCerts] / null
)

C509CRLInfo = [ CRLInfoData ]

CRLInfoData = (
  crlType                : uint,   ; 0 = C509CRL
  signatureAlgorithm     : IntAlgorithmIdentifier,
  authoritySubject       : Name / #6.121(bytes),
  authorityKeyIdentifier : bytes / null,
  crlNumber              : uint,
  thisUpdate             : ~time,
  nextUpdate             : uint / null,
  baseCrlNumber          : uint / null,
  crlExtensions          : Extensions,
)

PerIssuerRevokedCerts = (
  issuer                 : Name / #6.121(bytes) / null,
  revokedCertsControl    : RevokedCertsControl / null,
  extensions             : Extensions,
  revokedCerts           : bytes / null,
  removedFromCRLCerts    : bytes / null,
)

RevokedCertsControl = [
  flags               : uint,
  serialNumberLength  : uint,
  dateLength          : uint,
  baseDate            : ~time,
]
~~~~~~~~~~~
{: sourcecode-name="c509crl.cddl"}
{: #fig-CRLcddl title="CDDL for C509CRL"}

## Field Encodings {#crl-fields}

### CRLInfoData and C509CRLInfo

`CRLInfoData` is a CDDL group that carries all CRL fields except `revokedCertsList`.  `C509CRLInfo` is the standalone CBOR array form of `CRLInfoData`; it can be used to convey CRL freshness information (crlType, signature algorithm, issuer identity, CRL number, validity window, extensions) without the potentially large revocation list.  `TBSCertList` embeds `CRLInfoData` and adds `revokedCertsList`.

### crlType

The `crlType` field serves as the type discriminator for `C509CRL`, following the same extensibility pattern as `ocspRequestType` and `ocspResponseType`.  This document defines only type 0, corresponding to the `C509CRL` structure.  Future specifications may define additional types by assigning new integer values.

### signatureAlgorithm

Encoded identically to the `int` choice of `issuerSignatureAlgorithm` in C509 certificates (see {{I-D.ietf-cose-cbor-encoded-cert, Section 3.1.11}}).  Algorithm integer values are from the same registry used for C509 certificates.

Unlike in {{RFC5280}}, where the signature algorithm appears outside the `TBSCertList` and is therefore not covered by the CRL signature, `signatureAlgorithm` is part of `CRLInfoData` within `TBSCertList` and is therefore covered by the signature.  This prevents algorithm-substitution attacks on the CRL.

### authoritySubject and authorityKeyIdentifier

The `authoritySubject` and `authorityKeyIdentifier` fields identify the CRL authority.

The `authoritySubject` field identifies the subject of the CRL issuer.  When the CRL is issued by a C509 CA, `authoritySubject` is a `Name` value identical to the `subject` field of the authority C509 certificate.  When the CRL is issued by an X.509 CA (e.g., in a hybrid deployment where a legacy CA issues a C509-format CRL), `authoritySubject` is encoded as `#6.121(bytes)`, where the byte string contains the DER-encoded `Name` from the `subject` field of the issuing X.509 CA certificate ({{X.690}}).

The `authorityKeyIdentifier` field is identical to the value of the authority's `subjectKeyIdentifier` extension.  This field corresponds to the X.509 CRL extension `authorityKeyIdentifier` ({{RFC5280, Section 5.2.1}}).  It is promoted to a dedicated field because it MUST be present in conforming X.509 CRLs and because making it explicit simplifies the structure and reduces encoded size compared to representing it as a generic extension.

### crlNumber

The `crlNumber` field is encoded as an unsigned integer (`uint`).  It corresponds to the `cRLNumber` extension in {{RFC5280, Section 5.2.3}}, which this document replaces with a dedicated field.  The value is monotonically increasing for both full and delta CRLs.

### thisUpdate and nextUpdate

The `thisUpdate` field is encoded as described in {{time-encoding}}.  The `nextUpdate` field is encoded as a `uint` representing the number of seconds from `thisUpdate` until the next CRL is expected to be issued.  It is encoded as `null` when no next update time is known.

### baseCrlNumber

The `baseCrlNumber` field is encoded as `null` for a full CRL.  For a delta CRL, it contains the CRL number of the corresponding base full CRL.

### reasonCode Encoding {#reasoncode-encoding}

The `reasonCode` ENUMERATED value is encoded as one unsigned byte.  The byte values are aligned with the ENUMERATED values of the `CRLReason` type defined in {{RFC5280, Section 5.3.1}}; a C509 `revocationReason` byte value equals the corresponding ASN.1 ENUMERATED integer value for the same reason code.

| Byte | reasonCode             |
|:----:|:-----------------------|
| 0x00 | unspecified            |
| 0x01 | keyCompromise          |
| 0x02 | cACompromise           |
| 0x03 | affiliationChanged     |
| 0x04 | superseded             |
| 0x05 | cessationOfOperation   |
| 0x06 | certificateHold        |
|   -  | removeFromCRL          |
| 0x09 | privilegeWithdrawn     |
| 0x0A | aACompromise           |
{: #tab-reasoncode title="reasonCode encoding"}

`removeFromCRL` (enumeration value 0x08) is not encoded in `revokedCerts`.  Certificates removed from the CRL are instead indicated in the `removedFromCRLCerts` field of `PerIssuerRevokedCerts`.

### revokedCertsList and PerIssuerRevokedCerts

#### Design Considerations

In X.509 CRLs ({{RFC5280, Section 5.3.3}}), an indirect CRL uses the `certificateIssuer` CRL entry extension to indicate that a revocation entry — and all subsequent entries — belong to a different issuer.  This mechanism has two significant drawbacks: (1) it is implicit and positional, making it difficult to parse correctly and error-prone to implement; and (2) it is impossible to represent an issuer that has no currently revoked certificates (e.g., to carry per-issuer extensions or to explicitly indicate that the issuer is known but has an empty revocation list), because there is no entry to attach the `certificateIssuer` extension to.

`PerIssuerRevokedCerts` solves both problems by introducing an explicit intermediate structure that groups all revocation information for one issuer.  The issuer is identified directly in the `issuer` field of the structure rather than being inferred from the position of a CRL entry extension.  This makes the grouping unambiguous and easy to parse, and it allows an issuer to appear in the list even when it has no revoked certificates.

A second design problem in X.509 CRLs is that each revocation entry has variable length: the serial number length differs between certificates, the revocation date uses different encodings depending on whether the date falls before or after 2050, and optional per-entry extensions (e.g., reason code) may or may not be present.  This variable-length layout makes it impossible to determine whether a given serial number is present in the list without scanning every entry sequentially, resulting in O(n) lookup time.  In this document, the `revokedCertsControl` structure introduces fixed parameters (`serialNumberLength`, `dateLength`) that make every entry within `revokedCerts` exactly of the same size.  The `flags` field can additionally indicate that entries are sorted in ascending order by serial number, enabling binary search and reducing lookup time to O(log(n)).  Using a compact byte-string concatenation rather than a CBOR array of structured items further reduces encoded size and accelerates parsing.  Furthermore, certificates removed from the CRL (delta CRL `removeFromCRL` entries in X.509) are kept in a dedicated `removedFromCRLCerts` field rather than mixed into `revokedCerts`.  This keeps `revokedCerts` free of removal noise, reducing its size and allowing implementations to process currently-revoked and removed entries independently.

#### Fields

The `revokedCertsList` field is either a CBOR array of one or more `PerIssuerRevokedCerts` entries, each describing the revocation state for certificates issued by one issuer, or CBOR `null`.  `revokedCertsList` MUST be encoded as CBOR `null` when all of the following conditions hold: no certificates are currently revoked, no certificates have been removed from the CRL, the only issuer that would appear is the CRL's own `authoritySubject` (i.e., the `issuer` field is `null`), and there are no non-empty per-issuer extensions.

Each `PerIssuerRevokedCerts` entry describes revoked certificates for one issuer using the following fields:

- The `issuer` field identifies the issuer of the certificates covered by this `PerIssuerRevokedCerts` entry.  When the issuer is a C509 CA, it is encoded as a `Name` value identical to the `issuer` field of the covered C509 certificates.  When the issuer is an X.509 CA, it is encoded as `#6.121(bytes)` (tag 121 is alternative 0), where the byte string contains the DER-encoded `Name` from the `issuer` field of the covered X.509 certificates ({{X.690}}).  If the issuer is identical to the CRL's `authoritySubject` field, it MUST be encoded as CBOR `null`.

- The `revokedCertsControl` field defines the controls for interpreting `removedFromCRLCerts` and `revokedCerts`.  If either `removedFromCRLCerts` or `revokedCerts` is non-`null`, `revokedCertsControl` MUST NOT be `null`.  If both `removedFromCRLCerts` and `revokedCerts` are `null`, `revokedCertsControl` MUST be `null` to reduce CRL size.

  - The `flags` field is an unsigned integer encoding boolean control bits for `crlType = 0`: bit 0 (value 0x01) indicates whether entries in `revokedCerts` are sorted in ascending order by the integer value of the certificate serial number; bit 1 (value 0x02) indicates whether each entry contains a reason code.  Bits greater than 1 are reserved for `crlType = 0` and MUST be zero and MUST be ignored by receivers.  Future `crlType` values defined in successor documents may assign additional bit meanings.

  - The `serialNumberLength` field defines the length, in bytes, of a certificate serial number.  It MUST be greater than 0.  It SHOULD be the smallest value that can encode all certificate serial numbers without leading zeros.

   Each certificate serial number is encoded as a fixed-length big-endian integer of length `serialNumberLength`.  If the encoded value is shorter than `serialNumberLength`, it is left-padded with zeros.

  - The `dateLength` field defines the length, in bytes, of the big-endian encoded revocation-date offset relative to `baseDate`.  A value of 0 means that no revocation date is included in `revokedCerts` entries.  This is permitted in C509-native deployments where the revocation date is not required -- for example, when minimizing revocation data is more important than recording the revocation time.  Implementations that need to convert a C509 CRL to an RFC 5280 DER-encoded CRL MUST set `dateLength` to a non-zero value, since {{RFC5280, Section 5.1}} requires a `revocationDate` in every CRL entry.  When `dateLength` is non-zero, the offset MUST fit within the specified byte length without leading zero bytes.

  - The `baseDate` field is a reference time used to compute revocation and removal dates, encoded as described in {{time-encoding}}.  It MUST be greater than or equal to the issuer certificate's `notBefore`, which ensures that all stored offsets are non-negative.  It is RECOMMENDED to set `baseDate` to the earliest revocation date or removal-from-CRL date among all entries in this CRL, as this minimizes the magnitude of stored offsets and reduces encoding size.  Any time between the issuer certificate's `notBefore` (inclusive) and that earliest date (inclusive) is a conformant value.  Revocation dates in `revokedCerts` and removal dates in `removedFromCRLCerts` are stored as non-negative offsets, in seconds, from `baseDate`.

- The `extensions` field contains per-issuer extensions.  Only the `(extensionID: int, extensionValue: Defined)` choice is permitted.  If no per-issuer extensions are present, this field MUST be encoded as an empty CBOR array.

- The `revokedCerts` field is a CBOR byte string containing the concatenated byte sequence of revoked-certificate entries.  Each entry is the concatenation of:
  - a big-endian encoded certificate serial number of length `serialNumberLength`;
  - a big-endian encoded revocation-date offset from `baseDate`, in seconds, of length `dateLength` (absent when `dateLength` is 0); and
  - an optional reason code (1 byte if bit 1 of `flags` is set, absent otherwise).

  If there are no entries, this field MUST be encoded as CBOR `null` instead of a zero-length byte string.

  The revocation date for a given entry is recovered by adding the stored offset to `baseDate`.  When `dateLength` is 0, no revocation date is stored and no date recovery is possible.

  Revoked-certificate entries have fixed length.  If bit 0 of `flags` is set, entries are sorted in ascending order, enabling binary search for a given serial number in O(log(n)) time.

- The `removedFromCRLCerts` field contains a concatenated byte sequence of entries for certificates removed from the CRL since publication of the CRL with `crlNumber = baseCrlNumber`.  Each entry is the concatenation of:
  - a big-endian encoded certificate serial number of length `serialNumberLength`; and
  - a big-endian encoded removal-date offset from `baseDate`, in seconds, of length `dateLength` (absent when `dateLength` is 0).

  If there are no entries, this field MUST be encoded as CBOR `null` instead of a zero-length byte string.

  The removal date for a given entry is recovered by adding the stored offset to `baseDate`.  When `dateLength` is 0, no removal date is stored and no date recovery is possible.

  Removed-certificate entries have fixed length.  If bit 0 of `flags` is set, entries are sorted in ascending order, enabling binary search for a given serial number in O(log(n)) time.

### CRL Extensions

The `crlExtensions` field contains extensions for the CRL.  Only the `(extensionID: int, extensionValue: Defined)` choice is permitted.  This document does not define any new CRL-level extensions.

{{tab-crlExt}} lists X.509 CRL extensions and their equivalents.

| Code | Extension                | Reference         | Equivalent |
|:-----|:-------------------------|:------------------| :------------------|
| -    | authorityKeyIdentifier   | {{RFC5280, Section 5.2.1}}  | field `authorityKeyIdentifier` |
| -    | issuerAltName            | {{RFC5280, Section 5.2.2}}  | - |
| -    | cRLNumber                | {{RFC5280, Section 5.2.3}}  | field `crlNumber` |
| -    | deltaCRLIndicator        | {{RFC5280, Section 5.2.4}}  | field `baseCrlNumber` |
| -    | issuingDistributionPoint | {{RFC5280, Section 5.2.5}}  | - |
| -    | freshestCRL              | {{RFC5280, Section 5.2.6}}  | - |
| -    | authorityInfoAccess      | {{RFC5280, Section 5.2.7}}  | - |
| -    | orderedList              | OID 2.5.29.56 (ITU-T X.509, Section 9.5.2.5) | field `sorted` (ascSerialNum); - (ascRevDate) |
| -    | toBeRevoked              | OID 2.5.29.58 (ITU-T X.509, Section 9.5.2.6) | - |
| -    | revokedGroups            | OID 2.5.29.59 (ITU-T X.509, Section 9.5.2.7) | - |
{: #tab-crlExt title="CRL extensions and their equivalents"}

### Per-Issuer Extensions

The `extensions` field of `PerIssuerRevokedCerts` contains per-issuer extensions.  Only the `(extensionID: int, extensionValue: Defined)` choice is permitted.  This document defines one per-issuer extension (`expiredCertsOnCRL`, see {{ext-expired-certs}}).

{{tab-perIssuerExt}} lists per-issuer extensions defined in this document.

| Code | Extension                | Reference         | Equivalent |
|:-----|:-------------------------|:------------------| :------------------|
| TBD4 | expiredCertsOnCRL        | OID 2.5.29.60 (ITU-T X.509, Section 9.5.2.8)  | - |
{: #tab-perIssuerExt title="Per-issuer extensions and their equivalents"}

#### expiredCertsOnCRL {#ext-expired-certs}

The `expiredCertsOnCRL` extension indicates that this CRL includes revocation information for certificates that have already expired.  The extension value is a time value indicating the earliest expiration date of certificates included on the CRL; certificates that expired on or after this date are listed even if they are now expired.

The extension value MUST be encoded as follows.

~~~~~~~~~~~ cddl
ExpiredCertsOnCRL = ~time
~~~~~~~~~~~
{: sourcecode-name="c509crl.cddl"}

The value is encoded as described in {{time-encoding}}.  When this extension is present, a relying party processing expired certificates (for example, for audit or archiving purposes) SHOULD use the indicated date to determine the extent of historical revocation coverage.

### CRL Entry Extensions

{{tab-crlEntryExt}} lists X.509 CRL entry extensions.  No corresponding extension is defined in this document.

| Code | Extension           | Reference         | Equivalent |
|:-----|:--------------------|:------------------| :------------------|
| -    | reasonCode          | {{RFC5280, Section 5.3.1}} / ITU-T X.509, Section 9.6.2.1  | field `removedFromCRLCerts` and `revokedCerts` |
| -    | holdInstructionCode | {{RFC5280, Section 5.3.2}} / ITU-T X.509, Section 9.6.2.2  | - |
| -    | invalidityDate      | {{RFC5280, Section 5.3.2}} / ITU-T X.509, Section 9.6.2.3  | - |
| -    | certificateIssuer   | {{RFC5280, Section 5.3.3}} / ITU-T X.509, Section 9.6.2.4  | field `issuer` within `PerIssuerRevokedCerts` |
{: #tab-crlEntryExt title="CRL entry extensions defined for X.509 CRLs"}

### signatureValue

Encoded identically to `signatureValue` in C509 certificates (see {{I-D.ietf-cose-cbor-encoded-cert, Section 3.1.12}}).

# C509 OCSP {#c509ocsp}

## Overview

C509 OCSP defines CBOR encodings for OCSP requests and OCSP responses as defined in {{RFC6960}}.  The encoding follows the same compression principles as C509 CRL and C509 certificates.

C509 OCSP requests and responses are not wire-format-compatible with DER-encoded OCSP messages as defined in {{RFC6960}}.  The two formats cannot be mechanically converted to or from each other without semantic interpretation of the contained data.

`C509OCSPRequest` and `C509OCSPResponse` are designed to be extensible.  The first field of every message is `ocspRequestType` or `ocspResponseType`, an unsigned integer that identifies the structure type.  This document defines types 0, 1, and 2.  Future specifications may define additional types by assigning new integer values, enabling new request or response structures to be introduced without modifying the existing types.

## Identification of Certificates {#cert-identification}

To reduce OCSP message size, this document defines two truncated-hash identifier types used to refer to certificates compactly:

- `HashId8` — the leading 8 bytes of the hash value computed using the enclosing `hashAlgorithm`.  `HashId8` is used to identify issuer certificates and the certificates of OCSP requestors and responders in request and response structures where a short identifier provides sufficient uniqueness in the deployment context.

- `HashId20` — the leading 20 bytes of the hash value computed using the enclosing `hashAlgorithm`. `HashId20` is intended for identifying certificate serial numbers (the `serialNumberHash` field) when higher uniqueness is required to minimize collision risk. When derived from a secure hash (e.g., SHA‑256 or SHA‑3‑256) and treated as a random output, it gives ~2^160 preimage work and ~2^80 collision resistance (birthday bound) for the truncated value. Since the relying party verifies a certificate's signature before querying OCSP, an adversary needs to construct a different certificate that (a) validates under the same issuer chain and (b) has a serial number whose hash truncation equals an existing certificate's `HashId20`. Such a construction is practically infeasible.

~~~~~~~~~~~ cddl
HashId8   = bytes .size 8
HashId20  = bytes .size 20
~~~~~~~~~~~
{: sourcecode-name="c509ocsp.cddl"}

## C509 OCSP Request {#ocsp-request}

### CDDL {#ocsp-req-cddl}

~~~~~~~~~~~ cddl
C509OCSPRequest = C509UnsignedOCSPRequest /
                  C509SignedOCSPRequest /
                  C509SimpleOCSPRequest

C509UnsignedOCSPRequest = [
  ocspRequestType    : 0,
  hashAlgorithm      : IntAlgorithmIdentifier,
  nonce              : bytes / null,
  extensions         : Extensions,
  requests           : PerIssuerOCSPRequests
]

TBSOCSPRequest = (
  ocspRequestType    : 1,
  signatureAlgorithm : IntAlgorithmIdentifier,
  hashAlgorithm      : IntAlgorithmIdentifier,
  nonce              : bytes / null,
  requestorCertHash  : HashId8,
  extensions         : Extensions,
  requests           : PerIssuerOCSPRequests,
  requestorCerts     : COSE_C509 / #6.121(COSE_X509) / null,
)

C509SignedOCSPRequest = [
  TBSOCSPRequest,
  signatureValue     : any,
]

C509SimpleOCSPRequest = [
  ocspRequestType    : 2,
  hashAlgorithm      : IntAlgorithmIdentifier,
  nonce              : bytes / null,
  issuerCertHash     : HashId8,
  serialNumberHash   : HashId20,
  extensions         : Extensions
]

PerIssuerOCSPRequests = [ + PerIssuerOCSPRequest ]

PerIssuerOCSPRequest = (
  issuerCertHash   : HashId8,
  extensions       : Extensions,
  singleRequests   : SingleCertRequests,
)

SingleCertRequests  = [ + SingleCertRequest ]

SingleCertRequest = (
  serialNumberHash : HashId20,
  extensions       : Extensions,
)
~~~~~~~~~~~
{: sourcecode-name="c509ocsp.cddl"}
{: #fig-OCSPReqCDDL title="CDDL for C509OCSPRequest"}

### Field Encodings

#### ocspRequestType

The `ocspRequestType` field serves as the discriminator for `C509OCSPRequest`:

| Value | Type |
|:-----:|:-----|
| 0 | `C509UnsignedOCSPRequest` |
| 1 | `C509SignedOCSPRequest`   |
| 2 | `C509SimpleOCSPRequest`   |

#### issuerCertHash {#issuer-hash-id}

The `issuerCertHash` field appears in `PerIssuerOCSPRequest`, `PerIssuerOCSPResponse`, `C509SimpleOCSPRequest`, and `TBSSimpleOCSPResponse`.  It contains a hash of the issuer certificate:

- `issuerCertHash`: hash computed over the CBOR-encoded issuer C509 certificate, or over the DER-encoded issuer X.509 certificate ({{X.690}}).  The hash algorithm is specified by the `hashAlgorithm` field of the enclosing request or response structure.

In X.509 OCSP ({{RFC6960, Section 4.1.1}}), the `CertID` structure identifies the issuer using two separate hashes: `issuerNameHash` (a hash of the DER-encoded issuer name) and `issuerKeyHash` (a hash of the issuer's public key bit string).  This two-hash approach was designed for interoperability with DER-encoded X.509 structures, but it doubles the per-issuer overhead in the message.  In C509 OCSP, the issuer is identified by a single hash of the issuer certificate (`issuerCertHash`), which is simpler, smaller, and unambiguous.  Implementations that need to cross-reference a C509 `issuerCertHash` with an RFC 6960 DER-encoded `CertID` must recompute the respective hash inputs; the values are not directly comparable.

#### PerIssuerOCSPRequests, PerIssuerOCSPRequest, SingleCertRequests and SingleCertRequest {#per-issuer-requests}

`PerIssuerOCSPRequests` is a list of `PerIssuerOCSPRequest` entries.  In X.509 OCSP ({{RFC6960, Section 4.1.1}}), every `Request` entry embeds a full `CertID` containing the issuer identity fields (`hashAlgorithm`, `issuerNameHash`, `issuerKeyHash`) alongside the `serialNumber`.  When multiple certificates from the same issuer are queried in a single request, these issuer fields are repeated verbatim for every entry, wasting space.  `PerIssuerOCSPRequest` solves this by grouping all single-certificate requests for the same issuer under one entry: the `issuerCertHash` field is encoded once and shared across all `SingleCertRequest` entries in the `singleRequests` list, eliminating the per-entry duplication.

- The `extensions` field contains per-issuer extensions that apply to all single-certificate requests in this `PerIssuerOCSPRequest` entry; see {{ocsp-per-issuer-extensions}}.  If no per-issuer extensions are present, this field MUST be encoded as an empty CBOR array.
- The `singleRequests` field is a list of `SingleCertRequest` entries for certificates from this issuer.

Each `SingleCertRequest` contains:

- The `serialNumberHash` field is the truncated hash of the certificate serial number of the target certificate, computed using the `hashAlgorithm` of the enclosing request structure.  The serial number is encoded in big-endian byte order without a leading zero byte (as in C509 certificates) before hashing.  Using a hash rather than the plain serial number preserves the privacy of the requestor: an observer cannot determine which certificate is being queried without already knowing the serial number.
- The `extensions` field contains extensions for the single request; see {{ocsp-extensions}}.

#### C509UnsignedOCSPRequest {#C509UnsignedOCSPRequest}

- The `ocspRequestType` field MUST be 0, which discriminates `C509UnsignedOCSPRequest` from `C509SignedOCSPRequest`.
- The `hashAlgorithm` field specifies the hash algorithm used to compute `issuerCertHash` and `serialNumberHash`.  The algorithm is encoded as an integer from the "C509 Hash Algorithms" registry defined in {{hashalg}}.
- The `nonce` field contains the request nonce, or MUST be `null` when no nonce is present.
- The `extensions` field contains request-level extensions; see {{ocsp-extensions}}.
- The `requests` field is a list of `PerIssuerOCSPRequest` entries, each grouping target certificates by issuer; see {{per-issuer-requests}}.

#### C509SignedOCSPRequest

- The `ocspRequestType` field MUST be 1, which discriminates `C509SignedOCSPRequest` from `C509UnsignedOCSPRequest`.
- The `signatureAlgorithm` field specifies the signature algorithm, as defined in {{I-D.ietf-cose-cbor-encoded-cert, Section 3.1.11}}.
- The `hashAlgorithm` field specifies the hash algorithm used to compute `requestorCertHash`, `issuerCertHash`, and `serialNumberHash`.  The algorithm is encoded as an integer from the "C509 Hash Algorithms" registry defined in {{hashalg}}.
- The `nonce` field is as defined for `C509UnsignedOCSPRequest` ({{C509UnsignedOCSPRequest}}).
- The `requestorCertHash` field is a hash of the signer's certificate, computed using `hashAlgorithm`. `requestorCerts` MUST carry the corresponding certificate chain so that the receiver can verify the identity of the requestor.
- The `extensions` field contains request-level extensions; see {{ocsp-extensions}}.
- The `requests` field is as defined for `C509UnsignedOCSPRequest` ({{C509UnsignedOCSPRequest}}).
- The `requestorCerts` field contains a sorted certificate chain starting with the signer's certificate, or MUST be `null` if no certificates are transported.  When the signer holds a C509 certificate chain, the value is `COSE_C509`.  When the signer holds an X.509 certificate chain, the value is `#6.121(COSE_X509)`, wrapping a `COSE_X509` chain with CBOR tag 121 (alternative 0).
- The `signatureValue` field is the signature computed over the CBOR Sequence of the `TBSOCSPRequest` group.

#### C509SimpleOCSPRequest {#C509SimpleOCSPRequest}

`C509SimpleOCSPRequest` is a compact request format for querying the status of a single certificate.  Unlike `C509UnsignedOCSPRequest`, which uses a two-level `PerIssuerOCSPRequests` / `SingleCertRequest` grouping to batch multiple serial numbers across one or more issuers, `C509SimpleOCSPRequest` flattens the structure into a single CBOR array for the common case of a one-certificate query.

- The `ocspRequestType` field MUST be 2, which discriminates `C509SimpleOCSPRequest` from `C509UnsignedOCSPRequest` and `C509SignedOCSPRequest`.
- The `nonce` field contains the request nonce, or MUST be `null` when no nonce is present.
- The `issuerCertHash` field identifies the issuer of the target certificate; see {{issuer-hash-id}}.
- The `serialNumberHash` field is the hash of the certificate serial number of the target certificate, computed using the `hashAlgorithm` from `C509SimpleOCSPRequest`.  The serial number is encoded in big-endian byte order without a leading zero byte before hashing.  Using a hash rather than the plain serial number preserves the privacy of the requestor: an observer cannot determine which certificate is being queried without already knowing the serial number.
- The `extensions` field contains request-level extensions; see {{ocsp-extensions}}.  If no extensions are present, this field MUST be encoded as an empty CBOR array.

## C509 OCSP Response {#ocsp-response}

### CDDL {#ocsp-resp-cddl}

~~~~~~~~~~~ cddl
C509OCSPResponse = C509ErrorOCSPResponse /
                   C509BasicOCSPResponse /
                   C509SimpleOCSPResponse

C509ErrorOCSPResponse = [
  ocspResponseType  : 0,
  responseStatus    : int
]

TBSBasicOCSPResponse = (
  ocspResponseType   : 1,
  signatureAlgorithm : IntAlgorithmIdentifier,
  hashAlgorithm      : IntAlgorithmIdentifier,
  nonce              : bytes / null,
  responderCertHash  : HashId8,
  producedAt         : ~time,
  extensions         : Extensions,
  responses          : PerIssuerOCSPResponses,
  responderCerts     : COSE_C509 / #6.121(COSE_X509) / null,
)

C509BasicOCSPResponse = [
  TBSBasicOCSPResponse,
  signatureValue     : any
]

TBSSimpleOCSPResponse = (
  ocspResponseType   : 2,
  signatureAlgorithm : IntAlgorithmIdentifier,
  hashAlgorithm      : IntAlgorithmIdentifier,
  nonce              : bytes / null,
  responderCertHash  : HashId8,
  issuerCertHash     : HashId8,
  serialNumberHash   : HashId20,
  certStatus         : CertStatus,
  producedAt         : ~time,
  thisUpdate         : nint / 0,
  nextUpdate         : uint / null,
  extensions         : Extensions,
  responderCerts     : COSE_C509 / #6.121(COSE_X509) / null,
)

C509SimpleOCSPResponse = [
  TBSSimpleOCSPResponse,
  signatureValue     : any
]

PerIssuerOCSPResponses = [ + PerIssuerOCSPResponse ]

PerIssuerOCSPResponse = (
  issuerCertHash   : HashId8,
  extensions       : Extensions,
  singleResponses  : SingleCertResponses,
)

SingleCertResponses = [ + SingleCertResponse ]

SingleCertResponse = (
  serialNumberHash : HashId20,
  certStatus       : CertStatus,
  thisUpdate       : nint / 0,
  nextUpdate       : uint / null,
  extensions       : Extensions,
)

CertStatus = 0        ; good
           / 1        ; not-issued (issuer recognized,
                      ;   serial number not issued)
           / 2        ; unknown (issuer not recognized)
           / RevokedInfo

RevokedInfo = [
  revocationTime   : ~time,
  revocationReason : int,
]
~~~~~~~~~~~
{: sourcecode-name="c509ocsp.cddl"}
{: #fig-OCSPRespCDDL title="CDDL for C509OCSPResponse"}

### Field Encodings {#ocsp-resp-fields}

#### C509ErrorOCSPResponse

If the OCSP server cannot process the OCSP query, it returns a `C509ErrorOCSPResponse`.  The `ocspResponseType` value MUST be 0, and `responseStatus` has the following enumerated values:

| int | responseStatus     |
|:---:|:-------------------|
| -   | successful         |
| 1   | malformedRequest   |
| 2   | internalError      |
| 3   | tryLater           |
| 5   | sigRequired        |
| 6   | unauthorized       |
{: #tab-respstatus title="responseStatus values"}

#### C509BasicOCSPResponse

The `ocspResponseType` field of `C509BasicOCSPResponse` is 1, distinguishing it from `C509ErrorOCSPResponse`.  It corresponds to `BasicOCSPResponse` in {{RFC6960}}.

`TBSBasicOCSPResponse` is the group of fields to be signed. The `signatureValue` field is the only field outside the signed group.  Covering `signatureAlgorithm` and `responderCerts` within the signed content prevents algorithm-substitution and certificate-chain substitution attacks; this design goes beyond the protections offered by the DER-encoded `BasicOCSPResponse` defined in {{RFC6960}}.

#### C509SimpleOCSPResponse {#C509SimpleOCSPResponse}

`C509SimpleOCSPResponse` is a compact signed response for a single-certificate status query.  It is the response counterpart to `C509SimpleOCSPRequest` (see {{C509SimpleOCSPRequest}}).  Unlike `C509BasicOCSPResponse`, which uses a two-level `PerIssuerOCSPResponses` / `SingleCertResponse` grouping to carry status for multiple certificates across one or more issuers, `C509SimpleOCSPResponse` flattens the structure into a single signed CBOR array for the common case of a one-certificate response.

`TBSSimpleOCSPResponse` is the group of fields to be signed.  The `signatureValue` field is the only field outside the signed group.  Covering `signatureAlgorithm`, `responderCertHash`, and `responderCerts` within the signed content prevents algorithm-substitution and certificate-chain substitution attacks.

- The `ocspResponseType` field MUST be 2, which discriminates `C509SimpleOCSPResponse` from `C509ErrorOCSPResponse` and `C509BasicOCSPResponse`.
- The `signatureAlgorithm` field specifies the signature algorithm, as defined in {{I-D.ietf-cose-cbor-encoded-cert, Section 3.1.11}}.  It is part of `TBSSimpleOCSPResponse` and is therefore covered by the signature.
- The `hashAlgorithm` field specifies the hash algorithm used to compute `responderCertHash`, `issuerCertHash`, and `serialNumberHash`.  The algorithm is encoded as an integer from the "C509 Hash Algorithms" registry defined in {{hashalg}}.
- The `responderCertHash` field identifies the OCSP responder; see {{responderCertHash}}.
- The `nonce` field contains the request nonce, or MUST be `null` when no nonce is present.  If present, it MUST have the same value as the `nonce` in the corresponding `C509SimpleOCSPRequest`.
- The `issuerCertHash` field identifies the issuer of the queried certificate; see {{issuer-hash-id}}.
- The `serialNumberHash` field is the hash of the certificate serial number of the queried certificate, computed using `hashAlgorithm`.  The serial number is encoded in big-endian byte order without a leading zero byte before hashing; see {{serialNumberHash-section}}.
- The `producedAt` field is the time at which this response was produced, encoded as described in {{time-encoding}}.
- The `thisUpdate` field is encoded as a non-positive integer (`nint / 0`) representing the number of seconds from `producedAt` at which the indicated status is known to be correct.  It MUST be 0 or negative, since the status cannot be known at a time in the future relative to the time the response was produced.
- The `nextUpdate` field is encoded as a `uint` representing the number of seconds from `producedAt` until the next response update is expected, or `null` if the update time is unknown.
- The `certStatus` field encodes the revocation status; see {{SingleCertResponse}}.
- The `extensions` field contains response-level extensions; see {{ocsp-extensions}}.  If no extensions are present, this field MUST be encoded as an empty CBOR array.
- The `responderCerts` field carries the certificate chain starting with the responder certificate identified by `responderCertHash`; see {{responderCerts}}.
- The `signatureValue` field is the signature computed over the CBOR Sequence of the `TBSSimpleOCSPResponse` group.

#### nonce

If present, this field MUST have the same value as the `nonce` in the corresponding request.

#### responderCertHash {#responderCertHash}

`responderCertHash` is a truncated hash over the responder's certificate, computed using the same `hashAlgorithm` as `issuerCertHash`.  In X.509 OCSP ({{RFC6960}}), the responder is identified by a `ResponderID` CHOICE that carries either a distinguished name or a public-key hash.  C509 OCSP replaces this with a single hash over the entire responder certificate, which is consistent with the `issuerCertHash` design for issuer identification.

#### responderCerts {#responderCerts}

When present, the `responderCerts` field carries the certificate chain starting with the responder certificate identified by `responderCertHash`.  When the responder holds a C509 certificate chain, the value is `COSE_C509`.  When the responder holds an X.509 certificate chain, the value is `#6.121(COSE_X509)`, wrapping a `COSE_X509` chain with CBOR tag 121 (alternative 0).  The field is part of `TBSBasicOCSPResponse` and is therefore covered by the signature, which prevents certificate-chain substitution attacks.

#### signatureAlgorithm and signatureValue

- `signatureAlgorithm`: the signature algorithm used to compute `signatureValue`, as defined in {{I-D.ietf-cose-cbor-encoded-cert, Section 3.1.11}}.  It is part of the `TBSBasicOCSPResponse` group and is therefore covered by the signature.
- `signatureValue`: the signature computed over the CBOR Sequence of the `TBSBasicOCSPResponse` group.

#### producedAt, thisUpdate, nextUpdate

The `producedAt` field is encoded as described in {{time-encoding}}.  The `thisUpdate` field is encoded as a non-positive integer (`nint / 0`) representing the number of seconds from `producedAt` at which the indicated status is known to be correct; it MUST be 0 or negative, since the status cannot be known at a time in the future relative to when the response was produced.  The `nextUpdate` field is encoded as a `uint` representing the number of seconds from `producedAt` until the next update is expected to be available.  `nextUpdate` may be `null`, which indicates an unknown update time.

#### extensions

See {{ocsp-extensions}}.

#### PerIssuerOCSPResponses and PerIssuerOCSPResponse

`PerIssuerOCSPResponses` is a list of `PerIssuerOCSPResponse` entries.  For the same reason as on the request side (see {{per-issuer-requests}}), the `issuerCertHash` field is encoded once per issuer and shared across all `SingleCertResponse` entries in the `singleResponses` list, avoiding the per-entry repetition that would occur if the issuer identity were embedded in every individual response entry.  `PerIssuerOCSPResponse` groups single responses for certificates issued by the same issuer; the issuer is identified by `issuerCertHash` (see {{issuer-hash-id}}).

- The `extensions` field contains per-issuer extensions that apply to all single-certificate responses in this `PerIssuerOCSPResponse` entry; see {{ocsp-per-issuer-extensions}}.  If no per-issuer extensions are present, this field MUST be encoded as an empty CBOR array.
- The `singleResponses` field contains one `SingleCertResponse` for each queried certificate issued by that issuer.

#### SingleCertResponse {#SingleCertResponse}

##### serialNumberHash {#serialNumberHash-section}

This field contains the truncated hash of the serial number of the certificate being queried.  It is computed using the `hashAlgorithm` from the enclosing `TBSBasicOCSPResponse` and contains the first 20 bytes.  The serial number is encoded in big-endian byte order without a leading zero byte before hashing.  In X.509, a `CertificateSerialNumber` INTEGER is DER-encoded with a leading zero byte when the most-significant bit is set; that leading zero MUST be stripped before computing the hash.  In X.509 OCSP ({{RFC6960, Section 4.1.1}}), the `CertID` structure carries the plain `serialNumber` directly.  C509 OCSP replaces this with a hash to preserve privacy: an observer cannot determine which certificate was queried without already knowing the serial number.

##### extensions

See {{ocsp-extensions}}.

##### certStatus

`CertStatus` is encoded either as an integer (for `good`, `not-issued`, and `unknown`) or as a `RevokedInfo` array:

- 0: `good` -- the certificate is not revoked.
- 1: `not-issued` -- the issuer is recognized but the serial number is unknown.
- 2: `unknown` -- the responder does not recognize the issuer identified by `issuerCertHash`.
- `RevokedInfo`: `revoked` -- a fixed-length 2-element array carrying `revocationTime` and `revocationReason`.  The `revocationReason` field is encoded as specified in {{reasoncode-encoding}}.  When the revocation reason is not known, `revocationReason` MUST be set to 0 (unspecified).

The integer values are chosen to align with the ASN.1 IMPLICIT tag numbers of `CertStatus` in {{RFC6960}}: `good` uses \[0\] (value 0) and `unknown` uses \[2\] (value 2).  The ASN.1 `revoked` alternative uses \[1\]; since C509 represents the revoked status as the explicit `RevokedInfo` array, the integer value 1 becomes available.  It is assigned to the `not-issued` status, which was introduced in {{RFC6960, Section 4.4.8}} to distinguish unrecognized serial numbers from unrecognized issuers, thereby maintaining a contiguous integer range for the non-revoked statuses.

#### Per-Issuer OCSP Extensions {#ocsp-per-issuer-extensions}

`PerIssuerOCSPRequest.extensions` and `PerIssuerOCSPResponse.extensions` carry per-issuer extensions.  Only the `(extensionID: int, extensionValue: Defined)` choice of `Extensions` is permitted.  If no per-issuer extensions are present, the field MUST be encoded as an empty CBOR array `[]`.

{{tab-perIssuerOCSPExt}} lists the per-issuer extensions defined in this document.

| Code | Extension | Applied in | Comments |
|:----:|:----------|:-----------|:---------|
| (none defined) | | | |
{: #tab-perIssuerOCSPExt title="Per-issuer OCSP extensions"}

#### OCSP Extensions {#ocsp-extensions}

{{tab-ocspext}} describes the OCSP extensions defined in {{RFC6960}} and their mapping in this document.

| Code | Extension             | RFC Reference     | Applied in | Replaced in this document |
|:----:|:----------------------|:------------------| :----------|:--------------|
|  -   | nonce                 | {{RFC6960, Section 4.4.1}}  | Request Extension, Response Extension | field `nonce` |
|  -   | CRL References        | {{RFC6960, Section 4.4.2}}  | Single Response Extension | - |
| TBD2 | Acceptable Response Types | {{RFC6960, Section 4.4.3}}  | Request Extension | - |
|  -   | Archive Cutoff        | {{RFC6960, Section 4.4.4}}  | Response Extension | - |
|  -   | Service Locator       | {{RFC6960, Section 4.4.5}}  | Request Extension | - |
| TBD3 | Preferred Signature Algorithms | {{RFC6960, Section 4.4.7}} | Request Extension | - |
|  -   | Extended Revoked Definition | {{RFC6960, Section 4.4.8}}  | Response Extension | cert status `not-issued` (for serial numbers not issued by a recognized issuer) and `unknown` (for unrecognized issuers) |
| TBD6 | TN Query | {{I-D.ietf-stir-certificates-ocsp}} | Single Request Extension | - |
{: #tab-ocspext title="OCSP extensions defined in RFC 6960"}

This document defines the following extension values:

* Acceptable Response Types: The extension value MUST be encoded as follows.

~~~~~~~~~~~ cddl
AcceptableResponseTypes = [ + int]
~~~~~~~~~~~
{: sourcecode-name="c509ocsp.cddl"}

The integers in `AcceptableResponseTypes` form a sorted list of preferred `C509OCSPResponse` types, in descending order of preference, that the requestor is willing to accept.  This document defines types 0 (`C509ErrorOCSPResponse`), 1 (`C509BasicOCSPResponse`), and 2 (`C509SimpleOCSPResponse`).  Type 0 (`C509ErrorOCSPResponse`) is always implicitly supported and does not need to be listed.  When this extension is absent, an OCSP server responding to a `C509UnsignedOCSPRequest` or `C509SignedOCSPRequest` MUST reply with a `C509BasicOCSPResponse` (type 1); an OCSP server responding to a `C509SimpleOCSPRequest` MUST reply with a `C509SimpleOCSPResponse` (type 2).  If `AcceptableResponseTypes` contains type 2 but not type 1, and the corresponding request contains entries for two or more certificates, the server SHALL return a `C509ErrorOCSPResponse` with `responseStatus` set to `malformedRequest` (1), since `C509SimpleOCSPResponse` can only carry status for a single certificate.

* Preferred Signature Algorithms: The extension value MUST be encoded as follows.

~~~~~~~~~~~ cddl
PreferredSignatureAlgorithm = (
  sigIdentifier        : IntAlgorithmIdentifier,
  pubKeyAlgIdentifiers : [ 2* IntAlgorithmIdentifier ]
                         / IntAlgorithmIdentifier
                         / null,
)

IntAlgorithmIdentifier = int

PreferredSignatureAlgorithms = [ + PreferredSignatureAlgorithm ]
~~~~~~~~~~~
{: sourcecode-name="c509ocsp.cddl"}

The `sigIdentifier` field carries the signature algorithm identifier.  The `pubKeyAlgIdentifiers` field carries the public key algorithm identifier and MUST be one of:

- a CBOR array of two or more `IntAlgorithmIdentifier` values, sorted in descending order of preference, when the responder is willing to accept any of the listed public key algorithms as a match for this signature algorithm preference (e.g., to express hybrid or multi-algorithm key policies); the first entry in the array represents the most preferred public key algorithm,
- a single `IntAlgorithmIdentifier` value, when exactly one public key algorithm is acceptable, or
- `null`, when the public key algorithm is unconstrained or implied by `sigIdentifier`.

`PreferredSignatureAlgorithms` MUST be sorted in descending order of preference; the first entry represents the most preferred algorithm combination.

* TN Query: The extension value MUST be encoded as follows.

~~~~~~~~~~~ cddl
TNQuery = text .size (1..15)
~~~~~~~~~~~
{: sourcecode-name="c509ocsp.cddl"}

The `TNQuery` extension carries a telephone number string conforming to the TelephoneNumber ASN.1 type ({{RFC8226, Section 3}}).  When included in single request extensions, it specifies the telephone number for which the OCSP query is being performed (typically the number from the "orig" field of a PASSporT being validated).

Clients MUST include this extension in the single-request extensions per {{I-D.ietf-stir-certificates-ocsp}}.

## Certificate Type Interoperability {#cert-type-interop}

C509 OCSP uses a single set of request and response structures that handles both C509 and X.509 certificates without modification.  All participants -- requestor, responder, and issuer -- are identified by a hash over their certificate rather than by type-specific fields such as a Subject distinguished name, SubjectKeyIdentifier, or the X.509 `ResponderID` CHOICE (`byName` or `byKey`).  Because a hash applies uniformly regardless of the certificate encoding, the same OCSP structures accommodate C509 certificates (CBOR-encoded), X.509 certificates (DER-encoded), and any future certificate types.

The only per-type differences are in how identity hashes are computed and how certificate chains are carried:

| Field | C509 certificate | X.509 certificate |
|:------|:-----------------|:------------------|
| `issuerCertHash`    | Hash of CBOR-encoded `C509Certificate` | Hash of DER-encoded X.509 certificate |
| `requestorCertHash` | Hash of CBOR-encoded `C509Certificate` | Hash of DER-encoded X.509 certificate |
| `responderCertHash` | Hash of CBOR-encoded `C509Certificate` | Hash of DER-encoded X.509 certificate |
| `requestorCerts` / `responderCerts` | `COSE_C509` | `#6.121(COSE_X509)` |
{: #tab-certtypeinterop title="Per-type differences in C509 OCSP identity fields"}

In a hybrid deployment where the responder holds an X.509 certificate, `responderCertHash` contains the hash of the DER-encoded X.509 certificate and `responderCerts` carries a `#6.121(COSE_X509)` chain.  In a deployment using C509 certificates throughout, all identity hashes are computed over CBOR-encoded certificates and certificate chains are carried as `COSE_C509`.  The `hashAlgorithm` field at the top level of each request or response structure governs all hashes within that structure.

## OCSP Stapling in TLS

In standard TLS certificate status stapling (see the `status_request` extension, {{RFC8446, Section 4.4.2.1}}), the stapled OCSP response is a DER-encoded `OCSPResponse`.  To allow C509 OCSP stapling, this document defines a new TLS `CertificateStatusType` value {{RFC6066, Section 8}}:

| Value | Name              | Reference     |
|:-----:|:------------------|:--------------|
| TBD1  | c509_ocsp         | This document |
{: #tab-tlsstaple title="TLS CertificateStatusType for C509 OCSP"}

When `CertificateStatusType` is `c509_ocsp`, the `status` field contains a CBOR-encoded `C509OCSPResponse` instead of a DER-encoded `OCSPResponse`.

# C509 Hash Algorithms {#hashalg}

This document defines the following hash algorithms.

~~~~~~~~~~~
+-------+----------------------------------------------------------+
| Value | Hash Algorithm                                           |
+=======+==========================================================+
|   0   | Name:        SHA-256                                     |
|       | Identifiers: id-sha256                                   |
|       | OID:         2.16.840.1.101.3.4.2.1                      |
|       | Parameters:  absent                                      |
|       | DER:         60 86 48 01 65 03 04 02 01                  |
|       | Comments:                                                |
+-------+----------------------------------------------------------+
|   1   | Name:        SHA-384                                     |
|       | Identifiers: id-sha384                                   |
|       | OID:         2.16.840.1.101.3.4.2.2                      |
|       | Parameters:  absent                                      |
|       | DER:         60 86 48 01 65 03 04 02 02                  |
|       | Comments:                                                |
+-------+----------------------------------------------------------+
|   2   | Name:        SHA-512                                     |
|       | Identifiers: id-sha512                                   |
|       | OID:         2.16.840.1.101.3.4.2.3                      |
|       | Parameters:  absent                                      |
|       | DER:         60 86 48 01 65 03 04 02 03                  |
|       | Comments:                                                |
+-------+----------------------------------------------------------+
|   3   | Name:        SHA-224                                     |
|       | Identifiers: id-sha224                                   |
|       | OID:         2.16.840.1.101.3.4.2.4                      |
|       | Parameters:  absent                                      |
|       | DER:         60 86 48 01 65 03 04 02 04                  |
|       | Comments:                                                |
+-------+----------------------------------------------------------+
|   4   | Name:        SM3                                         |
|       | Identifiers: id-sm3                                      |
|       | OID:         1.2.156.10197.1.401                         |
|       | Parameters:  absent                                      |
|       | DER:         06 08 2A 81 1C 84 8E 35 01 04 01            |
|       | Comments:                                                |
+-------+----------------------------------------------------------+
|   5   | Name:        SHA3-256                                    |
|       | Identifiers: id-sha3-256                                 |
|       | OID:         2.16.840.1.101.3.4.2.8                      |
|       | Parameters:  absent                                      |
|       | DER:         60 86 48 01 65 03 04 02 08                  |
|       | Comments:                                                |
+-------+----------------------------------------------------------+
|   6   | Name:        SHA3-384                                    |
|       | Identifiers: id-sha3-384                                 |
|       | OID:         2.16.840.1.101.3.4.2.9                      |
|       | Parameters:  absent                                      |
|       | DER:         60 86 48 01 65 03 04 02 09                  |
|       | Comments:                                                |
+-------+----------------------------------------------------------+
|   7   | Name:        SHA3-512                                    |
|       | Identifiers: id-sha3-512                                 |
|       | OID:         2.16.840.1.101.3.4.2.10                     |
|       | Parameters:  absent                                      |
|       | DER:         60 86 48 01 65 03 04 02 0A                  |
|       | Comments:                                                |
+-------+----------------------------------------------------------+
|   8   | Name:        SHA3-224                                    |
|       | Identifiers: id-sha3-224                                 |
|       | OID:         2.16.840.1.101.3.4.2.7                      |
|       | Parameters:  absent                                      |
|       | DER:         60 86 48 01 65 03 04 02 07                  |
|       | Comments:                                                |
+-------+----------------------------------------------------------+
|   9   | Name:        SHAKE128                                    |
|       | Identifiers: id-shake128                                 |
|       | OID:         2.16.840.1.101.3.4.2.11                     |
|       | Parameters:  absent                                      |
|       | DER:         60 86 48 01 65 03 04 02 0B                  |
|       | Comments:                                                |
+-------+----------------------------------------------------------+
|   10  | Name:        SHAKE256                                    |
|       | Identifiers: id-shake256                                 |
|       | OID:         2.16.840.1.101.3.4.2.12                     |
|       | Parameters:  absent                                      |
|       | DER:         60 86 48 01 65 03 04 02 0C                  |
|       | Comments:                                                |
+-------+----------------------------------------------------------+
~~~~~~~~~~~
{: #tab-hash-alg title="C509 Hash Algorithms"}

# Security Considerations {#security}

TODO

# IANA Considerations {#iana}

This document has the following actions for IANA.

Note to RFC Editor: Please replace all occurrences of "{{&SELF}}" with the RFC number of this specification and delete this paragraph.

## Extension Identifiers Registry

IANA is requested to assign the new values shown in {{tab-extensions-iana}} in the "C509 Extensions" registry under the new registry group "CBOR Encoded X.509 (C509)" defined in {{I-D.ietf-cose-cbor-encoded-cert}}.

~~~
+-------+----------------------------------------------------------+
| Value | Extension                                                |
+=======+==========================================================+
| TBD2  | Name:            Acceptable Response Types               |
|       | Identifiers:     id-pkix-ocsp-response                   |
|       | OID:             1.3.6.1.5.5.7.48.1.4                    |
|       | DER:             06 09 2B 06 01 05 05 07 30 01 04        |
|       | Comments:        RFC 6960                                |
|       | extensionValue:  AcceptableResponseTypes                 |
+-------+----------------------------------------------------------+
| TBD3  | Name:            Preferred Signature Algorithms          |
|       | Identifiers:     id-pkix-ocsp-pref-sig-algs              |
|       | OID:             1.3.6.1.5.5.7.48.1.8                    |
|       | DER:             06 09 2B 06 01 05 05 07 30 01 08        |
|       | Comments:        RFC 6960                                |
|       | extensionValue:  PreferredSignatureAlgorithms            |
+-------+----------------------------------------------------------+
| TBD4  | Name:            Expired Certificates on CRL             |
|       | Identifiers:     id-ce-expiredCertsOnCRL                 |
|       | OID:             2.5.29.60                               |
|       | DER:             06 03 55 1D 3C                          |
|       | Comments:        ITU-T X.509, Section 9.5.2.8            |
|       | extensionValue:  ExpiredCertsOnCRL                       |
+-------+----------------------------------------------------------+
| TBD6  | Name:            TN Query                                |
|       | Identifiers:     id-pkix-ocsp-stir-tn                    |
|       | OID:             1.3.6.1.5.5.7.48.1.10                   |
|       | DER:             06 09 2B 06 01 05 05 07 30 01 0A        |
|       | Comments:        draft-ietf-stir-certificates-ocsp       |
|       | extensionValue:  TNQuery                                 |
+-------+----------------------------------------------------------+
~~~
{: #tab-extensions-iana title="C509 extension identifier allocation requests"}

## C509 Hash Algorithms Registry {#iana-hash-alg}

IANA is requested to create a new registry "C509 Hash Algorithms" under the registry group "CBOR Encoded X.509 (C509)" defined in {{I-D.ietf-cose-cbor-encoded-cert}}.

The registration policy is either "Private Use", "IETF Review with Expert Review", or "Expert Review" per {{RFC8126, Section 4.5}}. "Expert Review" guidelines are provided in {{expert-review-guidelines}}.

All assignments according to "IETF Review with Expert Review" are made on an "IETF Review" basis per {{RFC8126, Section 4.8}}, with Expert Review additionally required per {{RFC8126, Section 4.5}}. The procedure for early IANA allocation of Standards Track code points defined in {{RFC7120}} also applies. When such a procedure is used, IANA will ask the designated expert(s) to approve the early allocation before registration. In addition, WG chairs are encouraged to consult the expert(s) early during the process outlined in {{RFC7120, Section 3.1}}.

The columns of this registry are:

* Value: This field contains the value used to identify the C509 hash algorithm. These values MUST be unique. The value can be a positive integer or a negative integer. Different ranges of values use different registration policies {{RFC8126}}. Integer values from -24 to 23 are designated as "IETF Review with Expert Review". Integer values greater than 32767 are marked as "Private Use". All other integer values are designated as "Expert Review". This field MUST NOT be empty.

* Name: This field contains the name of the C509 hash algorithm. This field MUST NOT be empty.
* Identifiers: This field contains additional identifiers of the C509 hash algorithm, if any is available.
* OID: This field contains the OID corresponding to the C509 hash algorithm. This field MUST NOT be empty.
* Parameters: This field contains the parameters of the C509 hash algorithm. This field MUST NOT be empty. If the C509 hash algorithm has no parameters, this field contains the string "absent".
* DER: This field contains the DER encoding of the ASN.1 value of type DigestInfo for the C509 hash algorithm. This field MUST NOT be empty.
* Comments: This field contains any optional comment about the C509 hash algorithm.
* Reference: This field contains a pointer to the public specification for the C509 hash algorithm, if one is available.

This registry has been initially populated with the entries defined in {{hashalg}}.

## TLS CertificateStatusType Registry

IANA is requested to assign the value shown in {{tab-tls-certstatus-iana}} in the "TLS Certificate Status Types" registry under "Transport Layer Security (TLS) Extensions":

| Value | Description | Reference     | Comment |
|:-----:|:------------|:--------------|:--------------|
| TBD1  | c509_ocsp   | This document | N/A |
{: #tab-tls-certstatus-iana title="TLS CertificateStatusType allocation request"}

## Media Type Application Registry

IANA is requested to assign the following entries into the "application" registry in the registry group "Media Types" with this document as reference.

### Media Type application/c509-crl+cbor

When the application/c509-crl+cbor media type is used, the data is a C509CRL structure.

Subtype name: c509-crl+cbor

Required parameters: N/A

Encoding considerations: binary

Security considerations: See {{security}} of {{&SELF}}.

Interoperability considerations: N/A

Published specification: {{&SELF}}

Applications that use this media type: Any MIME-compliant transport

Fragment identifier considerations: N/A

Additional information:

* Deprecated alias names for this type: N/A
* Magic number(s): N/A
* File extension(s): .c509

* Macintosh file type code(s): N/A

Person & email address to contact for further information: iesg@ietf.org

Intended usage: COMMON

Restrictions on usage: N/A

Author: COSE WG

Change controller: IETF

### Media Type application/c509-crlinfo+cbor

When the application/c509-crlinfo+cbor media type is used, the data is a C509CRLInfo structure.

Subtype name: c509-crlinfo+cbor

Required parameters: N/A

Encoding considerations: binary

Security considerations: See {{security}} of {{&SELF}}.

Interoperability considerations: N/A

Published specification: {{&SELF}}

Applications that use this media type: Any MIME-compliant transport

Fragment identifier considerations: N/A

Additional information:

* Deprecated alias names for this type: N/A
* Magic number(s): N/A
* File extension(s): .c509

* Macintosh file type code(s): N/A

Person & email address to contact for further information: iesg@ietf.org

Intended usage: COMMON

Restrictions on usage: N/A

Author: COSE WG

Change controller: IETF

### Media Type application/c509-ocspreq+cbor

When the application/c509-ocspreq+cbor media type is used, the data is a C509OCSPRequest structure.

Subtype name: c509-ocspreq+cbor

Required parameters: N/A

Encoding considerations: binary

Security considerations: See {{security}} of {{&SELF}}.

Interoperability considerations: N/A

Published specification: {{&SELF}}

Applications that use this media type: OCSP clients

Fragment identifier considerations: N/A

Additional information:

* Deprecated alias names for this type: N/A
* Magic number(s): N/A
* File extension(s): .c509

* Macintosh file type code(s): N/A

Person & email address to contact for further information: iesg@ietf.org

Intended usage: COMMON

Restrictions on usage: N/A

Author: COSE WG

Change controller: IETF

### Media Type application/c509-ocspresp+cbor

When the application/c509-ocspresp+cbor media type is used, the data is a C509OCSPResponse structure.

Subtype name: c509-ocspresp+cbor

Required parameters: N/A

Encoding considerations: binary

Security considerations: See {{security}} of {{&SELF}}.

Interoperability considerations: N/A

Published specification: {{&SELF}}

Applications that use this media type: OCSP servers

Fragment identifier considerations: N/A

Additional information:

* Deprecated alias names for this type: N/A
* Magic number(s): N/A
* File extension(s): .c509

* Macintosh file type code(s): N/A

Person & email address to contact for further information: iesg@ietf.org

Intended usage: COMMON

Restrictions on usage: N/A

Author: COSE WG

Change controller: IETF

## CoAP Content-Formats Registry {#content-format}

IANA is requested to add entries for "application/c509-crl+cbor", "application/c509-crlinfo+cbor", "application/c509-ocspreq+cbor" and "application/c509-ocspresp+cbor" to the "CoAP Content-Formats" registry in the registry group "Constrained RESTful Environments (CoRE) Parameters".

~~~
+-------------------------+---------+-------+------------+
| Content                 | Content | ID    | Reference  |
| Type                    | Coding  |       |            |
+=========================+=========+=======+============+
| application/            | -       | TBD7  | [[this     |
| c509-crl+cbor           |         |       | document]] |
+-------------------------+---------+-------+------------+
| application/            |         |       | [[this     |
| c509-crlinfo+cbor       | -       | TBD8  | document]] |
+-------------------------+---------+-------+------------+
| application/            | -       | TBD9  | [[this     |
| c509-ocspreq+cbor       |         |       | document]] |
+-------------------------+---------+-------+------------+
| application/            | -       | TBD10 | [[this     |
| c509-ocspresp+cbor      |         |       | document]] |
+-------------------------+---------+-------+------------+
~~~

## Expert Review Guidelines {#expert-review-guidelines}

TODO

--- back


# Examples {#examples}

## Overview

| Section       | Description           | size(C509) | size(X509) | Size Reduction |
|:--------------|:----------------------|:-----------|:-----------|:----------------------|
| {{exam-crl-no-revoked}} | CRL Example Without Revoked Certificates | 147 | 120 | 18% |
| {{exam-crl-revoked}} | CRL Example With Revoked Certificates | 335 | 177 |47% |
| {{exam-delta-crl-revoked}} | Delta CRL Example With Revoked Certificates | 335 | 160 | 52% |
| {{exam-indirect-crl-revoked}} | Indirect CRL Example With Revoked Certificates | 409 | 202 | 51% |
| {{exam-simple-ocsp-req}} | Simple OCSP Request Example | 152 | 51 | 66% |
| {{exam-unsigned-ocsp-req}} | Unsigned OCSP Request Example | 483 | 132 | 73% |
| {{exam-signed-ocsp-req}} | Signed OCSP Request Example Without Requestor's Certificate | 592 | 209 | 65% |
| {{exam-signed-ocsp-req-withcert}} | Signed OCSP Request Example With Requestor's Certificate | 1043 | 420 | 60% |
| {{exam-signed-ocsp-req-withcertchain}} | Signed OCSP Request Example With Requestor's Certificate Chain | 1379 | 625 | 55% |
| {{exam-error-ocsp-resp}} | Error OCSP Response Example | 5 | 3 | 40% |
| {{exam-simple-ocsp-resp}} | Simple OCSP Response Example | 338 | 140 | 59% |
| {{exam-basic-ocsp-resp}} | Basic OCSP Response Example Without Responder's Certificate | 845 | 248 | 71% |
| {{exam-basic-ocsp-resp-withcert}} | Basic OCSP Response Example With Responder's Certificate | 1189 | 446 | 62% |
| {{exam-basic-ocsp-resp-withcertchain}} | Basic OCSP Response Example With Responder's Certificate Chain | 1525 | 651 | 57% |
{: #tab-examples-overview title="Size comparison in examples (TODO: update the percent data)"}

## Helper Keys and Certificates

### CA Private Key and Certificate

#### CA Private Key

[comment]: <> (replace-data:key/crlocsp-ca/prikey.pem)
~~~~~
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIDP+AdMbqXudBAN3YNAwoR0i3nl4IuoSSA6Hazy2oAKc
-----END PRIVATE KEY-----
~~~~~

#### CA Certificate {#ca-cert}

##### Plain Hex

[comment]: <> (replace-data:cert/crlocsp-ca/c509cert-t2.hex)
~~~~~
8B0241010C73746573742063726C6F6373702D726F6F7463611A677485801A6B36EC
7F6F746573742063726C6F6373702D63610C58205EF8A355A001A7C50D2349470120
8131A4BB2AB920D40BFB0EE1F6AB28FF74008801542F45E78D2CAEDF368CDF53C390
05D492450E1056211860230107542DA3A403F7D2F4E0B3D8031A73BA8A839F557F0F
5840E50465D60C02A2111EF3FC6E44F2A36008765B552351F9A3F5B2AA7C76F1F05D
259847A4F4250B2E4B0AE2099762A2596D3CC1DB2CCD180AA0A2D0E191310B0F
~~~~~

##### Textual Representation

[comment]: <> (replace-data:cert/crlocsp-ca/c509cert-t2.txt)
~~~~~
Certificate
  TBSCertificate
    Certificate Type: 2
    Serial Number
      01
    Signature Algorithm: Ed25519 (12)
    Issuer : CN=test crlocsp-rootca
    Subject: CN=test crlocsp-ca
    Validity
      Not Before: 2025-01-01T00:00:00Z
      Not After : 2026-12-31T23:59:59Z
    Subject Public Key Info:
      algorithm: Ed25519 (12)
      Raw public key
        5e:f8:a3:55:a0:01:a7:c5:0d:23:49:47:01:20:81:31:
        a4:bb:2a:b9:20:d4:0b:fb:0e:e1:f6:ab:28:ff:74:00
    Extensions
      SubjectKeyIdentifier (1)
        2f:45:e7:8d:2c:ae:df:36:8c:df:53:c3:90:05:d4:92:
        45:0e:10:56
      KeyUsage (2), critical
        0x60: [keyCertSign, cRLSign]
      BasicConstraints (4), critical
        CA: true, pathLenConstraint: 1
      AuthorityKeyIdentifier (7)
        Key Identifier
          2d:a3:a4:03:f7:d2:f4:e0:b3:d8:03:1a:73:ba:8a:83:
          9f:55:7f:0f
  Signature Value
    e5:04:65:d6:0c:02:a2:11:1e:f3:fc:6e:44:f2:a3:60:
    08:76:5b:55:23:51:f9:a3:f5:b2:aa:7c:76:f1:f0:5d:
    25:98:47:a4:f4:25:0b:2e:4b:0a:e2:09:97:62:a2:59:
    6d:3c:c1:db:2c:cd:18:0a:a0:a2:d0:e1:91:31:0b:0f
~~~~~

### CRL Signer Private Key and Certificate

#### CRL Signer Private Key

[comment]: <> (replace-data:key/crl-signer/prikey.pem)
~~~~~
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIOJ3HnsrBJ5g5Pb5oy7qlvijr3Wfx3ywAUvnmRV4354s
-----END PRIVATE KEY-----
~~~~~

#### CRL Signer Certificate {#crl-signer-cert}

##### Plain Hex

[comment]: <> (replace-data:cert/crl-signer/c509cert-t2.hex)
~~~~~
8B024212340C6F746573742063726C6F6373702D63611A6775D7001A69570A806A63
726C2D7369676E65720C5820C9BA1EC496DACB97AED087ADE390F398FBD477871EE9
203817EC0E31902789FF86015409E433582556550A27DB4A19BCE2D660884722B621
184007542F45E78D2CAEDF368CDF53C39005D492450E10565840D46E6A8F9FD53417
F36DFE56CBB8CACE0FC3E59ACBE72CD9916B3E4C5022D06D16CC9BF9AC54394037C9
5433644194FAE18FF783381959584A21BDC0E1C6CB0B
~~~~~

##### Textual Representation

[comment]: <> (replace-data:cert/crl-signer/c509cert-t2.txt)
~~~~~
Certificate
  TBSCertificate
    Certificate Type: 2
    Serial Number
      12:34
    Signature Algorithm: Ed25519 (12)
    Issuer : CN=test crlocsp-ca
    Subject: CN=crl-signer
    Validity
      Not Before: 2025-01-02T00:00:00Z
      Not After : 2026-01-02T00:00:00Z
    Subject Public Key Info:
      algorithm: Ed25519 (12)
      Raw public key
        c9:ba:1e:c4:96:da:cb:97:ae:d0:87:ad:e3:90:f3:98:
        fb:d4:77:87:1e:e9:20:38:17:ec:0e:31:90:27:89:ff
    Extensions
      SubjectKeyIdentifier (1)
        09:e4:33:58:25:56:55:0a:27:db:4a:19:bc:e2:d6:60:
        88:47:22:b6
      KeyUsage (2), critical
        0x40: [cRLSign]
      AuthorityKeyIdentifier (7)
        Key Identifier
          2f:45:e7:8d:2c:ae:df:36:8c:df:53:c3:90:05:d4:92:
          45:0e:10:56
  Signature Value
    d4:6e:6a:8f:9f:d5:34:17:f3:6d:fe:56:cb:b8:ca:ce:
    0f:c3:e5:9a:cb:e7:2c:d9:91:6b:3e:4c:50:22:d0:6d:
    16:cc:9b:f9:ac:54:39:40:37:c9:54:33:64:41:94:fa:
    e1:8f:f7:83:38:19:59:58:4a:21:bd:c0:e1:c6:cb:0b
~~~~~

### OCSP Requestor Private Key and Certificate

#### OCSP Requestor Private Key

[comment]: <> (replace-data:key/ocsp-requestor/prikey.pem)
~~~~~
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIDoXZF67Rh+ENmXzefN4vLk/o2fK5q/otI2G1xQYtThH
-----END PRIVATE KEY-----
~~~~~

#### OCSP Requestor Certificate {#ocsp-requestor-cert}

##### Plain Hex

[comment]: <> (replace-data:cert/ocsp-requestor/c509cert-t2.hex)
~~~~~
8B024212360C6F746573742063726C6F6373702D63611A6775D7001A69570A806E6F
6373702D726571756573746F720C582004530B1764EDD4B4E33AB44AF0F838961C00
7176D74B6A3546ECB7FD57320DD3860154DD51BDB2A2C791C062D4027856DBACF526
07F0BE210107542F45E78D2CAEDF368CDF53C39005D492450E10565840F8C6183ECF
8C3EFD50DD4942D172814C46EC0FC01DD586A597178DF864A0D9DA86B7CA17FC9F77
2FF04C80E98B60D5B4B62408A277A5B70D0D2A3F5ED5442D07
~~~~~

##### Textual Representation

[comment]: <> (replace-data:cert/ocsp-requestor/c509cert-t2.txt)
~~~~~
Certificate
  TBSCertificate
    Certificate Type: 2
    Serial Number
      12:36
    Signature Algorithm: Ed25519 (12)
    Issuer : CN=test crlocsp-ca
    Subject: CN=ocsp-requestor
    Validity
      Not Before: 2025-01-02T00:00:00Z
      Not After : 2026-01-02T00:00:00Z
    Subject Public Key Info:
      algorithm: Ed25519 (12)
      Raw public key
        04:53:0b:17:64:ed:d4:b4:e3:3a:b4:4a:f0:f8:38:96:
        1c:00:71:76:d7:4b:6a:35:46:ec:b7:fd:57:32:0d:d3
    Extensions
      SubjectKeyIdentifier (1)
        dd:51:bd:b2:a2:c7:91:c0:62:d4:02:78:56:db:ac:f5:
        26:07:f0:be
      KeyUsage (2), critical
        0x1: [digitalSignature]
      AuthorityKeyIdentifier (7)
        Key Identifier
          2f:45:e7:8d:2c:ae:df:36:8c:df:53:c3:90:05:d4:92:
          45:0e:10:56
  Signature Value
    f8:c6:18:3e:cf:8c:3e:fd:50:dd:49:42:d1:72:81:4c:
    46:ec:0f:c0:1d:d5:86:a5:97:17:8d:f8:64:a0:d9:da:
    86:b7:ca:17:fc:9f:77:2f:f0:4c:80:e9:8b:60:d5:b4:
    b6:24:08:a2:77:a5:b7:0d:0d:2a:3f:5e:d5:44:2d:07
~~~~~

### OCSP Responder Private Key and Certificate

#### OCSP Responder Private Key

[comment]: <> (replace-data:key/ocsp-responder/prikey.pem)
~~~~~
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEII5swSxWTjlZinUj+5kie//qjgBbzupdc0lmaHF9NkXl
-----END PRIVATE KEY-----
~~~~~

#### OCSP Responder Certificate {#ocsp-responder-cert}

##### Plain Hex

[comment]: <> (replace-data:cert/ocsp-responder/c509cert-t2.hex)
~~~~~
8B024212350C6F746573742063726C6F6373702D63611A6775D7001A69570A806E6F
6373702D726573706F6E6465720C582081947BBC248AAC79738211A8D75BF92CB777
D994073DF23AE06380EF2C573976880154B5B4CAF35401D06151DF9629DB579DC8CC
A453A8210107542F45E78D2CAEDF368CDF53C39005D492450E105627095840A01B0C
BF3E34A4762D05404FD08A7AEC103035358314686D72B6159078C76E1D88597F3753
1886A3F52F256FD722192B289D6844014467F1F17F05ACBB7B660A
~~~~~

##### Textual Representation

[comment]: <> (replace-data:cert/ocsp-responder/c509cert-t2.txt)
~~~~~
Certificate
  TBSCertificate
    Certificate Type: 2
    Serial Number
      12:35
    Signature Algorithm: Ed25519 (12)
    Issuer : CN=test crlocsp-ca
    Subject: CN=ocsp-responder
    Validity
      Not Before: 2025-01-02T00:00:00Z
      Not After : 2026-01-02T00:00:00Z
    Subject Public Key Info:
      algorithm: Ed25519 (12)
      Raw public key
        81:94:7b:bc:24:8a:ac:79:73:82:11:a8:d7:5b:f9:2c:
        b7:77:d9:94:07:3d:f2:3a:e0:63:80:ef:2c:57:39:76
    Extensions
      SubjectKeyIdentifier (1)
        b5:b4:ca:f3:54:01:d0:61:51:df:96:29:db:57:9d:c8:
        cc:a4:53:a8
      KeyUsage (2), critical
        0x1: [digitalSignature]
      AuthorityKeyIdentifier (7)
        Key Identifier
          2f:45:e7:8d:2c:ae:df:36:8c:df:53:c3:90:05:d4:92:
          45:0e:10:56
      ExtendedKeyUsage (8), critical
        OCSPSigning (9)
  Signature Value
    a0:1b:0c:bf:3e:34:a4:76:2d:05:40:4f:d0:8a:7a:ec:
    10:30:35:35:83:14:68:6d:72:b6:15:90:78:c7:6e:1d:
    88:59:7f:37:53:18:86:a3:f5:2f:25:6f:d7:22:19:2b:
    28:9d:68:44:01:44:67:f1:f1:7f:05:ac:bb:7b:66:0a
~~~~~

## CRL Examples

### CRL Example Without Revoked Certificates {#exam-crl-no-revoked}

[comment]: <> (replace-reduction:crl/full-direct-no-revocation-crl/crl.hex % crl/full-direct-no-revocation-crl/x509crl.pem)
- Size reduction: 18%
- Verifiable with certificate in {{ca-cert}}
- Direct CRL
- Full CRL
- No revoked certificates
- Note that the X.509 CRL and the C509 CRL are not convertible.

#### X.509 CRL

[comment]: <> (replace-size:crl/full-direct-no-revocation-crl/x509crl.pem)
PEM content (147 bytes):

[comment]: <> (replace-data:crl/full-direct-no-revocation-crl/x509crl.pem)
~~~~~
-----BEGIN X509 CRL-----
MIGQMEQCAQEwBQYDK2VwMBoxGDAWBgNVBAMMD3Rlc3QgY3Jsb2NzcC1jYRcNMjUw
MTAyMDAwMDAwWhcNMjUwMTA5MDAwMDAwWjAFBgMrZXADQQBeSb215S+/7HT9HjQN
zeuuETZAjRIwCLxCIZatpkiov3ndsI7fjXcabny/kx9d5Ce39o3RcDG3QiDDdWOi
R5UK
-----END X509 CRL-----
~~~~~

#### C509 CRL

[comment]: <> (replace-size:crl/full-direct-no-revocation-crl/crl.hex)
Plain Hex (120 bytes):

[comment]: <> (replace-data:crl/full-direct-no-revocation-crl/crl.hex)
~~~~~
8B000C6F746573742063726C6F6373702D6361542F45E78D2CAEDF368CDF53C39005
D492450E1056011A6775D7001A00093A80F680F6584013834F4E38AA9F0DC5B8D21C
8650C776A6D961C31C894C36A71A6433F5ED7D30E67F787F13C7E4C349B2848A181F
DBBCE361A14C220021C4A267367AD5F1D90D
~~~~~

Textual Representation

[comment]: <> (replace-data:crl/full-direct-no-revocation-crl/crl.txt)
~~~~~
C509CRL
  TBSCertList
    CRL Type: C509CRL (0)
    Signature Algorithm: Ed25519 (12)
    Authority Subject: CN=test crlocsp-ca
    Authority Key Identifier:
      2F:45:E7:8D:2C:AE:DF:36:8C:DF:53:C3:90:05:D4:92:
      45:0E:10:56
    CRL Number: 1
    This Update: 2025-01-02T00:00:00Z
    Next Update: 2025-01-09T00:00:00Z
    Base CRL Number: <null>
    Extensions: <empty>
  revokedCertsList: <null>
  Signature Value
    13:83:4f:4e:38:aa:9f:0d:c5:b8:d2:1c:86:50:c7:76:
    a6:d9:61:c3:1c:89:4c:36:a7:1a:64:33:f5:ed:7d:30:
    e6:7f:78:7f:13:c7:e4:c3:49:b2:84:8a:18:1f:db:bc:
    e3:61:a1:4c:22:00:21:c4:a2:67:36:7a:d5:f1:d9:0d
~~~~~

Annotated hex

[comment]: <> (replace-data:crl/full-direct-no-revocation-crl/crl.diag)
~~~~~
  0: 8B             # C509CRL=array[11]
  1:   00             # [0]. crlType=0
  2:   0C             # [1]. signatureAlgorithm=Ed25519 (12)
  3:   6F             # [2]. authoritySubject=char[15]
  4:     746573742063726C6F6373702D6361 # "test crlocsp-ca"
 19:   54             # [3]. authorityKeyIdentifier=byte[20]
 20:     2F45E78D2CAEDF368CDF53C39005D492450E1056
 40:   01             # [4]. crlNumber=1
 41:   1A 6775D700    # [5]. thisUpdate=1735776000:
                      #      2025-01-02T00:00:00Z
 46:   1A 00093A80    # [6]. nextUpdate=604800: 2025-01-09T00:00:00Z
 51:   F6             # [7]. baseCrlNumber=<null>
 52:   80             # [8]. crlExtensions=array[0]
 53:   F6             # [9]. revokedCertsList: <null>
 54:   58 40          # [10]. signature value=byte[64]
 56:     13834F4E38AA9F0DC5B8D21C8650C776A6D961C31C894C36A71A6433F5
 85:     ED7D30E67F787F13C7E4C349B2848A181FDBBCE361A14C220021C4A267
114:     367AD5F1D90D
~~~~~

### CRL Example With Revoked Certificates {#exam-crl-revoked}

[comment]: <> (replace-reduction:crl/full-direct-with-revocation-crl/crl.hex % crl/full-direct-with-revocation-crl/x509crl.pem)
- Size reduction: 47%
- Verifiable with certificate in {{ca-cert}}
- Direct CRL
- Full CRL
- With revoked certificates
- With Per-Issuer Extension ExpiredCertsOnCRL
- Note that the X.509 CRL and the C509 CRL are not convertible.

#### X.509 CRL

[comment]: <> (replace-size:crl/full-direct-with-revocation-crl/x509crl.pem)
PEM content (335 bytes):

[comment]: <> (replace-data:crl/full-direct-with-revocation-crl/x509crl.pem)
~~~~~
-----BEGIN X509 CRL-----
MIIBSzCB/gIBATAFBgMrZXAwGjEYMBYGA1UEAwwPdGVzdCBjcmxvY3NwLWNhFw0y
NTAxMDcwMDEyMzRaFw0yNTAxMTQwMDEyMzRaMIG3MCECAhEiFw0yNTAxMDYwMDEy
MzRaMAwwCgYDVR0VBAMKAQYwIQICEjQXDTI1MDEwMTAwMTIzNFowDDAKBgNVHRUE
AwoBATAhAgIzRBcNMjUwMTA0MDAxMjM0WjAMMAoGA1UdFQQDCgEGMCECAlVmFw0y
NTAxMDIwMDEyMzRaMAwwCgYDVR0VBAMKAQYwEwICVngXDTI1MDEwNTAwMTIzNFow
FAIDAJq8Fw0yNTAxMDMwMDEyMzRaMAUGAytlcANBAAK0jdEbZtlvJDmhKAJQTklZ
WqS7xaN9gHvLC/8lvmqsSdY8T/1YbdkVGCyKsWuDSBGVFtrM2DrBzSDarRKctwY=
-----END X509 CRL-----
~~~~~

#### C509 CRL

[comment]: <> (replace-size:crl/full-direct-with-revocation-crl/crl.hex)
Plain Hex (177 bytes):

[comment]: <> (replace-data:crl/full-direct-with-revocation-crl/crl.hex)
~~~~~
8B000C6F746573742063726C6F6373702D6361542F45E78D2CAEDF368CDF53C39005
D492450E1056021A677C71721A00093A80F68085F6840302031A677488728218571A
677485805824112206978006123400000001334403F4800655660151800656780546
00009ABC02A30000F6584070BB7A38065FBCABFE615170F05A9A9FE83DC892D5F735
812B2A053AF4B300EB466BABB4F1A387CDCE90D8302C680B77AA61566423D7C235F7
BD31344CF7F405
~~~~~

Textual Representation

[comment]: <> (replace-data:crl/full-direct-with-revocation-crl/crl.txt)
~~~~~
C509CRL
  TBSCertList
    CRL Type: C509CRL (0)
    Signature Algorithm: Ed25519 (12)
    Authority Subject: CN=test crlocsp-ca
    Authority Key Identifier:
      2F:45:E7:8D:2C:AE:DF:36:8C:DF:53:C3:90:05:D4:92:
      45:0E:10:56
    CRL Number: 2
    This Update: 2025-01-07T00:12:34Z
    Next Update: 2025-01-14T00:12:34Z
    Base CRL Number: <null>
    Extensions: <empty>
  revokedCertsList:
    PerIssuerRevokedCerts[0]
      Issuer: <null>
      RevokedCertsControl
        Flags: sorted, with reason (0x3)
        Serial number length: 2
        Date length: 3
        Base date: 2025-01-01T00:12:34Z
      Extensions
        ExpiredCertsOnCRL (87)
          2025-01-01T00:00:00Z
      RevokedCerts:
        0x1122, 2025-01-06T00:12:34Z, certificateHold
        0x1234, 2025-01-01T00:12:34Z, keyCompromise
        0x3344, 2025-01-04T00:12:34Z, certificateHold
        0x5566, 2025-01-02T00:12:34Z, certificateHold
        0x5678, 2025-01-05T00:12:34Z, unspecified
        0x9ABC, 2025-01-03T00:12:34Z, unspecified
      RemovedFromCRLCerts: <null>
  Signature Value
    70:bb:7a:38:06:5f:bc:ab:fe:61:51:70:f0:5a:9a:9f:
    e8:3d:c8:92:d5:f7:35:81:2b:2a:05:3a:f4:b3:00:eb:
    46:6b:ab:b4:f1:a3:87:cd:ce:90:d8:30:2c:68:0b:77:
    aa:61:56:64:23:d7:c2:35:f7:bd:31:34:4c:f7:f4:05
~~~~~

Annotated hex

[comment]: <> (replace-data:crl/full-direct-with-revocation-crl/crl.diag)
~~~~~
  0: 8B             # C509CRL=array[11]
  1:   00             # [0]. crlType=0
  2:   0C             # [1]. signatureAlgorithm=Ed25519 (12)
  3:   6F             # [2]. authoritySubject=char[15]
  4:     746573742063726C6F6373702D6361 # "test crlocsp-ca"
 19:   54             # [3]. authorityKeyIdentifier=byte[20]
 20:     2F45E78D2CAEDF368CDF53C39005D492450E1056
 40:   02             # [4]. crlNumber=2
 41:   1A 677C7172    # [5]. thisUpdate=1736208754:
                      #      2025-01-07T00:12:34Z
 46:   1A 00093A80    # [6]. nextUpdate=604800: 2025-01-14T00:12:34Z
 51:   F6             # [7]. baseCrlNumber=<null>
 52:   80             # [8]. crlExtensions=array[0]
 53:   85             # [9]. revokedCertsList=array[5]
                        #---PerIssuedRevokedCerts[0]---
 54:     F6             # [0]. issuer=<null>
 55:     84             # [1]. revokedCertsControl=array[4]
 56:       03             # [0]. flags: sorted, with reason (0x3)
 57:       02             # [1]. serialNumberLength=2
 58:       03             # [2]. dateLength=3
 59:       1A 67748872    # [3]. baseDate=1735690354:
                          #      2025-01-01T00:12:34Z
 64:     82             # [2]. extensions=array[2]
                          #---extension[0]---
 65:       18 57          # [0]. type=ExpiredCertsOnCRL (87)
 67:       1A 67748580    # [1]. value=1735689600:
                          #      2025-01-01T00:00:00Z
 72:     58 24          # [3]. revokedCerts=byte[36], 6 entries
                          #---entries[0]---
 74:       1122           # CSN=1122
 76:       069780         # date=069780: 2025-01-06T00:12:34Z
 79:       06             # reason=6: certificateHold
                          #---entries[1]---
 80:       1234           # CSN=1234
 82:       000000         # date=000000: 2025-01-01T00:12:34Z
 85:       01             # reason=1: keyCompromise
                          #---entries[2]---
 86:       3344           # CSN=3344
 88:       03F480         # date=03F480: 2025-01-04T00:12:34Z
 91:       06             # reason=6: certificateHold
                          #---entries[3]---
 92:       5566           # CSN=5566
 94:       015180         # date=015180: 2025-01-02T00:12:34Z
 97:       06             # reason=6: certificateHold
                          #---entries[4]---
 98:       5678           # CSN=5678
100:       054600         # date=054600: 2025-01-05T00:12:34Z
103:       00             # reason=0: unspecified
                          #---entries[5]---
104:       9ABC           # CSN=9ABC
106:       02A300         # date=02A300: 2025-01-03T00:12:34Z
109:       00             # reason=0: unspecified
110:     F6             # [4]. removedFromCRLCerts=<null>
111:   58 40          # [10]. signature value=byte[64]
113:     70BB7A38065FBCABFE615170F05A9A9FE83DC892D5F735812B2A053AF4
142:     B300EB466BABB4F1A387CDCE90D8302C680B77AA61566423D7C235F7BD
171:     31344CF7F405
~~~~~

### Delta CRL Example With Revoked Certificates {#exam-delta-crl-revoked}

[comment]: <> (replace-reduction:crl/delta-with-revocation-crl/crl.hex % crl/delta-with-revocation-crl/x509crl.pem)
- Size reduction: 52%
- Verifiable with certificate in {{ca-cert}}
- Direct CRL
- Delta CRL
- With revoked certificates
- With entries removed from CRL since last full CRL
- Note that the X.509 CRL and the C509 CRL are not convertible.

#### X.509 CRL

[comment]: <> (replace-size:crl/delta-with-revocation-crl/x509crl.pem)
PEM content (335 bytes):

[comment]: <> (replace-data:crl/delta-with-revocation-crl/x509crl.pem)
~~~~~
-----BEGIN X509 CRL-----
MIIBSzCB/gIBATAFBgMrZXAwGjEYMBYGA1UEAwwPdGVzdCBjcmxvY3NwLWNhFw0y
NTAxMDgwMDEyMzRaFw0yNTAxMTAwMDEyMzRaMIG3MCECAjQSFw0yNTAxMDcxMjEy
MzRaMAwwCgYDVR0VBAMKAQEwEwICeFYXDTI1MDEwODAwMTAzNFowFAIDALyaFw0y
NTAxMDgwMDA4MzRaMCECAhEiFw0yNTAxMDcxMzEyMzRaMAwwCgYDVR0VBAMKAQgw
IQICM0QXDTI1MDEwNzE0MTIzNFowDDAKBgNVHRUEAwoBCDAhAgJVZhcNMjUwMTA3
MTUxMjM0WjAMMAoGA1UdFQQDCgEIMAUGAytlcANBAKxSjqeefzjGdniA3bQCg3rL
d7rrJnfh8GfsWdawC9BHjK1G336hRYaxwLOtyQS4Mn80jjSwrN+bXg10spSA4gA=
-----END X509 CRL-----
~~~~~

#### C509 CRL

[comment]: <> (replace-size:crl/delta-with-revocation-crl/crl.hex)
Plain Hex (160 bytes):

[comment]: <> (replace-data:crl/delta-with-revocation-crl/crl.hex)
~~~~~
8B000C6F746573742063726C6F6373702D6361542F45E78D2CAEDF368CDF53C39005
D492450E1056031A677DC2F21A0002A300028085F6840302021A677D1A32804F3412
0000017856A84800BC9AA7D0004C11220E1033441C2055662A305840369C3E6412E9
D0537CD39EA1DA40C68C32B4EC0E5678650D6AF73677A5A0CF37F1CDE75D663DE374
9101F4354CCD6D8D05773887650046932B583C5365D7EB0B
~~~~~

Textual Representation

[comment]: <> (replace-data:crl/delta-with-revocation-crl/crl.txt)
~~~~~
C509CRL
  TBSCertList
    CRL Type: C509CRL (0)
    Signature Algorithm: Ed25519 (12)
    Authority Subject: CN=test crlocsp-ca
    Authority Key Identifier:
      2F:45:E7:8D:2C:AE:DF:36:8C:DF:53:C3:90:05:D4:92:
      45:0E:10:56
    CRL Number: 3
    This Update: 2025-01-08T00:12:34Z
    Next Update: 2025-01-10T00:12:34Z
    Base CRL Number: 2
    Extensions: <empty>
  revokedCertsList:
    PerIssuerRevokedCerts[0]
      Issuer: <null>
      RevokedCertsControl
        Flags: sorted, with reason (0x3)
        Serial number length: 2
        Date length: 2
        Base date: 2025-01-07T12:12:34Z
      Extensions: <empty>
      RevokedCerts:
        0x3412, 2025-01-07T12:12:34Z, keyCompromise
        0x7856, 2025-01-08T00:10:34Z, unspecified
        0xBC9A, 2025-01-08T00:08:34Z, unspecified
      RemovedFromCRLCerts:
        0x1122, 2025-01-07T13:12:34Z
        0x3344, 2025-01-07T14:12:34Z
        0x5566, 2025-01-07T15:12:34Z
  Signature Value
    36:9c:3e:64:12:e9:d0:53:7c:d3:9e:a1:da:40:c6:8c:
    32:b4:ec:0e:56:78:65:0d:6a:f7:36:77:a5:a0:cf:37:
    f1:cd:e7:5d:66:3d:e3:74:91:01:f4:35:4c:cd:6d:8d:
    05:77:38:87:65:00:46:93:2b:58:3c:53:65:d7:eb:0b
~~~~~

Annotated hex

[comment]: <> (replace-data:crl/delta-with-revocation-crl/crl.diag)
~~~~~
  0: 8B             # C509CRL=array[11]
  1:   00             # [0]. crlType=0
  2:   0C             # [1]. signatureAlgorithm=Ed25519 (12)
  3:   6F             # [2]. authoritySubject=char[15]
  4:     746573742063726C6F6373702D6361 # "test crlocsp-ca"
 19:   54             # [3]. authorityKeyIdentifier=byte[20]
 20:     2F45E78D2CAEDF368CDF53C39005D492450E1056
 40:   03             # [4]. crlNumber=3
 41:   1A 677DC2F2    # [5]. thisUpdate=1736295154:
                      #      2025-01-08T00:12:34Z
 46:   1A 0002A300    # [6]. nextUpdate=172800: 2025-01-10T00:12:34Z
 51:   02             # [7]. baseCrlNumber=2
 52:   80             # [8]. crlExtensions=array[0]
 53:   85             # [9]. revokedCertsList=array[5]
                        #---PerIssuedRevokedCerts[0]---
 54:     F6             # [0]. issuer=<null>
 55:     84             # [1]. revokedCertsControl=array[4]
 56:       03             # [0]. flags: sorted, with reason (0x3)
 57:       02             # [1]. serialNumberLength=2
 58:       02             # [2]. dateLength=2
 59:       1A 677D1A32    # [3]. baseDate=1736251954:
                          #      2025-01-07T12:12:34Z
 64:     80             # [2]. extensions=array[0]
 65:     4F             # [3]. revokedCerts=byte[15], 3 entries
                          #---entries[0]---
 66:       3412           # CSN=3412
 68:       0000           # date=0000: 2025-01-07T12:12:34Z
 70:       01             # reason=1: keyCompromise
                          #---entries[1]---
 71:       7856           # CSN=7856
 73:       A848           # date=A848: 2025-01-08T00:10:34Z
 75:       00             # reason=0: unspecified
                          #---entries[2]---
 76:       BC9A           # CSN=BC9A
 78:       A7D0           # date=A7D0: 2025-01-08T00:08:34Z
 80:       00             # reason=0: unspecified
 81:     4C             # [4]. removedFromCRLCerts=byte[12], 3
                        #      entries
                          #---entries[0]---
 82:       1122           # CSN=1122
 84:       0E10           # date=0E10: 2025-01-07T13:12:34Z
                          #---entries[1]---
 86:       3344           # CSN=3344
 88:       1C20           # date=1C20: 2025-01-07T14:12:34Z
                          #---entries[2]---
 90:       5566           # CSN=5566
 92:       2A30           # date=2A30: 2025-01-07T15:12:34Z
 94:   58 40          # [10]. signature value=byte[64]
 96:     369C3E6412E9D0537CD39EA1DA40C68C32B4EC0E5678650D6AF73677A5
125:     A0CF37F1CDE75D663DE3749101F4354CCD6D8D05773887650046932B58
154:     3C5365D7EB0B
~~~~~

### Indirect CRL Example With Revoked Certificates {#exam-indirect-crl-revoked}

[comment]: <> (replace-reduction:crl/full-indirect-with-revocation-crl/crl.hex % crl/full-indirect-with-revocation-crl/x509crl.pem)
- Size reduction: 51%
- Verifiable with certificate in {{crl-signer-cert}}
- Indirect CRL
- Full CRL
- With revoked certificates
- With two issuers
- Note that the X.509 CRL and the C509 CRL are not convertible.

#### X.509 CRL

[comment]: <> (replace-size:crl/full-indirect-with-revocation-crl/x509crl.pem)
PEM content (409 bytes):

[comment]: <> (replace-data:crl/full-indirect-with-revocation-crl/x509crl.pem)
~~~~~
-----BEGIN X509 CRL-----
MIIBlTCCAUcCAQEwBQYDK2VwMBUxEzARBgNVBAMMCmNybC1zaWduZXIXDTI1MDEw
NzAwMTIzNFoXDTI1MDExNDAwMTIzNFowggEEMEoCAhI0Fw0yNTAxMDEwMDEyMzRa
MDUwCgYDVR0VBAMKAQEwJwYDVR0dBCAwHqQcMBoxGDAWBgNVBAMMD3Rlc3QgY3Js
b2NzcC1jYTATAgJWeBcNMjUwMTA1MDAxMjM0WjAUAgMAmrwXDTI1MDEwMzAwMTIz
NFowRQICESIXDTI1MDEwNjAwMTIzNFowMDAKBgNVHRUEAwoBBjAiBgNVHR0EGzAZ
pBcwFTETMBEGA1UEAwwKZXhhbXBsZSBDQTAhAgIzRBcNMjUwMTA0MDAxMjM0WjAM
MAoGA1UdFQQDCgEGMCECAlVmFw0yNTAxMDIwMDEyMzRaMAwwCgYDVR0VBAMKAQYw
BQYDK2VwA0EAUMWMYunvDSqQzFV+lo5O5TZmopxPvnMBpuR0Do8kCA4P4PHGg/E8
1U6GfBu/9MvUuTOX13loPDedsjvs/uK8AQ==
-----END X509 CRL-----
~~~~~

#### C509 CRL

[comment]: <> (replace-size:crl/full-indirect-with-revocation-crl/crl.hex)
Plain Hex (202 bytes):

[comment]: <> (replace-data:crl/full-indirect-with-revocation-crl/crl.hex)
~~~~~
8B000C6A63726C2D7369676E65725409E433582556550A27DB4A19BCE2D660884722
B6041A677C71721A00093A80F6808A6F746573742063726C6F6373702D6361840302
031A6774887280521234000000015678054600009ABC02A30000F66A6578616D706C
65204341840302031A6775D9F28052112205460006334402A30006556600000006F6
5840F00D6270F91486A7F378D06F01A807E64E086BB366BE3A1592CE4A64BFFD621F
30E2AB93766B4F8818116AB7DA7BEDF7C3EBCBDEAC6D0455F5F5669712006205
~~~~~

Textual Representation

[comment]: <> (replace-data:crl/full-indirect-with-revocation-crl/crl.txt)
~~~~~
C509CRL
  TBSCertList
    CRL Type: C509CRL (0)
    Signature Algorithm: Ed25519 (12)
    Authority Subject: CN=crl-signer
    Authority Key Identifier:
      09:E4:33:58:25:56:55:0A:27:DB:4A:19:BC:E2:D6:60:
      88:47:22:B6
    CRL Number: 4
    This Update: 2025-01-07T00:12:34Z
    Next Update: 2025-01-14T00:12:34Z
    Base CRL Number: <null>
    Extensions: <empty>
  revokedCertsList:
    PerIssuerRevokedCerts[0]
      Issuer: CN=test crlocsp-ca
      RevokedCertsControl
        Flags: sorted, with reason (0x3)
        Serial number length: 2
        Date length: 3
        Base date: 2025-01-01T00:12:34Z
      Extensions: <empty>
      RevokedCerts:
        0x1234, 2025-01-01T00:12:34Z, keyCompromise
        0x5678, 2025-01-05T00:12:34Z, unspecified
        0x9ABC, 2025-01-03T00:12:34Z, unspecified
      RemovedFromCRLCerts: <null>
    PerIssuerRevokedCerts[1]
      Issuer: CN=example CA
      RevokedCertsControl
        Flags: sorted, with reason (0x3)
        Serial number length: 2
        Date length: 3
        Base date: 2025-01-02T00:12:34Z
      Extensions: <empty>
      RevokedCerts:
        0x1122, 2025-01-06T00:12:34Z, certificateHold
        0x3344, 2025-01-04T00:12:34Z, certificateHold
        0x5566, 2025-01-02T00:12:34Z, certificateHold
      RemovedFromCRLCerts: <null>
  Signature Value
    f0:0d:62:70:f9:14:86:a7:f3:78:d0:6f:01:a8:07:e6:
    4e:08:6b:b3:66:be:3a:15:92:ce:4a:64:bf:fd:62:1f:
    30:e2:ab:93:76:6b:4f:88:18:11:6a:b7:da:7b:ed:f7:
    c3:eb:cb:de:ac:6d:04:55:f5:f5:66:97:12:00:62:05
~~~~~

Annotated hex

[comment]: <> (replace-data:crl/full-indirect-with-revocation-crl/crl.diag)
~~~~~
  0: 8B             # C509CRL=array[11]
  1:   00             # [0]. crlType=0
  2:   0C             # [1]. signatureAlgorithm=Ed25519 (12)
  3:   6A             # [2]. authoritySubject=char[10]
  4:     63726C2D7369676E6572 # "crl-signer"
 14:   54             # [3]. authorityKeyIdentifier=byte[20]
 15:     09E433582556550A27DB4A19BCE2D660884722B6
 35:   04             # [4]. crlNumber=4
 36:   1A 677C7172    # [5]. thisUpdate=1736208754:
                      #      2025-01-07T00:12:34Z
 41:   1A 00093A80    # [6]. nextUpdate=604800: 2025-01-14T00:12:34Z
 46:   F6             # [7]. baseCrlNumber=<null>
 47:   80             # [8]. crlExtensions=array[0]
 48:   8A             # [9]. revokedCertsList=array[10]
                        #---PerIssuedRevokedCerts[0]---
 49:     6F             # [0]. issuer=char[15]
 50:       746573742063726C6F6373702D6361 # "test crlocsp-ca"
 65:     84             # [1]. revokedCertsControl=array[4]
 66:       03             # [0]. flags: sorted, with reason (0x3)
 67:       02             # [1]. serialNumberLength=2
 68:       03             # [2]. dateLength=3
 69:       1A 67748872    # [3]. baseDate=1735690354:
                          #      2025-01-01T00:12:34Z
 74:     80             # [2]. extensions=array[0]
 75:     52             # [3]. revokedCerts=byte[18], 3 entries
                          #---entries[0]---
 76:       1234           # CSN=1234
 78:       000000         # date=000000: 2025-01-01T00:12:34Z
 81:       01             # reason=1: keyCompromise
                          #---entries[1]---
 82:       5678           # CSN=5678
 84:       054600         # date=054600: 2025-01-05T00:12:34Z
 87:       00             # reason=0: unspecified
                          #---entries[2]---
 88:       9ABC           # CSN=9ABC
 90:       02A300         # date=02A300: 2025-01-03T00:12:34Z
 93:       00             # reason=0: unspecified
 94:     F6             # [4]. removedFromCRLCerts=<null>
                        #---PerIssuedRevokedCerts[1]---
 95:     6A             # [5]. issuer=char[10]
 96:       6578616D706C65204341 # "example CA"
106:     84             # [6]. revokedCertsControl=array[4]
107:       03             # [0]. flags: sorted, with reason (0x3)
108:       02             # [1]. serialNumberLength=2
109:       03             # [2]. dateLength=3
110:       1A 6775D9F2    # [3]. baseDate=1735776754:
                          #      2025-01-02T00:12:34Z
115:     80             # [7]. extensions=array[0]
116:     52             # [8]. revokedCerts=byte[18], 3 entries
                          #---entries[0]---
117:       1122           # CSN=1122
119:       054600         # date=054600: 2025-01-06T00:12:34Z
122:       06             # reason=6: certificateHold
                          #---entries[1]---
123:       3344           # CSN=3344
125:       02A300         # date=02A300: 2025-01-04T00:12:34Z
128:       06             # reason=6: certificateHold
                          #---entries[2]---
129:       5566           # CSN=5566
131:       000000         # date=000000: 2025-01-02T00:12:34Z
134:       06             # reason=6: certificateHold
135:     F6             # [9]. removedFromCRLCerts=<null>
136:   58 40          # [10]. signature value=byte[64]
138:     F00D6270F91486A7F378D06F01A807E64E086BB366BE3A1592CE4A64BF
167:     FD621F30E2AB93766B4F8818116AB7DA7BEDF7C3EBCBDEAC6D0455F5F5
196:     669712006205
~~~~~

## OCSP Request Examples

### Simple OCSP Request Example {#exam-simple-ocsp-req}

[comment]: <> (replace-reduction:ocspreq/simple-ocspreq/ocspreq.hex % ocspreq/simple-ocspreq/x509ocspreq.pem)
- Size reduction: 66%
- Simple OCSP Request (`C509SimpleOCSPRequest`)
- Note that the X.509 OCSP Request and the C509 OCSP Request are not convertible.

#### X.509 OCSP Request

[comment]: <> (replace-size:ocspreq/simple-ocspreq/x509ocspreq.pem)
PEM content (152 bytes):

[comment]: <> (replace-data:ocspreq/simple-ocspreq/x509ocspreq.pem)
~~~~~
-----BEGIN OCSP REQUEST-----
MIGVMIGSMG0wazBpMA0GCWCGSAFlAwQCAQUABCAyU450hb03rkVPHw0rl1XXWLkf
bo46evOXoPQAYFxv+AQgzBHIdAoFCexNoUzliG5yNkwPY7YO1jR/E8Fu5yW3ZqIC
FBI0EjQSNBI0EjQSNBI0EjQSNBI0oiEwHzAdBgkrBgEFBQcwAQIEEBERERERERER
ERERERERERE=
-----END OCSP REQUEST-----
~~~~~

#### C509 OCSP Request

[comment]: <> (replace-size:ocspreq/simple-ocspreq/ocspreq.hex)
Plain Hex (51 bytes):

[comment]: <> (replace-data:ocspreq/simple-ocspreq/ocspreq.hex)
~~~~~
860200501111111111111111111111111111111148A01C73A5F3B063345410652787
FA0527BC2449A1BFC5AB31AA5A6F0D8D80
~~~~~

Textual Representation

[comment]: <> (replace-data:ocspreq/simple-ocspreq/ocspreq.txt)
~~~~~
C509SimpleOCSPRequest
  Type: C509SimpleOCSPRequest (2)
  Hash Algorithm: SHA256 (0)
  IssuerCertHash:
    a0:1c:73:a5:f3:b0:63:34
  SerialNumberHash:
    10:65:27:87:fa:05:27:bc:24:49:a1:bf:c5:ab:31:aa:
    5a:6f:0d:8d
  Nonce
    11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11
  Extensions: <empty>
~~~~~

Annotated hex

[comment]: <> (replace-data:ocspreq/simple-ocspreq/ocspreq.diag)
~~~~~
 0: 86             # C509OCSPRequest=array[6]
 1:   02             # [0]. ocspRequestType=C509SimpleOCSPRequest
                     #      (2)
 2:   00             # [1]. hashAlgorithm=SHA256 (0)
 3:   50             # [2]. nonce=byte[16]
 4:     11111111111111111111111111111111
20:   48             # [3]. issuerCertHash=byte[8]
21:     A01C73A5F3B06334
29:   54             # [4]. serialNumberHash=byte[20]
30:     10652787FA0527BC2449A1BFC5AB31AA5A6F0D8D
50:   80             # [5]. extensions=array[0]
~~~~~

### Unsigned OCSP Request Example {#exam-unsigned-ocsp-req}

[comment]: <> (replace-reduction:ocspreq/unsigned-ocspreq/ocspreq.hex % ocspreq/unsigned-ocspreq/x509ocspreq.pem)
- Size reduction: 73%
- Unsigned OCSP Request (`C509UnsignedOCSPRequest`)
- Note that the X.509 OCSP Request and the C509 OCSP Request are not convertible.

#### X.509 OCSP Request

[comment]: <> (replace-size:ocspreq/unsigned-ocspreq/x509ocspreq.pem)
PEM content (483 bytes):

[comment]: <> (replace-data:ocspreq/unsigned-ocspreq/x509ocspreq.pem)
~~~~~
-----BEGIN OCSP REQUEST-----
MIIB3zCCAdswggG0MGswaTANBglghkgBZQMEAgEFAAQgMlOOdIW9N65FTx8NK5dV
11i5H26OOnrzl6D0AGBcb/gEIMwRyHQKBQnsTaFM5YhucjZMD2O2DtY0fxPBbucl
t2aiAhQSNBI0EjQSNBI0EjQSNBI0EjQSNDBrMGkwDQYJYIZIAWUDBAIBBQAEIDJT
jnSFvTeuRU8fDSuXVddYuR9ujjp685eg9ABgXG/4BCDMEch0CgUJ7E2hTOWIbnI2
TA9jtg7WNH8TwW7nJbdmogIUNFY0VjRWNFY0VjRWNFY0VjRWNFYwazBpMA0GCWCG
SAFlAwQCAQUABCAyU450hb03rkVPHw0rl1XXWLkfbo46evOXoPQAYFxv+AQgzBHI
dAoFCexNoUzliG5yNkwPY7YO1jR/E8Fu5yW3ZqICFFZ4VnhWeFZ4VnhWeFZ4VnhW
eFZ4MGswaTANBglghkgBZQMEAgEFAAQgMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMz
MzMzMzMzMzMEIEREREREREREREREREREREREREREREREREREREREREREAhQiMyIz
IjMiMyIzIjMiMyIzIjMiM6IhMB8wHQYJKwYBBQUHMAECBBARERERERERERERERER
ERER
-----END OCSP REQUEST-----
~~~~~

#### C509 OCSP Request

[comment]: <> (replace-size:ocspreq/unsigned-ocspreq/ocspreq.hex)
Plain Hex (132 bytes):

[comment]: <> (replace-data:ocspreq/unsigned-ocspreq/ocspreq.hex)
~~~~~
8500005011111111111111111111111111111111808648A01C73A5F3B06334808654
10652787FA0527BC2449A1BFC5AB31AA5A6F0D8D805475D8BC4FBAFC6694467641E7
48DFD53A8B9D176D8054D1AC135D7DA29BDCF4DCA0D5281A51605B67840080482222
222222222222808254D3A0C1E3DB92E8F6810537D45CFAECF6CE417E3B80
~~~~~

Textual Representation

[comment]: <> (replace-data:ocspreq/unsigned-ocspreq/ocspreq.txt)
~~~~~
C509UnsignedOCSPRequest
  Type: C509UnsignedOCSPRequest (0)
  Hash Algorithm: SHA256 (0)
  Nonce
    11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11
  Requests
    OcspPerIssuerRequest
      issuerCertHash
        a0:1c:73:a5:f3:b0:63:34
      extensions: <empty>
      singleRequests
        SingleCertRequest
          SerialNumberHash:
            10:65:27:87:fa:05:27:bc:24:49:a1:bf:c5:ab:31:aa:
            5a:6f:0d:8d
          Extensions: <empty>
        SingleCertRequest
          SerialNumberHash:
            75:d8:bc:4f:ba:fc:66:94:46:76:41:e7:48:df:d5:3a:
            8b:9d:17:6d
          Extensions: <empty>
        SingleCertRequest
          SerialNumberHash:
            d1:ac:13:5d:7d:a2:9b:dc:f4:dc:a0:d5:28:1a:51:60:
            5b:67:84:00
          Extensions: <empty>
    OcspPerIssuerRequest
      issuerCertHash
        22:22:22:22:22:22:22:22
      extensions: <empty>
      singleRequests
        SingleCertRequest
          SerialNumberHash:
            d3:a0:c1:e3:db:92:e8:f6:81:05:37:d4:5c:fa:ec:f6:
            ce:41:7e:3b
          Extensions: <empty>
  Extensions: <empty>
~~~~~

Annotated hex

[comment]: <> (replace-data:ocspreq/unsigned-ocspreq/ocspreq.diag)
~~~~~
  0: 85             # C509OCSPRequest=array[5]
  1:   00             # [0]. ocspRequestType=C509UnsignedOCSPRequest
                      #      (0)
  2:   00             # [1]. hashAlgorithm=SHA256 (0)
  3:   50             # [2]. nonce=byte[16]
  4:     11111111111111111111111111111111
 20:   80             # [3]. extensions=array[0]
 21:   86             # [4]. requests=array[6]
                        #---PerIssuerRequests[0]---
 22:     48             # [0]. issuerCertHash=byte[8]
 23:       A01C73A5F3B06334
 31:     80             # [1]. extensions=array[0]
 32:     86             # [2]. singleRequests=array[6]
                          #---SingleCertRequests[0]---
 33:       54             # [0]. serialNumberHash=byte[20]
 34:         10652787FA0527BC2449A1BFC5AB31AA5A6F0D8D
 54:       80             # [1]. extensions=array[0]
                          #---SingleCertRequests[1]---
 55:       54             # [2]. serialNumberHash=byte[20]
 56:         75D8BC4FBAFC6694467641E748DFD53A8B9D176D
 76:       80             # [3]. extensions=array[0]
                          #---SingleCertRequests[2]---
 77:       54             # [4]. serialNumberHash=byte[20]
 78:         D1AC135D7DA29BDCF4DCA0D5281A51605B678400
 98:       80             # [5]. extensions=array[0]
                        #---PerIssuerRequests[1]---
 99:     48             # [3]. issuerCertHash=byte[8]
100:       2222222222222222
108:     80             # [4]. extensions=array[0]
109:     82             # [5]. singleRequests=array[2]
                          #---SingleCertRequests[0]---
110:       54             # [0]. serialNumberHash=byte[20]
111:         D3A0C1E3DB92E8F6810537D45CFAECF6CE417E3B
131:       80             # [1]. extensions=array[0]
~~~~~

### Signed OCSP Request Example Without Requestor's Certificate {#exam-signed-ocsp-req}

[comment]: <> (replace-reduction:ocspreq/signed-ocspreq/ocspreq.hex % ocspreq/signed-ocspreq/x509ocspreq.pem)
- Size reduction: 65%
- Verifiable with certificate in {{ocsp-requestor-cert}}
- Signed OCSP Request (`C509UnsignedOCSPRequest`) without requestor's certificate
- Note that the X.509 OCSP Request and the C509 OCSP Request are not convertible.

#### X.509 OCSP Request

[comment]: <> (replace-size:ocspreq/signed-ocspreq/x509ocspreq.pem)
PEM content (592 bytes):

[comment]: <> (replace-data:ocspreq/signed-ocspreq/x509ocspreq.pem)
~~~~~
-----BEGIN OCSP REQUEST-----
MIICTDCCAfqhHaQbMBkxFzAVBgNVBAMMDm9jc3AtcmVxdWVzdG9yMIIBtDBrMGkw
DQYJYIZIAWUDBAIBBQAEIDJTjnSFvTeuRU8fDSuXVddYuR9ujjp685eg9ABgXG/4
BCDMEch0CgUJ7E2hTOWIbnI2TA9jtg7WNH8TwW7nJbdmogIUEjQSNBI0EjQSNBI0
EjQSNBI0EjQwazBpMA0GCWCGSAFlAwQCAQUABCAyU450hb03rkVPHw0rl1XXWLkf
bo46evOXoPQAYFxv+AQgzBHIdAoFCexNoUzliG5yNkwPY7YO1jR/E8Fu5yW3ZqIC
FDRWNFY0VjRWNFY0VjRWNFY0VjRWMGswaTANBglghkgBZQMEAgEFAAQgMlOOdIW9
N65FTx8NK5dV11i5H26OOnrzl6D0AGBcb/gEIMwRyHQKBQnsTaFM5YhucjZMD2O2
DtY0fxPBbuclt2aiAhRWeFZ4VnhWeFZ4VnhWeFZ4VnhWeDBrMGkwDQYJYIZIAWUD
BAIBBQAEIDMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzBCBERERERERE
RERERERERERERERERERERERERERERERERAIUIjMiMyIzIjMiMyIzIjMiMyIzIjOi
ITAfMB0GCSsGAQUFBzABAgQQEREREREREREREREREREREaBMMEowBQYDK2VwA0EA
DVI0VPbgwwEJDSdfds+dKJ6GpFdP724NTTYL1GMvn/loUMeJAnnJ7jbxvP/R1PE5
Zyh+lISXhR4F1lvXRAHYCA==
-----END OCSP REQUEST-----
~~~~~

#### C509 OCSP Request

[comment]: <> (replace-size:ocspreq/signed-ocspreq/ocspreq.hex)
Plain Hex (209 bytes):

[comment]: <> (replace-data:ocspreq/signed-ocspreq/ocspreq.hex)
~~~~~
89010C0050111111111111111111111111111111114844F0528B56F35AD9808648A0
1C73A5F3B0633480865410652787FA0527BC2449A1BFC5AB31AA5A6F0D8D805475D8
BC4FBAFC6694467641E748DFD53A8B9D176D8054D1AC135D7DA29BDCF4DCA0D5281A
51605B67840080482222222222222222808254D3A0C1E3DB92E8F6810537D45CFAEC
F6CE417E3B80F658407DA70BE70D8C88F5150218B2F60A21320D26FAF8DC198F1665
4D54CB617A1C3C3F420B3F2FBF74C9B107D81D1815C2CE09B22EAF491313003C49D4
3AAB8D970B
~~~~~

Textual Representation

[comment]: <> (replace-data:ocspreq/signed-ocspreq/ocspreq.txt)
~~~~~
C509SignedOCSPRequest
  TBSOCSPRequest
    Type: C509SignedOCSPRequest (1)
    Signature Algorithm: Ed25519 (12)
    Hash Algorithm: SHA256 (0)
    RequestorCertHash
      44:f0:52:8b:56:f3:5a:d9
    Nonce
      11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11
    Extensions: <empty>
    Requests
      OcspPerIssuerRequest
        issuerCertHash
          a0:1c:73:a5:f3:b0:63:34
        extensions: <empty>
        singleRequests
          SingleCertRequest
            SerialNumberHash:
              10:65:27:87:fa:05:27:bc:24:49:a1:bf:c5:ab:31:aa:
              5a:6f:0d:8d
            Extensions: <empty>
          SingleCertRequest
            SerialNumberHash:
              75:d8:bc:4f:ba:fc:66:94:46:76:41:e7:48:df:d5:3a:
              8b:9d:17:6d
            Extensions: <empty>
          SingleCertRequest
            SerialNumberHash:
              d1:ac:13:5d:7d:a2:9b:dc:f4:dc:a0:d5:28:1a:51:60:
              5b:67:84:00
            Extensions: <empty>
      OcspPerIssuerRequest
        issuerCertHash
          22:22:22:22:22:22:22:22
        extensions: <empty>
        singleRequests
          SingleCertRequest
            SerialNumberHash:
              d3:a0:c1:e3:db:92:e8:f6:81:05:37:d4:5c:fa:ec:f6:
              ce:41:7e:3b
            Extensions: <empty>
    Requestor Certs: null
  Signature Value
    7d:a7:0b:e7:0d:8c:88:f5:15:02:18:b2:f6:0a:21:32:
    0d:26:fa:f8:dc:19:8f:16:65:4d:54:cb:61:7a:1c:3c:
    3f:42:0b:3f:2f:bf:74:c9:b1:07:d8:1d:18:15:c2:ce:
    09:b2:2e:af:49:13:13:00:3c:49:d4:3a:ab:8d:97:0b
~~~~~

Annotated hex

[comment]: <> (replace-data:ocspreq/signed-ocspreq/ocspreq.diag)
~~~~~
  0: 89             # C509OCSPRequest=array[9]
  1:   01             # [0]. ocspRequestType=C509SignedOCSPRequest
                      #      (1)
  2:   0C             # [1]. signatureAlgorithm=Ed25519 (12)
  3:   00             # [2]. hashAlgorithm=SHA256 (0)
  4:   50             # [3]. nonce=byte[16]
  5:     11111111111111111111111111111111
 21:   48             # [4]. requestorCertHash=byte[8]
 22:     44F0528B56F35AD9
 30:   80             # [5]. extensions=array[0]
 31:   86             # [6]. requests=array[6]
                        #---PerIssuerRequests[0]---
 32:     48             # [0]. issuerCertHash=byte[8]
 33:       A01C73A5F3B06334
 41:     80             # [1]. extensions=array[0]
 42:     86             # [2]. singleRequests=array[6]
                          #---SingleCertRequests[0]---
 43:       54             # [0]. serialNumberHash=byte[20]
 44:         10652787FA0527BC2449A1BFC5AB31AA5A6F0D8D
 64:       80             # [1]. extensions=array[0]
                          #---SingleCertRequests[1]---
 65:       54             # [2]. serialNumberHash=byte[20]
 66:         75D8BC4FBAFC6694467641E748DFD53A8B9D176D
 86:       80             # [3]. extensions=array[0]
                          #---SingleCertRequests[2]---
 87:       54             # [4]. serialNumberHash=byte[20]
 88:         D1AC135D7DA29BDCF4DCA0D5281A51605B678400
108:       80             # [5]. extensions=array[0]
                        #---PerIssuerRequests[1]---
109:     48             # [3]. issuerCertHash=byte[8]
110:       2222222222222222
118:     80             # [4]. extensions=array[0]
119:     82             # [5]. singleRequests=array[2]
                          #---SingleCertRequests[0]---
120:       54             # [0]. serialNumberHash=byte[20]
121:         D3A0C1E3DB92E8F6810537D45CFAECF6CE417E3B
141:       80             # [1]. extensions=array[0]
142:   F6             # [7]. requestorCerts=<null>
143:   58 40          # [8]. signatureValue=byte[64]
145:     7DA70BE70D8C88F5150218B2F60A21320D26FAF8DC198F16654D54CB61
174:     7A1C3C3F420B3F2FBF74C9B107D81D1815C2CE09B22EAF491313003C49
203:     D43AAB8D970B
~~~~~

### Signed OCSP Request Example With Requestor's Certificate {#exam-signed-ocsp-req-withcert}

[comment]: <> (replace-reduction:ocspreq/signed-ocspreq-with-cert/ocspreq.hex % ocspreq/signed-ocspreq-with-cert/x509ocspreq.pem)
- Size reduction: 60%
- Verifiable with certificate in {{ocsp-requestor-cert}}
- Signed OCSP Request (`C509UnsignedOCSPRequest`) with embedded requestor's certificate
- Note that the X.509 OCSP Request and the C509 OCSP Request are not convertible.

#### X.509 OCSP Request

[comment]: <> (replace-size:ocspreq/signed-ocspreq-with-cert/x509ocspreq.pem)
PEM content (1043 bytes):

[comment]: <> (replace-data:ocspreq/signed-ocspreq-with-cert/x509ocspreq.pem)
~~~~~
-----BEGIN OCSP REQUEST-----
MIIEDzCCAnmhHaQbMBkxFzAVBgNVBAMMDm9jc3AtcmVxdWVzdG9yMIIBtDBrMGkw
DQYJYIZIAWUDBAIBBQAEIDJTjnSFvTeuRU8fDSuXVddYuR9ujjp685eg9ABgXG/4
BCDMEch0CgUJ7E2hTOWIbnI2TA9jtg7WNH8TwW7nJbdmogIUEjQSNBI0EjQSNBI0
EjQSNBI0EjQwazBpMA0GCWCGSAFlAwQCAQUABCAyU450hb03rkVPHw0rl1XXWLkf
bo46evOXoPQAYFxv+AQgzBHIdAoFCexNoUzliG5yNkwPY7YO1jR/E8Fu5yW3ZqIC
FDRWNFY0VjRWNFY0VjRWNFY0VjRWMGswaTANBglghkgBZQMEAgEFAAQgMlOOdIW9
N65FTx8NK5dV11i5H26OOnrzl6D0AGBcb/gEIMwRyHQKBQnsTaFM5YhucjZMD2O2
DtY0fxPBbuclt2aiAhRWeFZ4VnhWeFZ4VnhWeFZ4VnhWeDBrMGkwDQYJYIZIAWUD
BAIBBQAEIDMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzBCBERERERERE
RERERERERERERERERERERERERERERERERAIUIjMiMyIzIjMiMyIzIjMiMyIzIjOi
gZ8wgZwwGgYJKwYBBQUHMAEEBA0wCwYJKwYBBQUHMAEBMF8GCSsGAQUFBzABCARS
MFAwBzAFBgMrZXAwITAKBggqhkjOPQQDAjATBgcqhkjOPQIBBggqhkjOPQMBBzAi
MAoGCCqGSM49BAMCMBQGByqGSM49AgEGCSskAwMCCAEBBzAdBgkrBgEFBQcwAQIE
EBERERERERERERERERERERGgggGOMIIBijAFBgMrZXADQQDwRoT41xL70gT6+NTW
ayTN07XdRKwHRyfduMPbJy0AsRw9TKioMQoLnts6C+6k4s+rORjaTcvZ0Aqv5fQ6
UJMFoIIBPDCCATgwggE0MIHnoAMCAQICAhI2MAUGAytlcDAaMRgwFgYDVQQDDA90
ZXN0IGNybG9jc3AtY2EwHhcNMjUwMTAyMDAwMDAwWhcNMjYwMTAyMDAwMDAwWjAZ
MRcwFQYDVQQDDA5vY3NwLXJlcXVlc3RvcjAqMAUGAytlcAMhAARTCxdk7dS04zq0
SvD4OJYcAHF210tqNUbst/1XMg3To1IwUDAdBgNVHQ4EFgQUsTbUWYobG2qG2mUQ
rqVk2BKX5PkwDgYDVR0PAQH/BAQDAgeAMB8GA1UdIwQYMBaAFNl9d+Y0wvcAMAyl
j8h3NlsVUAeiMAUGAytlcANBAJj5kiFekcWb6v8et+o+/Suqfh29AdErA3eBmFnJ
Z5A/+c/q9jFbvdahCBJJteLJhUIc0BJ0GlmWOBLI0no1fQI=
-----END OCSP REQUEST-----
~~~~~

#### C509 OCSP Request

[comment]: <> (replace-size:ocspreq/signed-ocspreq-with-cert/ocspreq.hex)
Plain Hex (420 bytes):

[comment]: <> (replace-data:ocspreq/signed-ocspreq-with-cert/ocspreq.hex)
~~~~~
89010C0050111111111111111111111111111111114844F0528B56F35AD984185D82
0001185E840CF600820118188648A01C73A5F3B0633480865410652787FA0527BC24
49A1BFC5AB31AA5A6F0D8D805475D8BC4FBAFC6694467641E748DFD53A8B9D176D80
54D1AC135D7DA29BDCF4DCA0D5281A51605B67840080482222222222222222808254
D3A0C1E3DB92E8F6810537D45CFAECF6CE417E3B8058C38B024212360C6F74657374
2063726C6F6373702D63611A6775D7001A69570A806E6F6373702D72657175657374
6F720C582004530B1764EDD4B4E33AB44AF0F838961C007176D74B6A3546ECB7FD57
320DD3860154DD51BDB2A2C791C062D4027856DBACF52607F0BE210107542F45E78D
2CAEDF368CDF53C39005D492450E10565840F8C6183ECF8C3EFD50DD4942D172814C
46EC0FC01DD586A597178DF864A0D9DA86B7CA17FC9F772FF04C80E98B60D5B4B624
08A277A5B70D0D2A3F5ED5442D075840EBF95F92812C9DF3DBC7C19699D5254485AD
DC930695239D1D68BF7988F3F1B0C76A588BF42F4FCFF373C3705AEB56FC3B6CDEAA
F66DA0F5BBB735F4A1CDB004
~~~~~

Textual Representation

[comment]: <> (replace-data:ocspreq/signed-ocspreq-with-cert/ocspreq.txt)
~~~~~
C509SignedOCSPRequest
  TBSOCSPRequest
    Type: C509SignedOCSPRequest (1)
    Signature Algorithm: Ed25519 (12)
    Hash Algorithm: SHA256 (0)
    RequestorCertHash
      44:f0:52:8b:56:f3:5a:d9
    Nonce
      11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11
    Extensions
      AcceptOCSPResponseTypes (93)
        C509ErrorOCSPResponse (0)
        C509BasicOCSPResponse (1)
      preferredSignatureAlgorithms (94)
          Preferred Signature Algorithm:
            Signature Algorithm: Ed25519 (12)
          Preferred Signature Algorithm:
            Signature Algorithm: ecdsa-with-sha256 (0)
            Public Key Algorithms:
              EC public key on curve secp256r1 (1)
              EC public key on curve brainpoolp256r1 (24)
    Requests
      OcspPerIssuerRequest
        issuerCertHash
          a0:1c:73:a5:f3:b0:63:34
        extensions: <empty>
        singleRequests
          SingleCertRequest
            SerialNumberHash:
              10:65:27:87:fa:05:27:bc:24:49:a1:bf:c5:ab:31:aa:
              5a:6f:0d:8d
            Extensions: <empty>
          SingleCertRequest
            SerialNumberHash:
              75:d8:bc:4f:ba:fc:66:94:46:76:41:e7:48:df:d5:3a:
              8b:9d:17:6d
            Extensions: <empty>
          SingleCertRequest
            SerialNumberHash:
              d1:ac:13:5d:7d:a2:9b:dc:f4:dc:a0:d5:28:1a:51:60:
              5b:67:84:00
            Extensions: <empty>
      OcspPerIssuerRequest
        issuerCertHash
          22:22:22:22:22:22:22:22
        extensions: <empty>
        singleRequests
          SingleCertRequest
            SerialNumberHash:
              d3:a0:c1:e3:db:92:e8:f6:81:05:37:d4:5c:fa:ec:f6:
              ce:41:7e:3b
            Extensions: <empty>
    Requestor Certs
      C509Certificate
        8b:02:42:12:36:0c:6f:74:65:73:74:20:63:72:6c:6f:
        63:73:70:2d:63:61:1a:67:75:d7:00:1a:69:57:0a:80:
        6e:6f:63:73:70:2d:72:65:71:75:65:73:74:6f:72:0c:
        58:20:04:53:0b:17:64:ed:d4:b4:e3:3a:b4:4a:f0:f8:
        38:96:1c:00:71:76:d7:4b:6a:35:46:ec:b7:fd:57:32:
        0d:d3:86:01:54:dd:51:bd:b2:a2:c7:91:c0:62:d4:02:
        78:56:db:ac:f5:26:07:f0:be:21:01:07:54:2f:45:e7:
        8d:2c:ae:df:36:8c:df:53:c3:90:05:d4:92:45:0e:10:
        56:58:40:f8:c6:18:3e:cf:8c:3e:fd:50:dd:49:42:d1:
        72:81:4c:46:ec:0f:c0:1d:d5:86:a5:97:17:8d:f8:64:
        a0:d9:da:86:b7:ca:17:fc:9f:77:2f:f0:4c:80:e9:8b:
        60:d5:b4:b6:24:08:a2:77:a5:b7:0d:0d:2a:3f:5e:d5:
        44:2d:07
  Signature Value
    eb:f9:5f:92:81:2c:9d:f3:db:c7:c1:96:99:d5:25:44:
    85:ad:dc:93:06:95:23:9d:1d:68:bf:79:88:f3:f1:b0:
    c7:6a:58:8b:f4:2f:4f:cf:f3:73:c3:70:5a:eb:56:fc:
    3b:6c:de:aa:f6:6d:a0:f5:bb:b7:35:f4:a1:cd:b0:04
~~~~~

Annotated hex

[comment]: <> (replace-data:ocspreq/signed-ocspreq-with-cert/ocspreq.diag)
~~~~~
  0: 89             # C509OCSPRequest=array[9]
  1:   01             # [0]. ocspRequestType=C509SignedOCSPRequest
                      #      (1)
  2:   0C             # [1]. signatureAlgorithm=Ed25519 (12)
  3:   00             # [2]. hashAlgorithm=SHA256 (0)
  4:   50             # [3]. nonce=byte[16]
  5:     11111111111111111111111111111111
 21:   48             # [4]. requestorCertHash=byte[8]
 22:     44F0528B56F35AD9
 30:   84             # [5]. extensions=array[4]
                        #---extension[0]---
 31:     18 5D          # [0]. type=AcceptOCSPResponseTypes (93)
 33:     82             # [1]. value=array[2]
 34:       00             # [0]. C509ErrorOCSPResponse (0)
 35:       01             # [1]. C509BasicOCSPResponse (1)
                        #---extension[1]---
 36:     18 5E          # [2]. type=preferredSignatureAlgorithms
                        #      (94)
 38:     84             # [3]. value=array[4]
                          #---preferredSignatureAlgorithms[0]---
 39:       0C             # [0]. sigIdentifier=Ed25519 (12)
 40:       F6             # [1]. pubKeyAlgIdentifiers=<null>
                          #---preferredSignatureAlgorithms[1]---
 41:       00             # [2]. sigIdentifier=ecdsa-with-sha256 (0)
 42:       82             # [3]. pubKeyAlgIdentifiers=array[2]
 43:         01             # [0]. pubKeyAlgIdentifier=EC public key
                            #      on curve secp256r1 (1)
 44:         18 18          # [1]. pubKeyAlgIdentifier=EC public key
                            #      on curve brainpoolp256r1 (24)
 46:   86             # [6]. requests=array[6]
                        #---PerIssuerRequests[0]---
 47:     48             # [0]. issuerCertHash=byte[8]
 48:       A01C73A5F3B06334
 56:     80             # [1]. extensions=array[0]
 57:     86             # [2]. singleRequests=array[6]
                          #---SingleCertRequests[0]---
 58:       54             # [0]. serialNumberHash=byte[20]
 59:         10652787FA0527BC2449A1BFC5AB31AA5A6F0D8D
 79:       80             # [1]. extensions=array[0]
                          #---SingleCertRequests[1]---
 80:       54             # [2]. serialNumberHash=byte[20]
 81:         75D8BC4FBAFC6694467641E748DFD53A8B9D176D
101:       80             # [3]. extensions=array[0]
                          #---SingleCertRequests[2]---
102:       54             # [4]. serialNumberHash=byte[20]
103:         D1AC135D7DA29BDCF4DCA0D5281A51605B678400
123:       80             # [5]. extensions=array[0]
                        #---PerIssuerRequests[1]---
124:     48             # [3]. issuerCertHash=byte[8]
125:       2222222222222222
133:     80             # [4]. extensions=array[0]
134:     82             # [5]. singleRequests=array[2]
                          #---SingleCertRequests[0]---
135:       54             # [0]. serialNumberHash=byte[20]
136:         D3A0C1E3DB92E8F6810537D45CFAECF6CE417E3B
156:       80             # [1]. extensions=array[0]
157:   58 C3          # [7]. requestorCerts(COSE_C509)=byte[195]
159:     8B024212360C6F746573742063726C6F6373702D63611A6775D7001A69
188:     570A806E6F6373702D726571756573746F720C582004530B1764EDD4B4
217:     E33AB44AF0F838961C007176D74B6A3546ECB7FD57320DD3860154DD51
246:     BDB2A2C791C062D4027856DBACF52607F0BE210107542F45E78D2CAEDF
275:     368CDF53C39005D492450E10565840F8C6183ECF8C3EFD50DD4942D172
304:     814C46EC0FC01DD586A597178DF864A0D9DA86B7CA17FC9F772FF04C80
333:     E98B60D5B4B62408A277A5B70D0D2A3F5ED5442D07
354:   58 40          # [8]. signatureValue=byte[64]
356:     EBF95F92812C9DF3DBC7C19699D5254485ADDC930695239D1D68BF7988
385:     F3F1B0C76A588BF42F4FCFF373C3705AEB56FC3B6CDEAAF66DA0F5BBB7
414:     35F4A1CDB004
~~~~~

### Signed OCSP Request Example With Requestor's Certificate Chain {#exam-signed-ocsp-req-withcertchain}

[comment]: <> (replace-reduction:ocspreq/signed-ocspreq-with-certchain/ocspreq.hex % ocspreq/signed-ocspreq-with-certchain/x509ocspreq.pem)
- Size reduction: 55%
- Verifiable with certificate in {{ocsp-requestor-cert}}
- Signed OCSP Request (`C509UnsignedOCSPRequest`) with embedded requestor's certificate chain (2 certificates)
- Note that the X.509 OCSP Request and the C509 OCSP Request are not convertible.

#### X.509 OCSP Request

[comment]: <> (replace-size:ocspreq/signed-ocspreq-with-certchain/x509ocspreq.pem)
PEM content (1379 bytes):

[comment]: <> (replace-data:ocspreq/signed-ocspreq-with-certchain/x509ocspreq.pem)
~~~~~
-----BEGIN OCSP REQUEST-----
MIIFXzCCAnmhHaQbMBkxFzAVBgNVBAMMDm9jc3AtcmVxdWVzdG9yMIIBtDBrMGkw
DQYJYIZIAWUDBAIBBQAEIDJTjnSFvTeuRU8fDSuXVddYuR9ujjp685eg9ABgXG/4
BCDMEch0CgUJ7E2hTOWIbnI2TA9jtg7WNH8TwW7nJbdmogIUEjQSNBI0EjQSNBI0
EjQSNBI0EjQwazBpMA0GCWCGSAFlAwQCAQUABCAyU450hb03rkVPHw0rl1XXWLkf
bo46evOXoPQAYFxv+AQgzBHIdAoFCexNoUzliG5yNkwPY7YO1jR/E8Fu5yW3ZqIC
FDRWNFY0VjRWNFY0VjRWNFY0VjRWMGswaTANBglghkgBZQMEAgEFAAQgMlOOdIW9
N65FTx8NK5dV11i5H26OOnrzl6D0AGBcb/gEIMwRyHQKBQnsTaFM5YhucjZMD2O2
DtY0fxPBbuclt2aiAhRWeFZ4VnhWeFZ4VnhWeFZ4VnhWeDBrMGkwDQYJYIZIAWUD
BAIBBQAEIDMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzBCBERERERERE
RERERERERERERERERERERERERERERERERAIUIjMiMyIzIjMiMyIzIjMiMyIzIjOi
gZ8wgZwwGgYJKwYBBQUHMAEEBA0wCwYJKwYBBQUHMAEBMF8GCSsGAQUFBzABCARS
MFAwBzAFBgMrZXAwITAKBggqhkjOPQQDAjATBgcqhkjOPQIBBggqhkjOPQMBBzAi
MAoGCCqGSM49BAMCMBQGByqGSM49AgEGCSskAwMCCAEBBzAdBgkrBgEFBQcwAQIE
EBERERERERERERERERERERGgggLeMIIC2jAFBgMrZXADQQDwRoT41xL70gT6+NTW
ayTN07XdRKwHRyfduMPbJy0AsRw9TKioMQoLnts6C+6k4s+rORjaTcvZ0Aqv5fQ6
UJMFoIICjDCCAogwggE0MIHnoAMCAQICAhI2MAUGAytlcDAaMRgwFgYDVQQDDA90
ZXN0IGNybG9jc3AtY2EwHhcNMjUwMTAyMDAwMDAwWhcNMjYwMTAyMDAwMDAwWjAZ
MRcwFQYDVQQDDA5vY3NwLXJlcXVlc3RvcjAqMAUGAytlcAMhAARTCxdk7dS04zq0
SvD4OJYcAHF210tqNUbst/1XMg3To1IwUDAdBgNVHQ4EFgQUsTbUWYobG2qG2mUQ
rqVk2BKX5PkwDgYDVR0PAQH/BAQDAgeAMB8GA1UdIwQYMBaAFNl9d+Y0wvcAMAyl
j8h3NlsVUAeiMAUGAytlcANBAJj5kiFekcWb6v8et+o+/Suqfh29AdErA3eBmFnJ
Z5A/+c/q9jFbvdahCBJJteLJhUIc0BJ0GlmWOBLI0no1fQIwggFMMIH/oAMCAQIC
AQEwBQYDK2VwMB4xHDAaBgNVBAMME3Rlc3QgY3Jsb2NzcC1yb290Y2EwHhcNMjUw
MTAxMDAwMDAwWhcNMjYxMjMxMjM1OTU5WjAaMRgwFgYDVQQDDA90ZXN0IGNybG9j
c3AtY2EwKjAFBgMrZXADIQBe+KNVoAGnxQ0jSUcBIIExpLsquSDUC/sO4farKP90
AKNmMGQwHQYDVR0OBBYEFNl9d+Y0wvcAMAylj8h3NlsVUAeiMA4GA1UdDwEB/wQE
AwIBBjASBgNVHRMBAf8ECDAGAQH/AgEBMB8GA1UdIwQYMBaAFJEjnPr554Nssp9R
4TGR2xDTrhaTMAUGAytlcANBANZeAdfL+kF/sXuZ95ftaSevVi/2Po01s+On04Fg
zGRnQBBNjzkYl92rEZjz0FomGSBDYqb4PDOIIRs2vFY9QQI=
-----END OCSP REQUEST-----
~~~~~

#### C509 OCSP Request

[comment]: <> (replace-size:ocspreq/signed-ocspreq-with-certchain/ocspreq.hex)
Plain Hex (625 bytes):

[comment]: <> (replace-data:ocspreq/signed-ocspreq-with-certchain/ocspreq.hex)
~~~~~
89010C0050111111111111111111111111111111114844F0528B56F35AD984185D82
0001185E840CF600820118188648A01C73A5F3B0633480865410652787FA0527BC24
49A1BFC5AB31AA5A6F0D8D805475D8BC4FBAFC6694467641E748DFD53A8B9D176D80
54D1AC135D7DA29BDCF4DCA0D5281A51605B67840080482222222222222222808254
D3A0C1E3DB92E8F6810537D45CFAECF6CE417E3B808258C38B024212360C6F746573
742063726C6F6373702D63611A6775D7001A69570A806E6F6373702D726571756573
746F720C582004530B1764EDD4B4E33AB44AF0F838961C007176D74B6A3546ECB7FD
57320DD3860154DD51BDB2A2C791C062D4027856DBACF52607F0BE210107542F45E7
8D2CAEDF368CDF53C39005D492450E10565840F8C6183ECF8C3EFD50DD4942D17281
4C46EC0FC01DD586A597178DF864A0D9DA86B7CA17FC9F772FF04C80E98B60D5B4B6
2408A277A5B70D0D2A3F5ED5442D0758CA8B0241010C73746573742063726C6F6373
702D726F6F7463611A677485801A6B36EC7F6F746573742063726C6F6373702D6361
0C58205EF8A355A001A7C50D23494701208131A4BB2AB920D40BFB0EE1F6AB28FF74
008801542F45E78D2CAEDF368CDF53C39005D492450E1056211860230107542DA3A4
03F7D2F4E0B3D8031A73BA8A839F557F0F5840E50465D60C02A2111EF3FC6E44F2A3
6008765B552351F9A3F5B2AA7C76F1F05D259847A4F4250B2E4B0AE2099762A2596D
3CC1DB2CCD180AA0A2D0E191310B0F584071D39CBD6611FD5B0C3092FCE58016B966
232851AC3167CD0CDEF47DF0F0BC738616EB65BB2BA509C8CF45EDBC9B784A4A7092
5E97AE152871E9D665C477500E
~~~~~

Textual Representation

[comment]: <> (replace-data:ocspreq/signed-ocspreq-with-certchain/ocspreq.txt)
~~~~~
C509SignedOCSPRequest
  TBSOCSPRequest
    Type: C509SignedOCSPRequest (1)
    Signature Algorithm: Ed25519 (12)
    Hash Algorithm: SHA256 (0)
    RequestorCertHash
      44:f0:52:8b:56:f3:5a:d9
    Nonce
      11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11
    Extensions
      AcceptOCSPResponseTypes (93)
        C509ErrorOCSPResponse (0)
        C509BasicOCSPResponse (1)
      preferredSignatureAlgorithms (94)
          Preferred Signature Algorithm:
            Signature Algorithm: Ed25519 (12)
          Preferred Signature Algorithm:
            Signature Algorithm: ecdsa-with-sha256 (0)
            Public Key Algorithms:
              EC public key on curve secp256r1 (1)
              EC public key on curve brainpoolp256r1 (24)
    Requests
      OcspPerIssuerRequest
        issuerCertHash
          a0:1c:73:a5:f3:b0:63:34
        extensions: <empty>
        singleRequests
          SingleCertRequest
            SerialNumberHash:
              10:65:27:87:fa:05:27:bc:24:49:a1:bf:c5:ab:31:aa:
              5a:6f:0d:8d
            Extensions: <empty>
          SingleCertRequest
            SerialNumberHash:
              75:d8:bc:4f:ba:fc:66:94:46:76:41:e7:48:df:d5:3a:
              8b:9d:17:6d
            Extensions: <empty>
          SingleCertRequest
            SerialNumberHash:
              d1:ac:13:5d:7d:a2:9b:dc:f4:dc:a0:d5:28:1a:51:60:
              5b:67:84:00
            Extensions: <empty>
      OcspPerIssuerRequest
        issuerCertHash
          22:22:22:22:22:22:22:22
        extensions: <empty>
        singleRequests
          SingleCertRequest
            SerialNumberHash:
              d3:a0:c1:e3:db:92:e8:f6:81:05:37:d4:5c:fa:ec:f6:
              ce:41:7e:3b
            Extensions: <empty>
    Requestor Certs
      C509Certificate
        8b:02:42:12:36:0c:6f:74:65:73:74:20:63:72:6c:6f:
        63:73:70:2d:63:61:1a:67:75:d7:00:1a:69:57:0a:80:
        6e:6f:63:73:70:2d:72:65:71:75:65:73:74:6f:72:0c:
        58:20:04:53:0b:17:64:ed:d4:b4:e3:3a:b4:4a:f0:f8:
        38:96:1c:00:71:76:d7:4b:6a:35:46:ec:b7:fd:57:32:
        0d:d3:86:01:54:dd:51:bd:b2:a2:c7:91:c0:62:d4:02:
        78:56:db:ac:f5:26:07:f0:be:21:01:07:54:2f:45:e7:
        8d:2c:ae:df:36:8c:df:53:c3:90:05:d4:92:45:0e:10:
        56:58:40:f8:c6:18:3e:cf:8c:3e:fd:50:dd:49:42:d1:
        72:81:4c:46:ec:0f:c0:1d:d5:86:a5:97:17:8d:f8:64:
        a0:d9:da:86:b7:ca:17:fc:9f:77:2f:f0:4c:80:e9:8b:
        60:d5:b4:b6:24:08:a2:77:a5:b7:0d:0d:2a:3f:5e:d5:
        44:2d:07
      C509Certificate
        8b:02:41:01:0c:73:74:65:73:74:20:63:72:6c:6f:63:
        73:70:2d:72:6f:6f:74:63:61:1a:67:74:85:80:1a:6b:
        36:ec:7f:6f:74:65:73:74:20:63:72:6c:6f:63:73:70:
        2d:63:61:0c:58:20:5e:f8:a3:55:a0:01:a7:c5:0d:23:
        49:47:01:20:81:31:a4:bb:2a:b9:20:d4:0b:fb:0e:e1:
        f6:ab:28:ff:74:00:88:01:54:2f:45:e7:8d:2c:ae:df:
        36:8c:df:53:c3:90:05:d4:92:45:0e:10:56:21:18:60:
        23:01:07:54:2d:a3:a4:03:f7:d2:f4:e0:b3:d8:03:1a:
        73:ba:8a:83:9f:55:7f:0f:58:40:e5:04:65:d6:0c:02:
        a2:11:1e:f3:fc:6e:44:f2:a3:60:08:76:5b:55:23:51:
        f9:a3:f5:b2:aa:7c:76:f1:f0:5d:25:98:47:a4:f4:25:
        0b:2e:4b:0a:e2:09:97:62:a2:59:6d:3c:c1:db:2c:cd:
        18:0a:a0:a2:d0:e1:91:31:0b:0f
  Signature Value
    71:d3:9c:bd:66:11:fd:5b:0c:30:92:fc:e5:80:16:b9:
    66:23:28:51:ac:31:67:cd:0c:de:f4:7d:f0:f0:bc:73:
    86:16:eb:65:bb:2b:a5:09:c8:cf:45:ed:bc:9b:78:4a:
    4a:70:92:5e:97:ae:15:28:71:e9:d6:65:c4:77:50:0e
~~~~~

Annotated hex

[comment]: <> (replace-data:ocspreq/signed-ocspreq-with-certchain/ocspreq.diag)
~~~~~
  0: 89             # C509OCSPRequest=array[9]
  1:   01             # [0]. ocspRequestType=C509SignedOCSPRequest
                      #      (1)
  2:   0C             # [1]. signatureAlgorithm=Ed25519 (12)
  3:   00             # [2]. hashAlgorithm=SHA256 (0)
  4:   50             # [3]. nonce=byte[16]
  5:     11111111111111111111111111111111
 21:   48             # [4]. requestorCertHash=byte[8]
 22:     44F0528B56F35AD9
 30:   84             # [5]. extensions=array[4]
                        #---extension[0]---
 31:     18 5D          # [0]. type=AcceptOCSPResponseTypes (93)
 33:     82             # [1]. value=array[2]
 34:       00             # [0]. C509ErrorOCSPResponse (0)
 35:       01             # [1]. C509BasicOCSPResponse (1)
                        #---extension[1]---
 36:     18 5E          # [2]. type=preferredSignatureAlgorithms
                        #      (94)
 38:     84             # [3]. value=array[4]
                          #---preferredSignatureAlgorithms[0]---
 39:       0C             # [0]. sigIdentifier=Ed25519 (12)
 40:       F6             # [1]. pubKeyAlgIdentifiers=<null>
                          #---preferredSignatureAlgorithms[1]---
 41:       00             # [2]. sigIdentifier=ecdsa-with-sha256 (0)
 42:       82             # [3]. pubKeyAlgIdentifiers=array[2]
 43:         01             # [0]. pubKeyAlgIdentifier=EC public key
                            #      on curve secp256r1 (1)
 44:         18 18          # [1]. pubKeyAlgIdentifier=EC public key
                            #      on curve brainpoolp256r1 (24)
 46:   86             # [6]. requests=array[6]
                        #---PerIssuerRequests[0]---
 47:     48             # [0]. issuerCertHash=byte[8]
 48:       A01C73A5F3B06334
 56:     80             # [1]. extensions=array[0]
 57:     86             # [2]. singleRequests=array[6]
                          #---SingleCertRequests[0]---
 58:       54             # [0]. serialNumberHash=byte[20]
 59:         10652787FA0527BC2449A1BFC5AB31AA5A6F0D8D
 79:       80             # [1]. extensions=array[0]
                          #---SingleCertRequests[1]---
 80:       54             # [2]. serialNumberHash=byte[20]
 81:         75D8BC4FBAFC6694467641E748DFD53A8B9D176D
101:       80             # [3]. extensions=array[0]
                          #---SingleCertRequests[2]---
102:       54             # [4]. serialNumberHash=byte[20]
103:         D1AC135D7DA29BDCF4DCA0D5281A51605B678400
123:       80             # [5]. extensions=array[0]
                        #---PerIssuerRequests[1]---
124:     48             # [3]. issuerCertHash=byte[8]
125:       2222222222222222
133:     80             # [4]. extensions=array[0]
134:     82             # [5]. singleRequests=array[2]
                          #---SingleCertRequests[0]---
135:       54             # [0]. serialNumberHash=byte[20]
136:         D3A0C1E3DB92E8F6810537D45CFAECF6CE417E3B
156:       80             # [1]. extensions=array[0]
157:   82             # [7]. requestorCerts(COSE_C509)=array[2]
158:     58 C3          # [0]. C509CertData=byte[195]
160:       8B024212360C6F746573742063726C6F6373702D63611A6775D7001A
188:       69570A806E6F6373702D726571756573746F720C582004530B1764ED
216:       D4B4E33AB44AF0F838961C007176D74B6A3546ECB7FD57320DD38601
244:       54DD51BDB2A2C791C062D4027856DBACF52607F0BE210107542F45E7
272:       8D2CAEDF368CDF53C39005D492450E10565840F8C6183ECF8C3EFD50
300:       DD4942D172814C46EC0FC01DD586A597178DF864A0D9DA86B7CA17FC
328:       9F772FF04C80E98B60D5B4B62408A277A5B70D0D2A3F5ED5442D07
355:     58 CA          # [1]. C509CertData=byte[202]
357:       8B0241010C73746573742063726C6F6373702D726F6F7463611A6774
385:       85801A6B36EC7F6F746573742063726C6F6373702D63610C58205EF8
413:       A355A001A7C50D23494701208131A4BB2AB920D40BFB0EE1F6AB28FF
441:       74008801542F45E78D2CAEDF368CDF53C39005D492450E1056211860
469:       230107542DA3A403F7D2F4E0B3D8031A73BA8A839F557F0F5840E504
497:       65D60C02A2111EF3FC6E44F2A36008765B552351F9A3F5B2AA7C76F1
525:       F05D259847A4F4250B2E4B0AE2099762A2596D3CC1DB2CCD180AA0A2
553:       D0E191310B0F
559:   58 40          # [8]. signatureValue=byte[64]
561:     71D39CBD6611FD5B0C3092FCE58016B966232851AC3167CD0CDEF47DF0
590:     F0BC738616EB65BB2BA509C8CF45EDBC9B784A4A70925E97AE152871E9
619:     D665C477500E
~~~~~

## OCSP Response Examples

### Error OCSP Response Example {#exam-error-ocsp-resp}

[comment]: <> (replace-reduction:ocspresp/error-ocspresp/ocspresp.hex % ocspresp/error-ocspresp/x509ocspresp.pem)
- Size reduction: 40%
- Error Response (`C509ErrorOCSPResponse`)

#### X.509 OCSP Response

[comment]: <> (replace-size:ocspresp/error-ocspresp/x509ocspresp.pem)
PEM content (5 bytes):

[comment]: <> (replace-data:ocspresp/error-ocspresp/x509ocspresp.pem)
~~~~~
-----BEGIN OCSP RESPONSE-----
MAMKAQY=
-----END OCSP RESPONSE-----
~~~~~

#### C509 OCSP Response

[comment]: <> (replace-size:ocspresp/error-ocspresp/ocspresp.hex)
Plain Hex (3 bytes):

[comment]: <> (replace-data:ocspresp/error-ocspresp/ocspresp.hex)
~~~~~
820006
~~~~~

Textual Representation

[comment]: <> (replace-data:ocspresp/error-ocspresp/ocspresp.txt)
~~~~~
C509ErrorResponse
  Type:   C509ErrorOCSPResponse (0)
  Status: unauthorized (6)
~~~~~

Annotated hex

[comment]: <> (replace-data:ocspresp/error-ocspresp/ocspresp.diag)
~~~~~
0: 82             # C509OCSPResponse=array[2]
1:   00             # [0]. ocspResponseType=C509ErrorOCSPResponse
                    #      (0)
2:   06             # [1]. responseStatus=unauthorized (6)
~~~~~

### Simple OCSP Response Example {#exam-simple-ocsp-resp}

[comment]: <> (replace-reduction:ocspresp/simple-ocspresp/ocspresp.hex % ocspresp/simple-ocspresp/x509ocspresp.pem)
- Size reduction: 59%
- Verifiable with certificate in {{ocsp-responder-cert}}
- Simple OCSP Response (`C509SimpleOCSPResponse`) without responder's certificate
- Note that the X.509 OCSP response and the C509 OCSP response are not convertible.

#### X.509 OCSP Response

[comment]: <> (replace-size:ocspresp/simple-ocspresp/x509ocspresp.pem)
PEM content (338 bytes):

[comment]: <> (replace-data:ocspresp/simple-ocspresp/x509ocspresp.pem)
~~~~~
-----BEGIN OCSP RESPONSE-----
MIIBTgoBAKCCAUcwggFDBgkrBgEFBQcwAQEEggE0MIIBMDCB46IWBBTq5ZqK6ar0
EEsV5Q6O4BcVF3QYrxgPMjAyNTAzMDMwMDAwMDBaMIGUMIGRMGkwDQYJYIZIAWUD
BAIBBQAEIDJTjnSFvTeuRU8fDSuXVddYuR9ujjp685eg9ABgXG/4BCDMEch0CgUJ
7E2hTOWIbnI2TA9jtg7WNH8TwW7nJbdmogIUEjQSNBI0EjQSNBI0EjQSNBI0EjSA
ABgPMjAyNTAzMDIxNjAwMDBaoBEYDzIwMjUwMzAzMDcwMDAwWqEhMB8wHQYJKwYB
BQUHMAECBBARERERERERERERERERERERMAUGAytlcANBAGEzM3X9KkpZLfpEMRoz
3TwWMLEfWkJkVHA++53Yj9QrrI6Sqry4t9AouNcGLORbv42mroG3GkYESuMSK3uG
Wgg=
-----END OCSP RESPONSE-----
~~~~~

#### C509 OCSP Response

[comment]: <> (replace-size:ocspresp/simple-ocspresp/ocspresp.hex)
Plain Hex (140 bytes):

[comment]: <> (replace-data:ocspresp/simple-ocspresp/ocspresp.hex)
~~~~~
8E020C005011111111111111111111111111111111480600867838E3311A48A01C73
A5F3B063345410652787FA0527BC2449A1BFC5AB31AA5A6F0D8D001A67C4F1003970
7F19627080F65840E3419955AEB3D74AD5BC7D32264E8976C3AB6F68643C6BF66CC2
F9352FF3E861A0BD1506C78B09D3FAE869D1FD3C87EF461CF6D2096EA0AC11FCFF5E
BC0FA70C
~~~~~

Textual Representation

[comment]: <> (replace-data:ocspresp/simple-ocspresp/ocspresp.txt)
~~~~~
C509SimpleOCSPResponse
  TBSSimpleOCSPResponse
    Type: C509SimpleOCSPResponse (2)
    Signature Algorithm: Ed25519 (12)
    Hash Algorithm: SHA256 (0)
    Nonce
      11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11
    ResponderCertHash
      06:00:86:78:38:e3:31:1a
    IssuerCertHash
      a0:1c:73:a5:f3:b0:63:34
    SerialNumberHash
      10:65:27:87:fa:05:27:bc:24:49:a1:bf:c5:ab:31:aa:
      5a:6f:0d:8d
    Cert Status: good
    ProducedAt: 2025-03-03T00:00:00Z
    This Update: -28800, 2025-03-02T16:00:00Z
    Next Update: 25200, 2025-03-03T07:00:00Z
    Extensions: <empty>
    Responder Certs: null
  Signature Value
    e3:41:99:55:ae:b3:d7:4a:d5:bc:7d:32:26:4e:89:76:
    c3:ab:6f:68:64:3c:6b:f6:6c:c2:f9:35:2f:f3:e8:61:
    a0:bd:15:06:c7:8b:09:d3:fa:e8:69:d1:fd:3c:87:ef:
    46:1c:f6:d2:09:6e:a0:ac:11:fc:ff:5e:bc:0f:a7:0c
~~~~~

Annotated hex

[comment]: <> (replace-data:ocspresp/simple-ocspresp/ocspresp.diag)
~~~~~
  0: 8E             # C509OCSPResponse=array[14]
  1:   02             # [0]. ocspResponseType=C509SimpleOCSPResponse
                      #      (2)
  2:   0C             # [1]. signatureAlgorithm=Ed25519 (12)
  3:   00             # [2]. hashAlgorithm=SHA256 (0)
  4:   50             # [3]. nonce=byte[16]
  5:     11111111111111111111111111111111
 21:   48             # [4]. responderCertHash=byte[8]
 22:     0600867838E3311A
 30:   48             # [5]. issuerCertHash=byte[8]
 31:     A01C73A5F3B06334
 39:   54             # [6]. serialNumberHash=byte[20]
 40:     10652787FA0527BC2449A1BFC5AB31AA5A6F0D8D
 60:   00             # [7]. certStatus=good (0)
 61:   1A 67C4F100    # [8]. producedAt=1740960000:
                      #      2025-03-03T00:00:00Z
 66:   39 707F        # [9]. thisUpdate=-28800: 2025-03-02T16:00:00Z
 69:   19 6270        # [10]. nextUpdate=25200: 2025-03-03T07:00:00Z
 72:   80             # [11]. extensions=array[0]
 73:   F6             # [12]. responderCerts=<null>
 74:   58 40          # [13]. signatureValue=byte[64]
 76:     E3419955AEB3D74AD5BC7D32264E8976C3AB6F68643C6BF66CC2F9352F
105:     F3E861A0BD1506C78B09D3FAE869D1FD3C87EF461CF6D2096EA0AC11FC
134:     FF5EBC0FA70C
~~~~~


### Basic OCSP Response Example Without Responder's Certificate {#exam-basic-ocsp-resp}

[comment]: <> (replace-reduction:ocspresp/basic-ocspresp/ocspresp.hex % ocspresp/basic-ocspresp/x509ocspresp.pem)
- Size reduction: 71%
- Verifiable with certificate in {{ocsp-responder-cert}}
- Basic OCSP Response (`C509BasicOCSPResponse`) without responder's certificate
- Note that the X.509 OCSP response and the C509 OCSP response are not convertible.

#### X.509 OCSP Response

[comment]: <> (replace-size:ocspresp/basic-ocspresp/x509ocspresp.pem)
PEM content (845 bytes):

[comment]: <> (replace-data:ocspresp/basic-ocspresp/x509ocspresp.pem)
~~~~~
-----BEGIN OCSP RESPONSE-----
MIIDSQoBAKCCA0IwggM+BgkrBgEFBQcwAQEEggMvMIIDKzCCAt2iFgQU6uWaiumq
9BBLFeUOjuAXFRd0GK8YDzIwMjUwMzAzMDAwMDAwWjCCAnwwgZEwaTANBglghkgB
ZQMEAgEFAAQgMlOOdIW9N65FTx8NK5dV11i5H26OOnrzl6D0AGBcb/gEIMwRyHQK
BQnsTaFM5YhucjZMD2O2DtY0fxPBbuclt2aiAhQSNBI0EjQSNBI0EjQSNBI0EjQS
NIAAGA8yMDI1MDMwMjE2MDAwMFqgERgPMjAyNTAzMDMwNzAwMDBaMIGnMGkwDQYJ
YIZIAWUDBAIBBQAEIDJTjnSFvTeuRU8fDSuXVddYuR9ujjp685eg9ABgXG/4BCDM
Ech0CgUJ7E2hTOWIbnI2TA9jtg7WNH8TwW7nJbdmogIUNFY0VjRWNFY0VjRWNFY0
VjRWNFahFhgPMTk3MDAxMDEwMDAwMDBaoAMKAQYYDzIwMjUwMzAyMTYwMDAwWqAR
GA8yMDI1MDMwMzA3MDAwMFowgacwaTANBglghkgBZQMEAgEFAAQgMlOOdIW9N65F
Tx8NK5dV11i5H26OOnrzl6D0AGBcb/gEIMwRyHQKBQnsTaFM5YhucjZMD2O2DtY0
fxPBbuclt2aiAhRWeFZ4VnhWeFZ4VnhWeFZ4VnhWeKEWGA8yMDI1MDMwMTE2MDAw
MFqgAwoBBBgPMjAyNTAzMDIxNjAwMDBaoBEYDzIwMjUwMzAzMDcwMDAwWjCBkTBp
MA0GCWCGSAFlAwQCAQUABCAzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMz
MwQgREREREREREREREREREREREREREREREREREREREREREQCFCIzIjMiMyIzIjMi
MyIzIjMiMyIzggAYDzIwMjUwMzAyMTYwMDAwWqARGA8yMDI1MDMwMzA3MDAwMFqh
MjAwMB0GCSsGAQUFBzABAgQQERERERERERERERERERERETAPBgkrBgEFBQcwAQkE
AgUAMAUGAytlcANBAHrbfHeKVrcvjeFMQT9cTvhYU81DmwQpZiyRtH+MhBfSjqsl
riv95/TO4bhcpRnJl5T3D8ojWrMGiFJo1IB8gwc=
-----END OCSP RESPONSE-----
~~~~~

#### C509 OCSP Response

[comment]: <> (replace-size:ocspresp/basic-ocspresp/ocspresp.hex)
Plain Hex (248 bytes):

[comment]: <> (replace-data:ocspresp/basic-ocspresp/ocspresp.hex)
~~~~~
8A010C005011111111111111111111111111111111480600867838E3311A1A67C4F1
00808648A01C73A5F3B06334808F5410652787FA0527BC2449A1BFC5AB31AA5A6F0D
8D0039707F196270805475D8BC4FBAFC6694467641E748DFD53A8B9D176D0139707F
1962708054D1AC135D7DA29BDCF4DCA0D5281A51605B678400821A67C32F00043970
7F19627080482222222222222222808554D3A0C1E3DB92E8F6810537D45CFAECF6CE
417E3B0239707F19627080F65840E4869C57A66BAB501ACAEB7E5024105253D72F45
D349AE21FB941ABE4435F8A6C9D1CA5D2784AB30CF177FF075B5502AEAEE09C1146C
F490663EAED9243A760D
~~~~~

Textual Representation

[comment]: <> (replace-data:ocspresp/basic-ocspresp/ocspresp.txt)
~~~~~
C509BasicOCSPResponse
  TBSBasicOCSPResponse
    Type: C509BasicOCSPResponse (1)
    Signature Algorithm: Ed25519 (12)
    Hash Algorithm: SHA256 (0)
    Nonce
      11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11
    ResponderCertHash
      06:00:86:78:38:e3:31:1a
    ProducedAt: 2025-03-03T00:00:00Z
    Extensions: <empty>
    Responses
      OcspPerIssuerResponse
        IssuerCertHash
          a0:1c:73:a5:f3:b0:63:34
        Extensions: <empty>
        SingleResponses
          SingleCertResponse
            SerialNumberHash:
              10:65:27:87:fa:05:27:bc:24:49:a1:bf:c5:ab:31:aa:
              5a:6f:0d:8d
            Cert Status: good
            This Update: -28800, 2025-03-02T16:00:00Z
            Next Update: 25200, 2025-03-03T07:00:00Z
            Extensions: <empty>
          SingleCertResponse
            SerialNumberHash:
              75:d8:bc:4f:ba:fc:66:94:46:76:41:e7:48:df:d5:3a:
              8b:9d:17:6d
            Cert Status: not-issued
            This Update: -28800, 2025-03-02T16:00:00Z
            Next Update: 25200, 2025-03-03T07:00:00Z
            Extensions: <empty>
          SingleCertResponse
            SerialNumberHash:
              d1:ac:13:5d:7d:a2:9b:dc:f4:dc:a0:d5:28:1a:51:60:
              5b:67:84:00
            Cert Status: revoked (superseded)
              Revoked at 2025-03-01T16:00:00Z
            This Update: -28800, 2025-03-02T16:00:00Z
            Next Update: 25200, 2025-03-03T07:00:00Z
            Extensions: <empty>
      OcspPerIssuerResponse
        IssuerCertHash
          22:22:22:22:22:22:22:22
        Extensions: <empty>
        SingleResponses
          SingleCertResponse
            SerialNumberHash:
              d3:a0:c1:e3:db:92:e8:f6:81:05:37:d4:5c:fa:ec:f6:
              ce:41:7e:3b
            Cert Status: unknown
            This Update: -28800, 2025-03-02T16:00:00Z
            Next Update: 25200, 2025-03-03T07:00:00Z
            Extensions: <empty>
    Responder Certs: null
  Signature Value
    e4:86:9c:57:a6:6b:ab:50:1a:ca:eb:7e:50:24:10:52:
    53:d7:2f:45:d3:49:ae:21:fb:94:1a:be:44:35:f8:a6:
    c9:d1:ca:5d:27:84:ab:30:cf:17:7f:f0:75:b5:50:2a:
    ea:ee:09:c1:14:6c:f4:90:66:3e:ae:d9:24:3a:76:0d
~~~~~

Annotated hex

[comment]: <> (replace-data:ocspresp/basic-ocspresp/ocspresp.diag)
~~~~~
  0: 8A             # C509OCSPResponse=array[10]
  1:   01             # [0]. ocspResponseType=C509BasicOCSPResponse
                      #      (1)
  2:   0C             # [1]. signatureAlgorithm=Ed25519 (12)
  3:   00             # [2]. hashAlgorithm=SHA256 (0)
  4:   50             # [3]. nonce=byte[16]
  5:     11111111111111111111111111111111
 21:   48             # [4]. responderCertHash=byte[8]
 22:     0600867838E3311A
 30:   1A 67C4F100    # [5]. producedAt=1740960000:
                      #      2025-03-03T00:00:00Z
 35:   80             # [6]. extensions=array[0]
 36:   86             # [7]. responses=array[6]
                        #---PerIssuerResponses[0]---
 37:     48             # [0]. issuerCertHash=byte[8]
 38:       A01C73A5F3B06334
 46:     80             # [1]. extensions=array[0]
 47:     8F             # [2]. singleResponses=array[15]
                          #---SingleCertResponses[0]---
 48:       54             # [0]. serialNumberHash=byte[20]
 49:         10652787FA0527BC2449A1BFC5AB31AA5A6F0D8D
 69:       00             # [1]. certStatus=good (0)
 70:       39 707F        # [2]. thisUpdate=-28800:
                          #      2025-03-02T16:00:00Z
 73:       19 6270        # [3]. nextUpdate=25200:
                          #      2025-03-03T07:00:00Z
 76:       80             # [4]. extensions=array[0]
                          #---SingleCertResponses[1]---
 77:       54             # [5]. serialNumberHash=byte[20]
 78:         75D8BC4FBAFC6694467641E748DFD53A8B9D176D
 98:       01             # [6]. certStatus=not-issued (1)
 99:       39 707F        # [7]. thisUpdate=-28800:
                          #      2025-03-02T16:00:00Z
102:       19 6270        # [8]. nextUpdate=25200:
                          #      2025-03-03T07:00:00Z
105:       80             # [9]. extensions=array[0]
                          #---SingleCertResponses[2]---
106:       54             # [10]. serialNumberHash=byte[20]
107:         D1AC135D7DA29BDCF4DCA0D5281A51605B678400
127:       82             # [11]. certStatus=array[2]
128:         1A 67C32F00    # [0]. revocationTime=1740844800:
                            #      2025-03-01T16:00:00Z
133:         04             # [1]. revocationReason=superseded (4)
134:       39 707F        # [12]. thisUpdate=-28800:
                          #       2025-03-02T16:00:00Z
137:       19 6270        # [13]. nextUpdate=25200:
                          #       2025-03-03T07:00:00Z
140:       80             # [14]. extensions=array[0]
                        #---PerIssuerResponses[1]---
141:     48             # [3]. issuerCertHash=byte[8]
142:       2222222222222222
150:     80             # [4]. extensions=array[0]
151:     85             # [5]. singleResponses=array[5]
                          #---SingleCertResponses[0]---
152:       54             # [0]. serialNumberHash=byte[20]
153:         D3A0C1E3DB92E8F6810537D45CFAECF6CE417E3B
173:       02             # [1]. certStatus=unknown (2)
174:       39 707F        # [2]. thisUpdate=-28800:
                          #      2025-03-02T16:00:00Z
177:       19 6270        # [3]. nextUpdate=25200:
                          #      2025-03-03T07:00:00Z
180:       80             # [4]. extensions=array[0]
181:   F6             # [8]. responderCerts=<null>
182:   58 40          # [9]. signature value=byte[64]
184:     E4869C57A66BAB501ACAEB7E5024105253D72F45D349AE21FB941ABE44
213:     35F8A6C9D1CA5D2784AB30CF177FF075B5502AEAEE09C1146CF490663E
242:     AED9243A760D
~~~~~

### Basic OCSP Response Example With Responder's Certificate {#exam-basic-ocsp-resp-withcert}

[comment]: <> (replace-reduction:ocspresp/basic-ocspresp-with-cert/ocspresp.hex % ocspresp/basic-ocspresp-with-cert/x509ocspresp.pem)
- Size reduction: 62%
- Verifiable with certificate in {{ocsp-responder-cert}}
- Basic OCSP Response (`C509BasicOCSPResponse`) with embedded responder's certificate
- Note that the X.509 OCSP response and the C509 OCSP response are not convertible.

#### X.509 OCSP Response

[comment]: <> (replace-size:ocspresp/basic-ocspresp-with-cert/x509ocspresp.pem)
PEM content (1189 bytes):

[comment]: <> (replace-data:ocspresp/basic-ocspresp-with-cert/x509ocspresp.pem)
~~~~~
-----BEGIN OCSP RESPONSE-----
MIIEoQoBAKCCBJowggSWBgkrBgEFBQcwAQEEggSHMIIEgzCCAt2iFgQU6uWaiumq
9BBLFeUOjuAXFRd0GK8YDzIwMjUwMzAzMDAwMDAwWjCCAnwwgZEwaTANBglghkgB
ZQMEAgEFAAQgMlOOdIW9N65FTx8NK5dV11i5H26OOnrzl6D0AGBcb/gEIMwRyHQK
BQnsTaFM5YhucjZMD2O2DtY0fxPBbuclt2aiAhQSNBI0EjQSNBI0EjQSNBI0EjQS
NIAAGA8yMDI1MDMwMjE2MDAwMFqgERgPMjAyNTAzMDMwNzAwMDBaMIGnMGkwDQYJ
YIZIAWUDBAIBBQAEIDJTjnSFvTeuRU8fDSuXVddYuR9ujjp685eg9ABgXG/4BCDM
Ech0CgUJ7E2hTOWIbnI2TA9jtg7WNH8TwW7nJbdmogIUNFY0VjRWNFY0VjRWNFY0
VjRWNFahFhgPMTk3MDAxMDEwMDAwMDBaoAMKAQYYDzIwMjUwMzAyMTYwMDAwWqAR
GA8yMDI1MDMwMzA3MDAwMFowgacwaTANBglghkgBZQMEAgEFAAQgMlOOdIW9N65F
Tx8NK5dV11i5H26OOnrzl6D0AGBcb/gEIMwRyHQKBQnsTaFM5YhucjZMD2O2DtY0
fxPBbuclt2aiAhRWeFZ4VnhWeFZ4VnhWeFZ4VnhWeKEWGA8yMDI1MDMwMTE2MDAw
MFqgAwoBBBgPMjAyNTAzMDIxNjAwMDBaoBEYDzIwMjUwMzAzMDcwMDAwWjCBkTBp
MA0GCWCGSAFlAwQCAQUABCAzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMz
MwQgREREREREREREREREREREREREREREREREREREREREREQCFCIzIjMiMyIzIjMi
MyIzIjMiMyIzggAYDzIwMjUwMzAyMTYwMDAwWqARGA8yMDI1MDMwMzA3MDAwMFqh
MjAwMB0GCSsGAQUFBzABAgQQERERERERERERERERERERETAPBgkrBgEFBQcwAQkE
AgUAMAUGAytlcANBAHrbfHeKVrcvjeFMQT9cTvhYU81DmwQpZiyRtH+MhBfSjqsl
riv95/TO4bhcpRnJl5T3D8ojWrMGiFJo1IB8gwegggFUMIIBUDCCAUwwgf+gAwIB
AgICEjUwBQYDK2VwMBoxGDAWBgNVBAMMD3Rlc3QgY3Jsb2NzcC1jYTAeFw0yNTAx
MDIwMDAwMDBaFw0yNjAxMDIwMDAwMDBaMBkxFzAVBgNVBAMMDm9jc3AtcmVzcG9u
ZGVyMCowBQYDK2VwAyEAgZR7vCSKrHlzghGo11v5LLd32ZQHPfI64GOA7yxXOXaj
ajBoMB0GA1UdDgQWBBTq5ZqK6ar0EEsV5Q6O4BcVF3QYrzAOBgNVHQ8BAf8EBAMC
B4AwHwYDVR0jBBgwFoAU2X135jTC9wAwDKWPyHc2WxVQB6IwFgYDVR0lAQH/BAww
CgYIKwYBBQUHAwkwBQYDK2VwA0EAE6Mo4UW6t2eMBWxsYX3UvhUJnaoXUOH7fAsp
qSPXK/f3h5+FSrkt0RCxXzct4Flmgi+HToCGEf1F3T0sXCiHCA==
-----END OCSP RESPONSE-----
~~~~~

#### C509 OCSP Response

[comment]: <> (replace-size:ocspresp/basic-ocspresp-with-cert/ocspresp.hex)
Plain Hex (446 bytes):

[comment]: <> (replace-data:ocspresp/basic-ocspresp-with-cert/ocspresp.hex)
~~~~~
8A010C005011111111111111111111111111111111480600867838E3311A1A67C4F1
00808648A01C73A5F3B06334808F5410652787FA0527BC2449A1BFC5AB31AA5A6F0D
8D0039707F196270805475D8BC4FBAFC6694467641E748DFD53A8B9D176D0139707F
1962708054D1AC135D7DA29BDCF4DCA0D5281A51605B678400821A67C32F00043970
7F19627080482222222222222222808554D3A0C1E3DB92E8F6810537D45CFAECF6CE
417E3B0239707F1962708058C58B024212350C6F746573742063726C6F6373702D63
611A6775D7001A69570A806E6F6373702D726573706F6E6465720C582081947BBC24
8AAC79738211A8D75BF92CB777D994073DF23AE06380EF2C573976880154B5B4CAF3
5401D06151DF9629DB579DC8CCA453A8210107542F45E78D2CAEDF368CDF53C39005
D492450E105627095840A01B0CBF3E34A4762D05404FD08A7AEC103035358314686D
72B6159078C76E1D88597F37531886A3F52F256FD722192B289D6844014467F1F17F
05ACBB7B660A58400085EA27969E5A162EA31D371522F62F0DF278272225DEAD6F17
3C42D5482142A3F032872850A4E2C2D9A759A0F460E1250B6FDEBB6636B3672CA02E
FB880A04
~~~~~

Textual Representation

[comment]: <> (replace-data:ocspresp/basic-ocspresp-with-cert/ocspresp.txt)
~~~~~
C509BasicOCSPResponse
  TBSBasicOCSPResponse
    Type: C509BasicOCSPResponse (1)
    Signature Algorithm: Ed25519 (12)
    Hash Algorithm: SHA256 (0)
    Nonce
      11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11
    ResponderCertHash
      06:00:86:78:38:e3:31:1a
    ProducedAt: 2025-03-03T00:00:00Z
    Extensions: <empty>
    Responses
      OcspPerIssuerResponse
        IssuerCertHash
          a0:1c:73:a5:f3:b0:63:34
        Extensions: <empty>
        SingleResponses
          SingleCertResponse
            SerialNumberHash:
              10:65:27:87:fa:05:27:bc:24:49:a1:bf:c5:ab:31:aa:
              5a:6f:0d:8d
            Cert Status: good
            This Update: -28800, 2025-03-02T16:00:00Z
            Next Update: 25200, 2025-03-03T07:00:00Z
            Extensions: <empty>
          SingleCertResponse
            SerialNumberHash:
              75:d8:bc:4f:ba:fc:66:94:46:76:41:e7:48:df:d5:3a:
              8b:9d:17:6d
            Cert Status: not-issued
            This Update: -28800, 2025-03-02T16:00:00Z
            Next Update: 25200, 2025-03-03T07:00:00Z
            Extensions: <empty>
          SingleCertResponse
            SerialNumberHash:
              d1:ac:13:5d:7d:a2:9b:dc:f4:dc:a0:d5:28:1a:51:60:
              5b:67:84:00
            Cert Status: revoked (superseded)
              Revoked at 2025-03-01T16:00:00Z
            This Update: -28800, 2025-03-02T16:00:00Z
            Next Update: 25200, 2025-03-03T07:00:00Z
            Extensions: <empty>
      OcspPerIssuerResponse
        IssuerCertHash
          22:22:22:22:22:22:22:22
        Extensions: <empty>
        SingleResponses
          SingleCertResponse
            SerialNumberHash:
              d3:a0:c1:e3:db:92:e8:f6:81:05:37:d4:5c:fa:ec:f6:
              ce:41:7e:3b
            Cert Status: unknown
            This Update: -28800, 2025-03-02T16:00:00Z
            Next Update: 25200, 2025-03-03T07:00:00Z
            Extensions: <empty>
    Responder Certs
      C509Certificate
        8b:02:42:12:35:0c:6f:74:65:73:74:20:63:72:6c:6f:
        63:73:70:2d:63:61:1a:67:75:d7:00:1a:69:57:0a:80:
        6e:6f:63:73:70:2d:72:65:73:70:6f:6e:64:65:72:0c:
        58:20:81:94:7b:bc:24:8a:ac:79:73:82:11:a8:d7:5b:
        f9:2c:b7:77:d9:94:07:3d:f2:3a:e0:63:80:ef:2c:57:
        39:76:88:01:54:b5:b4:ca:f3:54:01:d0:61:51:df:96:
        29:db:57:9d:c8:cc:a4:53:a8:21:01:07:54:2f:45:e7:
        8d:2c:ae:df:36:8c:df:53:c3:90:05:d4:92:45:0e:10:
        56:27:09:58:40:a0:1b:0c:bf:3e:34:a4:76:2d:05:40:
        4f:d0:8a:7a:ec:10:30:35:35:83:14:68:6d:72:b6:15:
        90:78:c7:6e:1d:88:59:7f:37:53:18:86:a3:f5:2f:25:
        6f:d7:22:19:2b:28:9d:68:44:01:44:67:f1:f1:7f:05:
        ac:bb:7b:66:0a
  Signature Value
    00:85:ea:27:96:9e:5a:16:2e:a3:1d:37:15:22:f6:2f:
    0d:f2:78:27:22:25:de:ad:6f:17:3c:42:d5:48:21:42:
    a3:f0:32:87:28:50:a4:e2:c2:d9:a7:59:a0:f4:60:e1:
    25:0b:6f:de:bb:66:36:b3:67:2c:a0:2e:fb:88:0a:04
~~~~~

Annotated hex

[comment]: <> (replace-data:ocspresp/basic-ocspresp-with-cert/ocspresp.diag)
~~~~~
  0: 8A             # C509OCSPResponse=array[10]
  1:   01             # [0]. ocspResponseType=C509BasicOCSPResponse
                      #      (1)
  2:   0C             # [1]. signatureAlgorithm=Ed25519 (12)
  3:   00             # [2]. hashAlgorithm=SHA256 (0)
  4:   50             # [3]. nonce=byte[16]
  5:     11111111111111111111111111111111
 21:   48             # [4]. responderCertHash=byte[8]
 22:     0600867838E3311A
 30:   1A 67C4F100    # [5]. producedAt=1740960000:
                      #      2025-03-03T00:00:00Z
 35:   80             # [6]. extensions=array[0]
 36:   86             # [7]. responses=array[6]
                        #---PerIssuerResponses[0]---
 37:     48             # [0]. issuerCertHash=byte[8]
 38:       A01C73A5F3B06334
 46:     80             # [1]. extensions=array[0]
 47:     8F             # [2]. singleResponses=array[15]
                          #---SingleCertResponses[0]---
 48:       54             # [0]. serialNumberHash=byte[20]
 49:         10652787FA0527BC2449A1BFC5AB31AA5A6F0D8D
 69:       00             # [1]. certStatus=good (0)
 70:       39 707F        # [2]. thisUpdate=-28800:
                          #      2025-03-02T16:00:00Z
 73:       19 6270        # [3]. nextUpdate=25200:
                          #      2025-03-03T07:00:00Z
 76:       80             # [4]. extensions=array[0]
                          #---SingleCertResponses[1]---
 77:       54             # [5]. serialNumberHash=byte[20]
 78:         75D8BC4FBAFC6694467641E748DFD53A8B9D176D
 98:       01             # [6]. certStatus=not-issued (1)
 99:       39 707F        # [7]. thisUpdate=-28800:
                          #      2025-03-02T16:00:00Z
102:       19 6270        # [8]. nextUpdate=25200:
                          #      2025-03-03T07:00:00Z
105:       80             # [9]. extensions=array[0]
                          #---SingleCertResponses[2]---
106:       54             # [10]. serialNumberHash=byte[20]
107:         D1AC135D7DA29BDCF4DCA0D5281A51605B678400
127:       82             # [11]. certStatus=array[2]
128:         1A 67C32F00    # [0]. revocationTime=1740844800:
                            #      2025-03-01T16:00:00Z
133:         04             # [1]. revocationReason=superseded (4)
134:       39 707F        # [12]. thisUpdate=-28800:
                          #       2025-03-02T16:00:00Z
137:       19 6270        # [13]. nextUpdate=25200:
                          #       2025-03-03T07:00:00Z
140:       80             # [14]. extensions=array[0]
                        #---PerIssuerResponses[1]---
141:     48             # [3]. issuerCertHash=byte[8]
142:       2222222222222222
150:     80             # [4]. extensions=array[0]
151:     85             # [5]. singleResponses=array[5]
                          #---SingleCertResponses[0]---
152:       54             # [0]. serialNumberHash=byte[20]
153:         D3A0C1E3DB92E8F6810537D45CFAECF6CE417E3B
173:       02             # [1]. certStatus=unknown (2)
174:       39 707F        # [2]. thisUpdate=-28800:
                          #      2025-03-02T16:00:00Z
177:       19 6270        # [3]. nextUpdate=25200:
                          #      2025-03-03T07:00:00Z
180:       80             # [4]. extensions=array[0]
181:   58 C5          # [8]. responderCerts(COSE_C509)=byte[197]
183:     8B024212350C6F746573742063726C6F6373702D63611A6775D7001A69
212:     570A806E6F6373702D726573706F6E6465720C582081947BBC248AAC79
241:     738211A8D75BF92CB777D994073DF23AE06380EF2C573976880154B5B4
270:     CAF35401D06151DF9629DB579DC8CCA453A8210107542F45E78D2CAEDF
299:     368CDF53C39005D492450E105627095840A01B0CBF3E34A4762D05404F
328:     D08A7AEC103035358314686D72B6159078C76E1D88597F37531886A3F5
357:     2F256FD722192B289D6844014467F1F17F05ACBB7B660A
380:   58 40          # [9]. signature value=byte[64]
382:     0085EA27969E5A162EA31D371522F62F0DF278272225DEAD6F173C42D5
411:     482142A3F032872850A4E2C2D9A759A0F460E1250B6FDEBB6636B3672C
440:     A02EFB880A04
~~~~~

### Basic OCSP Response Example With Responder's Certificate Chain {#exam-basic-ocsp-resp-withcertchain}

[comment]: <> (replace-reduction:ocspresp/basic-ocspresp-with-certchain/ocspresp.hex % ocspresp/basic-ocspresp-with-certchain/x509ocspresp.pem)
- Size reduction: 57%
- Verifiable with certificate in {{ocsp-responder-cert}}
- Basic OCSP Response (`C509BasicOCSPResponse`) with embedded responder's certificate chain (2 certificates)
- Note that the X.509 OCSP response and the C509 OCSP response are not convertible.

#### X.509 OCSP Response

[comment]: <> (replace-size:ocspresp/basic-ocspresp-with-certchain/x509ocspresp.pem)
PEM content (1525 bytes):

[comment]: <> (replace-data:ocspresp/basic-ocspresp-with-certchain/x509ocspresp.pem)
~~~~~
-----BEGIN OCSP RESPONSE-----
MIIF8QoBAKCCBeowggXmBgkrBgEFBQcwAQEEggXXMIIF0zCCAt2iFgQU6uWaiumq
9BBLFeUOjuAXFRd0GK8YDzIwMjUwMzAzMDAwMDAwWjCCAnwwgZEwaTANBglghkgB
ZQMEAgEFAAQgMlOOdIW9N65FTx8NK5dV11i5H26OOnrzl6D0AGBcb/gEIMwRyHQK
BQnsTaFM5YhucjZMD2O2DtY0fxPBbuclt2aiAhQSNBI0EjQSNBI0EjQSNBI0EjQS
NIAAGA8yMDI1MDMwMjE2MDAwMFqgERgPMjAyNTAzMDMwNzAwMDBaMIGnMGkwDQYJ
YIZIAWUDBAIBBQAEIDJTjnSFvTeuRU8fDSuXVddYuR9ujjp685eg9ABgXG/4BCDM
Ech0CgUJ7E2hTOWIbnI2TA9jtg7WNH8TwW7nJbdmogIUNFY0VjRWNFY0VjRWNFY0
VjRWNFahFhgPMTk3MDAxMDEwMDAwMDBaoAMKAQYYDzIwMjUwMzAyMTYwMDAwWqAR
GA8yMDI1MDMwMzA3MDAwMFowgacwaTANBglghkgBZQMEAgEFAAQgMlOOdIW9N65F
Tx8NK5dV11i5H26OOnrzl6D0AGBcb/gEIMwRyHQKBQnsTaFM5YhucjZMD2O2DtY0
fxPBbuclt2aiAhRWeFZ4VnhWeFZ4VnhWeFZ4VnhWeKEWGA8yMDI1MDMwMTE2MDAw
MFqgAwoBBBgPMjAyNTAzMDIxNjAwMDBaoBEYDzIwMjUwMzAzMDcwMDAwWjCBkTBp
MA0GCWCGSAFlAwQCAQUABCAzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMz
MwQgREREREREREREREREREREREREREREREREREREREREREQCFCIzIjMiMyIzIjMi
MyIzIjMiMyIzggAYDzIwMjUwMzAyMTYwMDAwWqARGA8yMDI1MDMwMzA3MDAwMFqh
MjAwMB0GCSsGAQUFBzABAgQQERERERERERERERERERERETAPBgkrBgEFBQcwAQkE
AgUAMAUGAytlcANBAHrbfHeKVrcvjeFMQT9cTvhYU81DmwQpZiyRtH+MhBfSjqsl
riv95/TO4bhcpRnJl5T3D8ojWrMGiFJo1IB8gwegggKkMIICoDCCAUwwgf+gAwIB
AgICEjUwBQYDK2VwMBoxGDAWBgNVBAMMD3Rlc3QgY3Jsb2NzcC1jYTAeFw0yNTAx
MDIwMDAwMDBaFw0yNjAxMDIwMDAwMDBaMBkxFzAVBgNVBAMMDm9jc3AtcmVzcG9u
ZGVyMCowBQYDK2VwAyEAgZR7vCSKrHlzghGo11v5LLd32ZQHPfI64GOA7yxXOXaj
ajBoMB0GA1UdDgQWBBTq5ZqK6ar0EEsV5Q6O4BcVF3QYrzAOBgNVHQ8BAf8EBAMC
B4AwHwYDVR0jBBgwFoAU2X135jTC9wAwDKWPyHc2WxVQB6IwFgYDVR0lAQH/BAww
CgYIKwYBBQUHAwkwBQYDK2VwA0EAE6Mo4UW6t2eMBWxsYX3UvhUJnaoXUOH7fAsp
qSPXK/f3h5+FSrkt0RCxXzct4Flmgi+HToCGEf1F3T0sXCiHCDCCAUwwgf+gAwIB
AgIBATAFBgMrZXAwHjEcMBoGA1UEAwwTdGVzdCBjcmxvY3NwLXJvb3RjYTAeFw0y
NTAxMDEwMDAwMDBaFw0yNjEyMzEyMzU5NTlaMBoxGDAWBgNVBAMMD3Rlc3QgY3Js
b2NzcC1jYTAqMAUGAytlcAMhAF74o1WgAafFDSNJRwEggTGkuyq5INQL+w7h9qso
/3QAo2YwZDAdBgNVHQ4EFgQU2X135jTC9wAwDKWPyHc2WxVQB6IwDgYDVR0PAQH/
BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwHwYDVR0jBBgwFoAUkSOc+vnng2yy
n1HhMZHbENOuFpMwBQYDK2VwA0EA1l4B18v6QX+xe5n3l+1pJ69WL/Y+jTWz46fT
gWDMZGdAEE2PORiX3asRmPPQWiYZIENipvg8M4ghGza8Vj1BAg==
-----END OCSP RESPONSE-----
~~~~~

#### C509 OCSP Response

[comment]: <> (replace-size:ocspresp/basic-ocspresp-with-certchain/ocspresp.hex)
Plain Hex (651 bytes):

[comment]: <> (replace-data:ocspresp/basic-ocspresp-with-certchain/ocspresp.hex)
~~~~~
8A010C005011111111111111111111111111111111480600867838E3311A1A67C4F1
00808648A01C73A5F3B06334808F5410652787FA0527BC2449A1BFC5AB31AA5A6F0D
8D0039707F196270805475D8BC4FBAFC6694467641E748DFD53A8B9D176D0139707F
1962708054D1AC135D7DA29BDCF4DCA0D5281A51605B678400821A67C32F00043970
7F19627080482222222222222222808554D3A0C1E3DB92E8F6810537D45CFAECF6CE
417E3B0239707F196270808258C58B024212350C6F746573742063726C6F6373702D
63611A6775D7001A69570A806E6F6373702D726573706F6E6465720C582081947BBC
248AAC79738211A8D75BF92CB777D994073DF23AE06380EF2C573976880154B5B4CA
F35401D06151DF9629DB579DC8CCA453A8210107542F45E78D2CAEDF368CDF53C390
05D492450E105627095840A01B0CBF3E34A4762D05404FD08A7AEC10303535831468
6D72B6159078C76E1D88597F37531886A3F52F256FD722192B289D6844014467F1F1
7F05ACBB7B660A58CA8B0241010C73746573742063726C6F6373702D726F6F746361
1A677485801A6B36EC7F6F746573742063726C6F6373702D63610C58205EF8A355A0
01A7C50D23494701208131A4BB2AB920D40BFB0EE1F6AB28FF74008801542F45E78D
2CAEDF368CDF53C39005D492450E1056211860230107542DA3A403F7D2F4E0B3D803
1A73BA8A839F557F0F5840E50465D60C02A2111EF3FC6E44F2A36008765B552351F9
A3F5B2AA7C76F1F05D259847A4F4250B2E4B0AE2099762A2596D3CC1DB2CCD180AA0
A2D0E191310B0F5840B633C9598073E3920876FE12B86AD32422E7F2C2361177A6D5
90F20BEBBAA1EFDF94A0A944AC8CA67679CA04CEAF327C12CB9F1C2DCACA9D2E949B
FEA755C405
~~~~~

Textual Representation

[comment]: <> (replace-data:ocspresp/basic-ocspresp-with-certchain/ocspresp.txt)
~~~~~
C509BasicOCSPResponse
  TBSBasicOCSPResponse
    Type: C509BasicOCSPResponse (1)
    Signature Algorithm: Ed25519 (12)
    Hash Algorithm: SHA256 (0)
    Nonce
      11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11
    ResponderCertHash
      06:00:86:78:38:e3:31:1a
    ProducedAt: 2025-03-03T00:00:00Z
    Extensions: <empty>
    Responses
      OcspPerIssuerResponse
        IssuerCertHash
          a0:1c:73:a5:f3:b0:63:34
        Extensions: <empty>
        SingleResponses
          SingleCertResponse
            SerialNumberHash:
              10:65:27:87:fa:05:27:bc:24:49:a1:bf:c5:ab:31:aa:
              5a:6f:0d:8d
            Cert Status: good
            This Update: -28800, 2025-03-02T16:00:00Z
            Next Update: 25200, 2025-03-03T07:00:00Z
            Extensions: <empty>
          SingleCertResponse
            SerialNumberHash:
              75:d8:bc:4f:ba:fc:66:94:46:76:41:e7:48:df:d5:3a:
              8b:9d:17:6d
            Cert Status: not-issued
            This Update: -28800, 2025-03-02T16:00:00Z
            Next Update: 25200, 2025-03-03T07:00:00Z
            Extensions: <empty>
          SingleCertResponse
            SerialNumberHash:
              d1:ac:13:5d:7d:a2:9b:dc:f4:dc:a0:d5:28:1a:51:60:
              5b:67:84:00
            Cert Status: revoked (superseded)
              Revoked at 2025-03-01T16:00:00Z
            This Update: -28800, 2025-03-02T16:00:00Z
            Next Update: 25200, 2025-03-03T07:00:00Z
            Extensions: <empty>
      OcspPerIssuerResponse
        IssuerCertHash
          22:22:22:22:22:22:22:22
        Extensions: <empty>
        SingleResponses
          SingleCertResponse
            SerialNumberHash:
              d3:a0:c1:e3:db:92:e8:f6:81:05:37:d4:5c:fa:ec:f6:
              ce:41:7e:3b
            Cert Status: unknown
            This Update: -28800, 2025-03-02T16:00:00Z
            Next Update: 25200, 2025-03-03T07:00:00Z
            Extensions: <empty>
    Responder Certs
      C509Certificate
        8b:02:42:12:35:0c:6f:74:65:73:74:20:63:72:6c:6f:
        63:73:70:2d:63:61:1a:67:75:d7:00:1a:69:57:0a:80:
        6e:6f:63:73:70:2d:72:65:73:70:6f:6e:64:65:72:0c:
        58:20:81:94:7b:bc:24:8a:ac:79:73:82:11:a8:d7:5b:
        f9:2c:b7:77:d9:94:07:3d:f2:3a:e0:63:80:ef:2c:57:
        39:76:88:01:54:b5:b4:ca:f3:54:01:d0:61:51:df:96:
        29:db:57:9d:c8:cc:a4:53:a8:21:01:07:54:2f:45:e7:
        8d:2c:ae:df:36:8c:df:53:c3:90:05:d4:92:45:0e:10:
        56:27:09:58:40:a0:1b:0c:bf:3e:34:a4:76:2d:05:40:
        4f:d0:8a:7a:ec:10:30:35:35:83:14:68:6d:72:b6:15:
        90:78:c7:6e:1d:88:59:7f:37:53:18:86:a3:f5:2f:25:
        6f:d7:22:19:2b:28:9d:68:44:01:44:67:f1:f1:7f:05:
        ac:bb:7b:66:0a
      C509Certificate
        8b:02:41:01:0c:73:74:65:73:74:20:63:72:6c:6f:63:
        73:70:2d:72:6f:6f:74:63:61:1a:67:74:85:80:1a:6b:
        36:ec:7f:6f:74:65:73:74:20:63:72:6c:6f:63:73:70:
        2d:63:61:0c:58:20:5e:f8:a3:55:a0:01:a7:c5:0d:23:
        49:47:01:20:81:31:a4:bb:2a:b9:20:d4:0b:fb:0e:e1:
        f6:ab:28:ff:74:00:88:01:54:2f:45:e7:8d:2c:ae:df:
        36:8c:df:53:c3:90:05:d4:92:45:0e:10:56:21:18:60:
        23:01:07:54:2d:a3:a4:03:f7:d2:f4:e0:b3:d8:03:1a:
        73:ba:8a:83:9f:55:7f:0f:58:40:e5:04:65:d6:0c:02:
        a2:11:1e:f3:fc:6e:44:f2:a3:60:08:76:5b:55:23:51:
        f9:a3:f5:b2:aa:7c:76:f1:f0:5d:25:98:47:a4:f4:25:
        0b:2e:4b:0a:e2:09:97:62:a2:59:6d:3c:c1:db:2c:cd:
        18:0a:a0:a2:d0:e1:91:31:0b:0f
  Signature Value
    b6:33:c9:59:80:73:e3:92:08:76:fe:12:b8:6a:d3:24:
    22:e7:f2:c2:36:11:77:a6:d5:90:f2:0b:eb:ba:a1:ef:
    df:94:a0:a9:44:ac:8c:a6:76:79:ca:04:ce:af:32:7c:
    12:cb:9f:1c:2d:ca:ca:9d:2e:94:9b:fe:a7:55:c4:05
~~~~~

Annotated hex

[comment]: <> (replace-data:ocspresp/basic-ocspresp-with-certchain/ocspresp.diag)
~~~~~
  0: 8A             # C509OCSPResponse=array[10]
  1:   01             # [0]. ocspResponseType=C509BasicOCSPResponse
                      #      (1)
  2:   0C             # [1]. signatureAlgorithm=Ed25519 (12)
  3:   00             # [2]. hashAlgorithm=SHA256 (0)
  4:   50             # [3]. nonce=byte[16]
  5:     11111111111111111111111111111111
 21:   48             # [4]. responderCertHash=byte[8]
 22:     0600867838E3311A
 30:   1A 67C4F100    # [5]. producedAt=1740960000:
                      #      2025-03-03T00:00:00Z
 35:   80             # [6]. extensions=array[0]
 36:   86             # [7]. responses=array[6]
                        #---PerIssuerResponses[0]---
 37:     48             # [0]. issuerCertHash=byte[8]
 38:       A01C73A5F3B06334
 46:     80             # [1]. extensions=array[0]
 47:     8F             # [2]. singleResponses=array[15]
                          #---SingleCertResponses[0]---
 48:       54             # [0]. serialNumberHash=byte[20]
 49:         10652787FA0527BC2449A1BFC5AB31AA5A6F0D8D
 69:       00             # [1]. certStatus=good (0)
 70:       39 707F        # [2]. thisUpdate=-28800:
                          #      2025-03-02T16:00:00Z
 73:       19 6270        # [3]. nextUpdate=25200:
                          #      2025-03-03T07:00:00Z
 76:       80             # [4]. extensions=array[0]
                          #---SingleCertResponses[1]---
 77:       54             # [5]. serialNumberHash=byte[20]
 78:         75D8BC4FBAFC6694467641E748DFD53A8B9D176D
 98:       01             # [6]. certStatus=not-issued (1)
 99:       39 707F        # [7]. thisUpdate=-28800:
                          #      2025-03-02T16:00:00Z
102:       19 6270        # [8]. nextUpdate=25200:
                          #      2025-03-03T07:00:00Z
105:       80             # [9]. extensions=array[0]
                          #---SingleCertResponses[2]---
106:       54             # [10]. serialNumberHash=byte[20]
107:         D1AC135D7DA29BDCF4DCA0D5281A51605B678400
127:       82             # [11]. certStatus=array[2]
128:         1A 67C32F00    # [0]. revocationTime=1740844800:
                            #      2025-03-01T16:00:00Z
133:         04             # [1]. revocationReason=superseded (4)
134:       39 707F        # [12]. thisUpdate=-28800:
                          #       2025-03-02T16:00:00Z
137:       19 6270        # [13]. nextUpdate=25200:
                          #       2025-03-03T07:00:00Z
140:       80             # [14]. extensions=array[0]
                        #---PerIssuerResponses[1]---
141:     48             # [3]. issuerCertHash=byte[8]
142:       2222222222222222
150:     80             # [4]. extensions=array[0]
151:     85             # [5]. singleResponses=array[5]
                          #---SingleCertResponses[0]---
152:       54             # [0]. serialNumberHash=byte[20]
153:         D3A0C1E3DB92E8F6810537D45CFAECF6CE417E3B
173:       02             # [1]. certStatus=unknown (2)
174:       39 707F        # [2]. thisUpdate=-28800:
                          #      2025-03-02T16:00:00Z
177:       19 6270        # [3]. nextUpdate=25200:
                          #      2025-03-03T07:00:00Z
180:       80             # [4]. extensions=array[0]
181:   82             # [8]. responderCerts(COSE_C509)=array[2]
182:     58 C5          # [0]. C509CertData=byte[197]
184:       8B024212350C6F746573742063726C6F6373702D63611A6775D7001A
212:       69570A806E6F6373702D726573706F6E6465720C582081947BBC248A
240:       AC79738211A8D75BF92CB777D994073DF23AE06380EF2C5739768801
268:       54B5B4CAF35401D06151DF9629DB579DC8CCA453A8210107542F45E7
296:       8D2CAEDF368CDF53C39005D492450E105627095840A01B0CBF3E34A4
324:       762D05404FD08A7AEC103035358314686D72B6159078C76E1D88597F
352:       37531886A3F52F256FD722192B289D6844014467F1F17F05ACBB7B66
380:       0A
381:     58 CA          # [1]. C509CertData=byte[202]
383:       8B0241010C73746573742063726C6F6373702D726F6F7463611A6774
411:       85801A6B36EC7F6F746573742063726C6F6373702D63610C58205EF8
439:       A355A001A7C50D23494701208131A4BB2AB920D40BFB0EE1F6AB28FF
467:       74008801542F45E78D2CAEDF368CDF53C39005D492450E1056211860
495:       230107542DA3A403F7D2F4E0B3D8031A73BA8A839F557F0F5840E504
523:       65D60C02A2111EF3FC6E44F2A36008765B552351F9A3F5B2AA7C76F1
551:       F05D259847A4F4250B2E4B0AE2099762A2596D3CC1DB2CCD180AA0A2
579:       D0E191310B0F
585:   58 40          # [9]. signature value=byte[64]
587:     B633C9598073E3920876FE12B86AD32422E7F2C2361177A6D590F20BEB
616:     BAA1EFDF94A0A944AC8CA67679CA04CEAF327C12CB9F1C2DCACA9D2E94
645:     9BFEA755C405
~~~~~

# Acknowledgments # {#acknowledgments}
{:numbered="false"}

The authors thank xxx for reviewing and commenting on intermediate versions of the draft.

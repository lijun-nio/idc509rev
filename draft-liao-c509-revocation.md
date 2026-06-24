---
v: 3
title: "C509 Certificate Revocation Management"
docname: draft-liao-c509-revocation-latest
abbrev: C509 Revocation
ipr: trust200902
cat: std
submissiontype: IETF
coding: utf-8
pi:
  toc: yes
  sortrefs: yes
  symrefs: yes
  tocdepth: 4
venue:
  group: "CBOR Object Signing and Encryption"
  type: "Working Group"
  mail: "cose@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/cose/"
  github: "cose-wg/CBOR-certificates"

author:
  - name: Lijun Liao
    org: NIO
    email: lijun.liao@nio.io
  - name: Marco Tiloca
    org: RISE AB
    email: marco.tiloca@ri.se
  - name: Joel Höglund
    org: RISE AB
    email: joel.hoglund@ri.se
  - name: Rikard Höglund
    org: RISE AB
    email: rikard.hoglund@ri.se
  - name: Shahid Raza
    org: University of Glasgow
    email: shahid.raza@glasgow.ac.uk

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

  IANA-CBOR-TAGS:
    target: https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml
    title: Concise Binary Object Representation (CBOR) Tags
    author:
      -
        ins: IANA

--- abstract

This document specifies a set of CBOR-encoded PKI structures for use with C509 certificates {{I-D.ietf-cose-cbor-encoded-cert}}, X.509 certificates {{RFC5280}}, and any future certificate types.  It defines C509 CRL and C509 OCSP, compact CBOR encodings of X.509 Certificate Revocation Lists {{RFC5280}} and OCSP messages {{RFC6960}}, respectively.  The structures defined in this document are certificate-type agnostic: they can be used with C509 certificates, X.509 certificates, or any future certificate type without modification.  C509 OCSP builds upon and improves {{RFC6960}} by (1) signing over a wider set of fields than in {{RFC6960}} to prevent algorithm-substitution and certificate-chain substitution attacks, (2) replacing plaintext serial numbers with hashes to preserve requestor privacy, (3) replacing the two-hash issuer identity with a single certificate hash, and (4) identifying all participants (requestor, responder, issuer) by a uniform certificate hash rather than type-specific fields, enabling support for C509, X.509, and future certificate types without structural changes.  C509 CRL and C509 OCSP are not wire-format-compatible with their DER-encoded X.509 counterparts and cannot be converted to or from them without semantic interpretation.

--- middle

# Introduction {#intro}

Public Key Infrastructure (PKI) for constrained environments {{RFC7228}} requires compact certificate representations as well as compact revocation information.  {{I-D.ietf-cose-cbor-encoded-cert}} defines C509 certificates, a CBOR encoding of X.509 certificates {{RFC5280}} that reduces certificate size by over 50% for typical constrained-device profiles.  However, revocation mechanisms -- Certificate Revocation Lists (CRLs) and Online Certificate Status Protocol (OCSP) messages -- have not yet received the same treatment.

CRLs as defined in {{RFC5280}} can be large, especially when many certificates have been revoked or when CRL extensions add overhead.  OCSP responses as defined in {{RFC6960}} carry per-certificate status information and may be exchanged during TLS {{RFC8446}} and DTLS {{RFC9147}} handshakes via OCSP stapling {{RFC6066}}, directly affecting handshake latency.

This document specifies:

- **C509 CRL** -- a natively signed CBOR {{RFC8949}} encoding of X.509 CRLs ({{RFC5280, Section 5}}).  The signature is computed over the CBOR Sequence {{RFC8742}} `TBSCertList`; no ASN.1 encoding is involved.

- **C509 OCSP** -- a CBOR encoding of OCSP requests and responses ({{RFC6960}}).  The encoding compresses common fields while preserving semantic equivalence.  Four key improvements are made over {{RFC6960}}:

   - The signature in signed requests and responses is computed over a wider set of fields than in {{RFC6960}}, including the signature algorithm and the certificate chain, preventing algorithm-substitution and certificate-chain substitution attacks.
   - Certificate serial numbers in requests and responses are replaced by hashes (`serialNumberHash`), providing privacy against passive observers who do not already know the queried serial numbers.
   - The issuer is identified by a single hash over the issuer certificate (`issuerCertHash`) rather than by the two-hash `CertID`, reducing per-issuer overhead.
   - All participants -- requestor, responder, and issuer -- are identified by a hash over their certificate (`requestorCertHash`, `responderCertHash`, `issuerCertHash`) rather than by a plaintext Subject distinguished name or SubjectKeyIdentifier, avoiding structural `CHOICE` types such as the X.509 `ResponderID` (`byName` or `byKey`), providing a uniform, compact identity representation, and simplifying support for different certificate types (e.g., C509, X.509, or future types) since a hash applies uniformly regardless of the certificate encoding.

   See the field encoding sections of this document for details.

   The request and response structures defined in this document are certificate-type agnostic: they can be used with C509 certificates, X.509 certificates, or any future certificate type without modification; see {{cert-type-interop}}.

C509 CRL and C509 OCSP apply the same compression techniques as C509 certificates: static fields are elided, OIDs are replaced with short integers, time values are compressed to POSIX timestamps, and redundant encoding is removed.  Implementers can use the CBOR playground {{CborMe}} to inspect encoded examples.

C509 CRL and C509 OCSP are not wire-format-compatible with their DER-encoded counterparts defined in {{RFC5280}} and {{RFC6960}}.  Systems that use C509 CRL or C509 OCSP must explicitly support these CBOR-encoded formats; they cannot be transparently substituted for or derived from the corresponding DER-encoded structures.

C509 CRL and C509 OCSP are designed to be compatible with certificate profiles for constrained deployments, such as {{RFC7925}}.

# Notational Conventions {#notation}

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

~~~~~~~~~~~
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

A second design problem in X.509 CRLs is that each revocation entry has variable length: the serial number length differs between certificates, the revocation date uses different encodings depending on whether the date falls before or after 2050, and optional per-entry extensions (e.g., reason code) may or may not be present.  This variable-length layout makes it impossible to determine whether a given serial number is present in the list without scanning every entry sequentially, resulting in O(n) lookup time.  In this document, the `revokedCertsControl` structure introduces fixed parameters (`serialNumberLength`, `dateLength`) that make every entry within `revokedCerts` exactly of the same size.  The `flags` field can additionally indicate that entries are sorted in ascending order by serial number, enabling binary search and reducing lookup time to O(log n).  Using a compact byte-string concatenation rather than a CBOR array of structured items further reduces encoded size and accelerates parsing.  Furthermore, certificates removed from the CRL (delta CRL `removeFromCRL` entries in X.509) are kept in a dedicated `removedFromCRLCerts` field rather than mixed into `revokedCerts`.  This keeps `revokedCerts` free of removal noise, reducing its size and allowing implementations to process currently-revoked and removed entries independently.

#### Fields

The `revokedCertsList` field is either a CBOR array of one or more `PerIssuerRevokedCerts` entries, each describing the revocation state for certificates issued by one issuer, or CBOR `null`.  `revokedCertsList` MUST be encoded as CBOR `null` when all of the following conditions hold: no certificates are currently revoked, no certificates have been removed from the CRL, the only issuer that would appear is the CRL's own `authoritySubject` (i.e., the `issuer` field is `null`), and there are no non-empty per-issuer extensions.

Each `PerIssuerRevokedCerts` entry describes revoked certificates for one issuer using the following fields:

- The `issuer` field identifies the issuer of the certificates covered by this `PerIssuerRevokedCerts` entry.  When the issuer is a C509 CA, it is encoded as a `Name` value identical to the `issuer` field of the covered C509 certificates.  When the issuer is an X.509 CA, it is encoded as `#6.121(bytes)`, where the byte string contains the DER-encoded `Name` from the `issuer` field of the covered X.509 certificates ({{X.690}}).  If the issuer is identical to the CRL's `authoritySubject` field, it MUST be encoded as CBOR `null`.

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

~~~~~~~~~~~
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
  requestorCertHash  : bytes,
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
  issuerCertHash     : bytes,
  serialNumberHash   : bytes,
  extensions         : Extensions
]

PerIssuerOCSPRequests = [ + PerIssuerOCSPRequest ]

PerIssuerOCSPRequest = (
  issuerCertHash   : bytes,
  extensions       : Extensions,
  singleRequests   : SingleCertRequests,
)

SingleCertRequests  = [ + SingleCertRequest ]

SingleCertRequest = (
  serialNumberHash : bytes,
  extensions       : Extensions,
)
~~~~~~~~~~~
{: sourcecode-name="c509ocsp.cddl"}
{: #fig-OCSPReqCDDL title="CDDL for C509OCSPRequest"}

### Field Encodings

#### ocspRequestType

The `ocspRequestType` field serves as the discriminator for `C509OCSPRequest`:

| Value | Type |
|:---:|:---|
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

- The `serialNumberHash` field is the hash of the certificate serial number of the target certificate, computed using the `hashAlgorithm` of the enclosing request structure.  The serial number is encoded in big-endian byte order without a leading zero byte (as in C509 certificates) before hashing.  Using a hash rather than the plain serial number preserves the privacy of the requestor: an observer cannot determine which certificate is being queried without already knowing the serial number.
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
  responderCertHash  : bytes,
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
  responderCertHash  : bytes,
  issuerCertHash     : bytes,
  serialNumberHash   : bytes,
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
  issuerCertHash   : bytes,
  extensions       : Extensions,
  singleResponses  : SingleCertResponses,
)

SingleCertResponses = [ + SingleCertResponse ]

SingleCertResponse = (
  serialNumberHash : bytes,
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

`TBSBasicOCSPResponse` is the group of fields to be signed. The `signatureValue` field is the only field outside the signed group.  Covering `signatureAlgorithm` and `certs` within the signed content prevents algorithm-substitution and certificate-chain substitution attacks; this design goes beyond the protections offered by the DER-encoded `BasicOCSPResponse` defined in {{RFC6960}}.

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

`responderCertHash` is a hash over the responder's certificate, computed using the same `hashAlgorithm` as `issuerCertHash`.  In X.509 OCSP ({{RFC6960}}), the responder is identified by a `ResponderID` CHOICE that carries either a distinguished name or a public-key hash.  C509 OCSP replaces this with a single hash over the entire responder certificate, which is consistent with the `issuerCertHash` design for issuer identification.

#### responderCerts {#responderCerts}

When present, the `responderCerts` field carries the certificate chain starting with the responder certificate identified by `responderCertHash`.  When the responder holds a C509 certificate chain, the value is `COSE_C509`.  When the responder holds an X.509 certificate chain, the value is `#6.121(COSE_X509)`, wrapping a `COSE_X509` chain with CBOR tag 121 (alternative 0).  The field is part of `TBSBasicOCSPResponse` and is therefore covered by the signature, which prevents certificate-chain substitution attacks.

#### signatureAlgorithm and signatureValue

- `signatureAlgorithm`: the signature algorithm used to compute `signatureValue`, as defined in {{I-D.ietf-cose-cbor-encoded-cert, Section 3.1.11}}.  It is part of the `TBSBasicOCSPResponse` group and is therefore covered by the signature.
- `signatureValue`: the signature computed over the CBOR Sequence of the `TBSBasicOCSPResponse` group.

#### producedAt, thisUpdate, nextUpdate

The `producedAt` field is encoded as described in {{time-encoding}}.  The `thisUpdate` field is encoded as a non-positive integer (`nint / 0`) representing the number of seconds from `producedAt` at which the indicated status is known to be correct; it MUST be 0 or negative, since the status cannot be known at a time in the future relative to when the response was produced.  The `nextUpdate` field is encoded as a `uint` representing the number of seconds from `producedAt` until the next update is expected to be available.  `nextUpdate` may be `null`, which indicates an unknown update time.

#### responseExtensions

See {{ocsp-extensions}}.

#### PerIssuerOCSPResponses and PerIssuerOCSPResponse

`PerIssuerOCSPResponses` is a list of `PerIssuerOCSPResponse` entries.  For the same reason as on the request side (see {{per-issuer-requests}}), the `issuerCertHash` field is encoded once per issuer and shared across all `SingleCertResponse` entries in the `singleResponses` list, avoiding the per-entry repetition that would occur if the issuer identity were embedded in every individual response entry.  `PerIssuerOCSPResponse` groups single responses for certificates issued by the same issuer; the issuer is identified by `issuerCertHash` (see {{issuer-hash-id}}).

- The `extensions` field contains per-issuer extensions that apply to all single-certificate responses in this `PerIssuerOCSPResponse` entry; see {{ocsp-per-issuer-extensions}}.  If no per-issuer extensions are present, this field MUST be encoded as an empty CBOR array.
- The `singleResponses` field contains one `SingleCertResponse` for each queried certificate issued by that issuer.

#### SingleCertResponse {#SingleCertResponse}

##### serialNumberHash {#serialNumberHash-section}

This field contains the hash of the serial number of the certificate being queried.  It is computed using the `hashAlgorithm` from the enclosing `TBSBasicOCSPResponse`.  The serial number is encoded in big-endian byte order without a leading zero byte before hashing.  In X.509, a `CertificateSerialNumber` INTEGER is DER-encoded with a leading zero byte when the most-significant bit is set; that leading zero MUST be stripped before computing the hash.  In X.509 OCSP ({{RFC6960, Section 4.1.1}}), the `CertID` structure carries the plain `serialNumber` directly.  C509 OCSP replaces this with a hash to preserve privacy: an observer cannot determine which certificate was queried without already knowing the serial number.

##### singleExtensions

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

~~~~~~~~~~~
AcceptableResponseTypes = [ + int]
~~~~~~~~~~~
{: sourcecode-name="c509ocsp.cddl"}

The integers in `AcceptableResponseTypes` form a sorted list of preferred `C509OCSPResponse` types, in descending order of preference, that the requestor is willing to accept.  This document defines types 0 (`C509ErrorOCSPResponse`), 1 (`C509BasicOCSPResponse`), and 2 (`C509SimpleOCSPResponse`).  Type 0 (`C509ErrorOCSPResponse`) is always implicitly supported and does not need to be listed.  When this extension is absent, an OCSP server responding to a `C509UnsignedOCSPRequest` or `C509SignedOCSPRequest` MUST reply with a `C509BasicOCSPResponse` (type 1); an OCSP server responding to a `C509SimpleOCSPRequest` MUST reply with a `C509SimpleOCSPResponse` (type 2).  If `AcceptableResponseTypes` contains type 2 but not type 1, and the corresponding request contains entries for two or more certificates, the server SHALL return a `C509ErrorOCSPResponse` with `responseStatus` set to `malformedRequest` (1), since `C509SimpleOCSPResponse` can only carry status for a single certificate.

* Preferred Signature Algorithms: The extension value MUST be encoded as follows.

~~~~~~~~~~~
PreferredSignatureAlgorithm = (
  sigIdentifier        : IntAlgorithmIdentifier,
  pubKeyAlgIdentifiers : [ 2* IntAlgorithmIdentifier ]
                         / IntAlgorithmIdentifier
                         / null,
)

PreferredSignatureAlgorithms = [ + PreferredSignatureAlgorithm ]
~~~~~~~~~~~
{: sourcecode-name="c509ocsp.cddl"}

The `sigIdentifier` field carries the signature algorithm identifier.  The `pubKeyAlgIdentifiers` field carries the public key algorithm identifier and MUST be one of:

- a CBOR array of two or more `IntAlgorithmIdentifier` values, sorted in descending order of preference, when the responder is willing to accept any of the listed public key algorithms as a match for this signature algorithm preference (e.g., to express hybrid or multi-algorithm key policies); the first entry in the array represents the most preferred public key algorithm,
- a single `IntAlgorithmIdentifier` value, when exactly one public key algorithm is acceptable, or
- `null`, when the public key algorithm is unconstrained or implied by `sigIdentifier`.

`PreferredSignatureAlgorithms` MUST be sorted in descending order of preference; the first entry represents the most preferred algorithm combination.

* TN Query: The extension value MUST be encoded as follows.

~~~~~~~~~~~
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
| `issuerCertHash` | Hash of CBOR-encoded `C509Certificate` | Hash of DER-encoded X.509 certificate |
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

This document defines the followng hash algorithms.

~~~~~~~~~~~
+-------+----------------------------------------------------------+
| Value | Hash Algorithm                                           |
+=======+==========================================================+
|   0   | Name:        SHA-1                                       |
|       | Identifiers: id-sha1                                     |
|       | OID:         1.3.14.3.2.26                               |
|       | Parameters:  NULL                                        |
|       | DER:         2B 0E 03 02 1A                              |
|       | Comments:                                                |
+-------+----------------------------------------------------------+
|   1   | Name:        SHA-256                                     |
|       | Identifiers: id-sha256                                   |
|       | OID:         2.16.840.1.101.3.4.2.1                      |
|       | Parameters:  absent                                      |
|       | DER:         60 86 48 01 65 03 04 02 01                  |
|       | Comments:                                                |
+-------+----------------------------------------------------------+
|   2   | Name:        SHA-384                                     |
|       | Identifiers: id-sha384                                   |
|       | OID:         2.16.840.1.101.3.4.2.2                      |
|       | Parameters:  absent                                      |
|       | DER:         60 86 48 01 65 03 04 02 02                  |
|       | Comments:                                                |
+-------+----------------------------------------------------------+
|   3   | Name:        SHA-512                                     |
|       | Identifiers: id-sha512                                   |
|       | OID:         2.16.840.1.101.3.4.2.3                      |
|       | Parameters:  absent                                      |
|       | DER:         60 86 48 01 65 03 04 02 03                  |
|       | Comments:                                                |
+-------+----------------------------------------------------------+
|   4   | Name:        SHA-224                                     |
|       | Identifiers: id-sha224                                   |
|       | OID:         2.16.840.1.101.3.4.2.4                      |
|       | Parameters:  absent                                      |
|       | DER:         60 86 48 01 65 03 04 02 04                  |
|       | Comments:                                                |
+-------+----------------------------------------------------------+
|   5   | Name:        SHA-512/256                                 |
|       | Identifiers: id-sha512-256                               |
|       | OID:         2.16.840.1.101.3.4.2.6                      |
|       | Parameters:  absent                                      |
|       | DER:         60 86 48 01 65 03 04 02 06                  |
|       | Comments:                                                |
+-------+----------------------------------------------------------+
|   6   | Name:        SM3                                         |
|       | Identifiers: id-sm3                                      |
|       | OID:         1.2.156.10197.1.401                         |
|       | Parameters:  absent                                      |
|       | DER:         06 08 2A 81 1C 84 8E 35 01 04 01            |
|       | Comments:                                                |
+-------+----------------------------------------------------------+
|   7   | Name:        SHA3-224                                    |
|       | Identifiers: id-sha3-224                                 |
|       | OID:         2.16.840.1.101.3.4.2.7                      |
|       | Parameters:  absent                                      |
|       | DER:         60 86 48 01 65 03 04 02 07                  |
|       | Comments:                                                |
+-------+----------------------------------------------------------+
|   8   | Name:        SHA3-256                                    |
|       | Identifiers: id-sha3-256                                 |
|       | OID:         2.16.840.1.101.3.4.2.8                      |
|       | Parameters:  absent                                      |
|       | DER:         60 86 48 01 65 03 04 02 08                  |
|       | Comments:                                                |
+-------+----------------------------------------------------------+
|   9   | Name:        SHA3-384                                    |
|       | Identifiers: id-sha3-384                                 |
|       | OID:         2.16.840.1.101.3.4.2.9                      |
|       | Parameters:  absent                                      |
|       | DER:         60 86 48 01 65 03 04 02 09                  |
|       | Comments:                                                |
+-------+----------------------------------------------------------+
|   10  | Name:        SHA3-512                                    |
|       | Identifiers: id-sha3-512                                 |
|       | OID:         2.16.840.1.101.3.4.2.10                     |
|       | Parameters:  absent                                      |
|       | DER:         60 86 48 01 65 03 04 02 0A                  |
|       | Comments:                                                |
+-------+----------------------------------------------------------+
|   11  | Name:        SHAKE128                                    |
|       | Identifiers: id-shake128                                 |
|       | OID:         2.16.840.1.101.3.4.2.11                     |
|       | Parameters:  absent                                      |
|       | DER:         60 86 48 01 65 03 04 02 0B                  |
|       | Comments:                                                |
+-------+----------------------------------------------------------+
|   12  | Name:        SHAKE256                                    |
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

All assignments according to "IETF Review with Expert Review" are made on an "IETF Review" basis per {{RFC8126, Section 4.8}}, with Expert Review additionally required per {{RFC8126, Section 4.5}}. The procedure for early IANA allocation of Standards Track code points defined in {{RFC7120}} also applies. When such a procedure is used, IANA will ask the designated expert(s) to approve the early allocation before registration. In addition, WG chairs are encouraged to consult the expert(s) early during the process outlined in {{RFC7120, Section 3.1}.

The columns of this registry are:

* Value: This field contains the value used to identify the C509 hash algorithm. These values MUST be unique. The value can be a positive integer or a negative integer. Different ranges of values use different registration policies {{RFC8126}}. Integer values from -24 to 23 are designated as "IETF Review with Expert Review". Integer values greater than 32767 are marked as "Private Use", All other integer values are designated as "Expert Review". This field MUST NOT be empty.

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

### Media Type application/cose-c509-crl

When the application/cose-c509-crl media type is used, the data is a C509CRL structure.

Subtype name: cose-c509-crl

Required parameters: N/A

Encoding considerations: binary

Security considerations: See the Security Considerations section of [[this document]].

Interoperability considerations: N/A

Published specification: [[this document]]

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

### Media Type application/cose-c509-crlinfo

When the application/cose-c509-crlinfo media type is used, the data is a C509CRLInfo structure.

Subtype name: cose-c509-crlinfo

Required parameters: N/A

Encoding considerations: binary

Security considerations: See the Security Considerations section of [[this document]].

Interoperability considerations: N/A

Published specification: [[this document]]

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

### Media Type application/cose-c509-ocsp-request

When the application/cose-c509-ocsp-request media type is used, the data is a C509OCSPRequest structure.

Subtype name: cose-c509-ocsp-request

Required parameters: N/A

Encoding considerations: binary

Security considerations: See the Security Considerations section of [[this document]].

Interoperability considerations: N/A

Published specification: [[this document]]

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

### Media Type application/cose-c509-ocsp-response

When the application/cose-c509-ocsp-response media type is used, the data is a C509OCSPResponse structure.

Subtype name: cose-c509-ocsp-response

Required parameters: N/A

Encoding considerations: binary

Security considerations: See the Security Considerations section of [[this document]].

Interoperability considerations: N/A

Published specification: [[this document]]

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

IANA is requested to add entries for "application/cose-c509-crl", "application/cose-c509-crlinfo", "application/cose-c509-ocsp-request" and "application/cose-c509-ocsp-response" to the "CoAP Content-Formats" registry in the registry group "Constrained RESTful Environments (CoRE) Parameters".

~~~
+----------------------+---------+-------+------------+
| Content              | Content | ID    | Reference  |
| Type                 | Coding  |       |            |
+======================+=========+=======+============+
| application/         | -       | TBD7  | [[this     |
| cose-c509-crl        |         |       | document]] |
+----------------------+---------+-------+------------+
| application/         |         |       | [[this     |
| cose-c509-crlinfo    | -       | TBD8  | document]] |
+----------------------+---------+-------+------------+
| application/         | -       | TBD9  | [[this     |
| cose-c509-ocsp-      |         |       | document]] |
| request              |         |       |            |
+----------------------+---------+-------+------------+
| application/         | -       | TBD10 | [[this     |
| cose-c509-ocsp-      |         |       | document]] |
| response             |         |       |            |
+----------------------+---------+-------+------------+
~~~

## Expert Review Guidelinee {#expert-review-guidelines}

TODO

--- back


# Examples {#examples}

## Overview

| Section       | Description           | size(C509)/size(X509) |
|:--------------|:----------------------|:----------------------|
| {{exam-crl-no-revoked}} | CRL Example Without Revoked Certificates | 82% |
| {{exam-crl-revoked}} | CRL Example With Revoked Certificates | 53% |
| {{exam-delta-crl-revoked}} | Delta CRL Example With Revoked Certificates | 48% |
| {{exam-indirect-crl-revoked}} | Indirect CRL Example With Revoked Certificates | 49% |
| {{exam-simple-ocsp-req}} | Simple OCSP Request Example | 59% |
| {{exam-unsigned-ocsp-req}} | Unsigned OCSP Request Example | 49% |
| {{exam-signed-ocsp-req}} | Signed OCSP Request Example Without Requestor's Certificate | 58% |
| {{exam-signed-ocsp-req-withcert}} | Signed OCSP Request Example With Requestor's Certificate | 53% |
| {{exam-signed-ocsp-req-withcertchain}} | Signed OCSP Request Example With Requestor's Certificate Chain | 55% |
| {{exam-error-ocsp-resp}} | Error OCSP Response Example | 60% |
| {{exam-simple-ocsp-resp}} | Simple OCSP Response Example | 60% |
| {{exam-basic-ocsp-resp}} | Basic OCSP Response Example Without Responder's Certificate | 45% |
| {{exam-basic-ocsp-resp-withcert}} | Basic OCSP Response Example With Responder's Certificate | 48% |
| {{exam-basic-ocsp-resp-withcertchain}} | Basic OCSP Response Example With Responder's Certificate Chain | 51% |
{: #tab-examples-overview title="Size comparison in examples (TODO: update the percent data)"}

## Helper Certificates

### CA Certificate {#ca-cert}

#### Plain Hex

[comment]: <> (replace-data:cert/crlocsp-ca/c509cert-t2.hex)
~~~~~
0241010C73746573742063726C6F6373702D726F6F7463611A677485801A6B36EC7F
6F746573742063726C6F6373702D63610C58205EF8A355A001A7C50D234947012081
31A4BB2AB920D40BFB0EE1F6AB28FF74008801542F45E78D2CAEDF368CDF53C39005
D492450E1056211860230107542DA3A403F7D2F4E0B3D8031A73BA8A839F557F0F58
40E50465D60C02A2111EF3FC6E44F2A36008765B552351F9A3F5B2AA7C76F1F05D25
9847A4F4250B2E4B0AE2099762A2596D3CC1DB2CCD180AA0A2D0E191310B0F
~~~~~

#### Textual Representation

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

### CRL Signer Certificate {#crl-signer-cert}

#### Plain Hex

[comment]: <> (replace-data:cert/crl-signer/c509cert-t2.hex)
~~~~~
024212340C6F746573742063726C6F6373702D63611A6775D7001A69570A806A6372
6C2D7369676E65720C5820C9BA1EC496DACB97AED087ADE390F398FBD477871EE920
3817EC0E31902789FF86015409E433582556550A27DB4A19BCE2D660884722B62118
4007542F45E78D2CAEDF368CDF53C39005D492450E10565840D46E6A8F9FD53417F3
6DFE56CBB8CACE0FC3E59ACBE72CD9916B3E4C5022D06D16CC9BF9AC54394037C954
33644194FAE18FF783381959584A21BDC0E1C6CB0B
~~~~~

#### Textual Representation

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

### OCSP Requestor Certificate {#ocsp-requestor-cert}

#### Plain Hex

[comment]: <> (replace-data:cert/ocsp-requestor/c509cert-t2.hex)
~~~~~
024212360C6F746573742063726C6F6373702D63611A6775D7001A69570A806E6F63
73702D726571756573746F720C582004530B1764EDD4B4E33AB44AF0F838961C0071
76D74B6A3546ECB7FD57320DD3860154DD51BDB2A2C791C062D4027856DBACF52607
F0BE210107542F45E78D2CAEDF368CDF53C39005D492450E10565840F8C6183ECF8C
3EFD50DD4942D172814C46EC0FC01DD586A597178DF864A0D9DA86B7CA17FC9F772F
F04C80E98B60D5B4B62408A277A5B70D0D2A3F5ED5442D07
~~~~~

#### Textual Representation

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

### OCSP Responder Certificate {#ocsp-responder-cert}

#### Plain Hex

[comment]: <> (replace-data:cert/ocsp-responder/c509cert-t2.hex)
~~~~~
024212350C6F746573742063726C6F6373702D63611A6775D7001A69570A806E6F63
73702D726573706F6E6465720C582081947BBC248AAC79738211A8D75BF92CB777D9
94073DF23AE06380EF2C573976880154B5B4CAF35401D06151DF9629DB579DC8CCA4
53A8210107542F45E78D2CAEDF368CDF53C39005D492450E105627095840A01B0CBF
3E34A4762D05404FD08A7AEC103035358314686D72B6159078C76E1D88597F375318
86A3F52F256FD722192B289D6844014467F1F17F05ACBB7B660A
~~~~~

#### Textual Representation

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

[comment]: <> (replace-percent:crl/full-direct-no-revocation-crl/crl.hex % crl/full-direct-no-revocation-crl/x509crl.pem)
- size(C509) / size(X509): 81%
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
D492450E1056011A6775D7001A677F1180F680F6584078BEA0B6C4F89BCACB600D2C
6A878E6CE88C9313D2B32EE2AC289C95031EE0DFA5A2D42083F124BCC025C4A0B106
77B993B05B10D74825EEB25DD7BDFB96BD09
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
    78:be:a0:b6:c4:f8:9b:ca:cb:60:0d:2c:6a:87:8e:6c:
    e8:8c:93:13:d2:b3:2e:e2:ac:28:9c:95:03:1e:e0:df:
    a5:a2:d4:20:83:f1:24:bc:c0:25:c4:a0:b1:06:77:b9:
    93:b0:5b:10:d7:48:25:ee:b2:5d:d7:bd:fb:96:bd:09
~~~~~

Annotated hex

[comment]: <> (replace-data:crl/full-direct-no-revocation-crl/crl.diag)
~~~~~
  0: 8B             # C509CRL=array[11]
  1:   00             # [0]. crlType=0
  2:   0C             # [1]. signatureAlgorithm: Ed25519 (12)
  3:   6F             # [2]. authoritySubject=char[15]
  4:     746573742063726C6F6373702D6361 # "test crlocsp-ca"
 19:   54             # [3]. authorityKeyIdentifier=byte[20]
 20:     2F45E78D2CAEDF368CDF53C39005D492450E1056
 40:   01             # [4]. crlNumber=1
 41:   1A 6775D700    # [5]. thisUpdate=1735776000:
                      #      2025-01-02T00:00:00Z
 46:   1A 677F1180    # [6]. nextUpdate=1736380800:
                      #      2025-01-09T00:00:00Z
 51:   F6             # [7]. baseCrlNumber=<null>
 52:   80             # [8]. crlExtensions=array[0]
 53:   F6             # [9]. revokedCertsList: <null>
 54:   58 40          # [10]. signature value=byte[64]
 56:     78BEA0B6C4F89BCACB600D2C6A878E6CE88C9313D2B32EE2AC289C9503
 85:     1EE0DFA5A2D42083F124BCC025C4A0B10677B993B05B10D74825EEB25D
114:     D7BDFB96BD09
~~~~~

### CRL Example With Revoked Certificates {#exam-crl-revoked}

[comment]: <> (replace-percent:crl/full-direct-with-revocation-crl/crl.hex % crl/full-direct-with-revocation-crl/x509crl.pem)
- size(C509) / size(X509): 52%
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
D492450E1056021A677C71721A6785ABF2F68085F6840302031A677488728218571A
677485805824112206978006123400000001334403F4800655660151800656780546
00009ABC02A30000F6584071FA09F11E37B880CCDE7EE6DDE6A76244A36CA1F07F2E
C52AB03A7324C1E5D2A42A001731B3AF5977B30B0E2A38AE7CC745BC3464D349750E
0AE18AF6BF8D0F
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
    71:fa:09:f1:1e:37:b8:80:cc:de:7e:e6:dd:e6:a7:62:
    44:a3:6c:a1:f0:7f:2e:c5:2a:b0:3a:73:24:c1:e5:d2:
    a4:2a:00:17:31:b3:af:59:77:b3:0b:0e:2a:38:ae:7c:
    c7:45:bc:34:64:d3:49:75:0e:0a:e1:8a:f6:bf:8d:0f
~~~~~

Annotated hex

[comment]: <> (replace-data:crl/full-direct-with-revocation-crl/crl.diag)
~~~~~
  0: 8B             # C509CRL=array[11]
  1:   00             # [0]. crlType=0
  2:   0C             # [1]. signatureAlgorithm: Ed25519 (12)
  3:   6F             # [2]. authoritySubject=char[15]
  4:     746573742063726C6F6373702D6361 # "test crlocsp-ca"
 19:   54             # [3]. authorityKeyIdentifier=byte[20]
 20:     2F45E78D2CAEDF368CDF53C39005D492450E1056
 40:   02             # [4]. crlNumber=2
 41:   1A 677C7172    # [5]. thisUpdate=1736208754:
                      #      2025-01-07T00:12:34Z
 46:   1A 6785ABF2    # [6]. nextUpdate=1736813554:
                      #      2025-01-14T00:12:34Z
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
 65:       18 57          # [0]. type: ExpiredCertsOnCRL (87)
 67:       1A 67748580    # [1]. value=1735689600:
                          #      2025-01-01T00:00:00Z
 72:     58 24          # [3]. revokedCerts=byte[36]
 74:        112206978006  # CSN=1122, date=069780, reason=6
 80:        123400000001  # CSN=1234, date=000000, reason=1
 86:        334403F48006  # CSN=3344, date=03F480, reason=6
 92:        556601518006  # CSN=5566, date=015180, reason=6
 98:        567805460000  # CSN=5678, date=054600, reason=0
104:        9ABC02A30000  # CSN=9ABC, date=02A300, reason=0
110:     F6             # [4]. removedFromCRLCerts=<null>
111:   58 40          # [10]. signature value=byte[64]
113:     71FA09F11E37B880CCDE7EE6DDE6A76244A36CA1F07F2EC52AB03A7324
142:     C1E5D2A42A001731B3AF5977B30B0E2A38AE7CC745BC3464D349750E0A
171:     E18AF6BF8D0F
~~~~~

### Delta CRL Example With Revoked Certificates {#exam-delta-crl-revoked}

[comment]: <> (replace-percent:crl/delta-with-revocation-crl/crl.hex % crl/delta-with-revocation-crl/x509crl.pem)
- size(C509) / size(X509): 47%
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
NTAxMDgwMDA4MzRaMCECAhEiFw0yNTAxMDcxMjEyMzRaMAwwCgYDVR0VBAMKAQgw
IQICM0QXDTI1MDEwNzEyMTIzNFowDDAKBgNVHRUEAwoBCDAhAgJVZhcNMjUwMTA3
MTIxMjM0WjAMMAoGA1UdFQQDCgEIMAUGAytlcANBAHDD/7XEXjP0xrSaEatwHcgc
V31eqR+XfEh2fQssXZx18KKK4ybiBivLorhqg6aJpjx2z/HBcxhKI1Hrk2X8qwo=
-----END X509 CRL-----
~~~~~

#### C509 CRL

[comment]: <> (replace-size:crl/delta-with-revocation-crl/crl.hex)
Plain Hex (160 bytes):

[comment]: <> (replace-data:crl/delta-with-revocation-crl/crl.hex)
~~~~~
8B000C6F746573742063726C6F6373702D6361542F45E78D2CAEDF368CDF53C39005
D492450E1056031A677DC2F21A678065F2028085F6840302021A677D1A32804F3412
0000017856A84800BC9AA7D0004C11220000334400005566000058406A6DB5AFFBC1
E72B76709AA2B5EEAAF7660A9647D47520A32F61DB220AFDC6FC7C48E712993D4510
B35832B15FC003DA8BE95280678DC793FB0795E1CE6D220A
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
        0x1122, 2025-01-07T12:12:34Z
        0x3344, 2025-01-07T12:12:34Z
        0x5566, 2025-01-07T12:12:34Z
  Signature Value
    6a:6d:b5:af:fb:c1:e7:2b:76:70:9a:a2:b5:ee:aa:f7:
    66:0a:96:47:d4:75:20:a3:2f:61:db:22:0a:fd:c6:fc:
    7c:48:e7:12:99:3d:45:10:b3:58:32:b1:5f:c0:03:da:
    8b:e9:52:80:67:8d:c7:93:fb:07:95:e1:ce:6d:22:0a
~~~~~

Annotated hex

[comment]: <> (replace-data:crl/delta-with-revocation-crl/crl.diag)
~~~~~
  0: 8B             # C509CRL=array[11]
  1:   00             # [0]. crlType=0
  2:   0C             # [1]. signatureAlgorithm: Ed25519 (12)
  3:   6F             # [2]. authoritySubject=char[15]
  4:     746573742063726C6F6373702D6361 # "test crlocsp-ca"
 19:   54             # [3]. authorityKeyIdentifier=byte[20]
 20:     2F45E78D2CAEDF368CDF53C39005D492450E1056
 40:   03             # [4]. crlNumber=3
 41:   1A 677DC2F2    # [5]. thisUpdate=1736295154:
                      #      2025-01-08T00:12:34Z
 46:   1A 678065F2    # [6]. nextUpdate=1736467954:
                      #      2025-01-10T00:12:34Z
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
 65:     4F             # [3]. revokedCerts=byte[15]
 66:        3412000001    # CSN=3412, date=0000, reason=1
 71:        7856A84800    # CSN=7856, date=A848, reason=0
 76:        BC9AA7D000    # CSN=BC9A, date=A7D0, reason=0
 81:     4C             # [4]. removedFromCRLCerts=byte[12]
 82:        11220000      # CSN=1122, date=0000
 86:        33440000      # CSN=3344, date=0000
 90:        55660000      # CSN=5566, date=0000
 94:   58 40          # [10]. signature value=byte[64]
 96:     6A6DB5AFFBC1E72B76709AA2B5EEAAF7660A9647D47520A32F61DB220A
125:     FDC6FC7C48E712993D4510B35832B15FC003DA8BE95280678DC793FB07
154:     95E1CE6D220A
~~~~~

### Indirect CRL Example With Revoked Certificates {#exam-indirect-crl-revoked}

[comment]: <> (replace-percent:crl/full-indirect-with-revocation-crl/crl.hex % crl/full-indirect-with-revocation-crl/x509crl.pem)
- size(C509) / size(X509): 49%
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
B6041A677C71721A6785ABF2F6808A6F746573742063726C6F6373702D6361840302
031A6774887280521234000000015678054600009ABC02A30000F66A6578616D706C
65204341840302031A6775D9F28052112205460006334402A30006556600000006F6
5840A301BC4C9C68F5C4455CD811FDEBCB04D643F1799B8F61935E6270CB1992030C
0027960EAC7924A3F01ACDAE25CAAEA45E5C324B00164819E369784ADCD52509
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
    a3:01:bc:4c:9c:68:f5:c4:45:5c:d8:11:fd:eb:cb:04:
    d6:43:f1:79:9b:8f:61:93:5e:62:70:cb:19:92:03:0c:
    00:27:96:0e:ac:79:24:a3:f0:1a:cd:ae:25:ca:ae:a4:
    5e:5c:32:4b:00:16:48:19:e3:69:78:4a:dc:d5:25:09
~~~~~

Annotated hex

[comment]: <> (replace-data:crl/full-indirect-with-revocation-crl/crl.diag)
~~~~~
  0: 8B             # C509CRL=array[11]
  1:   00             # [0]. crlType=0
  2:   0C             # [1]. signatureAlgorithm: Ed25519 (12)
  3:   6A             # [2]. authoritySubject=char[10]
  4:     63726C2D7369676E6572 # "crl-signer"
 14:   54             # [3]. authorityKeyIdentifier=byte[20]
 15:     09E433582556550A27DB4A19BCE2D660884722B6
 35:   04             # [4]. crlNumber=4
 36:   1A 677C7172    # [5]. thisUpdate=1736208754:
                      #      2025-01-07T00:12:34Z
 41:   1A 6785ABF2    # [6]. nextUpdate=1736813554:
                      #      2025-01-14T00:12:34Z
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
 75:     52             # [3]. revokedCerts=byte[18]
 76:        123400000001  # CSN=1234, date=000000, reason=1
 82:        567805460000  # CSN=5678, date=054600, reason=0
 88:        9ABC02A30000  # CSN=9ABC, date=02A300, reason=0
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
116:     52             # [8]. revokedCerts=byte[18]
117:        112205460006  # CSN=1122, date=054600, reason=6
123:        334402A30006  # CSN=3344, date=02A300, reason=6
129:        556600000006  # CSN=5566, date=000000, reason=6
135:     F6             # [9]. removedFromCRLCerts=<null>
136:   58 40          # [10]. signature value=byte[64]
138:     A301BC4C9C68F5C4455CD811FDEBCB04D643F1799B8F61935E6270CB19
167:     92030C0027960EAC7924A3F01ACDAE25CAAEA45E5C324B00164819E369
196:     784ADCD52509
~~~~~

## OCSP Request Examples

### Simple OCSP Request Example {#exam-simple-ocsp-req}

[comment]: <> (replace-percent:ocspreq/simple-ocspreq/ocspreq.hex % ocspreq/simple-ocspreq/x509ocspreq.pem)
- size(C509) / size(X509): 59%
- Simpe OCSP Request (`C509SimpleOCSPRequest`)
- Note that the X.509 OCSP Request and the C509 OCSP Request are not convertible.

#### X.509 OCSP Request

[comment]: <> (replace-size:ocspreq/simple-ocspreq/x509ocspreq.pem)
PEM content (150 bytes):

[comment]: <> (replace-data:ocspreq/simple-ocspreq/x509ocspreq.pem)
~~~~~
-----BEGIN OCSP REQUEST-----
MIGTMIGQMGswaTBnMAsGCWCGSAFlAwQCAQQgMlOOdIW9N65FTx8NK5dV11i5H26O
Onrzl6D0AGBcb/gEIMwRyHQKBQnsTaFM5YhucjZMD2O2DtY0fxPBbuclt2aiAhQS
NBI0EjQSNBI0EjQSNBI0EjQSNKIhMB8wHQYJKwYBBQUHMAECBBARERERERERERER
ERERERER
-----END OCSP REQUEST-----
~~~~~

#### C509 OCSP Request

[comment]: <> (replace-size:ocspreq/simple-ocspreq/ocspreq.hex)
Plain Hex (89 bytes):

[comment]: <> (replace-data:ocspreq/simple-ocspreq/ocspreq.hex)
~~~~~
86020150111111111111111111111111111111115820A01C73A5F3B063344257D026
93059DED8E22C4433B1A4D85EFAE22F7F9D7E43C582010652787FA0527BC2449A1BF
C5AB31AA5A6F0D8D6B998E4FEDE7D90DCA47F00480
~~~~~

Textual Representation

[comment]: <> (replace-data:ocspreq/simple-ocspreq/ocspreq.txt)
~~~~~
C509SimpleOCSPRequest
  Type: C509SimpleOCSPRequest (2)
  Hash Algorithm: SHA256 (1)
  IssuerCertHash:
    a0:1c:73:a5:f3:b0:63:34:42:57:d0:26:93:05:9d:ed:
    8e:22:c4:43:3b:1a:4d:85:ef:ae:22:f7:f9:d7:e4:3c
  SerialNumberHash:
    10:65:27:87:fa:05:27:bc:24:49:a1:bf:c5:ab:31:aa:
    5a:6f:0d:8d:6b:99:8e:4f:ed:e7:d9:0d:ca:47:f0:04
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
 2:   01             # [1]. hashAlgorithm: SHA256 (1)
 3:   50             # [2]. nonce=byte[16]
 4:     11111111111111111111111111111111
20:   58 20          # [3]. issuerCertHash=byte[32]
22:     A01C73A5F3B063344257D02693059DED8E22C4433B1A4D85EFAE22F7F9
51:     D7E43C
54:   58 20          # [4]. serialNumberHash=byte[32]
56:     10652787FA0527BC2449A1BFC5AB31AA5A6F0D8D6B998E4FEDE7D90DCA
85:     47F004
88:   80             # [5]. extensions=array[0]
~~~~~

### Unsigned OCSP Request Example {#exam-unsigned-ocsp-req}

[comment]: <> (replace-percent:ocspreq/unsigned-ocspreq/ocspreq.hex % ocspreq/unsigned-ocspreq/x509ocspreq.pem)
- size(C509) / size(X509): 49%
- Unsigned OCSP Request (`C509UnsignedOCSPRequest`)
- Note that the X.509 OCSP Request and the C509 OCSP Request are not convertible.

#### X.509 OCSP Request

[comment]: <> (replace-size:ocspreq/unsigned-ocspreq/x509ocspreq.pem)
PEM content (475 bytes):

[comment]: <> (replace-data:ocspreq/unsigned-ocspreq/x509ocspreq.pem)
~~~~~
-----BEGIN OCSP REQUEST-----
MIIB1zCCAdMwggGsMGkwZzALBglghkgBZQMEAgEEIDJTjnSFvTeuRU8fDSuXVddY
uR9ujjp685eg9ABgXG/4BCDMEch0CgUJ7E2hTOWIbnI2TA9jtg7WNH8TwW7nJbdm
ogIUEjQSNBI0EjQSNBI0EjQSNBI0EjQwaTBnMAsGCWCGSAFlAwQCAQQgMlOOdIW9
N65FTx8NK5dV11i5H26OOnrzl6D0AGBcb/gEIMwRyHQKBQnsTaFM5YhucjZMD2O2
DtY0fxPBbuclt2aiAhQ0VjRWNFY0VjRWNFY0VjRWNFY0VjBpMGcwCwYJYIZIAWUD
BAIBBCAyU450hb03rkVPHw0rl1XXWLkfbo46evOXoPQAYFxv+AQgzBHIdAoFCexN
oUzliG5yNkwPY7YO1jR/E8Fu5yW3ZqICFFZ4VnhWeFZ4VnhWeFZ4VnhWeFZ4MGkw
ZzALBglghkgBZQMEAgEEIDMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMz
BCBERERERERERERERERERERERERERERERERERERERERERAIUIjMiMyIzIjMiMyIz
IjMiMyIzIjOiITAfMB0GCSsGAQUFBzABAgQQEREREREREREREREREREREQ==
-----END OCSP REQUEST-----
~~~~~

#### C509 OCSP Request

[comment]: <> (replace-size:ocspreq/unsigned-ocspreq/ocspreq.hex)
Plain Hex (234 bytes):

[comment]: <> (replace-data:ocspreq/unsigned-ocspreq/ocspreq.hex)
~~~~~
850001501111111111111111111111111111111180865820A01C73A5F3B063344257
D02693059DED8E22C4433B1A4D85EFAE22F7F9D7E43C8086582010652787FA0527BC
2449A1BFC5AB31AA5A6F0D8D6B998E4FEDE7D90DCA47F00480582075D8BC4FBAFC66
94467641E748DFD53A8B9D176DFA3D05B3E98A4D6E5C55F165805820D1AC135D7DA2
9BDCF4DCA0D5281A51605B678400C26408CADC3A32FC1B6AD5E38058202222222222
22222222222222222222222222222222222222222222222222222280825820D3A0C1
E3DB92E8F6810537D45CFAECF6CE417E3B264E50CB4F69DD853401C5DD80
~~~~~

Textual Representation

[comment]: <> (replace-data:ocspreq/unsigned-ocspreq/ocspreq.txt)
~~~~~
C509UnsignedOCSPRequest
  Type: C509UnsignedOCSPRequest (0)
  Hash Algorithm: SHA256 (1)
  Nonce
    11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11
  Requests
    OcspPerIssuerRequest
      issuerCertHash
        a0:1c:73:a5:f3:b0:63:34:42:57:d0:26:93:05:9d:ed:
        8e:22:c4:43:3b:1a:4d:85:ef:ae:22:f7:f9:d7:e4:3c
      extensions: <empty>
      singleRequests
        SingleCertRequest
          SerialNumberHash:
            10:65:27:87:fa:05:27:bc:24:49:a1:bf:c5:ab:31:aa:
            5a:6f:0d:8d:6b:99:8e:4f:ed:e7:d9:0d:ca:47:f0:04
          Extensions: <empty>
        SingleCertRequest
          SerialNumberHash:
            75:d8:bc:4f:ba:fc:66:94:46:76:41:e7:48:df:d5:3a:
            8b:9d:17:6d:fa:3d:05:b3:e9:8a:4d:6e:5c:55:f1:65
          Extensions: <empty>
        SingleCertRequest
          SerialNumberHash:
            d1:ac:13:5d:7d:a2:9b:dc:f4:dc:a0:d5:28:1a:51:60:
            5b:67:84:00:c2:64:08:ca:dc:3a:32:fc:1b:6a:d5:e3
          Extensions: <empty>
    OcspPerIssuerRequest
      issuerCertHash
        22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:
        22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22
      extensions: <empty>
      singleRequests
        SingleCertRequest
          SerialNumberHash:
            d3:a0:c1:e3:db:92:e8:f6:81:05:37:d4:5c:fa:ec:f6:
            ce:41:7e:3b:26:4e:50:cb:4f:69:dd:85:34:01:c5:dd
          Extensions: <empty>
  Extensions: <empty>
~~~~~

Annotated hex

[comment]: <> (replace-data:ocspreq/unsigned-ocspreq/ocspreq.diag)
~~~~~
  0: 85             # C509OCSPRequest=array[5]
  1:   00             # [0]. ocspRequestType=C509UnsignedOCSPRequest
                      #      (0)
  2:   01             # [1]. hashAlgorithm: SHA256 (1)
  3:   50             # [2]. nonce=byte[16]
  4:     11111111111111111111111111111111
 20:   80             # [3]. extensions=array[0]
 21:   86             # [4]. requests=array[6]
                        #---PerIssuerRequests[0]---
 22:     58 20          # [0]. issuerCertHash=byte[32]
 24:       A01C73A5F3B063344257D02693059DED8E22C4433B1A4D85EFAE22F7
 52:       F9D7E43C
 56:     80             # [1]. extensions=array[0]
 57:     86             # [2]. singleRequests=array[6]
                          #---SingleCertRequests[0]---
 58:       58 20          # [0]. serialNumberHash=byte[32]
 60:         10652787FA0527BC2449A1BFC5AB31AA5A6F0D8D6B998E4FEDE7D9
 87:         0DCA47F004
 92:       80             # [1]. extensions=array[0]
                          #---SingleCertRequests[1]---
 93:       58 20          # [2]. serialNumberHash=byte[32]
 95:         75D8BC4FBAFC6694467641E748DFD53A8B9D176DFA3D05B3E98A4D
122:         6E5C55F165
127:       80             # [3]. extensions=array[0]
                          #---SingleCertRequests[2]---
128:       58 20          # [4]. serialNumberHash=byte[32]
130:         D1AC135D7DA29BDCF4DCA0D5281A51605B678400C26408CADC3A32
157:         FC1B6AD5E3
162:       80             # [5]. extensions=array[0]
                        #---PerIssuerRequests[1]---
163:     58 20          # [3]. issuerCertHash=byte[32]
165:       22222222222222222222222222222222222222222222222222222222
193:       22222222
197:     80             # [4]. extensions=array[0]
198:     82             # [5]. singleRequests=array[2]
                          #---SingleCertRequests[0]---
199:       58 20          # [0]. serialNumberHash=byte[32]
201:         D3A0C1E3DB92E8F6810537D45CFAECF6CE417E3B264E50CB4F69DD
228:         853401C5DD
233:       80             # [1]. extensions=array[0]
~~~~~

### Signed OCSP Request Example Without Requestor's Certificate {#exam-signed-ocsp-req}

[comment]: <> (replace-percent:ocspreq/signed-ocspreq/ocspreq.hex % ocspreq/signed-ocspreq/x509ocspreq.pem)
- size(C509) / size(X509): 57%
- Verifiable with certificate in {{ocsp-requestor-cert}}
- Signed OCSP Request (`C509UnsignedOCSPRequest`) without requestor's certificate
- Note that the X.509 OCSP Request and the C509 OCSP Request are not convertible.

#### X.509 OCSP Request

[comment]: <> (replace-size:ocspreq/signed-ocspreq/x509ocspreq.pem)
PEM content (584 bytes):

[comment]: <> (replace-data:ocspreq/signed-ocspreq/x509ocspreq.pem)
~~~~~
-----BEGIN OCSP REQUEST-----
MIICRDCCAfKhHaQbMBkxFzAVBgNVBAMMDm9jc3AtcmVxdWVzdG9yMIIBrDBpMGcw
CwYJYIZIAWUDBAIBBCAyU450hb03rkVPHw0rl1XXWLkfbo46evOXoPQAYFxv+AQg
zBHIdAoFCexNoUzliG5yNkwPY7YO1jR/E8Fu5yW3ZqICFBI0EjQSNBI0EjQSNBI0
EjQSNBI0MGkwZzALBglghkgBZQMEAgEEIDJTjnSFvTeuRU8fDSuXVddYuR9ujjp6
85eg9ABgXG/4BCDMEch0CgUJ7E2hTOWIbnI2TA9jtg7WNH8TwW7nJbdmogIUNFY0
VjRWNFY0VjRWNFY0VjRWNFYwaTBnMAsGCWCGSAFlAwQCAQQgMlOOdIW9N65FTx8N
K5dV11i5H26OOnrzl6D0AGBcb/gEIMwRyHQKBQnsTaFM5YhucjZMD2O2DtY0fxPB
buclt2aiAhRWeFZ4VnhWeFZ4VnhWeFZ4VnhWeDBpMGcwCwYJYIZIAWUDBAIBBCAz
MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMwQgRERERERERERERERERERE
REREREREREREREREREREREQCFCIzIjMiMyIzIjMiMyIzIjMiMyIzoiEwHzAdBgkr
BgEFBQcwAQIEEBERERERERERERERERERERGgTDBKMAUGAytlcANBAJxdKYl8BFnb
nngr44EK7xqnJFQWfa8iM4Lje1eezFCTX1GiRVJEqS2Oe2HEdFggCngY5q5RkRaY
qvjTEhXlRwg=
-----END OCSP REQUEST-----
~~~~~

#### C509 OCSP Request

[comment]: <> (replace-size:ocspreq/signed-ocspreq/ocspreq.hex)
Plain Hex (336 bytes):

[comment]: <> (replace-data:ocspreq/signed-ocspreq/ocspreq.hex)
~~~~~
89010C015011111111111111111111111111111111582044F0528B56F35AD998049B
306FF9A8B06FA79DE8146946FE254B00C62A622A5D80865820A01C73A5F3B0633442
57D02693059DED8E22C4433B1A4D85EFAE22F7F9D7E43C8086582010652787FA0527
BC2449A1BFC5AB31AA5A6F0D8D6B998E4FEDE7D90DCA47F00480582075D8BC4FBAFC
6694467641E748DFD53A8B9D176DFA3D05B3E98A4D6E5C55F165805820D1AC135D7D
A29BDCF4DCA0D5281A51605B678400C26408CADC3A32FC1B6AD5E380582022222222
2222222222222222222222222222222222222222222222222222222280825820D3A0
C1E3DB92E8F6810537D45CFAECF6CE417E3B264E50CB4F69DD853401C5DD80F65840
FF755E078E731174DFD1F93E24C5B539CE3E1FE1A1CE51F387F12C6CD8C13AEA6D87
D4BE33B6B3BF20C268AFA19DCB6BAFEDF5E8A26131A027474E7B5831C106
~~~~~

Textual Representation

[comment]: <> (replace-data:ocspreq/signed-ocspreq/ocspreq.txt)
~~~~~
C509SignedOCSPRequest
  TBSOCSPRequest
    Type: C509SignedOCSPRequest (1)
    Signature Algorithm: Ed25519 (12)
    Hash Algorithm: SHA256 (1)
    RequestorCertHash
      44:f0:52:8b:56:f3:5a:d9:98:04:9b:30:6f:f9:a8:b0:
      6f:a7:9d:e8:14:69:46:fe:25:4b:00:c6:2a:62:2a:5d
    Nonce
      11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11
    Extensions: <empty>
    Requests
      OcspPerIssuerRequest
        issuerCertHash
          a0:1c:73:a5:f3:b0:63:34:42:57:d0:26:93:05:9d:ed:
          8e:22:c4:43:3b:1a:4d:85:ef:ae:22:f7:f9:d7:e4:3c
        extensions: <empty>
        singleRequests
          SingleCertRequest
            SerialNumberHash:
              10:65:27:87:fa:05:27:bc:24:49:a1:bf:c5:ab:31:aa:
              5a:6f:0d:8d:6b:99:8e:4f:ed:e7:d9:0d:ca:47:f0:04
            Extensions: <empty>
          SingleCertRequest
            SerialNumberHash:
              75:d8:bc:4f:ba:fc:66:94:46:76:41:e7:48:df:d5:3a:
              8b:9d:17:6d:fa:3d:05:b3:e9:8a:4d:6e:5c:55:f1:65
            Extensions: <empty>
          SingleCertRequest
            SerialNumberHash:
              d1:ac:13:5d:7d:a2:9b:dc:f4:dc:a0:d5:28:1a:51:60:
              5b:67:84:00:c2:64:08:ca:dc:3a:32:fc:1b:6a:d5:e3
            Extensions: <empty>
      OcspPerIssuerRequest
        issuerCertHash
          22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:
          22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22
        extensions: <empty>
        singleRequests
          SingleCertRequest
            SerialNumberHash:
              d3:a0:c1:e3:db:92:e8:f6:81:05:37:d4:5c:fa:ec:f6:
              ce:41:7e:3b:26:4e:50:cb:4f:69:dd:85:34:01:c5:dd
            Extensions: <empty>
    Requestor Certs: null
  Signature Value
    ff:75:5e:07:8e:73:11:74:df:d1:f9:3e:24:c5:b5:39:
    ce:3e:1f:e1:a1:ce:51:f3:87:f1:2c:6c:d8:c1:3a:ea:
    6d:87:d4:be:33:b6:b3:bf:20:c2:68:af:a1:9d:cb:6b:
    af:ed:f5:e8:a2:61:31:a0:27:47:4e:7b:58:31:c1:06
~~~~~

Annotated hex

[comment]: <> (replace-data:ocspreq/signed-ocspreq/ocspreq.diag)
~~~~~
  0: 89             # C509OCSPRequest=array[9]
  1:   01             # [0]. ocspRequestType=C509SignedOCSPRequest
                      #      (1)
  2:   0C             # [1]. signatureAlgorithm: Ed25519 (12)
  3:   01             # [2]. hashAlgorithm: SHA256 (1)
  4:   50             # [3]. nonce=byte[16]
  5:     11111111111111111111111111111111
 21:   58 20          # [4]. requestorCertHash=byte[32]
 23:     44F0528B56F35AD998049B306FF9A8B06FA79DE8146946FE254B00C62A
 52:     622A5D
 55:   80             # [5]. extensions=array[0]
 56:   86             # [6]. requests=array[6]
                        #---PerIssuerRequests[0]---
 57:     58 20          # [0]. issuerCertHash=byte[32]
 59:       A01C73A5F3B063344257D02693059DED8E22C4433B1A4D85EFAE22F7
 87:       F9D7E43C
 91:     80             # [1]. extensions=array[0]
 92:     86             # [2]. singleRequests=array[6]
                          #---SingleCertRequests[0]---
 93:       58 20          # [0]. serialNumberHash=byte[32]
 95:         10652787FA0527BC2449A1BFC5AB31AA5A6F0D8D6B998E4FEDE7D9
122:         0DCA47F004
127:       80             # [1]. extensions=array[0]
                          #---SingleCertRequests[1]---
128:       58 20          # [2]. serialNumberHash=byte[32]
130:         75D8BC4FBAFC6694467641E748DFD53A8B9D176DFA3D05B3E98A4D
157:         6E5C55F165
162:       80             # [3]. extensions=array[0]
                          #---SingleCertRequests[2]---
163:       58 20          # [4]. serialNumberHash=byte[32]
165:         D1AC135D7DA29BDCF4DCA0D5281A51605B678400C26408CADC3A32
192:         FC1B6AD5E3
197:       80             # [5]. extensions=array[0]
                        #---PerIssuerRequests[1]---
198:     58 20          # [3]. issuerCertHash=byte[32]
200:       22222222222222222222222222222222222222222222222222222222
228:       22222222
232:     80             # [4]. extensions=array[0]
233:     82             # [5]. singleRequests=array[2]
                          #---SingleCertRequests[0]---
234:       58 20          # [0]. serialNumberHash=byte[32]
236:         D3A0C1E3DB92E8F6810537D45CFAECF6CE417E3B264E50CB4F69DD
263:         853401C5DD
268:       80             # [1]. extensions=array[0]
269:   F6             # [7]. requestorCerts=<null>
270:   58 40          # [8]. signatureValue=byte[64]
272:     FF755E078E731174DFD1F93E24C5B539CE3E1FE1A1CE51F387F12C6CD8
301:     C13AEA6D87D4BE33B6B3BF20C268AFA19DCB6BAFEDF5E8A26131A02747
330:     4E7B5831C106
~~~~~

### Signed OCSP Request Example With Requestor's Certificate {#exam-signed-ocsp-req-withcert}

[comment]: <> (replace-percent:ocspreq/signed-ocspreq-with-cert/ocspreq.hex % ocspreq/signed-ocspreq-with-cert/x509ocspreq.pem)
- size(C509) / size(X509): 52%
- Verifiable with certificate in {{ocsp-requestor-cert}}
- Signed OCSP Request (`C509UnsignedOCSPRequest`) with embedded requestor's certificate
- Note that the X.509 OCSP Request and the C509 OCSP Request are not convertible.

#### X.509 OCSP Request

[comment]: <> (replace-size:ocspreq/signed-ocspreq-with-cert/x509ocspreq.pem)
PEM content (1035 bytes):

[comment]: <> (replace-data:ocspreq/signed-ocspreq-with-cert/x509ocspreq.pem)
~~~~~
-----BEGIN OCSP REQUEST-----
MIIEBzCCAnGhHaQbMBkxFzAVBgNVBAMMDm9jc3AtcmVxdWVzdG9yMIIBrDBpMGcw
CwYJYIZIAWUDBAIBBCAyU450hb03rkVPHw0rl1XXWLkfbo46evOXoPQAYFxv+AQg
zBHIdAoFCexNoUzliG5yNkwPY7YO1jR/E8Fu5yW3ZqICFBI0EjQSNBI0EjQSNBI0
EjQSNBI0MGkwZzALBglghkgBZQMEAgEEIDJTjnSFvTeuRU8fDSuXVddYuR9ujjp6
85eg9ABgXG/4BCDMEch0CgUJ7E2hTOWIbnI2TA9jtg7WNH8TwW7nJbdmogIUNFY0
VjRWNFY0VjRWNFY0VjRWNFYwaTBnMAsGCWCGSAFlAwQCAQQgMlOOdIW9N65FTx8N
K5dV11i5H26OOnrzl6D0AGBcb/gEIMwRyHQKBQnsTaFM5YhucjZMD2O2DtY0fxPB
buclt2aiAhRWeFZ4VnhWeFZ4VnhWeFZ4VnhWeDBpMGcwCwYJYIZIAWUDBAIBBCAz
MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMwQgRERERERERERERERERERE
REREREREREREREREREREREQCFCIzIjMiMyIzIjMiMyIzIjMiMyIzooGfMIGcMBoG
CSsGAQUFBzABBAQNMAsGCSsGAQUFBzABATBfBgkrBgEFBQcwAQgEUjBQMAcwBQYD
K2VwMCEwCgYIKoZIzj0EAwIwEwYHKoZIzj0CAQYIKoZIzj0DAQcwIjAKBggqhkjO
PQQDAjAUBgcqhkjOPQIBBgkrJAMDAggBAQcwHQYJKwYBBQUHMAECBBARERERERER
ERERERERERERoIIBjjCCAYowBQYDK2VwA0EAnqnZjVvfg50lAZOGBiSExUCuMKja
IHCZKykPyiVpW8ECz2Ejd8NiIQ/pnXvzTRvbQz1i7y+figq4L4YZYGfjAaCCATww
ggE4MIIBNDCB56ADAgECAgISNjAFBgMrZXAwGjEYMBYGA1UEAwwPdGVzdCBjcmxv
Y3NwLWNhMB4XDTI1MDEwMjAwMDAwMFoXDTI2MDEwMjAwMDAwMFowGTEXMBUGA1UE
AwwOb2NzcC1yZXF1ZXN0b3IwKjAFBgMrZXADIQAEUwsXZO3UtOM6tErw+DiWHABx
dtdLajVG7Lf9VzIN06NSMFAwHQYDVR0OBBYEFLE21FmKGxtqhtplEK6lZNgSl+T5
MA4GA1UdDwEB/wQEAwIHgDAfBgNVHSMEGDAWgBTZfXfmNML3ADAMpY/IdzZbFVAH
ojAFBgMrZXADQQCY+ZIhXpHFm+r/HrfqPv0rqn4dvQHRKwN3gZhZyWeQP/nP6vYx
W73WoQgSSbXiyYVCHNASdBpZljgSyNJ6NX0C
-----END OCSP REQUEST-----
~~~~~

#### C509 OCSP Request

[comment]: <> (replace-size:ocspreq/signed-ocspreq-with-cert/ocspreq.hex)
Plain Hex (546 bytes):

[comment]: <> (replace-data:ocspreq/signed-ocspreq-with-cert/ocspreq.hex)
~~~~~
89010C015011111111111111111111111111111111582044F0528B56F35AD998049B
306FF9A8B06FA79DE8146946FE254B00C62A622A5D84185D820001185E840CF60082
011818865820A01C73A5F3B063344257D02693059DED8E22C4433B1A4D85EFAE22F7
F9D7E43C8086582010652787FA0527BC2449A1BFC5AB31AA5A6F0D8D6B998E4FEDE7
D90DCA47F00480582075D8BC4FBAFC6694467641E748DFD53A8B9D176DFA3D05B3E9
8A4D6E5C55F165805820D1AC135D7DA29BDCF4DCA0D5281A51605B678400C26408CA
DC3A32FC1B6AD5E38058202222222222222222222222222222222222222222222222
22222222222222222280825820D3A0C1E3DB92E8F6810537D45CFAECF6CE417E3B26
4E50CB4F69DD853401C5DD8058C2024212360C6F746573742063726C6F6373702D63
611A6775D7001A69570A806E6F6373702D726571756573746F720C582004530B1764
EDD4B4E33AB44AF0F838961C007176D74B6A3546ECB7FD57320DD3860154DD51BDB2
A2C791C062D4027856DBACF52607F0BE210107542F45E78D2CAEDF368CDF53C39005
D492450E10565840F8C6183ECF8C3EFD50DD4942D172814C46EC0FC01DD586A59717
8DF864A0D9DA86B7CA17FC9F772FF04C80E98B60D5B4B62408A277A5B70D0D2A3F5E
D5442D07584059334BAFB83C250FB22F222B2DB594A00AA86BFAA5E249F7669DE076
7E08D1E36C800F31E23F152FC0EB2C1C209F3135243C7237D50783ACE0E1EB664B94
9207
~~~~~

Textual Representation

[comment]: <> (replace-data:ocspreq/signed-ocspreq-with-cert/ocspreq.txt)
~~~~~
C509SignedOCSPRequest
  TBSOCSPRequest
    Type: C509SignedOCSPRequest (1)
    Signature Algorithm: Ed25519 (12)
    Hash Algorithm: SHA256 (1)
    RequestorCertHash
      44:f0:52:8b:56:f3:5a:d9:98:04:9b:30:6f:f9:a8:b0:
      6f:a7:9d:e8:14:69:46:fe:25:4b:00:c6:2a:62:2a:5d
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
          a0:1c:73:a5:f3:b0:63:34:42:57:d0:26:93:05:9d:ed:
          8e:22:c4:43:3b:1a:4d:85:ef:ae:22:f7:f9:d7:e4:3c
        extensions: <empty>
        singleRequests
          SingleCertRequest
            SerialNumberHash:
              10:65:27:87:fa:05:27:bc:24:49:a1:bf:c5:ab:31:aa:
              5a:6f:0d:8d:6b:99:8e:4f:ed:e7:d9:0d:ca:47:f0:04
            Extensions: <empty>
          SingleCertRequest
            SerialNumberHash:
              75:d8:bc:4f:ba:fc:66:94:46:76:41:e7:48:df:d5:3a:
              8b:9d:17:6d:fa:3d:05:b3:e9:8a:4d:6e:5c:55:f1:65
            Extensions: <empty>
          SingleCertRequest
            SerialNumberHash:
              d1:ac:13:5d:7d:a2:9b:dc:f4:dc:a0:d5:28:1a:51:60:
              5b:67:84:00:c2:64:08:ca:dc:3a:32:fc:1b:6a:d5:e3
            Extensions: <empty>
      OcspPerIssuerRequest
        issuerCertHash
          22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:
          22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22
        extensions: <empty>
        singleRequests
          SingleCertRequest
            SerialNumberHash:
              d3:a0:c1:e3:db:92:e8:f6:81:05:37:d4:5c:fa:ec:f6:
              ce:41:7e:3b:26:4e:50:cb:4f:69:dd:85:34:01:c5:dd
            Extensions: <empty>
    Requestor Certs
      ~C509Certificate
        02:42:12:36:0c:6f:74:65:73:74:20:63:72:6c:6f:63:
        73:70:2d:63:61:1a:67:75:d7:00:1a:69:57:0a:80:6e:
        6f:63:73:70:2d:72:65:71:75:65:73:74:6f:72:0c:58:
        20:04:53:0b:17:64:ed:d4:b4:e3:3a:b4:4a:f0:f8:38:
        96:1c:00:71:76:d7:4b:6a:35:46:ec:b7:fd:57:32:0d:
        d3:86:01:54:dd:51:bd:b2:a2:c7:91:c0:62:d4:02:78:
        56:db:ac:f5:26:07:f0:be:21:01:07:54:2f:45:e7:8d:
        2c:ae:df:36:8c:df:53:c3:90:05:d4:92:45:0e:10:56:
        58:40:f8:c6:18:3e:cf:8c:3e:fd:50:dd:49:42:d1:72:
        81:4c:46:ec:0f:c0:1d:d5:86:a5:97:17:8d:f8:64:a0:
        d9:da:86:b7:ca:17:fc:9f:77:2f:f0:4c:80:e9:8b:60:
        d5:b4:b6:24:08:a2:77:a5:b7:0d:0d:2a:3f:5e:d5:44:
        2d:07
  Signature Value
    59:33:4b:af:b8:3c:25:0f:b2:2f:22:2b:2d:b5:94:a0:
    0a:a8:6b:fa:a5:e2:49:f7:66:9d:e0:76:7e:08:d1:e3:
    6c:80:0f:31:e2:3f:15:2f:c0:eb:2c:1c:20:9f:31:35:
    24:3c:72:37:d5:07:83:ac:e0:e1:eb:66:4b:94:92:07
~~~~~

Annotated hex

[comment]: <> (replace-data:ocspreq/signed-ocspreq-with-cert/ocspreq.diag)
~~~~~
  0: 89             # C509OCSPRequest=array[9]
  1:   01             # [0]. ocspRequestType=C509SignedOCSPRequest
                      #      (1)
  2:   0C             # [1]. signatureAlgorithm: Ed25519 (12)
  3:   01             # [2]. hashAlgorithm: SHA256 (1)
  4:   50             # [3]. nonce=byte[16]
  5:     11111111111111111111111111111111
 21:   58 20          # [4]. requestorCertHash=byte[32]
 23:     44F0528B56F35AD998049B306FF9A8B06FA79DE8146946FE254B00C62A
 52:     622A5D
 55:   84             # [5]. extensions=array[4]
                        #---extension[0]---
 56:     18 5D          # [0]. type: AcceptOCSPResponseTypes (93)
 58:     82             # [1]. value=array[2]
 59:       00             # [0]. C509ErrorOCSPResponse (0)
 60:       01             # [1]. C509BasicOCSPResponse (1)
                        #---extension[1]---
 61:     18 5E          # [2]. type: preferredSignatureAlgorithms
                        #      (94)
 63:     84             # [3]. value=array[4]
                          #---preferredSignatureAlgorithms[0]---
 64:       0C             # [0]. sigIdentifier: Ed25519 (12)
 65:       F6             # [1]. pubKeyAlgIdentifiers=<null>
                          #---preferredSignatureAlgorithms[1]---
 66:       00             # [2]. sigIdentifier: ecdsa-with-sha256
                          #      (0)
 67:       82             # [3]. pubKeyAlgIdentifiers=array[2]
 68:         01             # [0]. pubKeyAlgIdentifier: EC public
                            #      key on curve secp256r1 (1)
 69:         18 18          # [1]. pubKeyAlgIdentifier: EC public
                            #      key on curve brainpoolp256r1 (24)
 71:   86             # [6]. requests=array[6]
                        #---PerIssuerRequests[0]---
 72:     58 20          # [0]. issuerCertHash=byte[32]
 74:       A01C73A5F3B063344257D02693059DED8E22C4433B1A4D85EFAE22F7
102:       F9D7E43C
106:     80             # [1]. extensions=array[0]
107:     86             # [2]. singleRequests=array[6]
                          #---SingleCertRequests[0]---
108:       58 20          # [0]. serialNumberHash=byte[32]
110:         10652787FA0527BC2449A1BFC5AB31AA5A6F0D8D6B998E4FEDE7D9
137:         0DCA47F004
142:       80             # [1]. extensions=array[0]
                          #---SingleCertRequests[1]---
143:       58 20          # [2]. serialNumberHash=byte[32]
145:         75D8BC4FBAFC6694467641E748DFD53A8B9D176DFA3D05B3E98A4D
172:         6E5C55F165
177:       80             # [3]. extensions=array[0]
                          #---SingleCertRequests[2]---
178:       58 20          # [4]. serialNumberHash=byte[32]
180:         D1AC135D7DA29BDCF4DCA0D5281A51605B678400C26408CADC3A32
207:         FC1B6AD5E3
212:       80             # [5]. extensions=array[0]
                        #---PerIssuerRequests[1]---
213:     58 20          # [3]. issuerCertHash=byte[32]
215:       22222222222222222222222222222222222222222222222222222222
243:       22222222
247:     80             # [4]. extensions=array[0]
248:     82             # [5]. singleRequests=array[2]
                          #---SingleCertRequests[0]---
249:       58 20          # [0]. serialNumberHash=byte[32]
251:         D3A0C1E3DB92E8F6810537D45CFAECF6CE417E3B264E50CB4F69DD
278:         853401C5DD
283:       80             # [1]. extensions=array[0]
284:   58 C2          # [7]. requestorCerts(COSE_C509)=byte[194]
286:     024212360C6F746573742063726C6F6373702D63611A6775D7001A6957
315:     0A806E6F6373702D726571756573746F720C582004530B1764EDD4B4E3
344:     3AB44AF0F838961C007176D74B6A3546ECB7FD57320DD3860154DD51BD
373:     B2A2C791C062D4027856DBACF52607F0BE210107542F45E78D2CAEDF36
402:     8CDF53C39005D492450E10565840F8C6183ECF8C3EFD50DD4942D17281
431:     4C46EC0FC01DD586A597178DF864A0D9DA86B7CA17FC9F772FF04C80E9
460:     8B60D5B4B62408A277A5B70D0D2A3F5ED5442D07
480:   58 40          # [8]. signatureValue=byte[64]
482:     59334BAFB83C250FB22F222B2DB594A00AA86BFAA5E249F7669DE0767E
511:     08D1E36C800F31E23F152FC0EB2C1C209F3135243C7237D50783ACE0E1
540:     EB664B949207
~~~~~

### Signed OCSP Request Example With Requestor's Certificate Chain {#exam-signed-ocsp-req-withcertchain}

[comment]: <> (replace-percent:ocspreq/signed-ocspreq-with-certchain/ocspreq.hex % ocspreq/signed-ocspreq-with-certchain/x509ocspreq.pem)
- size(C509) / size(X509): 54%
- Verifiable with certificate in {{ocsp-requestor-cert}}
- Signed OCSP Request (`C509UnsignedOCSPRequest`) with embedded requestor's certificate chain (2 certificates)
- Note that the X.509 OCSP Request and the C509 OCSP Request are not convertible.

#### X.509 OCSP Request

[comment]: <> (replace-size:ocspreq/signed-ocspreq-with-certchain/x509ocspreq.pem)
PEM content (1371 bytes):

[comment]: <> (replace-data:ocspreq/signed-ocspreq-with-certchain/x509ocspreq.pem)
~~~~~
-----BEGIN OCSP REQUEST-----
MIIFVzCCAnGhHaQbMBkxFzAVBgNVBAMMDm9jc3AtcmVxdWVzdG9yMIIBrDBpMGcw
CwYJYIZIAWUDBAIBBCAyU450hb03rkVPHw0rl1XXWLkfbo46evOXoPQAYFxv+AQg
zBHIdAoFCexNoUzliG5yNkwPY7YO1jR/E8Fu5yW3ZqICFBI0EjQSNBI0EjQSNBI0
EjQSNBI0MGkwZzALBglghkgBZQMEAgEEIDJTjnSFvTeuRU8fDSuXVddYuR9ujjp6
85eg9ABgXG/4BCDMEch0CgUJ7E2hTOWIbnI2TA9jtg7WNH8TwW7nJbdmogIUNFY0
VjRWNFY0VjRWNFY0VjRWNFYwaTBnMAsGCWCGSAFlAwQCAQQgMlOOdIW9N65FTx8N
K5dV11i5H26OOnrzl6D0AGBcb/gEIMwRyHQKBQnsTaFM5YhucjZMD2O2DtY0fxPB
buclt2aiAhRWeFZ4VnhWeFZ4VnhWeFZ4VnhWeDBpMGcwCwYJYIZIAWUDBAIBBCAz
MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMwQgRERERERERERERERERERE
REREREREREREREREREREREQCFCIzIjMiMyIzIjMiMyIzIjMiMyIzooGfMIGcMBoG
CSsGAQUFBzABBAQNMAsGCSsGAQUFBzABATBfBgkrBgEFBQcwAQgEUjBQMAcwBQYD
K2VwMCEwCgYIKoZIzj0EAwIwEwYHKoZIzj0CAQYIKoZIzj0DAQcwIjAKBggqhkjO
PQQDAjAUBgcqhkjOPQIBBgkrJAMDAggBAQcwHQYJKwYBBQUHMAECBBARERERERER
ERERERERERERoIIC3jCCAtowBQYDK2VwA0EAnqnZjVvfg50lAZOGBiSExUCuMKja
IHCZKykPyiVpW8ECz2Ejd8NiIQ/pnXvzTRvbQz1i7y+figq4L4YZYGfjAaCCAoww
ggKIMIIBNDCB56ADAgECAgISNjAFBgMrZXAwGjEYMBYGA1UEAwwPdGVzdCBjcmxv
Y3NwLWNhMB4XDTI1MDEwMjAwMDAwMFoXDTI2MDEwMjAwMDAwMFowGTEXMBUGA1UE
AwwOb2NzcC1yZXF1ZXN0b3IwKjAFBgMrZXADIQAEUwsXZO3UtOM6tErw+DiWHABx
dtdLajVG7Lf9VzIN06NSMFAwHQYDVR0OBBYEFLE21FmKGxtqhtplEK6lZNgSl+T5
MA4GA1UdDwEB/wQEAwIHgDAfBgNVHSMEGDAWgBTZfXfmNML3ADAMpY/IdzZbFVAH
ojAFBgMrZXADQQCY+ZIhXpHFm+r/HrfqPv0rqn4dvQHRKwN3gZhZyWeQP/nP6vYx
W73WoQgSSbXiyYVCHNASdBpZljgSyNJ6NX0CMIIBTDCB/6ADAgECAgEBMAUGAytl
cDAeMRwwGgYDVQQDDBN0ZXN0IGNybG9jc3Atcm9vdGNhMB4XDTI1MDEwMTAwMDAw
MFoXDTI2MTIzMTIzNTk1OVowGjEYMBYGA1UEAwwPdGVzdCBjcmxvY3NwLWNhMCow
BQYDK2VwAyEAXvijVaABp8UNI0lHASCBMaS7Krkg1Av7DuH2qyj/dACjZjBkMB0G
A1UdDgQWBBTZfXfmNML3ADAMpY/IdzZbFVAHojAOBgNVHQ8BAf8EBAMCAQYwEgYD
VR0TAQH/BAgwBgEB/wIBATAfBgNVHSMEGDAWgBSRI5z6+eeDbLKfUeExkdsQ064W
kzAFBgMrZXADQQDWXgHXy/pBf7F7mfeX7Wknr1Yv9j6NNbPjp9OBYMxkZ0AQTY85
GJfdqxGY89BaJhkgQ2Km+DwziCEbNrxWPUEC
-----END OCSP REQUEST-----
~~~~~

#### C509 OCSP Request

[comment]: <> (replace-size:ocspreq/signed-ocspreq-with-certchain/ocspreq.hex)
Plain Hex (750 bytes):

[comment]: <> (replace-data:ocspreq/signed-ocspreq-with-certchain/ocspreq.hex)
~~~~~
89010C015011111111111111111111111111111111582044F0528B56F35AD998049B
306FF9A8B06FA79DE8146946FE254B00C62A622A5D84185D820001185E840CF60082
011818865820A01C73A5F3B063344257D02693059DED8E22C4433B1A4D85EFAE22F7
F9D7E43C8086582010652787FA0527BC2449A1BFC5AB31AA5A6F0D8D6B998E4FEDE7
D90DCA47F00480582075D8BC4FBAFC6694467641E748DFD53A8B9D176DFA3D05B3E9
8A4D6E5C55F165805820D1AC135D7DA29BDCF4DCA0D5281A51605B678400C26408CA
DC3A32FC1B6AD5E38058202222222222222222222222222222222222222222222222
22222222222222222280825820D3A0C1E3DB92E8F6810537D45CFAECF6CE417E3B26
4E50CB4F69DD853401C5DD808258C2024212360C6F746573742063726C6F6373702D
63611A6775D7001A69570A806E6F6373702D726571756573746F720C582004530B17
64EDD4B4E33AB44AF0F838961C007176D74B6A3546ECB7FD57320DD3860154DD51BD
B2A2C791C062D4027856DBACF52607F0BE210107542F45E78D2CAEDF368CDF53C390
05D492450E10565840F8C6183ECF8C3EFD50DD4942D172814C46EC0FC01DD586A597
178DF864A0D9DA86B7CA17FC9F772FF04C80E98B60D5B4B62408A277A5B70D0D2A3F
5ED5442D0758C90241010C73746573742063726C6F6373702D726F6F7463611A6774
85801A6B36EC7F6F746573742063726C6F6373702D63610C58205EF8A355A001A7C5
0D23494701208131A4BB2AB920D40BFB0EE1F6AB28FF74008801542F45E78D2CAEDF
368CDF53C39005D492450E1056211860230107542DA3A403F7D2F4E0B3D8031A73BA
8A839F557F0F5840E50465D60C02A2111EF3FC6E44F2A36008765B552351F9A3F5B2
AA7C76F1F05D259847A4F4250B2E4B0AE2099762A2596D3CC1DB2CCD180AA0A2D0E1
91310B0F58403780CA6F1CF3BF133E867BF8F2EF0BE8F6EA07CD08C2C8B5402700FD
78A001A24EBCFA01B9B05FDC0250540DC91E2BEAEE70E68E81AA9E74E3A2776D1858
B404
~~~~~

Textual Representation

[comment]: <> (replace-data:ocspreq/signed-ocspreq-with-certchain/ocspreq.txt)
~~~~~
C509SignedOCSPRequest
  TBSOCSPRequest
    Type: C509SignedOCSPRequest (1)
    Signature Algorithm: Ed25519 (12)
    Hash Algorithm: SHA256 (1)
    RequestorCertHash
      44:f0:52:8b:56:f3:5a:d9:98:04:9b:30:6f:f9:a8:b0:
      6f:a7:9d:e8:14:69:46:fe:25:4b:00:c6:2a:62:2a:5d
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
          a0:1c:73:a5:f3:b0:63:34:42:57:d0:26:93:05:9d:ed:
          8e:22:c4:43:3b:1a:4d:85:ef:ae:22:f7:f9:d7:e4:3c
        extensions: <empty>
        singleRequests
          SingleCertRequest
            SerialNumberHash:
              10:65:27:87:fa:05:27:bc:24:49:a1:bf:c5:ab:31:aa:
              5a:6f:0d:8d:6b:99:8e:4f:ed:e7:d9:0d:ca:47:f0:04
            Extensions: <empty>
          SingleCertRequest
            SerialNumberHash:
              75:d8:bc:4f:ba:fc:66:94:46:76:41:e7:48:df:d5:3a:
              8b:9d:17:6d:fa:3d:05:b3:e9:8a:4d:6e:5c:55:f1:65
            Extensions: <empty>
          SingleCertRequest
            SerialNumberHash:
              d1:ac:13:5d:7d:a2:9b:dc:f4:dc:a0:d5:28:1a:51:60:
              5b:67:84:00:c2:64:08:ca:dc:3a:32:fc:1b:6a:d5:e3
            Extensions: <empty>
      OcspPerIssuerRequest
        issuerCertHash
          22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:
          22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22
        extensions: <empty>
        singleRequests
          SingleCertRequest
            SerialNumberHash:
              d3:a0:c1:e3:db:92:e8:f6:81:05:37:d4:5c:fa:ec:f6:
              ce:41:7e:3b:26:4e:50:cb:4f:69:dd:85:34:01:c5:dd
            Extensions: <empty>
    Requestor Certs
      ~C509Certificate
        02:42:12:36:0c:6f:74:65:73:74:20:63:72:6c:6f:63:
        73:70:2d:63:61:1a:67:75:d7:00:1a:69:57:0a:80:6e:
        6f:63:73:70:2d:72:65:71:75:65:73:74:6f:72:0c:58:
        20:04:53:0b:17:64:ed:d4:b4:e3:3a:b4:4a:f0:f8:38:
        96:1c:00:71:76:d7:4b:6a:35:46:ec:b7:fd:57:32:0d:
        d3:86:01:54:dd:51:bd:b2:a2:c7:91:c0:62:d4:02:78:
        56:db:ac:f5:26:07:f0:be:21:01:07:54:2f:45:e7:8d:
        2c:ae:df:36:8c:df:53:c3:90:05:d4:92:45:0e:10:56:
        58:40:f8:c6:18:3e:cf:8c:3e:fd:50:dd:49:42:d1:72:
        81:4c:46:ec:0f:c0:1d:d5:86:a5:97:17:8d:f8:64:a0:
        d9:da:86:b7:ca:17:fc:9f:77:2f:f0:4c:80:e9:8b:60:
        d5:b4:b6:24:08:a2:77:a5:b7:0d:0d:2a:3f:5e:d5:44:
        2d:07
      ~C509Certificate
        02:41:01:0c:73:74:65:73:74:20:63:72:6c:6f:63:73:
        70:2d:72:6f:6f:74:63:61:1a:67:74:85:80:1a:6b:36:
        ec:7f:6f:74:65:73:74:20:63:72:6c:6f:63:73:70:2d:
        63:61:0c:58:20:5e:f8:a3:55:a0:01:a7:c5:0d:23:49:
        47:01:20:81:31:a4:bb:2a:b9:20:d4:0b:fb:0e:e1:f6:
        ab:28:ff:74:00:88:01:54:2f:45:e7:8d:2c:ae:df:36:
        8c:df:53:c3:90:05:d4:92:45:0e:10:56:21:18:60:23:
        01:07:54:2d:a3:a4:03:f7:d2:f4:e0:b3:d8:03:1a:73:
        ba:8a:83:9f:55:7f:0f:58:40:e5:04:65:d6:0c:02:a2:
        11:1e:f3:fc:6e:44:f2:a3:60:08:76:5b:55:23:51:f9:
        a3:f5:b2:aa:7c:76:f1:f0:5d:25:98:47:a4:f4:25:0b:
        2e:4b:0a:e2:09:97:62:a2:59:6d:3c:c1:db:2c:cd:18:
        0a:a0:a2:d0:e1:91:31:0b:0f
  Signature Value
    37:80:ca:6f:1c:f3:bf:13:3e:86:7b:f8:f2:ef:0b:e8:
    f6:ea:07:cd:08:c2:c8:b5:40:27:00:fd:78:a0:01:a2:
    4e:bc:fa:01:b9:b0:5f:dc:02:50:54:0d:c9:1e:2b:ea:
    ee:70:e6:8e:81:aa:9e:74:e3:a2:77:6d:18:58:b4:04
~~~~~

Annotated hex

[comment]: <> (replace-data:ocspreq/signed-ocspreq-with-certchain/ocspreq.diag)
~~~~~
  0: 89             # C509OCSPRequest=array[9]
  1:   01             # [0]. ocspRequestType=C509SignedOCSPRequest
                      #      (1)
  2:   0C             # [1]. signatureAlgorithm: Ed25519 (12)
  3:   01             # [2]. hashAlgorithm: SHA256 (1)
  4:   50             # [3]. nonce=byte[16]
  5:     11111111111111111111111111111111
 21:   58 20          # [4]. requestorCertHash=byte[32]
 23:     44F0528B56F35AD998049B306FF9A8B06FA79DE8146946FE254B00C62A
 52:     622A5D
 55:   84             # [5]. extensions=array[4]
                        #---extension[0]---
 56:     18 5D          # [0]. type: AcceptOCSPResponseTypes (93)
 58:     82             # [1]. value=array[2]
 59:       00             # [0]. C509ErrorOCSPResponse (0)
 60:       01             # [1]. C509BasicOCSPResponse (1)
                        #---extension[1]---
 61:     18 5E          # [2]. type: preferredSignatureAlgorithms
                        #      (94)
 63:     84             # [3]. value=array[4]
                          #---preferredSignatureAlgorithms[0]---
 64:       0C             # [0]. sigIdentifier: Ed25519 (12)
 65:       F6             # [1]. pubKeyAlgIdentifiers=<null>
                          #---preferredSignatureAlgorithms[1]---
 66:       00             # [2]. sigIdentifier: ecdsa-with-sha256
                          #      (0)
 67:       82             # [3]. pubKeyAlgIdentifiers=array[2]
 68:         01             # [0]. pubKeyAlgIdentifier: EC public
                            #      key on curve secp256r1 (1)
 69:         18 18          # [1]. pubKeyAlgIdentifier: EC public
                            #      key on curve brainpoolp256r1 (24)
 71:   86             # [6]. requests=array[6]
                        #---PerIssuerRequests[0]---
 72:     58 20          # [0]. issuerCertHash=byte[32]
 74:       A01C73A5F3B063344257D02693059DED8E22C4433B1A4D85EFAE22F7
102:       F9D7E43C
106:     80             # [1]. extensions=array[0]
107:     86             # [2]. singleRequests=array[6]
                          #---SingleCertRequests[0]---
108:       58 20          # [0]. serialNumberHash=byte[32]
110:         10652787FA0527BC2449A1BFC5AB31AA5A6F0D8D6B998E4FEDE7D9
137:         0DCA47F004
142:       80             # [1]. extensions=array[0]
                          #---SingleCertRequests[1]---
143:       58 20          # [2]. serialNumberHash=byte[32]
145:         75D8BC4FBAFC6694467641E748DFD53A8B9D176DFA3D05B3E98A4D
172:         6E5C55F165
177:       80             # [3]. extensions=array[0]
                          #---SingleCertRequests[2]---
178:       58 20          # [4]. serialNumberHash=byte[32]
180:         D1AC135D7DA29BDCF4DCA0D5281A51605B678400C26408CADC3A32
207:         FC1B6AD5E3
212:       80             # [5]. extensions=array[0]
                        #---PerIssuerRequests[1]---
213:     58 20          # [3]. issuerCertHash=byte[32]
215:       22222222222222222222222222222222222222222222222222222222
243:       22222222
247:     80             # [4]. extensions=array[0]
248:     82             # [5]. singleRequests=array[2]
                          #---SingleCertRequests[0]---
249:       58 20          # [0]. serialNumberHash=byte[32]
251:         D3A0C1E3DB92E8F6810537D45CFAECF6CE417E3B264E50CB4F69DD
278:         853401C5DD
283:       80             # [1]. extensions=array[0]
284:   82             # [7]. requestorCerts(COSE_C509)=array[2]
285:     58 C2          # [0]. C509CertData=byte[194]
287:       024212360C6F746573742063726C6F6373702D63611A6775D7001A69
315:       570A806E6F6373702D726571756573746F720C582004530B1764EDD4
343:       B4E33AB44AF0F838961C007176D74B6A3546ECB7FD57320DD3860154
371:       DD51BDB2A2C791C062D4027856DBACF52607F0BE210107542F45E78D
399:       2CAEDF368CDF53C39005D492450E10565840F8C6183ECF8C3EFD50DD
427:       4942D172814C46EC0FC01DD586A597178DF864A0D9DA86B7CA17FC9F
455:       772FF04C80E98B60D5B4B62408A277A5B70D0D2A3F5ED5442D07
481:     58 C9          # [1]. C509CertData=byte[201]
483:       0241010C73746573742063726C6F6373702D726F6F7463611A677485
511:       801A6B36EC7F6F746573742063726C6F6373702D63610C58205EF8A3
539:       55A001A7C50D23494701208131A4BB2AB920D40BFB0EE1F6AB28FF74
567:       008801542F45E78D2CAEDF368CDF53C39005D492450E105621186023
595:       0107542DA3A403F7D2F4E0B3D8031A73BA8A839F557F0F5840E50465
623:       D60C02A2111EF3FC6E44F2A36008765B552351F9A3F5B2AA7C76F1F0
651:       5D259847A4F4250B2E4B0AE2099762A2596D3CC1DB2CCD180AA0A2D0
679:       E191310B0F
684:   58 40          # [8]. signatureValue=byte[64]
686:     3780CA6F1CF3BF133E867BF8F2EF0BE8F6EA07CD08C2C8B5402700FD78
715:     A001A24EBCFA01B9B05FDC0250540DC91E2BEAEE70E68E81AA9E74E3A2
744:     776D1858B404
~~~~~

## OCSP Response Examples

### Error OCSP Response Example {#exam-error-ocsp-resp}

[comment]: <> (replace-percent:ocspresp/error-ocspresp/ocspresp.hex % ocspresp/error-ocspresp/x509ocspresp.pem)
- size(C509) / size(X509): 60%
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

[comment]: <> (replace-percent:ocspresp/simple-ocspresp/ocspresp.hex % ocspresp/simple-ocspresp/x509ocspresp.pem)
- size(C509) / size(X509): 60%
- Verifiable with certificate in {{ocsp-responder-cert}}
- Simple OCSP Response (`C509SimpleOCSPResponse`) without responder's certificate
- Note that the X.509 OCSP response and the C509 OCSP response are not convertible.

#### X.509 OCSP Response

[comment]: <> (replace-size:ocspresp/simple-ocspresp/x509ocspresp.pem)
PEM content (336 bytes):

[comment]: <> (replace-data:ocspresp/simple-ocspresp/x509ocspresp.pem)
~~~~~
-----BEGIN OCSP RESPONSE-----
MIIBTAoBAKCCAUUwggFBBgkrBgEFBQcwAQEEggEyMIIBLjCB4aIWBBTq5ZqK6ar0
EEsV5Q6O4BcVF3QYrxgPMjAyNTAzMDMwMDAwMDBaMIGSMIGPMGcwCwYJYIZIAWUD
BAIBBCAyU450hb03rkVPHw0rl1XXWLkfbo46evOXoPQAYFxv+AQgzBHIdAoFCexN
oUzliG5yNkwPY7YO1jR/E8Fu5yW3ZqICFBI0EjQSNBI0EjQSNBI0EjQSNBI0gAAY
DzIwMjUwMzAyMTYwMDAwWqARGA8yMDI1MDMwMzA3MDAwMFqhITAfMB0GCSsGAQUF
BzABAgQQERERERERERERERERERERETAFBgMrZXADQQAoVz6mB1JqePHWA2adyeK4
ElU3cwbFiAepAQkUhmtUT9vU4J4mc/QxA39Ja36kVABy8+f62xw0f+5v3G9LTS0M
-----END OCSP RESPONSE-----
~~~~~

#### C509 OCSP Response

[comment]: <> (replace-size:ocspresp/simple-ocspresp/ocspresp.hex)
Plain Hex (203 bytes):

[comment]: <> (replace-data:ocspresp/simple-ocspresp/ocspresp.hex)
~~~~~
8E020C01501111111111111111111111111111111158200600867838E3311AA78B9E
D60C631C86B09A6DE7BC43E02A7AA7006A3443A3B25820A01C73A5F3B063344257D0
2693059DED8E22C4433B1A4D85EFAE22F7F9D7E43C582010652787FA0527BC2449A1
BFC5AB31AA5A6F0D8D6B998E4FEDE7D90DCA47F004001A67C4F10039707F19627080
F65840BD269E74AC6C9EBFE4E0A46A64CFD432CC06068C4D073FD515D0D276437AE5
EC8BAA611D3A7795E6B299C7539AF3140EE768D19A05BD23B1E2C2F546C7738B07
~~~~~

Textual Representation

[comment]: <> (replace-data:ocspresp/simple-ocspresp/ocspresp.txt)
~~~~~
C509SimpleOCSPResponse
  TBSSimpleOCSPResponse
    Type: C509SimpleOCSPResponse (2)
    Signature Algorithm: Ed25519 (12)
    Hash Algorithm: SHA256 (1)
    Nonce
      11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11
    ResponderCertHash
      06:00:86:78:38:e3:31:1a:a7:8b:9e:d6:0c:63:1c:86:
      b0:9a:6d:e7:bc:43:e0:2a:7a:a7:00:6a:34:43:a3:b2
    IssuerCertHash
      a0:1c:73:a5:f3:b0:63:34:42:57:d0:26:93:05:9d:ed:
      8e:22:c4:43:3b:1a:4d:85:ef:ae:22:f7:f9:d7:e4:3c
    SerialNumberHash
      10:65:27:87:fa:05:27:bc:24:49:a1:bf:c5:ab:31:aa:
      5a:6f:0d:8d:6b:99:8e:4f:ed:e7:d9:0d:ca:47:f0:04
    Cert Status: good
      This Update: -28800 seconds
      Next Update: 25200 seconds
    Extensions: <empty>
    Responder Certs: null
  Signature Value
    bd:26:9e:74:ac:6c:9e:bf:e4:e0:a4:6a:64:cf:d4:32:
    cc:06:06:8c:4d:07:3f:d5:15:d0:d2:76:43:7a:e5:ec:
    8b:aa:61:1d:3a:77:95:e6:b2:99:c7:53:9a:f3:14:0e:
    e7:68:d1:9a:05:bd:23:b1:e2:c2:f5:46:c7:73:8b:07
~~~~~

Annotated hex

[comment]: <> (replace-data:ocspresp/simple-ocspresp/ocspresp.diag)
~~~~~
  0: 8E             # C509OCSPResponse=array[14]
  1:   02             # [0]. ocspResponseType=C509SimpleOCSPResponse
                      #      (2)
  2:   0C             # [1]. signatureAlgorithm: Ed25519 (12)
  3:   01             # [2]. hashAlgorithm: SHA256 (1)
  4:   50             # [3]. nonce=byte[16]
  5:     11111111111111111111111111111111
 21:   58 20          # [4]. responderCertHash=byte[32]
 23:     0600867838E3311AA78B9ED60C631C86B09A6DE7BC43E02A7AA7006A34
 52:     43A3B2
 55:   58 20          # [5]. issuerCertHash=byte[32]
 57:     A01C73A5F3B063344257D02693059DED8E22C4433B1A4D85EFAE22F7F9
 86:     D7E43C
 89:   58 20          # [6]. serialNumberHash=byte[32]
 91:     10652787FA0527BC2449A1BFC5AB31AA5A6F0D8D6B998E4FEDE7D90DCA
120:     47F004
123:   00             # [7]. certStatus=good (0)
124:   1A 67C4F100    # [8]. producedAt=1740960000:
                      #      2025-03-03T00:00:00Z
129:   39 707F        # [9]. thisUpdate=-28800
132:   19 6270        # [10]. nextUpdate=25200
135:   80             # [11]. extensions=array[0]
136:   F6             # [12]. responderCerts=<null>
137:   58 40          # [13]. signatureValue=byte[64]
139:     BD269E74AC6C9EBFE4E0A46A64CFD432CC06068C4D073FD515D0D27643
168:     7AE5EC8BAA611D3A7795E6B299C7539AF3140EE768D19A05BD23B1E2C2
197:     F546C7738B07
~~~~~


### Basic OCSP Response Example Without Responder's Certificate {#exam-basic-ocsp-resp}

[comment]: <> (replace-percent:ocspresp/basic-ocspresp/ocspresp.hex % ocspresp/basic-ocspresp/x509ocspresp.pem)
- size(C509) / size(X509): 44%
- Verifiable with certificate in {{ocsp-responder-cert}}
- Basic OCSP Response (`C509BasicOCSPResponse`) without responder's certificate
- Note that the X.509 OCSP response and the C509 OCSP response are not convertible.

#### X.509 OCSP Response

[comment]: <> (replace-size:ocspresp/basic-ocspresp/x509ocspresp.pem)
PEM content (837 bytes):

[comment]: <> (replace-data:ocspresp/basic-ocspresp/x509ocspresp.pem)
~~~~~
-----BEGIN OCSP RESPONSE-----
MIIDQQoBAKCCAzowggM2BgkrBgEFBQcwAQEEggMnMIIDIzCCAtWiFgQU6uWaiumq
9BBLFeUOjuAXFRd0GK8YDzIwMjYwNjA5MTc1NzEwWjCCAnQwgY8wZzALBglghkgB
ZQMEAgEEIDJTjnSFvTeuRU8fDSuXVddYuR9ujjp685eg9ABgXG/4BCDMEch0CgUJ
7E2hTOWIbnI2TA9jtg7WNH8TwW7nJbdmogIUEjQSNBI0EjQSNBI0EjQSNBI0EjSA
ABgPMjAyNjA2MDkwOTU3MTBaoBEYDzIwMjYwNjEwMDA1NzEwWjCBpTBnMAsGCWCG
SAFlAwQCAQQgMlOOdIW9N65FTx8NK5dV11i5H26OOnrzl6D0AGBcb/gEIMwRyHQK
BQnsTaFM5YhucjZMD2O2DtY0fxPBbuclt2aiAhQ0VjRWNFY0VjRWNFY0VjRWNFY0
VqEWGA8xOTcwMDEwMTAwMDAwMFqgAwoBBhgPMjAyNjA2MDkwOTU3MTBaoBEYDzIw
MjYwNjEwMDA1NzEwWjCBpTBnMAsGCWCGSAFlAwQCAQQgMlOOdIW9N65FTx8NK5dV
11i5H26OOnrzl6D0AGBcb/gEIMwRyHQKBQnsTaFM5YhucjZMD2O2DtY0fxPBbucl
t2aiAhRWeFZ4VnhWeFZ4VnhWeFZ4VnhWeKEWGA8yMDI1MDMwMTE2MDAwMFqgAwoB
BBgPMjAyNjA2MDkwOTU3MTBaoBEYDzIwMjYwNjEwMDA1NzEwWjCBjzBnMAsGCWCG
SAFlAwQCAQQgMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMEIERERERE
REREREREREREREREREREREREREREREREREREAhQiMyIzIjMiMyIzIjMiMyIzIjMi
M4IAGA8yMDI2MDYwOTA5NTcxMFqgERgPMjAyNjA2MTAwMDU3MTBaoTIwMDAdBgkr
BgEFBQcwAQIEEBEREREREREREREREREREREwDwYJKwYBBQUHMAEJBAIFADAFBgMr
ZXADQQCkIJZu415zr8fjnf0RiAg4rYVH/aBYaIGB1eYhWxu2zdQLdud66Ff+TAsN
1hQmDKNjLqOeIkzt82w5x5z7FMQF
-----END OCSP RESPONSE-----
~~~~~

#### C509 OCSP Response

[comment]: <> (replace-size:ocspresp/basic-ocspresp/ocspresp.hex)
Plain Hex (375 bytes):

[comment]: <> (replace-data:ocspresp/basic-ocspresp/ocspresp.hex)
~~~~~
8A010C01501111111111111111111111111111111158200600867838E3311AA78B9E
D60C631C86B09A6DE7BC43E02A7AA7006A3443A3B21A6A2853F680865820A01C73A5
F3B063344257D02693059DED8E22C4433B1A4D85EFAE22F7F9D7E43C808F58201065
2787FA0527BC2449A1BFC5AB31AA5A6F0D8D6B998E4FEDE7D90DCA47F0040039707F
19627080582075D8BC4FBAFC6694467641E748DFD53A8B9D176DFA3D05B3E98A4D6E
5C55F1650139707F196270805820D1AC135D7DA29BDCF4DCA0D5281A51605B678400
C26408CADC3A32FC1B6AD5E3821A67C32F000439707F196270805820222222222222
222222222222222222222222222222222222222222222222222280855820D3A0C1E3
DB92E8F6810537D45CFAECF6CE417E3B264E50CB4F69DD853401C5DD0239707F1962
7080F65840937EA7CCCAD3B9F113ED6AD0DF113BF5E70FBF326E020FF5183AC87E55
30FF06225F1AA048D76D39D412EC26C3AD9B74668791559E6973308E11DCABDA8262
07
~~~~~

Textual Representation

[comment]: <> (replace-data:ocspresp/basic-ocspresp/ocspresp.txt)
~~~~~
C509BasicOCSPResponse
  TBSBasicOCSPResponse
    Type: C509BasicOCSPResponse (1)
    Signature Algorithm: Ed25519 (12)
    Hash Algorithm: SHA256 (1)
    Nonce
      11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11
    ResponderCertHash
      06:00:86:78:38:e3:31:1a:a7:8b:9e:d6:0c:63:1c:86:
      b0:9a:6d:e7:bc:43:e0:2a:7a:a7:00:6a:34:43:a3:b2
    ProducedAt: 2026-06-09T17:57:10.299864Z
    Extensions: <empty>
    Responses
      OcspPerIssuerResponse
        IssuerCertHash
          a0:1c:73:a5:f3:b0:63:34:42:57:d0:26:93:05:9d:ed:
          8e:22:c4:43:3b:1a:4d:85:ef:ae:22:f7:f9:d7:e4:3c
        Extensions: <empty>
        SingleResponses
          SingleCertResponse
            SerialNumberHash:
              10:65:27:87:fa:05:27:bc:24:49:a1:bf:c5:ab:31:aa:
              5a:6f:0d:8d:6b:99:8e:4f:ed:e7:d9:0d:ca:47:f0:04
            Cert Status: good
            This Update: -28800 seconds
            Next Update: 25200 seconds
            Extensions: <empty>
          SingleCertResponse
            SerialNumberHash:
              75:d8:bc:4f:ba:fc:66:94:46:76:41:e7:48:df:d5:3a:
              8b:9d:17:6d:fa:3d:05:b3:e9:8a:4d:6e:5c:55:f1:65
            Cert Status: not-issued
            This Update: -28800 seconds
            Next Update: 25200 seconds
            Extensions: <empty>
          SingleCertResponse
            SerialNumberHash:
              d1:ac:13:5d:7d:a2:9b:dc:f4:dc:a0:d5:28:1a:51:60:
              5b:67:84:00:c2:64:08:ca:dc:3a:32:fc:1b:6a:d5:e3
            Cert Status: revoked (superseded)
              Revoked at 2025-03-01T16:00:00Z
            This Update: -28800 seconds
            Next Update: 25200 seconds
            Extensions: <empty>
      OcspPerIssuerResponse
        IssuerCertHash
          22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:
          22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22
        Extensions: <empty>
        SingleResponses
          SingleCertResponse
            SerialNumberHash:
              d3:a0:c1:e3:db:92:e8:f6:81:05:37:d4:5c:fa:ec:f6:
              ce:41:7e:3b:26:4e:50:cb:4f:69:dd:85:34:01:c5:dd
            Cert Status: unknown
            This Update: -28800 seconds
            Next Update: 25200 seconds
            Extensions: <empty>
    Responder Certs: null
  Signature Value
    93:7e:a7:cc:ca:d3:b9:f1:13:ed:6a:d0:df:11:3b:f5:
    e7:0f:bf:32:6e:02:0f:f5:18:3a:c8:7e:55:30:ff:06:
    22:5f:1a:a0:48:d7:6d:39:d4:12:ec:26:c3:ad:9b:74:
    66:87:91:55:9e:69:73:30:8e:11:dc:ab:da:82:62:07
~~~~~

Annotated hex

[comment]: <> (replace-data:ocspresp/basic-ocspresp/ocspresp.diag)
~~~~~
  0: 8A             # C509OCSPResponse=array[10]
  1:   01             # [0]. ocspResponseType=C509BasicOCSPResponse
                      #      (1)
  2:   0C             # [1]. signatureAlgorithm: Ed25519 (12)
  3:   01             # [2]. hashAlgorithm: SHA256 (1)
  4:   50             # [3]. nonce=byte[16]
  5:     11111111111111111111111111111111
 21:   58 20          # [4]. responderCertHash=byte[32]
 23:     0600867838E3311AA78B9ED60C631C86B09A6DE7BC43E02A7AA7006A34
 52:     43A3B2
 55:   1A 6A2853F6    # [5]. producedAt=1781027830:
                      #      2026-06-09T17:57:10Z
 60:   80             # [6]. extensions=array[0]
 61:   86             # [7]. responses=array[6]
                        #---PerIssuerResponses[0]---
 62:     58 20          # [0]. issuerCertHash=byte[32]
 64:       A01C73A5F3B063344257D02693059DED8E22C4433B1A4D85EFAE22F7
 92:       F9D7E43C
 96:     80             # [1]. extensions=array[0]
 97:     8F             # [2]. singleResponses=array[15]
                          #---SingleCertResponses[0]---
 98:       58 20          # [0]. serialNumberHash=byte[32]
100:         10652787FA0527BC2449A1BFC5AB31AA5A6F0D8D6B998E4FEDE7D9
127:         0DCA47F004
132:       00             # [1]. certStatus=good (0)
133:       39 707F        # [2]. thisUpdate=-28800
136:       19 6270        # [3]. nextUpdate=25200
139:       80             # [4]. extensions=array[0]
                          #---SingleCertResponses[1]---
140:       58 20          # [5]. serialNumberHash=byte[32]
142:         75D8BC4FBAFC6694467641E748DFD53A8B9D176DFA3D05B3E98A4D
169:         6E5C55F165
174:       01             # [6]. certStatus=not-issued (1)
175:       39 707F        # [7]. thisUpdate=-28800
178:       19 6270        # [8]. nextUpdate=25200
181:       80             # [9]. extensions=array[0]
                          #---SingleCertResponses[2]---
182:       58 20          # [10]. serialNumberHash=byte[32]
184:         D1AC135D7DA29BDCF4DCA0D5281A51605B678400C26408CADC3A32
211:         FC1B6AD5E3
216:       82             # [11]. certStatus=array[2]
217:         1A 67C32F00    # [0]. revocationTime=1740844800:
                            #      2025-03-01T16:00:00Z
222:         04             # [1]. revocationReason=superseded (4)
223:       39 707F        # [12]. thisUpdate=-28800
226:       19 6270        # [13]. nextUpdate=25200
229:       80             # [14]. extensions=array[0]
                        #---PerIssuerResponses[1]---
230:     58 20          # [3]. issuerCertHash=byte[32]
232:       22222222222222222222222222222222222222222222222222222222
260:       22222222
264:     80             # [4]. extensions=array[0]
265:     85             # [5]. singleResponses=array[5]
                          #---SingleCertResponses[0]---
266:       58 20          # [0]. serialNumberHash=byte[32]
268:         D3A0C1E3DB92E8F6810537D45CFAECF6CE417E3B264E50CB4F69DD
295:         853401C5DD
300:       02             # [1]. certStatus=unknown (2)
301:       39 707F        # [2]. thisUpdate=-28800
304:       19 6270        # [3]. nextUpdate=25200
307:       80             # [4]. extensions=array[0]
308:   F6             # [8]. responderCerts=<null>
309:   58 40          # [9]. signature value=byte[64]
311:     937EA7CCCAD3B9F113ED6AD0DF113BF5E70FBF326E020FF5183AC87E55
340:     30FF06225F1AA048D76D39D412EC26C3AD9B74668791559E6973308E11
369:     DCABDA826207
~~~~~

### Basic OCSP Response Example With Responder's Certificate {#exam-basic-ocsp-resp-withcert}

[comment]: <> (replace-percent:ocspresp/basic-ocspresp-with-cert/ocspresp.hex % ocspresp/basic-ocspresp-with-cert/x509ocspresp.pem)
- size(C509) / size(X509): 48%
- Verifiable with certificate in {{ocsp-responder-cert}}
- Basic OCSP Response (`C509BasicOCSPResponse`) with embedded responder's certificate
- Note that the X.509 OCSP response and the C509 OCSP response are not convertible.

#### X.509 OCSP Response

[comment]: <> (replace-size:ocspresp/basic-ocspresp-with-cert/x509ocspresp.pem)
PEM content (1181 bytes):

[comment]: <> (replace-data:ocspresp/basic-ocspresp-with-cert/x509ocspresp.pem)
~~~~~
-----BEGIN OCSP RESPONSE-----
MIIEmQoBAKCCBJIwggSOBgkrBgEFBQcwAQEEggR/MIIEezCCAtWiFgQU6uWaiumq
9BBLFeUOjuAXFRd0GK8YDzIwMjYwNjA5MTc1NzEwWjCCAnQwgY8wZzALBglghkgB
ZQMEAgEEIDJTjnSFvTeuRU8fDSuXVddYuR9ujjp685eg9ABgXG/4BCDMEch0CgUJ
7E2hTOWIbnI2TA9jtg7WNH8TwW7nJbdmogIUEjQSNBI0EjQSNBI0EjQSNBI0EjSA
ABgPMjAyNjA2MDkwOTU3MTBaoBEYDzIwMjYwNjEwMDA1NzEwWjCBpTBnMAsGCWCG
SAFlAwQCAQQgMlOOdIW9N65FTx8NK5dV11i5H26OOnrzl6D0AGBcb/gEIMwRyHQK
BQnsTaFM5YhucjZMD2O2DtY0fxPBbuclt2aiAhQ0VjRWNFY0VjRWNFY0VjRWNFY0
VqEWGA8xOTcwMDEwMTAwMDAwMFqgAwoBBhgPMjAyNjA2MDkwOTU3MTBaoBEYDzIw
MjYwNjEwMDA1NzEwWjCBpTBnMAsGCWCGSAFlAwQCAQQgMlOOdIW9N65FTx8NK5dV
11i5H26OOnrzl6D0AGBcb/gEIMwRyHQKBQnsTaFM5YhucjZMD2O2DtY0fxPBbucl
t2aiAhRWeFZ4VnhWeFZ4VnhWeFZ4VnhWeKEWGA8yMDI1MDMwMTE2MDAwMFqgAwoB
BBgPMjAyNjA2MDkwOTU3MTBaoBEYDzIwMjYwNjEwMDA1NzEwWjCBjzBnMAsGCWCG
SAFlAwQCAQQgMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMEIERERERE
REREREREREREREREREREREREREREREREREREAhQiMyIzIjMiMyIzIjMiMyIzIjMi
M4IAGA8yMDI2MDYwOTA5NTcxMFqgERgPMjAyNjA2MTAwMDU3MTBaoTIwMDAdBgkr
BgEFBQcwAQIEEBEREREREREREREREREREREwDwYJKwYBBQUHMAEJBAIFADAFBgMr
ZXADQQCkIJZu415zr8fjnf0RiAg4rYVH/aBYaIGB1eYhWxu2zdQLdud66Ff+TAsN
1hQmDKNjLqOeIkzt82w5x5z7FMQFoIIBVDCCAVAwggFMMIH/oAMCAQICAhI1MAUG
AytlcDAaMRgwFgYDVQQDDA90ZXN0IGNybG9jc3AtY2EwHhcNMjUwMTAyMDAwMDAw
WhcNMjYwMTAyMDAwMDAwWjAZMRcwFQYDVQQDDA5vY3NwLXJlc3BvbmRlcjAqMAUG
AytlcAMhAIGUe7wkiqx5c4IRqNdb+Sy3d9mUBz3yOuBjgO8sVzl2o2owaDAdBgNV
HQ4EFgQU6uWaiumq9BBLFeUOjuAXFRd0GK8wDgYDVR0PAQH/BAQDAgeAMB8GA1Ud
IwQYMBaAFNl9d+Y0wvcAMAylj8h3NlsVUAeiMBYGA1UdJQEB/wQMMAoGCCsGAQUF
BwMJMAUGAytlcANBABOjKOFFurdnjAVsbGF91L4VCZ2qF1Dh+3wLKakj1yv394ef
hUq5LdEQsV83LeBZZoIvh06AhhH9Rd09LFwohwg=
-----END OCSP RESPONSE-----
~~~~~

#### C509 OCSP Response

[comment]: <> (replace-size:ocspresp/basic-ocspresp-with-cert/ocspresp.hex)
Plain Hex (572 bytes):

[comment]: <> (replace-data:ocspresp/basic-ocspresp-with-cert/ocspresp.hex)
~~~~~
8A010C01501111111111111111111111111111111158200600867838E3311AA78B9E
D60C631C86B09A6DE7BC43E02A7AA7006A3443A3B21A6A2853F680865820A01C73A5
F3B063344257D02693059DED8E22C4433B1A4D85EFAE22F7F9D7E43C808F58201065
2787FA0527BC2449A1BFC5AB31AA5A6F0D8D6B998E4FEDE7D90DCA47F0040039707F
19627080582075D8BC4FBAFC6694467641E748DFD53A8B9D176DFA3D05B3E98A4D6E
5C55F1650139707F196270805820D1AC135D7DA29BDCF4DCA0D5281A51605B678400
C26408CADC3A32FC1B6AD5E3821A67C32F000439707F196270805820222222222222
222222222222222222222222222222222222222222222222222280855820D3A0C1E3
DB92E8F6810537D45CFAECF6CE417E3B264E50CB4F69DD853401C5DD0239707F1962
708058C4024212350C6F746573742063726C6F6373702D63611A6775D7001A69570A
806E6F6373702D726573706F6E6465720C582081947BBC248AAC79738211A8D75BF9
2CB777D994073DF23AE06380EF2C573976880154B5B4CAF35401D06151DF9629DB57
9DC8CCA453A8210107542F45E78D2CAEDF368CDF53C39005D492450E105627095840
A01B0CBF3E34A4762D05404FD08A7AEC103035358314686D72B6159078C76E1D8859
7F37531886A3F52F256FD722192B289D6844014467F1F17F05ACBB7B660A5840BEEC
17B64803DB982258D246C443EBEF3757BBB236C578DB2E61FE4D2AD15111AD1E51C2
93F7D47A07839ECBF9A0EE96B7DB34342CFBDCD664ACB2B8928EE408
~~~~~

Textual Representation

[comment]: <> (replace-data:ocspresp/basic-ocspresp-with-cert/ocspresp.txt)
~~~~~
C509BasicOCSPResponse
  TBSBasicOCSPResponse
    Type: C509BasicOCSPResponse (1)
    Signature Algorithm: Ed25519 (12)
    Hash Algorithm: SHA256 (1)
    Nonce
      11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11
    ResponderCertHash
      06:00:86:78:38:e3:31:1a:a7:8b:9e:d6:0c:63:1c:86:
      b0:9a:6d:e7:bc:43:e0:2a:7a:a7:00:6a:34:43:a3:b2
    ProducedAt: 2026-06-09T17:57:10.309347Z
    Extensions: <empty>
    Responses
      OcspPerIssuerResponse
        IssuerCertHash
          a0:1c:73:a5:f3:b0:63:34:42:57:d0:26:93:05:9d:ed:
          8e:22:c4:43:3b:1a:4d:85:ef:ae:22:f7:f9:d7:e4:3c
        Extensions: <empty>
        SingleResponses
          SingleCertResponse
            SerialNumberHash:
              10:65:27:87:fa:05:27:bc:24:49:a1:bf:c5:ab:31:aa:
              5a:6f:0d:8d:6b:99:8e:4f:ed:e7:d9:0d:ca:47:f0:04
            Cert Status: good
            This Update: -28800 seconds
            Next Update: 25200 seconds
            Extensions: <empty>
          SingleCertResponse
            SerialNumberHash:
              75:d8:bc:4f:ba:fc:66:94:46:76:41:e7:48:df:d5:3a:
              8b:9d:17:6d:fa:3d:05:b3:e9:8a:4d:6e:5c:55:f1:65
            Cert Status: not-issued
            This Update: -28800 seconds
            Next Update: 25200 seconds
            Extensions: <empty>
          SingleCertResponse
            SerialNumberHash:
              d1:ac:13:5d:7d:a2:9b:dc:f4:dc:a0:d5:28:1a:51:60:
              5b:67:84:00:c2:64:08:ca:dc:3a:32:fc:1b:6a:d5:e3
            Cert Status: revoked (superseded)
              Revoked at 2025-03-01T16:00:00Z
            This Update: -28800 seconds
            Next Update: 25200 seconds
            Extensions: <empty>
      OcspPerIssuerResponse
        IssuerCertHash
          22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:
          22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22
        Extensions: <empty>
        SingleResponses
          SingleCertResponse
            SerialNumberHash:
              d3:a0:c1:e3:db:92:e8:f6:81:05:37:d4:5c:fa:ec:f6:
              ce:41:7e:3b:26:4e:50:cb:4f:69:dd:85:34:01:c5:dd
            Cert Status: unknown
            This Update: -28800 seconds
            Next Update: 25200 seconds
            Extensions: <empty>
    Responder Certs
      ~C509Certificate
        02:42:12:35:0c:6f:74:65:73:74:20:63:72:6c:6f:63:
        73:70:2d:63:61:1a:67:75:d7:00:1a:69:57:0a:80:6e:
        6f:63:73:70:2d:72:65:73:70:6f:6e:64:65:72:0c:58:
        20:81:94:7b:bc:24:8a:ac:79:73:82:11:a8:d7:5b:f9:
        2c:b7:77:d9:94:07:3d:f2:3a:e0:63:80:ef:2c:57:39:
        76:88:01:54:b5:b4:ca:f3:54:01:d0:61:51:df:96:29:
        db:57:9d:c8:cc:a4:53:a8:21:01:07:54:2f:45:e7:8d:
        2c:ae:df:36:8c:df:53:c3:90:05:d4:92:45:0e:10:56:
        27:09:58:40:a0:1b:0c:bf:3e:34:a4:76:2d:05:40:4f:
        d0:8a:7a:ec:10:30:35:35:83:14:68:6d:72:b6:15:90:
        78:c7:6e:1d:88:59:7f:37:53:18:86:a3:f5:2f:25:6f:
        d7:22:19:2b:28:9d:68:44:01:44:67:f1:f1:7f:05:ac:
        bb:7b:66:0a
  Signature Value
    be:ec:17:b6:48:03:db:98:22:58:d2:46:c4:43:eb:ef:
    37:57:bb:b2:36:c5:78:db:2e:61:fe:4d:2a:d1:51:11:
    ad:1e:51:c2:93:f7:d4:7a:07:83:9e:cb:f9:a0:ee:96:
    b7:db:34:34:2c:fb:dc:d6:64:ac:b2:b8:92:8e:e4:08
~~~~~

Annotated hex

[comment]: <> (replace-data:ocspresp/basic-ocspresp-with-cert/ocspresp.diag)
~~~~~
  0: 8A             # C509OCSPResponse=array[10]
  1:   01             # [0]. ocspResponseType=C509BasicOCSPResponse
                      #      (1)
  2:   0C             # [1]. signatureAlgorithm: Ed25519 (12)
  3:   01             # [2]. hashAlgorithm: SHA256 (1)
  4:   50             # [3]. nonce=byte[16]
  5:     11111111111111111111111111111111
 21:   58 20          # [4]. responderCertHash=byte[32]
 23:     0600867838E3311AA78B9ED60C631C86B09A6DE7BC43E02A7AA7006A34
 52:     43A3B2
 55:   1A 6A2853F6    # [5]. producedAt=1781027830:
                      #      2026-06-09T17:57:10Z
 60:   80             # [6]. extensions=array[0]
 61:   86             # [7]. responses=array[6]
                        #---PerIssuerResponses[0]---
 62:     58 20          # [0]. issuerCertHash=byte[32]
 64:       A01C73A5F3B063344257D02693059DED8E22C4433B1A4D85EFAE22F7
 92:       F9D7E43C
 96:     80             # [1]. extensions=array[0]
 97:     8F             # [2]. singleResponses=array[15]
                          #---SingleCertResponses[0]---
 98:       58 20          # [0]. serialNumberHash=byte[32]
100:         10652787FA0527BC2449A1BFC5AB31AA5A6F0D8D6B998E4FEDE7D9
127:         0DCA47F004
132:       00             # [1]. certStatus=good (0)
133:       39 707F        # [2]. thisUpdate=-28800
136:       19 6270        # [3]. nextUpdate=25200
139:       80             # [4]. extensions=array[0]
                          #---SingleCertResponses[1]---
140:       58 20          # [5]. serialNumberHash=byte[32]
142:         75D8BC4FBAFC6694467641E748DFD53A8B9D176DFA3D05B3E98A4D
169:         6E5C55F165
174:       01             # [6]. certStatus=not-issued (1)
175:       39 707F        # [7]. thisUpdate=-28800
178:       19 6270        # [8]. nextUpdate=25200
181:       80             # [9]. extensions=array[0]
                          #---SingleCertResponses[2]---
182:       58 20          # [10]. serialNumberHash=byte[32]
184:         D1AC135D7DA29BDCF4DCA0D5281A51605B678400C26408CADC3A32
211:         FC1B6AD5E3
216:       82             # [11]. certStatus=array[2]
217:         1A 67C32F00    # [0]. revocationTime=1740844800:
                            #      2025-03-01T16:00:00Z
222:         04             # [1]. revocationReason=superseded (4)
223:       39 707F        # [12]. thisUpdate=-28800
226:       19 6270        # [13]. nextUpdate=25200
229:       80             # [14]. extensions=array[0]
                        #---PerIssuerResponses[1]---
230:     58 20          # [3]. issuerCertHash=byte[32]
232:       22222222222222222222222222222222222222222222222222222222
260:       22222222
264:     80             # [4]. extensions=array[0]
265:     85             # [5]. singleResponses=array[5]
                          #---SingleCertResponses[0]---
266:       58 20          # [0]. serialNumberHash=byte[32]
268:         D3A0C1E3DB92E8F6810537D45CFAECF6CE417E3B264E50CB4F69DD
295:         853401C5DD
300:       02             # [1]. certStatus=unknown (2)
301:       39 707F        # [2]. thisUpdate=-28800
304:       19 6270        # [3]. nextUpdate=25200
307:       80             # [4]. extensions=array[0]
308:   58 C4          # [8]. responderCerts(COSE_C509)=byte[196]
310:     024212350C6F746573742063726C6F6373702D63611A6775D7001A6957
339:     0A806E6F6373702D726573706F6E6465720C582081947BBC248AAC7973
368:     8211A8D75BF92CB777D994073DF23AE06380EF2C573976880154B5B4CA
397:     F35401D06151DF9629DB579DC8CCA453A8210107542F45E78D2CAEDF36
426:     8CDF53C39005D492450E105627095840A01B0CBF3E34A4762D05404FD0
455:     8A7AEC103035358314686D72B6159078C76E1D88597F37531886A3F52F
484:     256FD722192B289D6844014467F1F17F05ACBB7B660A
506:   58 40          # [9]. signature value=byte[64]
508:     BEEC17B64803DB982258D246C443EBEF3757BBB236C578DB2E61FE4D2A
537:     D15111AD1E51C293F7D47A07839ECBF9A0EE96B7DB34342CFBDCD664AC
566:     B2B8928EE408
~~~~~

### Basic OCSP Response Example With Responder's Certificate Chain {#exam-basic-ocsp-resp-withcertchain}

[comment]: <> (replace-percent:ocspresp/basic-ocspresp-with-certchain/ocspresp.hex % ocspresp/basic-ocspresp-with-certchain/x509ocspresp.pem)
- size(C509) / size(X509): 51%
- Verifiable with certificate in {{ocsp-responder-cert}}
- Basic OCSP Response (`C509BasicOCSPResponse`) with embedded responder's certificate chain (2 certificates)
- Note that the X.509 OCSP response and the C509 OCSP response are not convertible.

#### X.509 OCSP Response

[comment]: <> (replace-size:ocspresp/basic-ocspresp-with-certchain/x509ocspresp.pem)
PEM content (1517 bytes):

[comment]: <> (replace-data:ocspresp/basic-ocspresp-with-certchain/x509ocspresp.pem)
~~~~~
-----BEGIN OCSP RESPONSE-----
MIIF6QoBAKCCBeIwggXeBgkrBgEFBQcwAQEEggXPMIIFyzCCAtWiFgQU6uWaiumq
9BBLFeUOjuAXFRd0GK8YDzIwMjYwNjA5MTc1NzEwWjCCAnQwgY8wZzALBglghkgB
ZQMEAgEEIDJTjnSFvTeuRU8fDSuXVddYuR9ujjp685eg9ABgXG/4BCDMEch0CgUJ
7E2hTOWIbnI2TA9jtg7WNH8TwW7nJbdmogIUEjQSNBI0EjQSNBI0EjQSNBI0EjSA
ABgPMjAyNjA2MDkwOTU3MTBaoBEYDzIwMjYwNjEwMDA1NzEwWjCBpTBnMAsGCWCG
SAFlAwQCAQQgMlOOdIW9N65FTx8NK5dV11i5H26OOnrzl6D0AGBcb/gEIMwRyHQK
BQnsTaFM5YhucjZMD2O2DtY0fxPBbuclt2aiAhQ0VjRWNFY0VjRWNFY0VjRWNFY0
VqEWGA8xOTcwMDEwMTAwMDAwMFqgAwoBBhgPMjAyNjA2MDkwOTU3MTBaoBEYDzIw
MjYwNjEwMDA1NzEwWjCBpTBnMAsGCWCGSAFlAwQCAQQgMlOOdIW9N65FTx8NK5dV
11i5H26OOnrzl6D0AGBcb/gEIMwRyHQKBQnsTaFM5YhucjZMD2O2DtY0fxPBbucl
t2aiAhRWeFZ4VnhWeFZ4VnhWeFZ4VnhWeKEWGA8yMDI1MDMwMTE2MDAwMFqgAwoB
BBgPMjAyNjA2MDkwOTU3MTBaoBEYDzIwMjYwNjEwMDA1NzEwWjCBjzBnMAsGCWCG
SAFlAwQCAQQgMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMEIERERERE
REREREREREREREREREREREREREREREREREREAhQiMyIzIjMiMyIzIjMiMyIzIjMi
M4IAGA8yMDI2MDYwOTA5NTcxMFqgERgPMjAyNjA2MTAwMDU3MTBaoTIwMDAdBgkr
BgEFBQcwAQIEEBEREREREREREREREREREREwDwYJKwYBBQUHMAEJBAIFADAFBgMr
ZXADQQCkIJZu415zr8fjnf0RiAg4rYVH/aBYaIGB1eYhWxu2zdQLdud66Ff+TAsN
1hQmDKNjLqOeIkzt82w5x5z7FMQFoIICpDCCAqAwggFMMIH/oAMCAQICAhI1MAUG
AytlcDAaMRgwFgYDVQQDDA90ZXN0IGNybG9jc3AtY2EwHhcNMjUwMTAyMDAwMDAw
WhcNMjYwMTAyMDAwMDAwWjAZMRcwFQYDVQQDDA5vY3NwLXJlc3BvbmRlcjAqMAUG
AytlcAMhAIGUe7wkiqx5c4IRqNdb+Sy3d9mUBz3yOuBjgO8sVzl2o2owaDAdBgNV
HQ4EFgQU6uWaiumq9BBLFeUOjuAXFRd0GK8wDgYDVR0PAQH/BAQDAgeAMB8GA1Ud
IwQYMBaAFNl9d+Y0wvcAMAylj8h3NlsVUAeiMBYGA1UdJQEB/wQMMAoGCCsGAQUF
BwMJMAUGAytlcANBABOjKOFFurdnjAVsbGF91L4VCZ2qF1Dh+3wLKakj1yv394ef
hUq5LdEQsV83LeBZZoIvh06AhhH9Rd09LFwohwgwggFMMIH/oAMCAQICAQEwBQYD
K2VwMB4xHDAaBgNVBAMME3Rlc3QgY3Jsb2NzcC1yb290Y2EwHhcNMjUwMTAxMDAw
MDAwWhcNMjYxMjMxMjM1OTU5WjAaMRgwFgYDVQQDDA90ZXN0IGNybG9jc3AtY2Ew
KjAFBgMrZXADIQBe+KNVoAGnxQ0jSUcBIIExpLsquSDUC/sO4farKP90AKNmMGQw
HQYDVR0OBBYEFNl9d+Y0wvcAMAylj8h3NlsVUAeiMA4GA1UdDwEB/wQEAwIBBjAS
BgNVHRMBAf8ECDAGAQH/AgEBMB8GA1UdIwQYMBaAFJEjnPr554Nssp9R4TGR2xDT
rhaTMAUGAytlcANBANZeAdfL+kF/sXuZ95ftaSevVi/2Po01s+On04FgzGRnQBBN
jzkYl92rEZjz0FomGSBDYqb4PDOIIRs2vFY9QQI=
-----END OCSP RESPONSE-----
~~~~~

#### C509 OCSP Response

[comment]: <> (replace-size:ocspresp/basic-ocspresp-with-certchain/ocspresp.hex)
Plain Hex (776 bytes):

[comment]: <> (replace-data:ocspresp/basic-ocspresp-with-certchain/ocspresp.hex)
~~~~~
8A010C01501111111111111111111111111111111158200600867838E3311AA78B9E
D60C631C86B09A6DE7BC43E02A7AA7006A3443A3B21A6A2853F680865820A01C73A5
F3B063344257D02693059DED8E22C4433B1A4D85EFAE22F7F9D7E43C808F58201065
2787FA0527BC2449A1BFC5AB31AA5A6F0D8D6B998E4FEDE7D90DCA47F0040039707F
19627080582075D8BC4FBAFC6694467641E748DFD53A8B9D176DFA3D05B3E98A4D6E
5C55F1650139707F196270805820D1AC135D7DA29BDCF4DCA0D5281A51605B678400
C26408CADC3A32FC1B6AD5E3821A67C32F000439707F196270805820222222222222
222222222222222222222222222222222222222222222222222280855820D3A0C1E3
DB92E8F6810537D45CFAECF6CE417E3B264E50CB4F69DD853401C5DD0239707F1962
70808258C4024212350C6F746573742063726C6F6373702D63611A6775D7001A6957
0A806E6F6373702D726573706F6E6465720C582081947BBC248AAC79738211A8D75B
F92CB777D994073DF23AE06380EF2C573976880154B5B4CAF35401D06151DF9629DB
579DC8CCA453A8210107542F45E78D2CAEDF368CDF53C39005D492450E1056270958
40A01B0CBF3E34A4762D05404FD08A7AEC103035358314686D72B6159078C76E1D88
597F37531886A3F52F256FD722192B289D6844014467F1F17F05ACBB7B660A58C902
41010C73746573742063726C6F6373702D726F6F7463611A677485801A6B36EC7F6F
746573742063726C6F6373702D63610C58205EF8A355A001A7C50D23494701208131
A4BB2AB920D40BFB0EE1F6AB28FF74008801542F45E78D2CAEDF368CDF53C39005D4
92450E1056211860230107542DA3A403F7D2F4E0B3D8031A73BA8A839F557F0F5840
E50465D60C02A2111EF3FC6E44F2A36008765B552351F9A3F5B2AA7C76F1F05D2598
47A4F4250B2E4B0AE2099762A2596D3CC1DB2CCD180AA0A2D0E191310B0F58404C24
DD230EC5BC0760176761E0C085486BA084C3B2E97C4BE18CD4D341AF733E66F41120
11AACA150279F9CCDB34407D3F26448580F27B257C812A8CB2505B07
~~~~~

Textual Representation

[comment]: <> (replace-data:ocspresp/basic-ocspresp-with-certchain/ocspresp.txt)
~~~~~
C509BasicOCSPResponse
  TBSBasicOCSPResponse
    Type: C509BasicOCSPResponse (1)
    Signature Algorithm: Ed25519 (12)
    Hash Algorithm: SHA256 (1)
    Nonce
      11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11
    ResponderCertHash
      06:00:86:78:38:e3:31:1a:a7:8b:9e:d6:0c:63:1c:86:
      b0:9a:6d:e7:bc:43:e0:2a:7a:a7:00:6a:34:43:a3:b2
    ProducedAt: 2026-06-09T17:57:10.313310Z
    Extensions: <empty>
    Responses
      OcspPerIssuerResponse
        IssuerCertHash
          a0:1c:73:a5:f3:b0:63:34:42:57:d0:26:93:05:9d:ed:
          8e:22:c4:43:3b:1a:4d:85:ef:ae:22:f7:f9:d7:e4:3c
        Extensions: <empty>
        SingleResponses
          SingleCertResponse
            SerialNumberHash:
              10:65:27:87:fa:05:27:bc:24:49:a1:bf:c5:ab:31:aa:
              5a:6f:0d:8d:6b:99:8e:4f:ed:e7:d9:0d:ca:47:f0:04
            Cert Status: good
            This Update: -28800 seconds
            Next Update: 25200 seconds
            Extensions: <empty>
          SingleCertResponse
            SerialNumberHash:
              75:d8:bc:4f:ba:fc:66:94:46:76:41:e7:48:df:d5:3a:
              8b:9d:17:6d:fa:3d:05:b3:e9:8a:4d:6e:5c:55:f1:65
            Cert Status: not-issued
            This Update: -28800 seconds
            Next Update: 25200 seconds
            Extensions: <empty>
          SingleCertResponse
            SerialNumberHash:
              d1:ac:13:5d:7d:a2:9b:dc:f4:dc:a0:d5:28:1a:51:60:
              5b:67:84:00:c2:64:08:ca:dc:3a:32:fc:1b:6a:d5:e3
            Cert Status: revoked (superseded)
              Revoked at 2025-03-01T16:00:00Z
            This Update: -28800 seconds
            Next Update: 25200 seconds
            Extensions: <empty>
      OcspPerIssuerResponse
        IssuerCertHash
          22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:
          22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22
        Extensions: <empty>
        SingleResponses
          SingleCertResponse
            SerialNumberHash:
              d3:a0:c1:e3:db:92:e8:f6:81:05:37:d4:5c:fa:ec:f6:
              ce:41:7e:3b:26:4e:50:cb:4f:69:dd:85:34:01:c5:dd
            Cert Status: unknown
            This Update: -28800 seconds
            Next Update: 25200 seconds
            Extensions: <empty>
    Responder Certs
      ~C509Certificate
        02:42:12:35:0c:6f:74:65:73:74:20:63:72:6c:6f:63:
        73:70:2d:63:61:1a:67:75:d7:00:1a:69:57:0a:80:6e:
        6f:63:73:70:2d:72:65:73:70:6f:6e:64:65:72:0c:58:
        20:81:94:7b:bc:24:8a:ac:79:73:82:11:a8:d7:5b:f9:
        2c:b7:77:d9:94:07:3d:f2:3a:e0:63:80:ef:2c:57:39:
        76:88:01:54:b5:b4:ca:f3:54:01:d0:61:51:df:96:29:
        db:57:9d:c8:cc:a4:53:a8:21:01:07:54:2f:45:e7:8d:
        2c:ae:df:36:8c:df:53:c3:90:05:d4:92:45:0e:10:56:
        27:09:58:40:a0:1b:0c:bf:3e:34:a4:76:2d:05:40:4f:
        d0:8a:7a:ec:10:30:35:35:83:14:68:6d:72:b6:15:90:
        78:c7:6e:1d:88:59:7f:37:53:18:86:a3:f5:2f:25:6f:
        d7:22:19:2b:28:9d:68:44:01:44:67:f1:f1:7f:05:ac:
        bb:7b:66:0a
      ~C509Certificate
        02:41:01:0c:73:74:65:73:74:20:63:72:6c:6f:63:73:
        70:2d:72:6f:6f:74:63:61:1a:67:74:85:80:1a:6b:36:
        ec:7f:6f:74:65:73:74:20:63:72:6c:6f:63:73:70:2d:
        63:61:0c:58:20:5e:f8:a3:55:a0:01:a7:c5:0d:23:49:
        47:01:20:81:31:a4:bb:2a:b9:20:d4:0b:fb:0e:e1:f6:
        ab:28:ff:74:00:88:01:54:2f:45:e7:8d:2c:ae:df:36:
        8c:df:53:c3:90:05:d4:92:45:0e:10:56:21:18:60:23:
        01:07:54:2d:a3:a4:03:f7:d2:f4:e0:b3:d8:03:1a:73:
        ba:8a:83:9f:55:7f:0f:58:40:e5:04:65:d6:0c:02:a2:
        11:1e:f3:fc:6e:44:f2:a3:60:08:76:5b:55:23:51:f9:
        a3:f5:b2:aa:7c:76:f1:f0:5d:25:98:47:a4:f4:25:0b:
        2e:4b:0a:e2:09:97:62:a2:59:6d:3c:c1:db:2c:cd:18:
        0a:a0:a2:d0:e1:91:31:0b:0f
  Signature Value
    4c:24:dd:23:0e:c5:bc:07:60:17:67:61:e0:c0:85:48:
    6b:a0:84:c3:b2:e9:7c:4b:e1:8c:d4:d3:41:af:73:3e:
    66:f4:11:20:11:aa:ca:15:02:79:f9:cc:db:34:40:7d:
    3f:26:44:85:80:f2:7b:25:7c:81:2a:8c:b2:50:5b:07
~~~~~

Annotated hex

[comment]: <> (replace-data:ocspresp/basic-ocspresp-with-certchain/ocspresp.diag)
~~~~~
  0: 8A             # C509OCSPResponse=array[10]
  1:   01             # [0]. ocspResponseType=C509BasicOCSPResponse
                      #      (1)
  2:   0C             # [1]. signatureAlgorithm: Ed25519 (12)
  3:   01             # [2]. hashAlgorithm: SHA256 (1)
  4:   50             # [3]. nonce=byte[16]
  5:     11111111111111111111111111111111
 21:   58 20          # [4]. responderCertHash=byte[32]
 23:     0600867838E3311AA78B9ED60C631C86B09A6DE7BC43E02A7AA7006A34
 52:     43A3B2
 55:   1A 6A2853F6    # [5]. producedAt=1781027830:
                      #      2026-06-09T17:57:10Z
 60:   80             # [6]. extensions=array[0]
 61:   86             # [7]. responses=array[6]
                        #---PerIssuerResponses[0]---
 62:     58 20          # [0]. issuerCertHash=byte[32]
 64:       A01C73A5F3B063344257D02693059DED8E22C4433B1A4D85EFAE22F7
 92:       F9D7E43C
 96:     80             # [1]. extensions=array[0]
 97:     8F             # [2]. singleResponses=array[15]
                          #---SingleCertResponses[0]---
 98:       58 20          # [0]. serialNumberHash=byte[32]
100:         10652787FA0527BC2449A1BFC5AB31AA5A6F0D8D6B998E4FEDE7D9
127:         0DCA47F004
132:       00             # [1]. certStatus=good (0)
133:       39 707F        # [2]. thisUpdate=-28800
136:       19 6270        # [3]. nextUpdate=25200
139:       80             # [4]. extensions=array[0]
                          #---SingleCertResponses[1]---
140:       58 20          # [5]. serialNumberHash=byte[32]
142:         75D8BC4FBAFC6694467641E748DFD53A8B9D176DFA3D05B3E98A4D
169:         6E5C55F165
174:       01             # [6]. certStatus=not-issued (1)
175:       39 707F        # [7]. thisUpdate=-28800
178:       19 6270        # [8]. nextUpdate=25200
181:       80             # [9]. extensions=array[0]
                          #---SingleCertResponses[2]---
182:       58 20          # [10]. serialNumberHash=byte[32]
184:         D1AC135D7DA29BDCF4DCA0D5281A51605B678400C26408CADC3A32
211:         FC1B6AD5E3
216:       82             # [11]. certStatus=array[2]
217:         1A 67C32F00    # [0]. revocationTime=1740844800:
                            #      2025-03-01T16:00:00Z
222:         04             # [1]. revocationReason=superseded (4)
223:       39 707F        # [12]. thisUpdate=-28800
226:       19 6270        # [13]. nextUpdate=25200
229:       80             # [14]. extensions=array[0]
                        #---PerIssuerResponses[1]---
230:     58 20          # [3]. issuerCertHash=byte[32]
232:       22222222222222222222222222222222222222222222222222222222
260:       22222222
264:     80             # [4]. extensions=array[0]
265:     85             # [5]. singleResponses=array[5]
                          #---SingleCertResponses[0]---
266:       58 20          # [0]. serialNumberHash=byte[32]
268:         D3A0C1E3DB92E8F6810537D45CFAECF6CE417E3B264E50CB4F69DD
295:         853401C5DD
300:       02             # [1]. certStatus=unknown (2)
301:       39 707F        # [2]. thisUpdate=-28800
304:       19 6270        # [3]. nextUpdate=25200
307:       80             # [4]. extensions=array[0]
308:   82             # [8]. responderCerts(COSE_C509)=array[2]
309:     58 C4          # [0]. C509CertData=byte[196]
311:       024212350C6F746573742063726C6F6373702D63611A6775D7001A69
339:       570A806E6F6373702D726573706F6E6465720C582081947BBC248AAC
367:       79738211A8D75BF92CB777D994073DF23AE06380EF2C573976880154
395:       B5B4CAF35401D06151DF9629DB579DC8CCA453A8210107542F45E78D
423:       2CAEDF368CDF53C39005D492450E105627095840A01B0CBF3E34A476
451:       2D05404FD08A7AEC103035358314686D72B6159078C76E1D88597F37
479:       531886A3F52F256FD722192B289D6844014467F1F17F05ACBB7B660A
507:     58 C9          # [1]. C509CertData=byte[201]
509:       0241010C73746573742063726C6F6373702D726F6F7463611A677485
537:       801A6B36EC7F6F746573742063726C6F6373702D63610C58205EF8A3
565:       55A001A7C50D23494701208131A4BB2AB920D40BFB0EE1F6AB28FF74
593:       008801542F45E78D2CAEDF368CDF53C39005D492450E105621186023
621:       0107542DA3A403F7D2F4E0B3D8031A73BA8A839F557F0F5840E50465
649:       D60C02A2111EF3FC6E44F2A36008765B552351F9A3F5B2AA7C76F1F0
677:       5D259847A4F4250B2E4B0AE2099762A2596D3CC1DB2CCD180AA0A2D0
705:       E191310B0F
710:   58 40          # [9]. signature value=byte[64]
712:     4C24DD230EC5BC0760176761E0C085486BA084C3B2E97C4BE18CD4D341
741:     AF733E66F4112011AACA150279F9CCDB34407D3F26448580F27B257C81
770:     2A8CB2505B07
~~~~~

# Acknowledgements {#acknowledgements}
{:numbered="false"}

The authors thank xxx for reviewing and commenting on intermediate versions of the draft.

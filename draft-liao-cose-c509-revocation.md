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
    org: NIO Inc.
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
  RFC7468:
  RFC8226:
  RFC8610:
  RFC8742:
  RFC8949:
  RFC9147:
  RFC9054:
  RFC9360:
  RFC9682:
  RFC9277:
  RFC9846:
  I-D.ietf-cose-cbor-encoded-cert:
  STIR-OCSP: I-D.ietf-stir-certificates-ocsp
  IANA.cose:
  IANA.tls-extensiontype-values:

informative:
  RFC3280:
  RFC7228:
  RFC7252:
  RFC7925:
  RFC9654:
  RFC9861:
  FIPS180-4:
    title: Secure Hash Standard (SHS)
    author:
      org: National Institute of Standards and Technology
    date: August 2015
    seriesinfo:
      "FIPS PUB": "180-4"
      DOI: 10.6028/NIST.FIPS.180-4
    target: https://doi.org/10.6028/NIST.FIPS.180-4
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
  CRLSets:
    title: CRLSets - The Chromium Projects
    target: https://www.chromium.org/Home/chromium-security/crlsets/
  CRLite:
    title: mozilla/crlite
    target: https://github.com/mozilla/crlite
  X.690:
    title: "ASN.1 encoding rules: Specification of Basic Encoding Rules (BER), Canonical Encoding Rules (CER) and Distinguished Encoding Rules (DER)"
    target: https://www.itu.int/rec/T-REC-X.690
  TinyOCSP:
    title: "Lightweight certificate revocation for low-power IoT with end-to-end security"
    author:
      - ins: J. Höglund
      - ins: M. Furuhed
      - ins: S. Raza
    date: 2023
    seriesinfo:
      "Journal of Information Security and Applications": "73:103424"
      DOI: 10.1016/j.jisa.2023.103424
    target: https://doi.org/10.1016/j.jisa.2023.103424

entity:
  SELF: "[RFC-XXXX]"

--- abstract

This document specifies CBOR-encoded PKI structures for use with C509 certificates (draft-ietf-cose-cbor-encoded-cert), X.509 certificates (RFC 5280), and future certificate types. It defines C509 CRL and C509 OCSP, compact CBOR encodings of X.509 Certificate Revocation Lists (RFC 5280) and OCSP messages (RFC 6960), respectively. The structures defined in this document are certificate-type agnostic and can be used with C509 certificates, X.509 certificates, or future certificate types without modification. C509 OCSP improves on RFC 6960 by signing a wider set of fields to prevent algorithm-substitution and certificate-chain substitution attacks, replacing the two-hash issuer identity with a single certificate hash, and identifying all participants (requestor, responder, issuer) by a uniform certificate hash rather than type-specific fields. C509 CRL and C509 OCSP are not wire-format-compatible with their DER-encoded X.509 counterparts and cannot be converted to or from them without semantic interpretation. Additionally, this document specifies the PEM representation of the C509 structures following the framework of RFC 7468.


--- middle

# Introduction {#intro}

Public Key Infrastructure (PKI) for constrained environments {{RFC7228}} requires compact certificate representations and compact revocation information.  {{I-D.ietf-cose-cbor-encoded-cert}} defines C509 certificates, a CBOR encoding of X.509 certificates {{RFC5280}} that reduces certificate size by over 50% for typical constrained-device profiles. However, revocation mechanisms such as Certificate Revocation Lists (CRLs) and Online Certificate Status Protocol (OCSP) messages have not yet received the same treatment.

CRLs as defined in {{RFC5280}} can be large, especially when many certificates have been revoked or when CRL extensions add overhead.  In the complementary OCSP mechanism defined in {{RFC6960}}, OCSP responses carry per-certificate status information and may be exchanged during TLS {{RFC9846}} and DTLS {{RFC9147}} handshakes via OCSP stapling {{RFC6066}}, directly affecting handshake latency.

Note on terminology: The label "C509" is used for consistency with the C509 certificate encoding and to promote a cohesive C509 PKI ecosystem (C509 certificates, CRLs, OCSP, and related tooling). Although this document uses "C509" in its names, the encodings and protocols defined here are certificate-type agnostic and apply equally to X.509 certificates and other certificate types; see {{cert-type-interop}}.

This document specifies:

- **C509 CRL** -- a natively signed CBOR {{RFC8949}} encoding of X.509 CRLs ({{RFC5280, Section 5}}).  The signature is computed over the CBOR Sequence {{RFC8742}} `TBSCertList`; no ASN.1 encoding is involved. Three key improvements are made over {{RFC5280}}:

   - Reduce the search complexity for a given certificate serial number from O(n) to O(log(n)):

     - Replace the implicit `certificateIssuer` mechanism with explicit per-issuer grouping.

     - Use a dedicated list for the `removeFromCRL` revocation entries.

     - Use fixed-length entry encoding.

   - Define a new standalone `C509CRLInfo` structure to carry CRL information without the (large) revocation list itself.

   - Define dedicated fields for the common extensions to simplify the encoding: `crlNumber`, `authorityKeyIdentifier`, `deltaCRLIndicator`.

- **C509 OCSP** -- a CBOR encoding of OCSP requests and responses ({{RFC6960}}).  The encoding compresses common fields while preserving semantic equivalence.  Three key improvements are made over {{RFC6960}}:

   - The signature in signed requests and responses is computed over a wider set of fields than in {{RFC6960}}, including the signature algorithm and the certificate chain, preventing algorithm-substitution and certificate-chain substitution attacks.

   - The issuer is identified by a single hash over the issuer certificate (`issuerCertHash`) rather than by the two-hash `CertID`, reducing per-issuer overhead.

   - All participants (requestor, responder, issuer) are identified by a hash over their certificate (`requestorCertHash`, `responderCertHash`, `issuerCertHash`) rather than by a plaintext Subject distinguished name or SubjectKeyIdentifier, avoiding structural `CHOICE` types such as the X.509 `ResponderID` (`byName` or `byKey`) and simplifying support for different certificate types (e.g., C509, X.509, or future types) because the same hash applies regardless of the certificate encoding.

The CRL and OCSP structures defined in this document are certificate-type agnostic: they can be used with C509 certificates, X.509 certificates, or any future certificate type without modification; see {{cert-type-interop}}.

C509 CRL and C509 OCSP apply the same compression techniques as C509 certificates: static fields are elided, OIDs are replaced with short integers, time values are compressed to POSIX timestamps, and redundant encoding is removed.  Implementers may use the CBOR playground {{CborMe}} to inspect encoded examples.

C509 CRL and C509 OCSP are not wire-format-compatible with their DER-encoded counterparts defined in {{RFC5280}} and {{RFC6960}}.  Systems that use C509 CRL or C509 OCSP must explicitly support these CBOR-encoded formats; they cannot be transparently substituted for or derived from the corresponding DER-encoded structures.

C509 CRL and C509 OCSP are designed to be compatible with certificate profiles for constrained deployments, such as {{RFC7925}}.

# Alternative Certificate Status Checking Mechanisms {#status-alternatives}

This section considers both widely deployed certificate-status mechanisms and closely related prior work for constrained environments.  Several such mechanisms can be used to check certificate status, but none of them replaces the work in this document.

- **X.509 CRLs and OCSP** ({{RFC5280}}, {{RFC6960}}) provide the baseline revocation mechanisms, but their DER encodings are not compact enough for constrained deployments and are not certificate-type agnostic.  This document keeps their semantics while defining CBOR encodings that are smaller and easier to process.

- **OCSP stapling** ({{RFC6066}}, {{RFC9846}}) reduces client latency by having the server provide a fresh OCSP response, but it does not define a revocation status format of its own.  It still depends on the underlying OCSP message structure, so it cannot replace a compact, standalone status representation.

- **Short-lived certificates** reduce reliance on revocation, but they do not provide revocation status when certificates must remain valid for longer periods or must be withdrawn immediately after compromise.  They also shift the problem to more frequent issuance and renewal rather than eliminating status checking.

- **CRLSets** {{CRLSets}} are a browser-distributed revocation blocklist rather than a general-purpose revocation protocol.  They cover only a limited subset of certificates and are tied to a specific browser ecosystem, so they cannot provide complete, interoperable status checking for arbitrary C509, X.509, or future certificate types.

- **CRLite** {{CRLite}} compresses revocation information into a browser-oriented filter-based representation, which is useful for client-side deployment at scale.  However, it is not a wire-format replacement for CRLs or OCSP, does not preserve the full per-certificate status structures defined here, and is not a certificate-type-agnostic status format that other implementations can exchange directly.

- **Compact CBOR revocation for IoT (TinyOCSP and CCRL)** {{TinyOCSP}} are prior research mechanisms that reduce OCSP and CRL overhead for low-power IoT, confirming the feasibility and benefits of CBOR-based revocation on constrained hardware.  They are a precursor to this work.  However, they were specified as point solutions rather than as interoperable, certificate-type-agnostic wire formats aligned with the C509 certificate encoding {{I-D.ietf-cose-cbor-encoded-cert}}; this document generalizes those mechanisms into complete C509 CRL and C509 OCSP structures usable with C509, X.509, and future certificate types.

The compactness benefit over the DER-encoded baselines is concrete and substantial.  For the representative profiles in the worked examples ({{examples}}), C509 CRLs are 17% to 41% smaller than the equivalent X.509 CRLs (for example, a CRL carrying revoked certificates is reduced from 421 to 263 bytes, a 38% reduction), and C509 OCSP messages are 40% to 69% smaller (for example, a Simple OCSP request from 146 to 59 bytes, and a Basic OCSP response without the responder's certificate from 821 to 268 bytes); see {{tab-examples-overview}}.

These alternatives are useful in specific deployments, but they do not provide the CBOR-based, certificate-type-agnostic revocation structures defined here for C509, X.509, and future certificate types.

# Terminology {#terminology}

{::boilerplate bcp14-tagged}

This document uses the terminology from {{RFC5280}}, {{RFC6960}}, {{RFC7228}}, {{RFC8610}}, {{RFC8742}}, {{RFC8949}}, and {{RFC9682}}.  Unless otherwise stated, "CBOR" refers to deterministically encoded CBOR as specified in {{RFC8949, Sections 4.2.1 and 4.2.2}}.

# Common Types {#common-types}

The following types are imported from {{I-D.ietf-cose-cbor-encoded-cert}}: `Name`, `Extension`, `Extensions`, `Defined`, `COSE_C509`, and `AlgorithmIdentifier`. Additionally, the following type is imported from {{RFC9360}}: `COSE_X509`.

This document further defines the following constrained aliases for use in all CDDL definitions:

~~~~~~~~~~~ cddl
uint8 = uint .le 255

uint32 = 0..4294967295             ; 2^32 - 1

uint63 = 0..9223372036854775807    ; 2^63 - 1

int16 = -32768..32767

IntAlgorithmIdentifier = int16

IntExtension = ( extensionID: IntExtensionID,
                 extensionValue: Defined )

IntExtensionID = 1..9223372036854775807 / ;   2^63 - 1
                 -9223372036854775807..-1  ; -(2^63 - 1)

IntExtensions = [ * IntExtension ]
~~~~~~~~~~~
{: sourcecode-name="c509common.cddl"}

The CDDL definitions in this document are split into three files: `c509common.cddl` (the definitions above), `c509crl.cddl` ({{c509crl}}), and `c509ocsp.cddl` ({{c509ocsp}}).  Both `c509crl.cddl` and `c509ocsp.cddl` depend on `c509common.cddl` and on the types imported from {{I-D.ietf-cose-cbor-encoded-cert}} and {{RFC9360}}.

`IntAlgorithmIdentifier` is the `int`-only instantiation of `AlgorithmIdentifier` from {{I-D.ietf-cose-cbor-encoded-cert}}.  It is used throughout this document wherever an algorithm identifier appears in the wire encoding.

`IntExtension` is the instantiation of `Extension` from {{I-D.ietf-cose-cbor-encoded-cert}} with an integer `extensionID`.  As in C509 certificates ({{I-D.ietf-cose-cbor-encoded-cert, Section 3.1.10}}), the absolute value of `extensionID` is the value from the "C509 Extensions" registry, and its sign indicates whether the extension is critical: critical extensions are encoded with a negative sign and non-critical extensions with a positive sign.  It is used throughout this document wherever a single extension appears in the wire encoding.

`IntExtensions` is the instantiation of `Extensions` from {{I-D.ietf-cose-cbor-encoded-cert}} where all embedded `Extension` entries are `IntExtension` entries.  An `IntExtensions` field with no extensions is encoded as an empty array.

# Encoding of Time Fields {#time-encoding}

Time fields are encoded as unwrapped CBOR epoch-based date/time (`~time`).  The value MUST be a non-negative integer.  In POSIX time {{POSIX}}, leap seconds are ignored; a leap second has the same POSIX time as the second before it.

# C509 CRL {#c509crl}

## Overview

A C509 CRL is a natively signed CBOR {{RFC8949}} encoding of an X.509 v2 CRL as defined in {{RFC5280, Section 5}}.  The signature is computed over the CBOR Sequence {{RFC8742}} `TBSCertList`; no ASN.1 encoding is involved.  A C509 CRL preserves the semantics of the corresponding DER-encoded X.509 CRL for the subset of RFC 5280 structures supported by this document.

A C509 CRL is not wire-format-compatible with a DER-encoded X.509 CRL.  The two formats cannot be mechanically converted to or from each other without semantic interpretation of the contained data.

## C509 CRL CDDL {#crl-cddl}

The following CDDL defines the top-level `C509CertificateList` structure and the `TBSCertList` sequence:

~~~~~~~~~~~ cddl
C509CertificateList = [
  TBSCertList,
  signatureValue : any,
]

TBSCertList = (
  CRLInfoData,
  revokedCertsList       : [+ PerIssuerRevokedCerts] / null
)

C509CRLInfo = [ CRLInfoData ]

CRLInfoData = (
  crlType                : 0, ; int16
  signatureAlgorithm     : IntAlgorithmIdentifier,
  authoritySubject       : NameVariant,
  authorityKeyIdentifier : bytes,
  crlNumber              : CRLNumber,
  thisUpdate             : ~time,
  nextUpdate             : uint63 / null,
  baseCrlNumber          : CRLNumber / null,
  crlExtensions          : IntExtensions,
)

CRLNumber = 1..9223372036854775807

PerIssuerRevokedCerts = (
  issuer                 : NameVariant / null,
  revokedCertsControl    : RevokedCertsControl / null,
  extensions             : IntExtensions,
  revokedCerts           : bytes .size (1..2147483647) / null,
  removedFromCRLCerts    : bytes .size (1..2147483647) / null,
)

NameVariant = [
  type                   : uint .le 255,
  name                   : any,
]

RevokedCertsControl = [
  flags               : uint32,
  serialNumberLength  : 1..20,
  dateLength          : uint .le 8,
  baseDate            : ~time,
]
~~~~~~~~~~~
{: sourcecode-name="c509crl.cddl"}
{: #fig-CRLcddl title="CDDL for C509CertificateList"}

## Field Encodings {#crl-fields}

### CRLInfoData and C509CRLInfo {#crlinfo}

`CRLInfoData` is a CDDL group that carries all CRL fields except `revokedCertsList`.  `C509CRLInfo` is the standalone CBOR array form of `CRLInfoData`; it can be used to convey CRL information (crlType, signature algorithm, issuer identity, CRL number, validity window, base CRL number, extensions) without the potentially large revocation list.  `TBSCertList` embeds `CRLInfoData` and adds `revokedCertsList`.

### crlType

The `crlType` field identifies the format of `C509CertificateList` and `C509CRLInfo`:

| Value | Type | Description |
|:-----:|:-----|:------------|
| 0 | Basic | The format defined in this document |
{: #tab-crl-types title="CRL types"}

Future specifications may define additional types by assigning new integer values.

### signatureAlgorithm

Encoded identically to the `int` choice of `issuerSignatureAlgorithm` in C509 certificates (see {{I-D.ietf-cose-cbor-encoded-cert, Section 3.1.3}}).  Algorithm integer values are from the same registry used for C509 certificates.

Unlike in {{RFC5280}}, where the signature algorithm appears outside the `TBSCertList` and is therefore not covered by the CRL signature, `signatureAlgorithm` is part of `CRLInfoData` within `TBSCertList` and is therefore covered by the signature.  This prevents algorithm-substitution attacks on the CRL.

### NameVariant {#name-variant}

A `NameVariant` carries the name of a CA, together with the type of the certificate from which the name is taken.  This allows a C509 CRL to identify CAs that hold C509 certificates, X.509 certificates, or certificates of other types.

- The `type` field identifies the certificate type.  Its value is taken from the "TLS Certificate Types" registry {{IANA.tls-extensiontype-values}}.
- The `name` field contains the name, encoded as determined by `type`.

This document defines the encoding of `name` for the following certificate types:

- `type` = 0 (X509): `name` is a byte string containing the DER-encoded ({{X.690}}) X.501 `Name` ({{RFC5280, Section 4.1.2.4}}).
- `type` = 4 (C509): `name` is a `Name` as defined in {{I-D.ietf-cose-cbor-encoded-cert}}.

For any other certificate type that defines names, the name is encoded as follows, unless the specification of that certificate type defines otherwise: if the certificate type is CBOR-encoded, `name` is the CBOR data item that represents the name in the certificate; otherwise, `name` is a byte string containing the name in the original encoding of the certificate type.

A receiver that does not support the certificate type indicated by `type` cannot interpret `name`.  It MUST NOT match such a `NameVariant` with any certificate.

### authoritySubject and authorityKeyIdentifier

The `authoritySubject` and `authorityKeyIdentifier` fields identify the CRL authority.

The `authoritySubject` field identifies the subject of the CRL issuer as a `NameVariant` ({{name-variant}}).  Its `type` is the type of the CRL issuer's certificate, and its `name` is the `subject` field of that certificate.  For example, when the CRL is issued by a C509 CA, `authoritySubject` is `[4, subject]`, where `subject` is identical to the `subject` field of the authority C509 certificate.  When the CRL is issued by an X.509 CA (e.g., in a hybrid deployment where a legacy CA issues a C509-format CRL), `authoritySubject` is `[0, subject]`, where `subject` is a byte string containing the DER-encoded `subject` field of the issuing X.509 CA certificate.

The `authorityKeyIdentifier` field is identical to the value of the authority's `subjectKeyIdentifier` extension.  This field corresponds to the X.509 CRL extension `authorityKeyIdentifier` ({{RFC5280, Section 5.2.1}}).  It is promoted to a dedicated field because it MUST be present in conforming X.509 CRLs and because making it explicit simplifies the structure and reduces encoded size compared to representing it as a generic extension.

### crlNumber

The `crlNumber` field is encoded as a positive integer (`CRLNumber`, from 1 to 2^63 - 1).  It corresponds to the `cRLNumber` extension in {{RFC5280, Section 5.2.3}}, which this document replaces with a dedicated field.  The value is monotonically increasing for both full and delta CRLs.

### thisUpdate and nextUpdate

The `thisUpdate` field is encoded as described in {{time-encoding}}.  The `nextUpdate` field is encoded as a `uint63` representing the number of seconds from `thisUpdate` until the next CRL is expected to be issued.  It is encoded as `null` when no next update time is known.

### baseCrlNumber

The `baseCrlNumber` field is encoded as `null` for a full CRL.  For a delta CRL, it contains the CRL number of the corresponding base full CRL.  It corresponds to the `deltaCRLIndicator` extension in {{RFC5280, Section 5.2.4}}, which this document replaces with a dedicated field.

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

### revokedCertsList and PerIssuerRevokedCerts {#revoked-certs-list}

#### Design Considerations

In X.509 CRLs ({{RFC5280, Section 5.3.3}}), an indirect CRL uses the `certificateIssuer` CRL entry extension to indicate that a revocation entry -- and all subsequent entries -- belongs to a different issuer.  This mechanism has two significant drawbacks:

- It is implicit and positional, making it difficult to parse correctly and error-prone to implement.
- It is impossible to represent an issuer that has no currently revoked certificates (e.g., to carry per-issuer extensions or to explicitly indicate that the issuer is known but has an empty revocation list), because there is no entry to attach the `certificateIssuer` extension to.

`PerIssuerRevokedCerts` solves both problems by introducing an explicit intermediate structure that groups all revocation information for one issuer.  The issuer is identified directly in the `issuer` field of the structure rather than being inferred from the position of a CRL entry extension.  This makes the grouping unambiguous and easy to parse, and it allows an issuer to appear in the list even when it has no revoked certificates.

A second design problem in X.509 CRLs is that each revocation entry has variable length because:

- the serial number length differs between certificates,

- the revocation date uses different encodings depending on whether the date falls before or after 2050,

- optional per-entry extensions (e.g., reason code) may or may not be present.

This variable-length layout makes it impossible to determine whether a given serial number is present in the list without scanning every entry sequentially, resulting in O(n) lookup time.

In this document, the `revokedCertsControl` structure introduces fixed parameters (`serialNumberLength`, `dateLength`) that make every entry within `revokedCerts` exactly the same size.  The `flags` field can additionally indicate that entries are sorted in ascending order by serial number, enabling binary search and reducing lookup time to O(log(n)).  Using a compact byte-string concatenation rather than a CBOR array of structured items further reduces encoded size and accelerates parsing.  Furthermore, certificates removed from the CRL (delta CRL `removeFromCRL` entries in X.509) are kept in a dedicated `removedFromCRLCerts` field rather than mixed into `revokedCerts`.  This keeps `revokedCerts` free of removal noise, reducing its size and allowing implementations to process currently revoked and removed entries independently.

#### Fields

The `revokedCertsList` field is either a CBOR array of one or more `PerIssuerRevokedCerts` entries, each describing the revocation state for certificates issued by one issuer, or CBOR `null`.  Since `PerIssuerRevokedCerts` is a CDDL group, the fields of each entry are inlined in the array rather than wrapped in a nested array; an array with n entries therefore contains 5n elements.  `revokedCertsList` MUST be encoded as CBOR `null` when all of the following conditions hold: no certificates are currently revoked, no certificates have been removed from the CRL, the only issuer that would appear is the CRL's own `authoritySubject` (i.e., the `issuer` field is `null`), and there are no non-empty per-issuer extensions.

Since each `PerIssuerRevokedCerts` entry identifies its issuer by a `NameVariant` ({{name-variant}}), a single C509 CRL may contain entries for certificates of different types.  For example, a CRL may contain one `PerIssuerRevokedCerts` entry for C509 certificates and one for X.509 certificates.  All certificates covered by one `PerIssuerRevokedCerts` entry are of the type indicated by the `type` of its `issuer`, or of `authoritySubject` if `issuer` is `null`; certificates of different types are listed in separate entries.

Each `PerIssuerRevokedCerts` entry describes revoked certificates for one issuer using the following fields:

- The `issuer` field identifies the issuer of the certificates covered by this `PerIssuerRevokedCerts` entry as a `NameVariant` ({{name-variant}}).  Its `type` is the type of the covered certificates, and its `name` is their `issuer` field.  For example, when the covered certificates are C509 certificates, `issuer` is `[4, name]`, where `name` is identical to the `issuer` field of the covered C509 certificates; when they are X.509 certificates, `issuer` is `[0, name]`, where `name` is a byte string containing the DER-encoded `issuer` field of the covered X.509 certificates.  If the issuer is identical to the CRL's `authoritySubject` field, it MUST be encoded as CBOR `null`.

- The `revokedCertsControl` field defines the controls for interpreting `removedFromCRLCerts` and `revokedCerts`.  If either `removedFromCRLCerts` or `revokedCerts` is non-`null`, `revokedCertsControl` MUST NOT be `null`.  If both `removedFromCRLCerts` and `revokedCerts` are `null`, `revokedCertsControl` MUST be `null` to reduce CRL size.

  - The `flags` field is an unsigned integer encoding boolean control bits for `crlType = 0`: bit 0 indicates whether entries in `revokedCerts` are sorted in ascending order by the integer value of the certificate serial number; bit 1 indicates whether each entry contains a reason code.  Bits 2 and higher are reserved for `crlType = 0` and MUST be zero and MUST be ignored by receivers.  Future `crlType` values defined in successor documents may assign additional bit meanings.

  - The `serialNumberLength` field defines the length, in bytes, of a certificate serial number.  It MUST be greater than 0.  It is the smallest value that can encode all certificate serial numbers without leading zeros.

    Each certificate serial number is encoded as a fixed-length big-endian integer of length `serialNumberLength`.  If the encoded value is shorter than `serialNumberLength`, it is left-padded with zeros.

  - The `dateLength` field defines the length, in bytes, of the big-endian encoded revocation-date offset relative to `baseDate`.  A value of 0 means that no revocation date is included in `revokedCerts` entries.  This is permitted in C509-native deployments where the revocation date is not required -- for example, when minimizing revocation data is more important than recording the revocation time.  Implementations that need to convert a C509 CRL to an RFC 5280 DER-encoded CRL MUST set `dateLength` to a non-zero value, since {{RFC5280, Section 5.1}} requires a `revocationDate` in every CRL entry.  When `dateLength` is non-zero, the offset MUST fit within the specified byte length without leading zero bytes.

  - The `baseDate` field is a reference time used to compute revocation and removal dates, encoded as described in {{time-encoding}}.  It MUST be greater than or equal to the issuer certificate's `notBefore`, which ensures that all stored offsets are non-negative.  It is RECOMMENDED to set `baseDate` to the earliest revocation date and removal-from-CRL date among all entries in this CRL, as this minimizes the magnitude of stored offsets and reduces encoding size.  Any time between the issuer certificate's `notBefore` (inclusive) and that earliest date (inclusive) is a conformant value.  Revocation dates in `revokedCerts` and removal dates in `removedFromCRLCerts` are stored as non-negative offsets, in seconds, from `baseDate`.

- The `extensions` field contains per-issuer extensions.

- The `revokedCerts` field is a CBOR byte string containing the concatenated byte sequence of revoked-certificate entries.  Each entry is the concatenation of:
  - a big-endian encoded certificate serial number of length `serialNumberLength`;
  - a big-endian encoded revocation-date offset from `baseDate`, in seconds, of length `dateLength` (absent when `dateLength` is 0); and
  - an optional reason code (1 byte if bit 1 of `flags` is set, absent otherwise).

  If there are no entries, this field MUST be encoded as CBOR `null` instead of a zero-length byte string.

  The revocation date for a given entry is recovered by adding the stored offset to `baseDate`.  When `dateLength` is 0, no revocation date is stored and no date recovery is possible.

  Revoked-certificate entries have a fixed length.  If bit 0 of `flags` is set, entries are sorted in ascending order, enabling binary search for a given serial number in O(log(n)) time.

- The `removedFromCRLCerts` field contains a concatenated byte sequence of entries for certificates removed from the CRL since publication of the CRL with `crlNumber = baseCrlNumber`.  Each entry is the concatenation of:
  - a big-endian encoded certificate serial number of length `serialNumberLength`; and
  - a big-endian encoded removal-date offset from `baseDate`, in seconds, of length `dateLength` (absent when `dateLength` is 0).

  If there are no entries, this field MUST be encoded as CBOR `null` instead of a zero-length byte string.

  The removal date for a given entry is recovered by adding the stored offset to `baseDate`.  When `dateLength` is 0, no removal date is stored and no date recovery is possible.

  Removed-certificate entries have a fixed length.  If bit 0 of `flags` is set, entries are sorted in ascending order, enabling binary search for a given serial number in O(log(n)) time.

### CRL Extensions

The `crlExtensions` field contains extensions for the CRL.  This document does not define any new CRL-level extensions.

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
| -    | orderedList              | OID 2.5.29.56 (ITU-T X.509, Section 9.5.2.5) | bit 0 of `flags` (ascSerialNum); - (ascRevDate) |
| -    | toBeRevoked              | OID 2.5.29.58 (ITU-T X.509, Section 9.5.2.6) | - |
| -    | revokedGroups            | OID 2.5.29.59 (ITU-T X.509, Section 9.5.2.7) | - |
{: #tab-crlExt title="CRL extensions and their equivalents"}

### Per-Issuer Extensions

The `extensions` field of `PerIssuerRevokedCerts` contains per-issuer extensions. This document defines one per-issuer extension (`expiredCertsOnCRL`, see {{ext-expired-certs}}).

{{tab-perIssuerExt}} lists per-issuer extensions defined in this document.

| Code | Extension                | Reference         | Equivalent |
|:-----|:-------------------------|:------------------| :------------------|
| TBD1 (128) | expiredCertsOnCRL        | OID 2.5.29.60 (ITU-T X.509, Section 9.5.2.8)  | - |
{: #tab-perIssuerExt title="Per-issuer extensions and their equivalents"}

#### expiredCertsOnCRL {#ext-expired-certs}

The `expiredCertsOnCRL` extension indicates that this CRL includes revocation information for certificates that have already expired.  The extension value is a time value indicating the earliest expiration date of certificates included on the CRL; certificates that expired on or after this date are listed even if they are expired when the CRL is generated.

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
| -    | reasonCode          | {{RFC5280, Section 5.3.1}} / ITU-T X.509, Section 9.6.2.1  | fields `removedFromCRLCerts` and `revokedCerts` |
| -    | holdInstructionCode | {{RFC3280, Section 5.3.2}} / ITU-T X.509, Section 9.6.2.2  | - |
| -    | invalidityDate      | {{RFC5280, Section 5.3.2}} / ITU-T X.509, Section 9.6.2.3  | - |
| -    | certificateIssuer   | {{RFC5280, Section 5.3.3}} / ITU-T X.509, Section 9.6.2.4  | field `issuer` within `PerIssuerRevokedCerts` |
{: #tab-crlEntryExt title="CRL entry extensions defined for X.509 CRLs"}

### signatureValue

Encoded identically to `signatureValue` in C509 certificates (see {{I-D.ietf-cose-cbor-encoded-cert, Section 3.1.12}}).

## PEM Representation

The CBOR-encoded C509CertificateList is first Base64-encoded and then wrapped between "-----BEGIN C509 CRL-----" and "-----END C509 CRL-----", following the framework of {{RFC7468}}.

~~~
-----BEGIN C509 CRL-----
(base64-encoded CBOR C509CertificateList)
-----END C509 CRL-----
~~~
{: #fig-pem-c509-crl title="C509 CRL PEM Encoding"}

# C509 OCSP {#c509ocsp}

## Overview

C509 OCSP defines CBOR encodings for OCSP requests and OCSP responses as defined in {{RFC6960}}.  The encoding follows the same compression principles as C509 CRL and C509 certificates.

C509 OCSP requests and responses are not wire-format-compatible with DER-encoded OCSP messages as defined in {{RFC6960}}.  The two formats cannot be mechanically converted to or from each other without semantic interpretation of the contained data.

`C509OCSPRequest` and `C509OCSPResponse` are designed to be extensible.  The first field of every message is `ocspRequestType` or `ocspResponseType`, an integer that identifies the structure type. Future specifications may define additional types by assigning new integer values, enabling new request or response structures to be introduced without modifying the existing types.

## Conformance Requirements {#ocsp-conformance}

To ensure interoperability, implementations of C509 OCSP MUST support the following message types:

- An OCSP client MUST support `C509SimpleOCSPRequest` ({{C509SimpleOCSPRequest}}) and `C509SimpleOCSPResponse` ({{C509SimpleOCSPResponse}}).  An OCSP client MAY support `C509BasicOCSPRequest`.  If an OCSP client supports `C509BasicOCSPRequest`, it MUST support `C509BasicOCSPResponse`.

- An OCSP responder MUST support `C509SimpleOCSPRequest`, `C509SimpleOCSPResponse`, `C509BasicOCSPRequest`, and `C509BasicOCSPResponse`.

- Both OCSP clients and OCSP responders MUST support `C509ErrorOCSPResponse`.

## Hash Algorithms {#hash-algs}

The `hashAlgorithm` field of C509 OCSP requests and responses identifies the hash algorithm used to compute the certificate hashes (`issuerCertHash`, `requestorCertHash`, and `responderCertHash`) within the enclosing structure.  Its value is the integer identifier of a hash algorithm from the "COSE Algorithms" registry {{IANA.cose}}, e.g., -16 for SHA-256, -43 for SHA-384, and -44 for SHA-512 {{RFC9054}}.  Any hash algorithm in that registry can be used, subject to the restrictions below; for example, SHA3-256 or SM3 can be used once they are registered.

The hash algorithm MUST produce an output whose length is at least that of the `HashedId` values derived from it (see {{cert-identification}}).  SHA-256/64 (-15) MUST NOT be used.  Other truncated hash algorithms, such as SHA-512/256 (-17), SHOULD NOT be used: this document already defines the truncated identifier `HashedId`, so using a truncated hash algorithm provides no benefit.  SHA-1 (-14) MUST NOT be used either, since it is not collision resistant.  For SHAKE128 (-18) and SHAKE256 (-45), the output length is as specified in {{RFC9054}}, i.e., 256 and 512 bits, respectively.  For an extendable-output function whose output length is not fixed by its registration, such as TurboSHAKE128 (-261) and TurboSHAKE256 (-262) {{RFC9861}}, the output length is the length of the `HashedId` being computed.

## Identification of Certificates {#cert-identification}

To reduce OCSP message size, this document defines a truncated-hash identifier type used to refer to certificates compactly:

- `HashedId`: the leading bytes, i.e., the leftmost bytes, of the hash value computed using the enclosing `hashAlgorithm`.  A `HashedId` is 8 to 64 bytes long.  This is aligned with the truncation of hash values in SHA-512/256 {{FIPS180-4}} and SHA-256/64 {{RFC9054}}, which also keep the leftmost bits.  `HashedId` is used to identify issuer certificates and the certificates of OCSP requestors and responders in request and response structures.

~~~~~~~~~~~ cddl
HashedId = bytes .size (8..64)
~~~~~~~~~~~
{: sourcecode-name="c509ocsp.cddl"}

The sender chooses the length of a `HashedId`; it MUST NOT be longer than the output of the hash algorithm.  The length is a trade-off between message size and collision resistance; see {{sec-truncated-hash}}.  A receiver compares a received `HashedId` with a certificate by computing the hash value of the certificate using `hashAlgorithm` and comparing its leading bytes, as many as the received `HashedId` has, with the received `HashedId`.  An OCSP responder MUST use in a response the same `issuerCertHash` value as in the corresponding request.

## Certificate Chains {#cert-chain-variant}

The `requestorCerts` and `responderCerts` fields carry the ordered certificate chain of the signer as a `CertChainVariant`, together with the type of the certificates in the chain.  This follows the same pattern as `NameVariant` ({{name-variant}}).

~~~~~~~~~~~ cddl
CertChainVariant = [
  type  : uint .le 255,
  chain : any,
]
~~~~~~~~~~~
{: sourcecode-name="c509ocsp.cddl"}

- The `type` field identifies the certificate type.  Its value is taken from the "TLS Certificate Types" registry {{IANA.tls-extensiontype-values}}.
- The `chain` field contains the ordered certificate chain, starting with the signer's certificate, encoded as determined by `type`.

This document defines the encoding of `chain` for the following certificate types:

- `type` = 0 (X509): `chain` is a `COSE_X509` ({{RFC9360}}) containing an ordered chain of X.509 certificates.
- `type` = 4 (C509): `chain` is a `COSE_C509` ({{I-D.ietf-cose-cbor-encoded-cert}}) containing an ordered chain of C509 certificates.

For any other certificate type, the ordered certificate chain is encoded as follows, unless the specification of that certificate type defines otherwise: if the certificate type is CBOR-encoded, `chain` is a CBOR array of the CBOR data items representing the certificates; otherwise, `chain` is a CBOR array of byte strings, each containing a certificate in the original encoding of the certificate type.

A receiver that does not support the certificate type indicated by `type` cannot interpret `chain`.  It MUST NOT use such a `CertChainVariant` to verify the signature.

## Certificate Serial Numbers {#cert-serial-number}

The certificate whose status is requested or reported is identified by `issuerCertHash` together with its serial number, carried in the `serialNumber` field.

~~~~~~~~~~~ cddl
SerialNumber = bytes .size (1..20)
~~~~~~~~~~~
{: sourcecode-name="c509ocsp.cddl"}

The `serialNumber` field contains the serial number of the target certificate, encoded as a byte string.  Its value depends on the certificate type.

For a C509 certificate, `serialNumber` is the `certificateSerialNumber` of the certificate ({{I-D.ietf-cose-cbor-encoded-cert}}) as is.

For an X.509 certificate, the serial number is an ASN.1 INTEGER ({{RFC5280, Section 4.1.2.2}}).  Its DER encoding is two's complement and therefore contains a leading zero byte when the most-significant bit of the value is set.  This leading zero byte is not part of `serialNumber`: the value is the contents octets of the DER-encoded INTEGER with a leading zero byte removed (if present).  For example, the DER-encoded serial number `02 03 00 8F 01` gives `serialNumber` `h'8F01'`, and the DER-encoded serial number `02 02 0F 01` gives `serialNumber` `h'0F01'`.

{{RFC5280, Section 4.1.2.2}} requires serial numbers to be positive.  A non-conforming X.509 certificate with serial number zero (DER-encoded `02 01 00`) would result in an empty `serialNumber`, which is not a valid `SerialNumber`.  An OCSP responder MUST reject a request with an invalid `serialNumber` by returning a `C509ErrorOCSPResponse` with `responseStatus` set to `malformedRequest` (1).

As in the `CertID` of {{RFC6960}}, the serial number is carried in plain form and is not hashed.  Serial numbers are not secret, and an unsalted hash would not prevent an observer with a set of candidate serial numbers from identifying the queried certificate (see {{sec-privacy}}).  The plain serial number is at most 20 bytes long, lets an OCSP responder look up the certificate directly, and cannot collide.

## C509 OCSP Request {#ocsp-request}

### CDDL {#ocsp-req-cddl}

~~~~~~~~~~~ cddl
C509OCSPRequest = C509BasicOCSPRequest /
                  C509SimpleOCSPRequest

C509BasicOCSPRequest = [
  ocspRequestType    : 1, ; int16
  signatureAlgorithm : IntAlgorithmIdentifier / null, ; null=unsigned
  hashAlgorithm      : IntAlgorithmIdentifier,
  nonce              : bytes .size (16..128) / null,
  extensions         : IntExtensions,
  requests           : PerIssuerOCSPRequests,
  ? (                  ; present if and only if signed
    requestorCertHash  : HashedId,
    requestorCerts     : CertChainVariant / null,
    signatureValue     : any,
  )
]

C509SimpleOCSPRequest = [
  ocspRequestType    : 2, ; int16
  hashAlgorithm      : IntAlgorithmIdentifier,
  nonce              : bytes .size (16..128) / null,
  issuerCertHash     : HashedId,
  serialNumber       : SerialNumber,
  extensions         : IntExtensions
]

PerIssuerOCSPRequests = [ + PerIssuerOCSPRequest ]

PerIssuerOCSPRequest = (
  issuerCertHash   : HashedId,
  extensions       : IntExtensions,
  singleRequests   : SingleCertRequests,
)

SingleCertRequests  = [ + SingleCertRequest ]

SingleCertRequest = (
  serialNumber     : SerialNumber,
  extensions       : IntExtensions,
)
~~~~~~~~~~~
{: sourcecode-name="c509ocsp.cddl"}
{: #fig-OCSPReqCDDL title="CDDL for C509OCSPRequest"}

### Field Encodings

#### ocspRequestType

The `ocspRequestType` field serves as the discriminator for `C509OCSPRequest`:

| Value | Type |
|:-----:|:-----|
| 0 | Reserved |
| 1 | `C509BasicOCSPRequest`  |
| 2 | `C509SimpleOCSPRequest` |
{: #tab-ocspreq-types title="OCSP request types"}

#### issuerCertHash {#issuer-hash-id}

The `issuerCertHash` field appears in `PerIssuerOCSPRequest`, `PerIssuerOCSPResponse`, `C509SimpleOCSPRequest`, and `TBSSimpleOCSPResponse`.  It contains a hash of the issuer certificate:

- `issuerCertHash`: hash computed over the deterministically encoded certificate, i.e., the CBOR-encoded C509Certificate or the DER-encoded ({{X.690}}) X.509 certificate.  For a CBOR re-encoded X.509 certificate (`c509CertificateType` = 3, see {{I-D.ietf-cose-cbor-encoded-cert, Section 3.1.1}}), the hash MUST be computed over the DER-encoded X.509 certificate, not over its C509 encoding, since such a certificate may have more than one conformant CBOR encoding (see {{I-D.ietf-cose-cbor-encoded-cert, Section 3.4}}).  The hash algorithm is specified by the `hashAlgorithm` field of the enclosing request or response structure.

In X.509 OCSP ({{RFC6960, Section 4.1.1}}), the `CertID` structure identifies the issuer using two separate hashes: `issuerNameHash` (a hash of the DER-encoded issuer name) and `issuerKeyHash` (a hash of the issuer's public key bit string).  This two-hash approach was designed for interoperability with DER-encoded X.509 structures, but it doubles the per-issuer overhead in the message.  In C509 OCSP, the issuer is identified by a single hash of the issuer certificate (`issuerCertHash`), which is simpler, smaller, and unambiguous.  Implementations that need to cross-reference a C509 `issuerCertHash` with an RFC 6960 DER-encoded `CertID` must recompute the respective hash inputs; the values are not directly comparable.

#### PerIssuerOCSPRequests, PerIssuerOCSPRequest, SingleCertRequests and SingleCertRequest {#per-issuer-requests}

`PerIssuerOCSPRequests` is a list of `PerIssuerOCSPRequest` entries.  In X.509 OCSP ({{RFC6960, Section 4.1.1}}), every `Request` entry embeds a full `CertID` containing the issuer identity fields (`hashAlgorithm`, `issuerNameHash`, `issuerKeyHash`) alongside the `serialNumber`.  When multiple certificates from the same issuer are queried in a single request, these issuer fields are repeated verbatim for every entry, wasting space.  `PerIssuerOCSPRequest` solves this by grouping all single-certificate requests for the same issuer under one entry: the `issuerCertHash` field is encoded once and shared across all `SingleCertRequest` entries in the `singleRequests` list, eliminating the per-entry duplication.  Since `PerIssuerOCSPRequest` and `SingleCertRequest` are CDDL groups, the fields of each entry are inlined in the enclosing array rather than wrapped in a nested array.

- The `extensions` field contains per-issuer extensions that apply to all single-certificate requests in this `PerIssuerOCSPRequest` entry; see {{ocsp-per-issuer-extensions}}.
- The `singleRequests` field is a list of `SingleCertRequest` entries for certificates from this issuer.

Each `SingleCertRequest` contains:

- The `serialNumber` field is the certificate serial number of the target certificate; see {{cert-serial-number}}.
- The `extensions` field contains extensions for the single request; see {{ocsp-extensions}}.

#### C509BasicOCSPRequest {#C509BasicOCSPRequest}

`C509BasicOCSPRequest` is used for both unsigned and signed requests.  A request is signed if and only if `signatureAlgorithm` is not `null`.  An unsigned request ends with the `requests` field; a signed request additionally contains the fields `requestorCertHash`, `requestorCerts`, and `signatureValue`.  An OCSP responder MUST reject a request in which `signatureAlgorithm` is `null` and these fields are present, or in which `signatureAlgorithm` is not `null` and these fields are absent, by returning a `C509ErrorOCSPResponse` with `responseStatus` set to `malformedRequest` (1).

- The `ocspRequestType` field MUST be 1.
- The `signatureAlgorithm` field specifies the signature algorithm, as defined in {{I-D.ietf-cose-cbor-encoded-cert, Section 3.1.3}}, or MUST be `null` if the request is unsigned.  It is placed before the other fields, and not in the group of fields present only in a signed request, so that a receiver knows the signature algorithm before processing the signed data, which allows one-pass signature verification.
- The `hashAlgorithm` field specifies the hash algorithm used to compute `issuerCertHash` and, in a signed request, `requestorCertHash`.  The algorithm is encoded as specified in {{hash-algs}}.
- The `nonce` field contains the request nonce, or MUST be `null` when no nonce is present.  The nonce MUST be generated by a cryptographically strong pseudorandom number generator and MUST be between 16 and 128 bytes long.  An OCSP responder MUST reject a request whose nonce is shorter than 16 bytes or longer than 128 bytes by returning a `C509ErrorOCSPResponse` with `responseStatus` set to `malformedRequest` (1).
- The `extensions` field contains request-level extensions; see {{ocsp-extensions}}.
- The `requests` field is a list of `PerIssuerOCSPRequest` entries, each grouping target certificates by issuer; see {{per-issuer-requests}}.
- The `requestorCertHash` field, present only in a signed request, is a hash of the signer's certificate, computed using `hashAlgorithm`.
- The `requestorCerts` field, present only in a signed request, contains the ordered certificate chain of the signer as a `CertChainVariant` ({{cert-chain-variant}}), so that the receiver can verify the identity of the requestor, or MUST be `null` if no certificates are transported.
- The `signatureValue` field, present only in a signed request, is the signature computed over the CBOR Sequence of all elements of the `C509BasicOCSPRequest` array except `signatureValue`, i.e., from `ocspRequestType` to `requestorCerts`.

#### C509SimpleOCSPRequest {#C509SimpleOCSPRequest}

`C509SimpleOCSPRequest` is a compact request format for querying the status of a single certificate.  Unlike `C509BasicOCSPRequest`, which uses a two-level `PerIssuerOCSPRequests` / `SingleCertRequest` grouping to batch multiple serial numbers across one or more issuers, `C509SimpleOCSPRequest` flattens the structure into a single CBOR array for the common case of a one-certificate query.

- The `ocspRequestType` field MUST be 2.
- The `hashAlgorithm` field specifies the hash algorithm used to compute `issuerCertHash`.  The algorithm is encoded as specified in {{hash-algs}}.
- The `nonce` field is as defined for `C509BasicOCSPRequest` ({{C509BasicOCSPRequest}}).
- The `issuerCertHash` field identifies the issuer of the target certificate; see {{issuer-hash-id}}.
- The `serialNumber` field is the certificate serial number of the target certificate; see {{cert-serial-number}}.
- The `extensions` field contains request-level extensions; see {{ocsp-extensions}}.

### PEM Representation

The CBOR-encoded C509 OCSP request is first Base64-encoded and then wrapped between "-----BEGIN C509 OCSP REQUEST-----" and "-----END C509 OCSP REQUEST-----", following the framework of {{RFC7468}}.

~~~
-----BEGIN C509 OCSP REQUEST-----
(base64-encoded CBOR C509 OCSP Request)
-----END C509 OCSP REQUEST-----
~~~
{: #fig-pem-c509-ocsp-req title="C509 OCSP Request PEM Encoding"}


## C509 OCSP Response {#ocsp-response}

### CDDL {#ocsp-resp-cddl}

~~~~~~~~~~~ cddl
C509OCSPResponse = C509ErrorOCSPResponse /
                   C509BasicOCSPResponse /
                   C509SimpleOCSPResponse

C509ErrorOCSPResponse = [
  ocspResponseType  : 0,  ; int16
  responseStatus    : -128..127
]

TBSBasicOCSPResponse = (
  ocspResponseType   : 1, ; int16
  signatureAlgorithm : IntAlgorithmIdentifier,
  hashAlgorithm      : IntAlgorithmIdentifier,
  nonce              : bytes .size (16..128) / null,
  responderCertHash  : HashedId,
  producedAt         : ~time,
  extensions         : IntExtensions,
  responses          : PerIssuerOCSPResponses,
  responderCerts     : CertChainVariant / null,
)

C509BasicOCSPResponse = [
  TBSBasicOCSPResponse,
  signatureValue     : any
]

TBSSimpleOCSPResponse = (
  ocspResponseType   : 2, ; int16
  signatureAlgorithm : IntAlgorithmIdentifier,
  hashAlgorithm      : IntAlgorithmIdentifier,
  nonce              : bytes .size (16..128) / null,
  responderCertHash  : HashedId,
  issuerCertHash     : HashedId,
  serialNumber       : SerialNumber,
  certStatus         : CertStatus,
  producedAt         : ~time,
  thisUpdate         : nint / 0,
  nextUpdate         : uint63 / null,
  extensions         : IntExtensions,
  responderCerts     : CertChainVariant / null,
)

C509SimpleOCSPResponse = [
  TBSSimpleOCSPResponse,
  signatureValue     : any
]

PerIssuerOCSPResponses = [ + PerIssuerOCSPResponse ]

PerIssuerOCSPResponse = (
  issuerCertHash   : HashedId,
  extensions       : IntExtensions,
  singleResponses  : SingleCertResponses,
)

SingleCertResponses = [ + SingleCertResponse ]

SingleCertResponse = (
  serialNumber     : SerialNumber,
  certStatus       : CertStatus,
  thisUpdate       : nint / 0,
  nextUpdate       : uint63 / null,
  extensions       : IntExtensions,
)

CertStatus = 0        ; good
           / 1        ; not-issued (issuer recognized,
                      ;   serial number not issued)
           / 2        ; unknown (issuer not recognized)
           / RevokedInfo

RevokedInfo = [
  revocationTime   : ~time,
  revocationReason : uint8,
]
~~~~~~~~~~~
{: sourcecode-name="c509ocsp.cddl"}
{: #fig-OCSPRespCDDL title="CDDL for C509OCSPResponse"}

### Field Encodings {#ocsp-resp-fields}

#### C509ErrorOCSPResponse

If the OCSP responder cannot process the OCSP query, it returns a `C509ErrorOCSPResponse`.  The `ocspResponseType` value MUST be 0, and `responseStatus` has the following enumerated values, as in {{RFC6960, Section 4.2.1}}:

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

The `ocspResponseType` field of `C509BasicOCSPResponse` is 1, distinguishing it from `C509ErrorOCSPResponse` and `C509SimpleOCSPResponse`.  It corresponds to `BasicOCSPResponse` in {{RFC6960}}.

`TBSBasicOCSPResponse` is the group of fields to be signed. The `signatureValue` field is the only field outside the signed group.  Covering `signatureAlgorithm` and `responderCerts` within the signed content prevents algorithm-substitution and certificate-chain substitution attacks; this design goes beyond the protections offered by the DER-encoded `BasicOCSPResponse` defined in {{RFC6960}}.

#### C509SimpleOCSPResponse {#C509SimpleOCSPResponse}

`C509SimpleOCSPResponse` is a compact signed response for a single-certificate status query.  It is the response counterpart to `C509SimpleOCSPRequest` (see {{C509SimpleOCSPRequest}}).  Unlike `C509BasicOCSPResponse`, which uses a two-level `PerIssuerOCSPResponses` / `SingleCertResponse` grouping to carry status for multiple certificates across one or more issuers, `C509SimpleOCSPResponse` flattens the structure into a single signed CBOR array for the common case of a one-certificate response.

`TBSSimpleOCSPResponse` is the group of fields to be signed.  The `signatureValue` field is the only field outside the signed group.  Covering `signatureAlgorithm`, `responderCertHash`, and `responderCerts` within the signed content prevents algorithm-substitution and certificate-chain substitution attacks.

- The `ocspResponseType` field MUST be 2, which discriminates `C509SimpleOCSPResponse` from `C509ErrorOCSPResponse` and `C509BasicOCSPResponse`.
- The `signatureAlgorithm` field specifies the signature algorithm, as defined in {{I-D.ietf-cose-cbor-encoded-cert, Section 3.1.3}}.  It is part of `TBSSimpleOCSPResponse` and is therefore covered by the signature.
- The `hashAlgorithm` field specifies the hash algorithm used to compute `responderCertHash` and `issuerCertHash`.  The algorithm is encoded as specified in {{hash-algs}}.
- The `nonce` field contains the request nonce, or MUST be `null` when no nonce is present.  If present, it MUST have the same value as the `nonce` in the corresponding `C509SimpleOCSPRequest`.
- The `responderCertHash` field identifies the OCSP responder; see {{responderCertHash}}.
- The `issuerCertHash` field identifies the issuer of the queried certificate; see {{issuer-hash-id}}.
- The `serialNumber` field is the certificate serial number of the target certificate; see {{cert-serial-number}}.
- The `certStatus` field encodes the revocation status; see {{SingleCertResponse}}.
- The `producedAt` field is the time at which this response was produced, encoded as described in {{time-encoding}}.
- The `thisUpdate` field is encoded as a non-positive integer (`nint / 0`) representing the number of seconds from `producedAt` at which the indicated status is known to be correct.  It MUST be 0 or negative, since the status cannot be known at a time in the future relative to the time the response was produced.
- The `nextUpdate` field is encoded as a `uint63` representing the number of seconds from `producedAt` until the next response update is expected, or `null` if the update time is unknown.
- The `extensions` field contains response-level extensions; see {{ocsp-extensions}}.
- The `responderCerts` field carries the certificate chain starting with the responder certificate identified by `responderCertHash`; see {{responderCerts}}.
- The `signatureValue` field is the signature computed over the CBOR Sequence of the `TBSSimpleOCSPResponse` group.

#### nonce

If present, this field MUST have the same value as the `nonce` in the corresponding request.

#### responderCertHash {#responderCertHash}

`responderCertHash` is a truncated hash over the responder's certificate, computed using the same `hashAlgorithm` as `issuerCertHash`.  In X.509 OCSP ({{RFC6960}}), the responder is identified by a `ResponderID` CHOICE that carries either a distinguished name or a public-key hash.  C509 OCSP replaces this with a single hash over the entire responder certificate, which is consistent with the `issuerCertHash` design for issuer identification.

#### responderCerts {#responderCerts}

When present, the `responderCerts` field carries the certificate chain starting with the responder certificate identified by `responderCertHash`, as a `CertChainVariant` ({{cert-chain-variant}}).  The field is part of `TBSBasicOCSPResponse` or `TBSSimpleOCSPResponse` and is therefore covered by the signature, which prevents certificate-chain substitution attacks.

#### signatureAlgorithm and signatureValue

- `signatureAlgorithm`: the signature algorithm used to compute `signatureValue`, as defined in {{I-D.ietf-cose-cbor-encoded-cert, Section 3.1.3}}.  It is part of the `TBSBasicOCSPResponse` or `TBSSimpleOCSPResponse` group and is therefore covered by the signature.
- `signatureValue`: the signature computed over the CBOR Sequence of the `TBSBasicOCSPResponse` or `TBSSimpleOCSPResponse` group.

#### producedAt, thisUpdate, nextUpdate

The `producedAt` field is encoded as described in {{time-encoding}}.  The `thisUpdate` field is encoded as a non-positive integer (`nint / 0`) representing the number of seconds from `producedAt` at which the indicated status is known to be correct; it MUST be 0 or negative, since the status cannot be known at a time in the future relative to when the response was produced.  The `nextUpdate` field is encoded as a `uint63` representing the number of seconds from `producedAt` until the next update is expected to be available.  `nextUpdate` may be `null`, which indicates an unknown update time.

#### extensions

See {{ocsp-extensions}}.

#### PerIssuerOCSPResponses and PerIssuerOCSPResponse

`PerIssuerOCSPResponses` is a list of `PerIssuerOCSPResponse` entries.  For the same reason as on the request side (see {{per-issuer-requests}}), the `issuerCertHash` field is encoded once per issuer and shared across all `SingleCertResponse` entries in the `singleResponses` list, avoiding the per-entry repetition that would occur if the issuer identity were embedded in every individual response entry.  `PerIssuerOCSPResponse` groups single responses for certificates issued by the same issuer; the issuer is identified by `issuerCertHash` (see {{issuer-hash-id}}).  As on the request side, `PerIssuerOCSPResponse` and `SingleCertResponse` are CDDL groups whose fields are inlined in the enclosing array.

- The `extensions` field contains per-issuer extensions that apply to all single-certificate responses in this `PerIssuerOCSPResponse` entry; see {{ocsp-per-issuer-extensions}}.
- The `singleResponses` field contains one `SingleCertResponse` for each queried certificate issued by that issuer.

#### SingleCertResponse {#SingleCertResponse}

##### serialNumber {#serialNumber-section}

This field contains the serial number of the certificate being queried; see {{cert-serial-number}}.

##### extensions

See {{ocsp-extensions}}.

##### certStatus

`CertStatus` is encoded either as an integer (for `good`, `not-issued`, and `unknown`) or as a `RevokedInfo` array:

- 0: `good` -- the certificate is not revoked.
- 1: `not-issued` -- the issuer is recognized but the serial number is unknown.
- 2: `unknown` -- the responder does not recognize the issuer identified by `issuerCertHash`.
- `RevokedInfo`: `revoked` -- an array carrying `revocationTime` and `revocationReason`.  The `revocationReason` field is encoded as specified in {{reasoncode-encoding}}.  When the revocation reason is not known, `revocationReason` MUST be set to 0 (unspecified).

The integer values are chosen to align with the ASN.1 IMPLICIT tag numbers of `CertStatus` in {{RFC6960}}: `good` uses ASN.1 tag 0 and `unknown` uses ASN.1 tag 2.  The ASN.1 `revoked` alternative uses ASN.1 tag 1; since C509 represents the revoked status as the explicit `RevokedInfo` array, the integer value 1 becomes available.  It is assigned to the `not-issued` status, which was introduced in {{RFC6960, Section 4.4.8}} to distinguish unrecognized serial numbers from unrecognized issuers, thereby maintaining a contiguous integer range for the non-revoked statuses.

#### Per-Issuer OCSP Extensions {#ocsp-per-issuer-extensions}

`PerIssuerOCSPRequest.extensions` and `PerIssuerOCSPResponse.extensions` carry per-issuer extensions.

{{tab-perIssuerOCSPExt}} lists the per-issuer extensions defined in this document.

| Code | Extension | Applied in | Comments |
|:----:|:----------|:-----------|:---------|
| (none defined) | | | |
{: #tab-perIssuerOCSPExt title="Per-issuer OCSP extensions"}

#### OCSP Extensions {#ocsp-extensions}

{{tab-ocspext}} describes the OCSP extensions defined in {{RFC6960}} and {{STIR-OCSP}} and their mapping in this document.

| Code | Extension             | Reference         | Applied in | Replaced in this document |
|:----:|:----------------------|:------------------| :----------|:--------------|
|  -   | nonce                 | {{RFC6960, Section 4.4.1}}  | Request Extension, Response Extension | field `nonce` |
|  -   | CRL References        | {{RFC6960, Section 4.4.2}}  | Single Response Extension | - |
| TBD2 (129) | Acceptable Response Types | {{RFC6960, Section 4.4.3}}  | Request Extension | - |
|  -   | Archive Cutoff        | {{RFC6960, Section 4.4.4}}  | Response Extension | - |
|  -   | Service Locator       | {{RFC6960, Section 4.4.5}}  | Request Extension | - |
| TBD3 (130) | Preferred Signature Algorithms | {{RFC6960, Section 4.4.7}} | Request Extension | - |
|  -   | Extended Revoked Definition | {{RFC6960, Section 4.4.8}}  | Response Extension | cert status `not-issued` (for serial numbers not issued by a recognized issuer) and `unknown` (for unrecognized issuers) |
| TBD4 (131) | TN Query | {{STIR-OCSP}} | Single Request Extension | - |
{: #tab-ocspext title="OCSP extensions and their mapping"}

This document defines the following extension values:

* Acceptable Response Types: The extension value MUST be encoded as follows.

~~~~~~~~~~~ cddl
AcceptableResponseTypes = [ + int ]
~~~~~~~~~~~
{: sourcecode-name="c509ocsp.cddl"}

The integers in `AcceptableResponseTypes` form a sorted list of preferred `C509OCSPResponse` types, in descending order of preference, that the requestor is willing to accept.  This document defines types 0 (`C509ErrorOCSPResponse`), 1 (`C509BasicOCSPResponse`), and 2 (`C509SimpleOCSPResponse`).  Type 0 (`C509ErrorOCSPResponse`) is always implicitly supported and does not need to be listed.  When this extension is absent, an OCSP responder responding to a `C509BasicOCSPRequest` MUST reply with a `C509BasicOCSPResponse` (type 1); an OCSP responder responding to a `C509SimpleOCSPRequest` MUST reply with a `C509SimpleOCSPResponse` (type 2).  If `AcceptableResponseTypes` contains type 2 but not type 1, and the corresponding request contains entries for two or more certificates, the server SHALL return a `C509ErrorOCSPResponse` with `responseStatus` set to `malformedRequest` (1), since `C509SimpleOCSPResponse` can only carry status for a single certificate.

* Preferred Signature Algorithms: The extension value MUST be encoded as follows.

~~~~~~~~~~~ cddl
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

- a CBOR array of two or more `IntAlgorithmIdentifier` values, sorted in descending order of preference, when the requestor is willing to accept any of the listed public key algorithms as a match for this signature algorithm preference (e.g., to express hybrid or multi-algorithm key policies); the first entry in the array represents the most preferred public key algorithm,
- a single `IntAlgorithmIdentifier` value, when exactly one public key algorithm is acceptable, or
- `null`, when the public key algorithm is unconstrained or implied by `sigIdentifier`.

`PreferredSignatureAlgorithms` MUST be sorted in descending order of preference; the first entry represents the most preferred algorithm combination.  Since `PreferredSignatureAlgorithm` is a CDDL group, the fields of each entry are inlined in the array rather than wrapped in a nested array.

* TN Query: The extension value MUST be encoded as follows.

~~~~~~~~~~~ cddl
TNQuery = text .size (1..15)
~~~~~~~~~~~
{: sourcecode-name="c509ocsp.cddl"}

The `TNQuery` extension carries a telephone number string conforming to the TelephoneNumber ASN.1 type ({{RFC8226, Section 3}}).  When included in single-request extensions, it specifies the telephone number for which the OCSP query is being performed (typically the number from the "orig" field of a PASSporT being validated).

This extension is allowed only in the single-request extensions per {{STIR-OCSP}}.

### PEM Representation

The CBOR-encoded C509 OCSP response is first Base64-encoded and then wrapped between "-----BEGIN C509 OCSP RESPONSE-----" and "-----END C509 OCSP RESPONSE-----", following the framework of {{RFC7468}}.

~~~
-----BEGIN C509 OCSP RESPONSE-----
(base64-encoded CBOR C509 OCSP Response)
-----END C509 OCSP RESPONSE-----
~~~
{: #fig-pem-c509-ocsp-resp title="C509 OCSP Response PEM Encoding"}

## Certificate Type Interoperability {#cert-type-interop}

C509 OCSP uses a single set of request and response structures that handles C509 certificates and X.509 certificates without modification.  All participants (requestor, responder, issuer) are identified by a hash over their certificate rather than by type-specific fields such as a Subject distinguished name, SubjectKeyIdentifier, or the X.509 `ResponderID` CHOICE (`byName` or `byKey`).  Because a hash applies uniformly regardless of the certificate encoding, the same OCSP structures accommodate C509 certificates (CBOR-encoded), X.509 certificates (DER-encoded), and any future certificate types.

The only per-type differences are in how identity hashes and serial numbers are computed and how certificate chains are carried:

| Field | C509 certificate | X.509 certificate |
|:------|:-----------------|:------------------|
| `issuerCertHash` / `requestorCertHash` / `responderCertHash` | Hash of CBOR-encoded `C509Certificate` | Hash of DER-encoded X.509 certificate |
| `serialNumber`      | Serial number as is | Serial number without leading zero byte |
| `requestorCerts` / `responderCerts` | `[4, COSE_C509]` | `[0, COSE_X509]` |
{: #tab-certtypeinterop title="Per-type differences in C509 OCSP identity fields"}

In this table, "C509 certificate" refers to a natively signed C509 certificate (`c509CertificateType` = 2).  A CBOR re-encoded X.509 certificate (`c509CertificateType` = 3) is treated as an X.509 certificate: its identity hash MUST be computed over the DER-encoded X.509 certificate.

In a hybrid deployment where the responder holds an X.509 certificate, `responderCertHash` contains the hash of the DER-encoded X.509 certificate and `responderCerts` carries `[0, COSE_X509]`.  In a deployment using C509 certificates throughout, all identity hashes are computed over CBOR-encoded certificates and certificate chains are carried as `[4, COSE_C509]`.  The `hashAlgorithm` field at the top level of each request or response structure governs all certificate hashes within that structure.

## OCSP Stapling in TLS {#ocsp-stapling}

In standard TLS certificate status stapling (see the `status_request` extension, {{RFC9846}}), the stapled OCSP response is a DER-encoded `OCSPResponse`.  To allow C509 OCSP stapling, this document defines a new TLS `CertificateStatusType` value (see {{RFC6066, Section 8}}):

| Value | Name              | Reference     |
|:-----:|:------------------|:--------------|
| TBD5  | c509_ocsp         | This document |
{: #tab-tlsstaple title="TLS CertificateStatusType for C509 OCSP"}

When `CertificateStatusType` is `c509_ocsp`, the `status` field contains a CBOR-encoded `C509SimpleOCSPResponse` ({{C509SimpleOCSPResponse}}) instead of a DER-encoded `OCSPResponse`.  Other C509 OCSP response types MUST NOT be used.  A TLS client that receives a different response type MUST treat the stapled response as absent.

The `issuerCertHash` and `serialNumber` of the stapled response MUST match the certificate the response is stapled to.  Since a stapled response is not obtained in reply to a request from the TLS client, its `nonce` is not checked by the TLS client; the TLS server, acting as OCSP client, SHOULD send its request to the OCSP responder without a nonce.

# Implementation Status # {#sec-implementation-status}
{:removeinrfc}

Note to RFC Editor: Please remove this section before publication.  When deleting this section, please also delete RFC 7942 from the references of this document.

{::boilerplate rfc7942info}

## Implementation \#1 # {#sec-implementation-1}

- Organization: RISE AB

- Implementation: c509rev, available in the `c509rev` directory of the GitHub repository of this document (https://github.com/lijun-nio/idc509rev)

- Description: A reference implementation of the C509 CRL and C509 OCSP structures specified in this document, written in Rust.

- Implementation's level of maturity: Prototype.  Intended for testing and reference purposes, not for production use.

- Coverage:
  - C509 CRL, including the compact `revokedCertsList` encoding with fixed-length revoked-certificate and removed-from-CRL entries.
  - C509 OCSP requests of all defined types (simple and basic, the latter both unsigned and signed).  The signed requests carrying the requestor's certificate or certificate chain are supported only as an opaque pass-through.
  - C509 OCSP responses of all defined types (error, basic, and simple).
  - The hash algorithms SHA-256, SHA-384, and SHA-512, including truncated identity hashes.
  - Time encoding, including the delta encodings used in OCSP.
  - Signing and signature verification with Ed25519 and ECDSA with secp256r1 and SHA-256.
  - PEM textual representation of C509 CRLs and C509 OCSP messages, as specified in this document.
  - Names are supported only in the single common-name text form.

- Version compatibility: draft-liao-cose-c509-revocation-02

- Interoperability: The encoder output matches the examples in this document byte for byte (for signed objects, the to-be-signed part), and all examples successfully round-trip through decoding and re-encoding.  No interoperability testing with independent implementations has been performed yet.

- Licensing: See the repository of this document.

- Contact: Joel Höglund (joel.hoglund@ri.se)

## Implementation \#2 # {#sec-implementation-2}

- Organization: NIO Inc.

- Implementation: Internal project, not publicly available

- Description: An implementation of the C509 CRL and C509 OCSP structures specified in this document, written in Java.

- Implementation's level of maturity: Prototype.

- Coverage: All structures and features specified in this document.

- Version compatibility: draft-liao-cose-c509-revocation-02

- Interoperability: This implementation was used to produce the examples in the appendices of this document.

- Licensing: Internal use only.

- Contact: Lijun Liao (lijun.liao@nio.io)

# Security Considerations {#security}

The security considerations of {{RFC5280}}, {{RFC6960}}, {{I-D.ietf-cose-cbor-encoded-cert}}, and {{RFC8949, Section 10}} apply.  This section covers the considerations specific to this document.

## Signature Verification {#sec-signature}

The signatures of C509 CRLs and of signed C509 OCSP messages cover all fields except `signatureValue`, including `signatureAlgorithm` and `requestorCerts` or `responderCerts`.  This prevents algorithm and certificate-chain substitution, but does not replace the validation of {{RFC5280}} and {{RFC6960}}: the verifier MUST check that `signatureAlgorithm` matches the signer's public key, MUST validate the signer's certificate chain (a transported chain is only a hint for path construction), and MUST verify that the signer is authorized, as specified in {{RFC6960, Section 4.2.2.2}} for OCSP responses and in {{RFC5280, Section 6.3}} for CRLs.  The signature SHOULD be verified over the bytes as received rather than over a re-encoding.

`C509ErrorOCSPResponse` and `C509CRLInfo` ({{crlinfo}}) are not signed.  An error response MUST NOT be interpreted as status information about any certificate.  A `C509CRLInfo` MUST NOT be used for revocation or freshness decisions unless it was obtained over a channel that authenticates the CRL issuer.

## Truncated Hash Identifiers {#sec-truncated-hash}

`HashedId` ({{cert-identification}}) only selects a certificate and does not authenticate it; security relies on the signature verification in {{sec-signature}}.  A relying party MUST match a response to its request using hash values it has computed itself from the certificates it holds.  A receiver that finds several certificates matching a `HashedId` MUST NOT assume that a particular one is intended.  An OCSP responder for which an `issuerCertHash` matches more than one of its issuers MUST NOT return the status `good` for that entry.

`HashedId` identifies only the certificates of CAs, OCSP requestors, and OCSP responders; the certificate whose status is queried is identified by its serial number, not by a hash.  The number of certificates among which a `HashedId` must be unique is therefore small, typically the CA and responder certificates known to a relying party or the CA certificates served by an OCSP responder.  For a `HashedId` of L bytes, the probability that any two of n distinct certificates have the same `HashedId` is about n^2 / 2^(8L+1).  For n = 10^6 such certificates, this is about 2^-25 for L = 8, about 2^-89 (below 10^-26) for L = 16, and about 2^-121 (below 10^-36) for L = 20.

Finding a certificate whose `HashedId` equals that of a given certificate, e.g., to make a response for one certificate apply to another, requires about 2^(8L) operations for a secure hash algorithm, i.e., 2^64 for L = 8 and 2^128 for L = 16.  An attacker can find two certificates with the same `HashedId` with about 2^(4L) operations, but both certificates are then under the attacker's control; since `HashedId` only selects a certificate and trust is established by the signature verification and the authorization checks in {{sec-signature}}, such a collision gives the attacker no advantage.  Since the serial number is carried in plain form, the pair of `issuerCertHash` and `serialNumber` is as unambiguous as `issuerCertHash` alone.

A `HashedId` of 8 bytes is sufficient in closed deployments with a small number of CA, requestor, and responder certificates.  Where an attacker may be able to obtain certificates with chosen content from a CA that the relying party trusts, a `HashedId` of at least 16 bytes SHOULD be used.

The serial number MUST be normalized as specified in {{cert-serial-number}}; otherwise, a revoked certificate is not found.

## Privacy {#sec-privacy}

As in {{RFC6960}}, the serial number in a request or response is not protected: an observer can identify the queried certificate and link repeated queries, and `issuerCertHash` reveals the issuer.  Where this matters, requests and responses SHOULD be protected, e.g., by DTLS or OSCORE, or OCSP stapling ({{ocsp-stapling}}) SHOULD be used.

## Freshness and Replay {#sec-freshness}

A relying party MUST check the validity interval of an OCSP response ({{RFC6960, Section 4.2.2.1}}) and, if it sent a nonce, that the response carries the same nonce.  Without a nonce, a response can be replayed until it expires; relying parties without a reliable clock SHOULD use nonces.

The nonce is 16 to 128 bytes long ({{C509BasicOCSPRequest}}), whereas {{RFC9654}} requires OCSP requesters to use at least 32 octets in the Nonce extension of {{RFC6960}}; the maximum of 128 bytes is the same as in {{RFC9654}}.  A replay succeeds only if the attacker has obtained, from the OCSP responder, a response for the nonce that the relying party later chooses.  With N such responses and M requests, the probability is about N * M / 2^128 for a 16-byte nonce, i.e., about 2^-48 even for N = M = 2^40, and the attack can be neither performed offline nor accelerated by a quantum computer.  A 32-byte nonce adds no practical security but 16 bytes to each request and response, which is significant on constrained links.

A relying party MUST NOT use a CRL after `thisUpdate + nextUpdate`, SHOULD reject a CRL whose `crlNumber` is lower than that of a CRL previously accepted for the same scope, and MUST combine a delta CRL only with a full CRL whose `crlNumber` is at least `baseCrlNumber` ({{RFC5280, Section 5.2.4}}).

## Completeness of CRLs {#sec-completeness}

- Certificates whose serial number is not a positive integer of at most 20 bytes, as required by {{RFC5280, Section 4.1.2.2}}, are not supported by this document; C509 CRLs cannot list some of them, and relying parties MUST reject them.
- When `dateLength` is 0, no revocation date is available, and a listed certificate MUST be treated as revoked at all times.
- When bit 1 of `flags` is not set, no reason code is available, and the reason MUST be treated as `unspecified`.
- The issuer MUST be compared in the representation that matches the certificate type, as indicated by the `type` of the `NameVariant` ({{name-variant}}).

Implementations MUST reject a CRL in which the length of `revokedCerts` or `removedFromCRLCerts` is not a multiple of the entry length.  An implementation that uses binary search based on bit 0 of `flags` MUST verify that the entries are sorted, since otherwise a revoked certificate can be missed.

## Parsing and Denial of Service {#sec-parsing}

Messages are parsed before their signature is verified, and unsigned requests are never authenticated.  Implementations MUST reject input that does not conform to the CDDL, SHOULD limit message sizes and the number of entries, and MUST reject input for which computing an absolute time from a base time and an offset overflows.

Answering a request may require a signature, and responses are larger than requests, which exposes OCSP responders to resource exhaustion and to abuse for traffic amplification over UDP ({{RFC7252, Section 11.3}}).  OCSP responders SHOULD rate-limit requests and MAY require signed requests.

A stapled `C509SimpleOCSPResponse` ({{ocsp-stapling}}) MUST be validated as if obtained directly from the OCSP responder.

# IANA Considerations {#iana}

This document has the following actions for IANA.

Note to RFC Editor: Please replace all occurrences of "{{&SELF}}" with the RFC number of this specification and delete this paragraph.

## C509 CRL Types Registry {#crltypes}

IANA is requested to create a new registry titled "C509 CRL Types" under the registry group "CBOR Encoded X.509 (C509)". The fields of the registry are Value, Description, and Reference, where Value is an integer from -32768 to 32767, and the other columns are text strings. It is mandatory to specify content in all columns. For values from -24 to 23, the registration procedure is "IETF Review with Expert Review", and for all other values, the registration procedure is "Expert Review". The initial contents of the registry are:

~~~~~~~~~~~
+-------+-------------------------------+-------------------+
| Value | Description                   | Reference         |
+=======+===============================+===================+
|     0 | Basic                         | [[this document]] |
+-------+-------------------------------+-------------------+
~~~~~~~~~~~
{: #fig-crltypes title="C509 CRL Types"}
{: artwork-align="center"}

## C509 OCSP Request Types Registry {#ocspreqtypes}

IANA is requested to create a new registry titled "C509 OCSP Request Types" under the registry group "CBOR Encoded X.509 (C509)". The fields of the registry are Value, Description, and Reference, where Value is an integer from -32768 to 32767, and the other columns are text strings. It is mandatory to specify content in all columns. For values from -24 to 23, the registration procedure is "IETF Review with Expert Review", and for all other values, the registration procedure is "Expert Review". The initial contents of the registry are:

~~~~~~~~~~~
+-------+-------------------------------+-------------------+
| Value | Description                   | Reference         |
+=======+===============================+===================+
|     0 | Reserved                      | [[this document]] |
+-------+-------------------------------+-------------------+
|     1 | C509 Basic OCSP Request       | [[this document]] |
+-------+-------------------------------+-------------------+
|     2 | C509 Simple OCSP Request      | [[this document]] |
+-------+-------------------------------+-------------------+
~~~~~~~~~~~
{: #fig-ocspreqtypes title="C509 OCSP Request Types"}
{: artwork-align="center"}


## C509 OCSP Response Types Registry {#ocspresptypes}

IANA is requested to create a new registry titled "C509 OCSP Response Types" under the registry group "CBOR Encoded X.509 (C509)". The fields of the registry are Value, Description, and Reference, where Value is an integer from -32768 to 32767, and the other columns are text strings. It is mandatory to specify content in all columns. For values from -24 to 23, the registration procedure is "IETF Review with Expert Review", and for all other values, the registration procedure is "Expert Review". The initial contents of the registry are:

~~~~~~~~~~~
+-------+-------------------------------+-------------------+
| Value | Description                   | Reference         |
+=======+===============================+===================+
|     0 | C509 Error OCSP Response      | [[this document]] |
+-------+-------------------------------+-------------------+
|     1 | C509 Basic OCSP Response      | [[this document]] |
+-------+-------------------------------+-------------------+
|     2 | C509 Simple OCSP Response     | [[this document]] |
+-------+-------------------------------+-------------------+
~~~~~~~~~~~
{: #fig-ocspresptypes title="C509 OCSP Response Types"}
{: artwork-align="center"}

## Extension Identifiers Registry

IANA is requested to assign the new values shown in {{tab-extensions-iana}} in the "C509 Extensions" registry under the new registry group "CBOR Encoded X.509 (C509)" defined in {{I-D.ietf-cose-cbor-encoded-cert}}.  The values in parentheses are suggested values; they are used by the implementation in {{sec-implementation-2}}.

~~~
+-------+----------------------------------------------------------+
| Value | Extension                                                |
+=======+==========================================================+
| TBD1  | Name:            Expired Certificates on CRL             |
| (128) | Identifiers:     id-ce-expiredCertsOnCRL                 |
|       | OID:             2.5.29.60                               |
|       | DER:             06 03 55 1D 3C                          |
|       | Comments:        ITU-T X.509, Section 9.5.2.8            |
|       | extensionValue:  ExpiredCertsOnCRL                       |
|       | Reference:       [[this document]]                       |
+-------+----------------------------------------------------------+
| TBD2  | Name:            Acceptable Response Types               |
| (129) | Identifiers:     id-pkix-ocsp-response                   |
|       | OID:             1.3.6.1.5.5.7.48.1.4                    |
|       | DER:             06 09 2B 06 01 05 05 07 30 01 04        |
|       | Comments:        RFC 6960                                |
|       | extensionValue:  AcceptableResponseTypes                 |
|       | Reference:       [[this document]]                       |
+-------+----------------------------------------------------------+
| TBD3  | Name:            Preferred Signature Algorithms          |
| (130) | Identifiers:     id-pkix-ocsp-pref-sig-algs              |
|       | OID:             1.3.6.1.5.5.7.48.1.8                    |
|       | DER:             06 09 2B 06 01 05 05 07 30 01 08        |
|       | Comments:        RFC 6960                                |
|       | extensionValue:  PreferredSignatureAlgorithms            |
|       | Reference:       [[this document]]                       |
+-------+----------------------------------------------------------+
| TBD4  | Name:            TN Query                                |
| (131) | Identifiers:     id-pkix-ocsp-stir-tn                    |
|       | OID:             1.3.6.1.5.5.7.48.1.10                   |
|       | DER:             06 09 2B 06 01 05 05 07 30 01 0A        |
|       | Comments:        draft-ietf-stir-certificates-ocsp       |
|       | extensionValue:  TNQuery                                 |
|       | Reference:       [[this document]]                       |
+-------+----------------------------------------------------------+
~~~
{: #tab-extensions-iana title="C509 extension identifier allocation requests"}

## TLS CertificateStatusType Registry

IANA is requested to assign the value shown in {{tab-tls-certstatus-iana}} in the "TLS Certificate Status Types" registry under "Transport Layer Security (TLS) Extensions":

| Value | Description | Reference     | Comment |
|:-----:|:------------|:--------------|:--------------|
| TBD5  | c509_ocsp   | {{&SELF}}     | N/A |
{: #tab-tls-certstatus-iana title="TLS CertificateStatusType allocation request"}

## PEM Label Registry {#iana-pem}

IANA is requested to register the following entries in the "Textual Encoding Label" registry under the registry group "PKIX Parameters" {{RFC7468}}:

| Label | Reference |
|:---|:---|
| `C509 CRL` | {{&SELF}} |
| `C509 OCSP REQUEST` | {{&SELF}} |
| `C509 OCSP RESPONSE` | {{&SELF}} |
{: #tab-iana-pem title="PEM Label Registrations"}

## Media Type Application Registry

IANA is requested to assign the following entries in the "application" registry in the registry group "Media Types" with this document as reference.

### Media Type application/c509-crl+cbor

When the application/c509-crl+cbor media type is used, the data is a C509CertificateList structure.  A stored file format is defined with "magic number" TBD6 using the reserved CBOR tag 55799 and the Content-Format TBD7, enveloped as described in {{RFC9277, Section 2.2}}.

Subtype name: c509-crl+cbor

Required parameters: N/A

Optional parameters: N/A

Encoding considerations: binary

Security considerations: See {{security}} of {{&SELF}}.

Interoperability considerations: N/A

Published specification: {{&SELF}}

Applications that use this media type: Any MIME-compliant transport

Fragment identifier considerations: N/A

Additional information:

* Deprecated alias names for this type: N/A
* Magic number(s): TBD6
* File extension(s): .c509
* Macintosh file type code(s): N/A

Person & email address to contact for further information: iesg@ietf.org

Intended usage: COMMON

Restrictions on usage: N/A

Author: COSE WG

Change controller: IETF

### Media Type application/c509-crlinfo+cbor

When the application/c509-crlinfo+cbor media type is used, the data is a C509CRLInfo structure.  A stored file format is defined with "magic number" TBD8 using the reserved CBOR tag 55799 and the Content-Format TBD9, enveloped as described in {{RFC9277, Section 2.2}}.

Subtype name: c509-crlinfo+cbor

Required parameters: N/A

Optional parameters: N/A

Encoding considerations: binary

Security considerations: See {{security}} of {{&SELF}}.

Interoperability considerations: N/A

Published specification: {{&SELF}}

Applications that use this media type: Any MIME-compliant transport

Fragment identifier considerations: N/A

Additional information:

* Deprecated alias names for this type: N/A
* Magic number(s): TBD8
* File extension(s): .c509
* Macintosh file type code(s): N/A

Person & email address to contact for further information: iesg@ietf.org

Intended usage: COMMON

Restrictions on usage: N/A

Author: COSE WG

Change controller: IETF

### Media Type application/c509-ocspreq+cbor

When the application/c509-ocspreq+cbor media type is used, the data is a C509OCSPRequest structure.  A stored file format is defined with "magic number" TBD10 using the reserved CBOR tag 55799 and the Content-Format TBD11, enveloped as described in {{RFC9277, Section 2.2}}.

Subtype name: c509-ocspreq+cbor

Required parameters: N/A

Optional parameters: N/A

Encoding considerations: binary

Security considerations: See {{security}} of {{&SELF}}.

Interoperability considerations: N/A

Published specification: {{&SELF}}

Applications that use this media type: OCSP clients

Fragment identifier considerations: N/A

Additional information:

* Deprecated alias names for this type: N/A
* Magic number(s): TBD10
* File extension(s): .c509
* Macintosh file type code(s): N/A

Person & email address to contact for further information: iesg@ietf.org

Intended usage: COMMON

Restrictions on usage: N/A

Author: COSE WG

Change controller: IETF

### Media Type application/c509-ocspresp+cbor

When the application/c509-ocspresp+cbor media type is used, the data is a C509OCSPResponse structure.  A stored file format is defined with "magic number" TBD12 using the reserved CBOR tag 55799 and the Content-Format TBD13, enveloped as described in {{RFC9277, Section 2.2}}.

Subtype name: c509-ocspresp+cbor

Required parameters: N/A

Optional parameters: N/A

Encoding considerations: binary

Security considerations: See {{security}} of {{&SELF}}.

Interoperability considerations: N/A

Published specification: {{&SELF}}

Applications that use this media type: OCSP responders

Fragment identifier considerations: N/A

Additional information:

* Deprecated alias names for this type: N/A
* Magic number(s): TBD12
* File extension(s): .c509
* Macintosh file type code(s): N/A

Person & email address to contact for further information: iesg@ietf.org

Intended usage: COMMON

Restrictions on usage: N/A

Author: COSE WG

Change controller: IETF

## CoAP Content-Formats Registry {#content-format}

IANA is requested to add entries for "application/c509-crl+cbor", "application/c509-crlinfo+cbor", "application/c509-ocspreq+cbor", and "application/c509-ocspresp+cbor" to the "CoAP Content-Formats" registry in the registry group "Constrained RESTful Environments (CoRE) Parameters".

~~~
+-------------------------+---------+-------+------------+
| Content                 | Content | ID    | Reference  |
| Type                    | Coding  |       |            |
+=========================+=========+=======+============+
| application/            | -       | TBD7  | [[this     |
| c509-crl+cbor           |         |       | document]] |
+-------------------------+---------+-------+------------+
| application/            | -       | TBD9  | [[this     |
| c509-crlinfo+cbor       |         |       | document]] |
+-------------------------+---------+-------+------------+
| application/            | -       | TBD11 | [[this     |
| c509-ocspreq+cbor       |         |       | document]] |
+-------------------------+---------+-------+------------+
| application/            | -       | TBD13 | [[this     |
| c509-ocspresp+cbor      |         |       | document]] |
+-------------------------+---------+-------+------------+
~~~

## Expert Review Guidelines {#expert-review-guidelines}

TODO

--- back


# Examples {#examples}

## Overview

| Section       | Description           | size(X509) | size(C509) | Size Reduction |
|:--------------|:----------------------|:-----------|:-----------|:----------------------|
| {{exam-crl-no-revoked}} | CRL Example Without Revoked Certificates | 147 | 122 | 17% |
| {{exam-crl-revoked}} | CRL Example With Revoked Certificates | 421 | 263 | 38% |
| {{exam-delta-crl-revoked}} | Delta CRL Example With Revoked Certificates | 421 | 248 | 41% |
| {{exam-indirect-crl-revoked}} | Indirect CRL Example With Revoked Certificates | 493 | 294 | 40% |
| {{exam-simple-ocsp-req}} | Simple OCSP Request Example | 146 | 55 | 62% |
| {{exam-unsigned-ocsp-req}} | Unsigned Basic OCSP Request Example | 459 | 133 | 71% |
| {{exam-signed-ocsp-req}} | Signed Basic OCSP Request Example Without Requestor's Certificate | 568 | 217 | 62% |
| {{exam-signed-ocsp-req-withcert}} | Signed Basic OCSP Request Example With Requestor's Certificate | 1019 | 430 | 58% |
| {{exam-signed-ocsp-req-withcertchain}} | Signed Basic OCSP Request Example With Requestor's Certificate Chain | 1355 | 635 | 53% |
| {{exam-error-ocsp-resp}} | Error OCSP Response Example | 5 | 3 | 40% |
| {{exam-simple-ocsp-resp}} | Simple OCSP Response Example | 332 | 152 | 54% |
| {{exam-basic-ocsp-resp}} | Basic OCSP Response Example Without Responder's Certificate | 821 | 256 | 69% |
| {{exam-basic-ocsp-resp-withcert}} | Basic OCSP Response Example With Responder's Certificate | 1165 | 456 | 61% |
| {{exam-basic-ocsp-resp-withcertchain}} | Basic OCSP Response Example With Responder's Certificate Chain | 1501 | 661 | 56% |
{: #tab-examples-overview title="Size comparison in examples"}

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
- Size reduction: 17%
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
Plain Hex (122 bytes):

[comment]: <> (replace-data:crl/full-direct-no-revocation-crl/crl.hex)
~~~~~
8B000C82046F746573742063726C6F6373702D6361542F45E78D2CAEDF368CDF53C3
9005D492450E1056011A6775D7001A00093A80F680F65840C0B34844655B30E03DFB
A07705452FD5F9394B083430ACDB679FEE32A4503F05719E546838897F9F5DC9A509
C3CBDBCB32B4780EC76DDB5EF2AAAD7A92A4F20E
~~~~~

Textual Representation

[comment]: <> (replace-data:crl/full-direct-no-revocation-crl/crl.txt)
~~~~~
C509CRL
  TBSCertList
    CRL Type: C509CRL (0)
    Signature Algorithm: Ed25519 (12)
    Authority Subject
      Type: C509
      Name: CN=test crlocsp-ca
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
    c0:b3:48:44:65:5b:30:e0:3d:fb:a0:77:05:45:2f:d5:
    f9:39:4b:08:34:30:ac:db:67:9f:ee:32:a4:50:3f:05:
    71:9e:54:68:38:89:7f:9f:5d:c9:a5:09:c3:cb:db:cb:
    32:b4:78:0e:c7:6d:db:5e:f2:aa:ad:7a:92:a4:f2:0e
~~~~~

Annotated hex

[comment]: <> (replace-data:crl/full-direct-no-revocation-crl/crl.diag)
~~~~~
  0: 8B             # C509CertificateList=array[11]
  1:   00             # [0]. crlType=0
  2:   0C             # [1]. signatureAlgorithm=Ed25519 (12)
  3:   82             # [2]. authoritySubject=array[2]
  4:     04             # Type=C509 (4)
  5:     6F             # Name=char[15]
  6:       746573742063726C6F6373702D6361 # "test crlocsp-ca"
 21:   54             # [3]. authorityKeyIdentifier=byte[20]
 22:     2F45E78D2CAEDF368CDF53C39005D492450E1056
 42:   01             # [4]. crlNumber=1
 43:   1A 6775D700    # [5]. thisUpdate=1735776000:
                      #      2025-01-02T00:00:00Z
 48:   1A 00093A80    # [6]. nextUpdate=604800: 2025-01-09T00:00:00Z
 53:   F6             # [7]. baseCrlNumber=<null>
 54:   80             # [8]. crlExtensions=array[0]
 55:   F6             # [9]. revokedCertsList: <null>
 56:   58 40          # [10]. signature value=byte[64]
 58:     C0B34844655B30E03DFBA07705452FD5F9394B083430ACDB679FEE32A4
 87:     503F05719E546838897F9F5DC9A509C3CBDBCB32B4780EC76DDB5EF2AA
116:     AD7A92A4F20E
~~~~~

### CRL Example With Revoked Certificates {#exam-crl-revoked}

[comment]: <> (replace-reduction:crl/full-direct-with-revocation-crl/crl.hex % crl/full-direct-with-revocation-crl/x509crl.pem)
- Size reduction: 38%
- Verifiable with certificate in {{ca-cert}}
- Direct CRL
- Full CRL
- With revoked certificates
- With Per-Issuer Extension ExpiredCertsOnCRL
- Note that the X.509 CRL and the C509 CRL are not convertible.

#### X.509 CRL

[comment]: <> (replace-size:crl/full-direct-with-revocation-crl/x509crl.pem)
PEM content (421 bytes):

[comment]: <> (replace-data:crl/full-direct-with-revocation-crl/x509crl.pem)
~~~~~
-----BEGIN X509 CRL-----
MIIBoTCCAVMCAQEwBQYDK2VwMBoxGDAWBgNVBAMMD3Rlc3QgY3Jsb2NzcC1jYRcN
MjUwMTA3MDAxMjM0WhcNMjUwMTE0MDAxMjM0WjCCAQswLwIQESIRIhEiESIRIhEi
ESIRIhcNMjUwMTA2MDAxMjM0WjAMMAoGA1UdFQQDCgEGMC8CEBI0EjQSNBI0EjQS
NBI0EjQXDTI1MDEwMTAwMTIzNFowDDAKBgNVHRUEAwoBATAvAhAzRDNEM0QzRDNE
M0QzRDNEFw0yNTAxMDQwMDEyMzRaMAwwCgYDVR0VBAMKAQYwLwIQVWZVZlVmVWZV
ZlVmVWZVZhcNMjUwMTAyMDAxMjM0WjAMMAoGA1UdFQQDCgEGMCECEFZ4VnhWeFZ4
VnhWeFZ4VngXDTI1MDEwNTAwMTIzNFowIgIRAJq8mryavJq8mryavJq8mrwXDTI1
MDEwMzAwMTIzNFowBQYDK2VwA0EAp6wCUk3+65Hj8Et8zSI8gfA8yltepQBFCUav
DLvkH2IryYN59RidnfX/MyK5k1GaHLDsXE3NRlQ+0BbTIPqxDw==
-----END X509 CRL-----
~~~~~

#### C509 CRL

[comment]: <> (replace-size:crl/full-direct-with-revocation-crl/crl.hex)
Plain Hex (263 bytes):

[comment]: <> (replace-data:crl/full-direct-with-revocation-crl/crl.hex)
~~~~~
8B000C82046F746573742063726C6F6373702D6361542F45E78D2CAEDF368CDF53C3
9005D492450E1056021A677C71721A00093A80F68085F6840310031A677488728218
801A6774858058781122112211221122112211221122112206978006123412341234
12341234123412341234000000013344334433443344334433443344334403F48006
55665566556655665566556655665566015180065678567856785678567856785678
5678054600009ABC9ABC9ABC9ABC9ABC9ABC9ABC9ABC02A30000F65840E4BCF220CE
CFB32410FB6AD0B90993F87CB3630F396CFF0016CBE45A86315EDC53F3C5275188A5
3DA4912CA2E37C4C5154349CB1E3AC3F4414579C7E1CE65C0D
~~~~~

Textual Representation

[comment]: <> (replace-data:crl/full-direct-with-revocation-crl/crl.txt)
~~~~~
C509CRL
  TBSCertList
    CRL Type: C509CRL (0)
    Signature Algorithm: Ed25519 (12)
    Authority Subject
      Type: C509
      Name: CN=test crlocsp-ca
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
        Serial number length: 16
        Date length: 3
        Base date: 2025-01-01T00:12:34Z
      Extensions
        ExpiredCertsOnCRL (128)
          2025-01-01T00:00:00Z
      RevokedCerts:
        0x11221122112211221122112211221122
            2025-01-06T00:12:34Z, certificateHold
        0x12341234123412341234123412341234
            2025-01-01T00:12:34Z, keyCompromise
        0x33443344334433443344334433443344
            2025-01-04T00:12:34Z, certificateHold
        0x55665566556655665566556655665566
            2025-01-02T00:12:34Z, certificateHold
        0x56785678567856785678567856785678
            2025-01-05T00:12:34Z, unspecified
        0x9ABC9ABC9ABC9ABC9ABC9ABC9ABC9ABC
            2025-01-03T00:12:34Z, unspecified
      RemovedFromCRLCerts: <null>
  Signature Value
    e4:bc:f2:20:ce:cf:b3:24:10:fb:6a:d0:b9:09:93:f8:
    7c:b3:63:0f:39:6c:ff:00:16:cb:e4:5a:86:31:5e:dc:
    53:f3:c5:27:51:88:a5:3d:a4:91:2c:a2:e3:7c:4c:51:
    54:34:9c:b1:e3:ac:3f:44:14:57:9c:7e:1c:e6:5c:0d
~~~~~

Annotated hex

[comment]: <> (replace-data:crl/full-direct-with-revocation-crl/crl.diag)
~~~~~
  0: 8B             # C509CertificateList=array[11]
  1:   00             # [0]. crlType=0
  2:   0C             # [1]. signatureAlgorithm=Ed25519 (12)
  3:   82             # [2]. authoritySubject=array[2]
  4:     04             # Type=C509 (4)
  5:     6F             # Name=char[15]
  6:       746573742063726C6F6373702D6361 # "test crlocsp-ca"
 21:   54             # [3]. authorityKeyIdentifier=byte[20]
 22:     2F45E78D2CAEDF368CDF53C39005D492450E1056
 42:   02             # [4]. crlNumber=2
 43:   1A 677C7172    # [5]. thisUpdate=1736208754:
                      #      2025-01-07T00:12:34Z
 48:   1A 00093A80    # [6]. nextUpdate=604800: 2025-01-14T00:12:34Z
 53:   F6             # [7]. baseCrlNumber=<null>
 54:   80             # [8]. crlExtensions=array[0]
 55:   85             # [9]. revokedCertsList=array[5]
                        #---PerIssuerRevokedCerts[0]---
 56:     F6             # [0]. issuer=<null>
 57:     84             # [1]. revokedCertsControl=array[4]
 58:       03             # [0]. flags: sorted, with reason (0x3)
 59:       10             # [1]. serialNumberLength=16
 60:       03             # [2]. dateLength=3
 61:       1A 67748872    # [3]. baseDate=1735690354:
                          #      2025-01-01T00:12:34Z
 66:     82             # [2]. extensions=array[2]
                          #---extension[0]---
 67:       18 80          # [0]. type=ExpiredCertsOnCRL (128)
 69:       1A 67748580    # [1]. value=1735689600:
                          #      2025-01-01T00:00:00Z
 74:     58 78          # [3]. revokedCerts=byte[120], 6 entries
                          #---entries[0]---
 76:       11221122112211221122112211221122 # CSN=112211221122112211
                                            # 22112211221122
 92:       069780         # date=069780: 2025-01-06T00:12:34Z
 95:       06             # reason=6: certificateHold
                          #---entries[1]---
 96:       12341234123412341234123412341234 # CSN=123412341234123412
                                            # 34123412341234
112:       000000         # date=000000: 2025-01-01T00:12:34Z
115:       01             # reason=1: keyCompromise
                          #---entries[2]---
116:       33443344334433443344334433443344 # CSN=334433443344334433
                                            # 44334433443344
132:       03F480         # date=03F480: 2025-01-04T00:12:34Z
135:       06             # reason=6: certificateHold
                          #---entries[3]---
136:       55665566556655665566556655665566 # CSN=556655665566556655
                                            # 66556655665566
152:       015180         # date=015180: 2025-01-02T00:12:34Z
155:       06             # reason=6: certificateHold
                          #---entries[4]---
156:       56785678567856785678567856785678 # CSN=567856785678567856
                                            # 78567856785678
172:       054600         # date=054600: 2025-01-05T00:12:34Z
175:       00             # reason=0: unspecified
                          #---entries[5]---
176:       9ABC9ABC9ABC9ABC9ABC9ABC9ABC9ABC # CSN=9ABC9ABC9ABC9ABC9A
                                            # BC9ABC9ABC9ABC
192:       02A300         # date=02A300: 2025-01-03T00:12:34Z
195:       00             # reason=0: unspecified
196:     F6             # [4]. removedFromCRLCerts=<null>
197:   58 40          # [10]. signature value=byte[64]
199:     E4BCF220CECFB32410FB6AD0B90993F87CB3630F396CFF0016CBE45A86
228:     315EDC53F3C5275188A53DA4912CA2E37C4C5154349CB1E3AC3F441457
257:     9C7E1CE65C0D
~~~~~

### Delta CRL Example With Revoked Certificates {#exam-delta-crl-revoked}

[comment]: <> (replace-reduction:crl/delta-with-revocation-crl/crl.hex % crl/delta-with-revocation-crl/x509crl.pem)
- Size reduction: 41%
- Verifiable with certificate in {{ca-cert}}
- Direct CRL
- Delta CRL
- With revoked certificates
- With entries removed from the CRL since the last full CRL
- Note that the X.509 CRL and the C509 CRL are not convertible.

#### X.509 CRL

[comment]: <> (replace-size:crl/delta-with-revocation-crl/x509crl.pem)
PEM content (421 bytes):

[comment]: <> (replace-data:crl/delta-with-revocation-crl/x509crl.pem)
~~~~~
-----BEGIN X509 CRL-----
MIIBoTCCAVMCAQEwBQYDK2VwMBoxGDAWBgNVBAMMD3Rlc3QgY3Jsb2NzcC1jYRcN
MjUwMTA4MDAxMjM0WhcNMjUwMTEwMDAxMjM0WjCCAQswLwIQNBI0EjQSNBI0EjQS
NBI0EhcNMjUwMTA3MTIxMjM0WjAMMAoGA1UdFQQDCgEBMCECEHhWeFZ4VnhWeFZ4
VnhWeFYXDTI1MDEwODAwMTAzNFowIgIRALyavJq8mryavJq8mryavJoXDTI1MDEw
ODAwMDgzNFowLwIQESIRIhEiESIRIhEiESIRIhcNMjUwMTA3MTMxMjM0WjAMMAoG
A1UdFQQDCgEIMC8CEDNEM0QzRDNEM0QzRDNEM0QXDTI1MDEwNzE0MTIzNFowDDAK
BgNVHRUEAwoBCDAvAhBVZlVmVWZVZlVmVWZVZlVmFw0yNTAxMDcxNTEyMzRaMAww
CgYDVR0VBAMKAQgwBQYDK2VwA0EA6CPCyItZkaGr9HRhjhCk3z1KClmwg5XdUabY
xLYoJYfGT0y9X7JTPfxd6vRqc6Uq7yiW42mnahGBd7rLgs3DDQ==
-----END X509 CRL-----
~~~~~

#### C509 CRL

[comment]: <> (replace-size:crl/delta-with-revocation-crl/crl.hex)
Plain Hex (248 bytes):

[comment]: <> (replace-data:crl/delta-with-revocation-crl/crl.hex)
~~~~~
8B000C82046F746573742063726C6F6373702D6361542F45E78D2CAEDF368CDF53C3
9005D492450E1056031A677DC2F21A0002A300028085F6840310021A677D1A328058
39341234123412341234123412341234120000017856785678567856785678567856
7856A84800BC9ABC9ABC9ABC9ABC9ABC9ABC9ABC9AA7D00058361122112211221122
11221122112211220E10334433443344334433443344334433441C20556655665566
556655665566556655662A305840070CC4DB7217D0A23AC5B6808602290E7D58E3D8
AC2BEC32936F27C7271B26B4BC646DC8CDCBCF3F513CBC734DF36B2DBD8A1B237E1F
B26342928497985AE706
~~~~~

Textual Representation

[comment]: <> (replace-data:crl/delta-with-revocation-crl/crl.txt)
~~~~~
C509CRL
  TBSCertList
    CRL Type: C509CRL (0)
    Signature Algorithm: Ed25519 (12)
    Authority Subject
      Type: C509
      Name: CN=test crlocsp-ca
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
        Serial number length: 16
        Date length: 2
        Base date: 2025-01-07T12:12:34Z
      Extensions: <empty>
      RevokedCerts:
        0x34123412341234123412341234123412
            2025-01-07T12:12:34Z, keyCompromise
        0x78567856785678567856785678567856
            2025-01-08T00:10:34Z, unspecified
        0xBC9ABC9ABC9ABC9ABC9ABC9ABC9ABC9A
            2025-01-08T00:08:34Z, unspecified
      RemovedFromCRLCerts:
        0x11221122112211221122112211221122, 2025-01-07T13:12:34Z
        0x33443344334433443344334433443344, 2025-01-07T14:12:34Z
        0x55665566556655665566556655665566, 2025-01-07T15:12:34Z
  Signature Value
    07:0c:c4:db:72:17:d0:a2:3a:c5:b6:80:86:02:29:0e:
    7d:58:e3:d8:ac:2b:ec:32:93:6f:27:c7:27:1b:26:b4:
    bc:64:6d:c8:cd:cb:cf:3f:51:3c:bc:73:4d:f3:6b:2d:
    bd:8a:1b:23:7e:1f:b2:63:42:92:84:97:98:5a:e7:06
~~~~~

Annotated hex

[comment]: <> (replace-data:crl/delta-with-revocation-crl/crl.diag)
~~~~~
  0: 8B             # C509CertificateList=array[11]
  1:   00             # [0]. crlType=0
  2:   0C             # [1]. signatureAlgorithm=Ed25519 (12)
  3:   82             # [2]. authoritySubject=array[2]
  4:     04             # Type=C509 (4)
  5:     6F             # Name=char[15]
  6:       746573742063726C6F6373702D6361 # "test crlocsp-ca"
 21:   54             # [3]. authorityKeyIdentifier=byte[20]
 22:     2F45E78D2CAEDF368CDF53C39005D492450E1056
 42:   03             # [4]. crlNumber=3
 43:   1A 677DC2F2    # [5]. thisUpdate=1736295154:
                      #      2025-01-08T00:12:34Z
 48:   1A 0002A300    # [6]. nextUpdate=172800: 2025-01-10T00:12:34Z
 53:   02             # [7]. baseCrlNumber=2
 54:   80             # [8]. crlExtensions=array[0]
 55:   85             # [9]. revokedCertsList=array[5]
                        #---PerIssuerRevokedCerts[0]---
 56:     F6             # [0]. issuer=<null>
 57:     84             # [1]. revokedCertsControl=array[4]
 58:       03             # [0]. flags: sorted, with reason (0x3)
 59:       10             # [1]. serialNumberLength=16
 60:       02             # [2]. dateLength=2
 61:       1A 677D1A32    # [3]. baseDate=1736251954:
                          #      2025-01-07T12:12:34Z
 66:     80             # [2]. extensions=array[0]
 67:     58 39          # [3]. revokedCerts=byte[57], 3 entries
                          #---entries[0]---
 69:       34123412341234123412341234123412 # CSN=341234123412341234
                                            # 12341234123412
 85:       0000           # date=0000: 2025-01-07T12:12:34Z
 87:       01             # reason=1: keyCompromise
                          #---entries[1]---
 88:       78567856785678567856785678567856 # CSN=785678567856785678
                                            # 56785678567856
104:       A848           # date=A848: 2025-01-08T00:10:34Z
106:       00             # reason=0: unspecified
                          #---entries[2]---
107:       BC9ABC9ABC9ABC9ABC9ABC9ABC9ABC9A # CSN=BC9ABC9ABC9ABC9ABC
                                            # 9ABC9ABC9ABC9A
123:       A7D0           # date=A7D0: 2025-01-08T00:08:34Z
125:       00             # reason=0: unspecified
126:     58 36          # [4]. removedFromCRLCerts=byte[54], 3
                        #      entries
                          #---entries[0]---
128:       11221122112211221122112211221122 # CSN=112211221122112211
                                            # 22112211221122
144:       0E10           # date=0E10: 2025-01-07T13:12:34Z
                          #---entries[1]---
146:       33443344334433443344334433443344 # CSN=334433443344334433
                                            # 44334433443344
162:       1C20           # date=1C20: 2025-01-07T14:12:34Z
                          #---entries[2]---
164:       55665566556655665566556655665566 # CSN=556655665566556655
                                            # 66556655665566
180:       2A30           # date=2A30: 2025-01-07T15:12:34Z
182:   58 40          # [10]. signature value=byte[64]
184:     070CC4DB7217D0A23AC5B6808602290E7D58E3D8AC2BEC32936F27C727
213:     1B26B4BC646DC8CDCBCF3F513CBC734DF36B2DBD8A1B237E1FB2634292
242:     8497985AE706
~~~~~

### Indirect CRL Example With Revoked Certificates {#exam-indirect-crl-revoked}

[comment]: <> (replace-reduction:crl/full-indirect-with-revocation-crl/crl.hex % crl/full-indirect-with-revocation-crl/x509crl.pem)
- Size reduction: 40%
- Verifiable with certificate in {{crl-signer-cert}}
- Indirect CRL
- Full CRL
- With revoked certificates
- With two issuers
- Note that the X.509 CRL and the C509 CRL are not convertible.

#### X.509 CRL

[comment]: <> (replace-size:crl/full-indirect-with-revocation-crl/x509crl.pem)
PEM content (493 bytes):

[comment]: <> (replace-data:crl/full-indirect-with-revocation-crl/x509crl.pem)
~~~~~
-----BEGIN X509 CRL-----
MIIB6TCCAZsCAQEwBQYDK2VwMBUxEzARBgNVBAMMCmNybC1zaWduZXIXDTI1MDEw
NzAwMTIzNFoXDTI1MDExNDAwMTIzNFowggFYMFgCEBI0EjQSNBI0EjQSNBI0EjQX
DTI1MDEwMTAwMTIzNFowNTAKBgNVHRUEAwoBATAnBgNVHR0EIDAepBwwGjEYMBYG
A1UEAwwPdGVzdCBjcmxvY3NwLWNhMCECEFZ4VnhWeFZ4VnhWeFZ4VngXDTI1MDEw
NTAwMTIzNFowIgIRAJq8mryavJq8mryavJq8mrwXDTI1MDEwMzAwMTIzNFowUwIQ
ESIRIhEiESIRIhEiESIRIhcNMjUwMTA2MDAxMjM0WjAwMAoGA1UdFQQDCgEGMCIG
A1UdHQQbMBmkFzAVMRMwEQYDVQQDDApleGFtcGxlIENBMC8CEDNEM0QzRDNEM0Qz
RDNEM0QXDTI1MDEwNDAwMTIzNFowDDAKBgNVHRUEAwoBBjAvAhBVZlVmVWZVZlVm
VWZVZlVmFw0yNTAxMDIwMDEyMzRaMAwwCgYDVR0VBAMKAQYwBQYDK2VwA0EAADkt
kX+MK72oObWup1D7jfxivgh1Wpc5UP2PEEsBlntLXB6aZrfMf6ipCw9ZrCZw1+6C
VO/+Tzxxlkv8pnFxDw==
-----END X509 CRL-----
~~~~~

#### C509 CRL

[comment]: <> (replace-size:crl/full-indirect-with-revocation-crl/crl.hex)
Plain Hex (294 bytes):

[comment]: <> (replace-data:crl/full-indirect-with-revocation-crl/crl.hex)
~~~~~
8B000C82046A63726C2D7369676E65725409E433582556550A27DB4A19BCE2D66088
4722B6041A677C71721A00093A80F6808A82046F746573742063726C6F6373702D63
61840310031A6774887280583C123412341234123412341234123412340000000156
785678567856785678567856785678054600009ABC9ABC9ABC9ABC9ABC9ABC9ABC9A
BC02A30000F682046A6578616D706C65204341840310031A6775D9F280583C112211
22112211221122112211221122054600063344334433443344334433443344334402
A300065566556655665566556655665566556600000006F65840514A1E910A7CBB56
E652B18779A8DC6427DD55B5313DD1F20DDE47777A6F6B3D83988991828092278E70
88E7FDBD40D107B9F30B6AC0E4219CE495CF0CAEC70A
~~~~~

Textual Representation

[comment]: <> (replace-data:crl/full-indirect-with-revocation-crl/crl.txt)
~~~~~
C509CRL
  TBSCertList
    CRL Type: C509CRL (0)
    Signature Algorithm: Ed25519 (12)
    Authority Subject
      Type: C509
      Name: CN=crl-signer
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
      Issuer
        Type: C509
        Name: CN=test crlocsp-ca
      RevokedCertsControl
        Flags: sorted, with reason (0x3)
        Serial number length: 16
        Date length: 3
        Base date: 2025-01-01T00:12:34Z
      Extensions: <empty>
      RevokedCerts:
        0x12341234123412341234123412341234
            2025-01-01T00:12:34Z, keyCompromise
        0x56785678567856785678567856785678
            2025-01-05T00:12:34Z, unspecified
        0x9ABC9ABC9ABC9ABC9ABC9ABC9ABC9ABC
            2025-01-03T00:12:34Z, unspecified
      RemovedFromCRLCerts: <null>
    PerIssuerRevokedCerts[1]
      Issuer
        Type: C509
        Name: CN=example CA
      RevokedCertsControl
        Flags: sorted, with reason (0x3)
        Serial number length: 16
        Date length: 3
        Base date: 2025-01-02T00:12:34Z
      Extensions: <empty>
      RevokedCerts:
        0x11221122112211221122112211221122
            2025-01-06T00:12:34Z, certificateHold
        0x33443344334433443344334433443344
            2025-01-04T00:12:34Z, certificateHold
        0x55665566556655665566556655665566
            2025-01-02T00:12:34Z, certificateHold
      RemovedFromCRLCerts: <null>
  Signature Value
    51:4a:1e:91:0a:7c:bb:56:e6:52:b1:87:79:a8:dc:64:
    27:dd:55:b5:31:3d:d1:f2:0d:de:47:77:7a:6f:6b:3d:
    83:98:89:91:82:80:92:27:8e:70:88:e7:fd:bd:40:d1:
    07:b9:f3:0b:6a:c0:e4:21:9c:e4:95:cf:0c:ae:c7:0a
~~~~~

Annotated hex

[comment]: <> (replace-data:crl/full-indirect-with-revocation-crl/crl.diag)
~~~~~
  0: 8B             # C509CertificateList=array[11]
  1:   00             # [0]. crlType=0
  2:   0C             # [1]. signatureAlgorithm=Ed25519 (12)
  3:   82             # [2]. authoritySubject=array[2]
  4:     04             # Type=C509 (4)
  5:     6A             # Name=char[10]
  6:       63726C2D7369676E6572 # "crl-signer"
 16:   54             # [3]. authorityKeyIdentifier=byte[20]
 17:     09E433582556550A27DB4A19BCE2D660884722B6
 37:   04             # [4]. crlNumber=4
 38:   1A 677C7172    # [5]. thisUpdate=1736208754:
                      #      2025-01-07T00:12:34Z
 43:   1A 00093A80    # [6]. nextUpdate=604800: 2025-01-14T00:12:34Z
 48:   F6             # [7]. baseCrlNumber=<null>
 49:   80             # [8]. crlExtensions=array[0]
 50:   8A             # [9]. revokedCertsList=array[10]
                        #---PerIssuerRevokedCerts[0]---
 51:     82             # [0]. issuer=array[2]
 52:       04             # Type=C509 (4)
 53:       6F             # Name=char[15]
 54:         746573742063726C6F6373702D6361 # "test crlocsp-ca"
 69:     84             # [1]. revokedCertsControl=array[4]
 70:       03             # [0]. flags: sorted, with reason (0x3)
 71:       10             # [1]. serialNumberLength=16
 72:       03             # [2]. dateLength=3
 73:       1A 67748872    # [3]. baseDate=1735690354:
                          #      2025-01-01T00:12:34Z
 78:     80             # [2]. extensions=array[0]
 79:     58 3C          # [3]. revokedCerts=byte[60], 3 entries
                          #---entries[0]---
 81:       12341234123412341234123412341234 # CSN=123412341234123412
                                            # 34123412341234
 97:       000000         # date=000000: 2025-01-01T00:12:34Z
100:       01             # reason=1: keyCompromise
                          #---entries[1]---
101:       56785678567856785678567856785678 # CSN=567856785678567856
                                            # 78567856785678
117:       054600         # date=054600: 2025-01-05T00:12:34Z
120:       00             # reason=0: unspecified
                          #---entries[2]---
121:       9ABC9ABC9ABC9ABC9ABC9ABC9ABC9ABC # CSN=9ABC9ABC9ABC9ABC9A
                                            # BC9ABC9ABC9ABC
137:       02A300         # date=02A300: 2025-01-03T00:12:34Z
140:       00             # reason=0: unspecified
141:     F6             # [4]. removedFromCRLCerts=<null>
                        #---PerIssuerRevokedCerts[1]---
142:     82             # [5]. issuer=array[2]
143:       04             # Type=C509 (4)
144:       6A             # Name=char[10]
145:         6578616D706C65204341 # "example CA"
155:     84             # [6]. revokedCertsControl=array[4]
156:       03             # [0]. flags: sorted, with reason (0x3)
157:       10             # [1]. serialNumberLength=16
158:       03             # [2]. dateLength=3
159:       1A 6775D9F2    # [3]. baseDate=1735776754:
                          #      2025-01-02T00:12:34Z
164:     80             # [7]. extensions=array[0]
165:     58 3C          # [8]. revokedCerts=byte[60], 3 entries
                          #---entries[0]---
167:       11221122112211221122112211221122 # CSN=112211221122112211
                                            # 22112211221122
183:       054600         # date=054600: 2025-01-06T00:12:34Z
186:       06             # reason=6: certificateHold
                          #---entries[1]---
187:       33443344334433443344334433443344 # CSN=334433443344334433
                                            # 44334433443344
203:       02A300         # date=02A300: 2025-01-04T00:12:34Z
206:       06             # reason=6: certificateHold
                          #---entries[2]---
207:       55665566556655665566556655665566 # CSN=556655665566556655
                                            # 66556655665566
223:       000000         # date=000000: 2025-01-02T00:12:34Z
226:       06             # reason=6: certificateHold
227:     F6             # [9]. removedFromCRLCerts=<null>
228:   58 40          # [10]. signature value=byte[64]
230:     514A1E910A7CBB56E652B18779A8DC6427DD55B5313DD1F20DDE47777A
259:     6F6B3D83988991828092278E7088E7FDBD40D107B9F30B6AC0E4219CE4
288:     95CF0CAEC70A
~~~~~

## OCSP Request Examples

### Simple OCSP Request Example {#exam-simple-ocsp-req}

[comment]: <> (replace-reduction:ocspreq/simple-ocspreq/ocspreq.hex % ocspreq/simple-ocspreq/x509ocspreq.pem)
- Size reduction: 62%
- Simple OCSP Request (`C509SimpleOCSPRequest`)
- Note that the X.509 OCSP Request and the C509 OCSP Request are not convertible.

#### X.509 OCSP Request

[comment]: <> (replace-size:ocspreq/simple-ocspreq/x509ocspreq.pem)
PEM content (146 bytes):

[comment]: <> (replace-data:ocspreq/simple-ocspreq/x509ocspreq.pem)
~~~~~
-----BEGIN OCSP REQUEST-----
MIGPMIGMMGcwZTBjMAsGCWCGSAFlAwQCAQQgMlOOdIW9N65FTx8NK5dV11i5H26O
Onrzl6D0AGBcb/gEIMwRyHQKBQnsTaFM5YhucjZMD2O2DtY0fxPBbuclt2aiAhAS
NBI0EjQSNBI0EjQSNBI0oiEwHzAdBgkrBgEFBQcwAQIEEBERERERERERERERERER
ERE=
-----END OCSP REQUEST-----
~~~~~

#### C509 OCSP Request

[comment]: <> (replace-size:ocspreq/simple-ocspreq/ocspreq.hex)
Plain Hex (55 bytes):

[comment]: <> (replace-data:ocspreq/simple-ocspreq/ocspreq.hex)
~~~~~
86022F501111111111111111111111111111111150A01C73A5F3B063344257D02693
059DED501234123412341234123412341234123480
~~~~~

Textual Representation

[comment]: <> (replace-data:ocspreq/simple-ocspreq/ocspreq.txt)
~~~~~
C509SimpleOCSPRequest
  Type: C509SimpleOCSPRequest (2)
  Hash Algorithm: SHA256 (-16)
  IssuerCertHash:
    a0:1c:73:a5:f3:b0:63:34:42:57:d0:26:93:05:9d:ed
  SerialNumber:
    12:34:12:34:12:34:12:34:12:34:12:34:12:34:12:34
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
 2:   2F             # [1]. hashAlgorithm=SHA256 (-16)
 3:   50             # [2]. nonce=byte[16]
 4:     11111111111111111111111111111111
20:   50             # [3]. issuerCertHash=byte[16]
21:     A01C73A5F3B063344257D02693059DED
37:   50             # [4]. serialNumber=byte[16]
38:     12341234123412341234123412341234
54:   80             # [5]. extensions=array[0]
~~~~~

### Unsigned Basic OCSP Request Example {#exam-unsigned-ocsp-req}

[comment]: <> (replace-reduction:ocspreq/unsigned-ocspreq/ocspreq.hex % ocspreq/unsigned-ocspreq/x509ocspreq.pem)
- Size reduction: 71%
- Unsigned Basic OCSP Request (`C509BasicOCSPRequest`)
- Note that the X.509 OCSP Request and the C509 OCSP Request are not convertible.

#### X.509 OCSP Request

[comment]: <> (replace-size:ocspreq/unsigned-ocspreq/x509ocspreq.pem)
PEM content (459 bytes):

[comment]: <> (replace-data:ocspreq/unsigned-ocspreq/x509ocspreq.pem)
~~~~~
-----BEGIN OCSP REQUEST-----
MIIBxzCCAcMwggGcMGUwYzALBglghkgBZQMEAgEEIDJTjnSFvTeuRU8fDSuXVddY
uR9ujjp685eg9ABgXG/4BCDMEch0CgUJ7E2hTOWIbnI2TA9jtg7WNH8TwW7nJbdm
ogIQEjQSNBI0EjQSNBI0EjQSNDBlMGMwCwYJYIZIAWUDBAIBBCAyU450hb03rkVP
Hw0rl1XXWLkfbo46evOXoPQAYFxv+AQgzBHIdAoFCexNoUzliG5yNkwPY7YO1jR/
E8Fu5yW3ZqICEDRWNFY0VjRWNFY0VjRWNFYwZTBjMAsGCWCGSAFlAwQCAQQgMlOO
dIW9N65FTx8NK5dV11i5H26OOnrzl6D0AGBcb/gEIMwRyHQKBQnsTaFM5YhucjZM
D2O2DtY0fxPBbuclt2aiAhBWeFZ4VnhWeFZ4VnhWeFZ4MGUwYzALBglghkgBZQME
AgEEIDMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzBCBERERERERERERE
RERERERERERERERERERERERERERERAIQIjMiMyIzIjMiMyIzIjMiM6IhMB8wHQYJ
KwYBBQUHMAECBBARERERERERERERERERERER
-----END OCSP REQUEST-----
~~~~~

#### C509 OCSP Request

[comment]: <> (replace-size:ocspreq/unsigned-ocspreq/ocspreq.hex)
Plain Hex (133 bytes):

[comment]: <> (replace-data:ocspreq/unsigned-ocspreq/ocspreq.hex)
~~~~~
8601F62F5011111111111111111111111111111111808650A01C73A5F3B063344257
D02693059DED80865012341234123412341234123412341234805034563456345634
56345634563456345680505678567856785678567856785678567880502222222222
22222222222222222222228082502233223322332233223322332233223380
~~~~~

Textual Representation

[comment]: <> (replace-data:ocspreq/unsigned-ocspreq/ocspreq.txt)
~~~~~
C509BasicOCSPRequest
  Type: BasicOCSPRequest (1)
  Signature Algorithm: null
  Hash Algorithm: SHA256 (-16)
  Nonce
    11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11
  Extensions: <empty>
  Requests
    OcspPerIssuerRequest
      issuerCertHash
        a0:1c:73:a5:f3:b0:63:34:42:57:d0:26:93:05:9d:ed
      extensions: <empty>
      singleRequests
        SingleCertRequest
          SerialNumber:
            12:34:12:34:12:34:12:34:12:34:12:34:12:34:12:34
          Extensions: <empty>
        SingleCertRequest
          SerialNumber:
            34:56:34:56:34:56:34:56:34:56:34:56:34:56:34:56
          Extensions: <empty>
        SingleCertRequest
          SerialNumber:
            56:78:56:78:56:78:56:78:56:78:56:78:56:78:56:78
          Extensions: <empty>
    OcspPerIssuerRequest
      issuerCertHash
        22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22
      extensions: <empty>
      singleRequests
        SingleCertRequest
          SerialNumber:
            22:33:22:33:22:33:22:33:22:33:22:33:22:33:22:33
          Extensions: <empty>
~~~~~

Annotated hex

[comment]: <> (replace-data:ocspreq/unsigned-ocspreq/ocspreq.diag)
~~~~~
  0: 86             # C509OCSPRequest=array[6]
  1:   01             # [0]. ocspRequestType=BasicOCSPRequest (1)
  2:   F6             # signatureAlgorithm=<null>
  3:   2F             # [1]. hashAlgorithm=SHA256 (-16)
  4:   50             # [2]. nonce=byte[16]
  5:     11111111111111111111111111111111
 21:   80             # [3]. extensions=array[0]
 22:   86             # [4]. requests=array[6]
                        #---PerIssuerRequests[0]---
 23:     50             # [0]. issuerCertHash=byte[16]
 24:       A01C73A5F3B063344257D02693059DED
 40:     80             # [1]. extensions=array[0]
 41:     86             # [2]. singleRequests=array[6]
                          #---SingleCertRequests[0]---
 42:       50             # [0]. serialNumber=byte[16]
 43:         12341234123412341234123412341234
 59:       80             # [1]. extensions=array[0]
                          #---SingleCertRequests[1]---
 60:       50             # [2]. serialNumber=byte[16]
 61:         34563456345634563456345634563456
 77:       80             # [3]. extensions=array[0]
                          #---SingleCertRequests[2]---
 78:       50             # [4]. serialNumber=byte[16]
 79:         56785678567856785678567856785678
 95:       80             # [5]. extensions=array[0]
                        #---PerIssuerRequests[1]---
 96:     50             # [3]. issuerCertHash=byte[16]
 97:       22222222222222222222222222222222
113:     80             # [4]. extensions=array[0]
114:     82             # [5]. singleRequests=array[2]
                          #---SingleCertRequests[0]---
115:       50             # [0]. serialNumber=byte[16]
116:         22332233223322332233223322332233
132:       80             # [1]. extensions=array[0]
~~~~~

### Signed Basic OCSP Request Example Without Requestor's Certificate {#exam-signed-ocsp-req}

[comment]: <> (replace-reduction:ocspreq/signed-ocspreq/ocspreq.hex % ocspreq/signed-ocspreq/x509ocspreq.pem)
- Size reduction: 62%
- Verifiable with certificate in {{ocsp-requestor-cert}}
- Signed Basic OCSP Request (`C509BasicOCSPRequest`) without requestor's certificate
- Note that the X.509 OCSP Request and the C509 OCSP Request are not convertible.

#### X.509 OCSP Request

[comment]: <> (replace-size:ocspreq/signed-ocspreq/x509ocspreq.pem)
PEM content (568 bytes):

[comment]: <> (replace-data:ocspreq/signed-ocspreq/x509ocspreq.pem)
~~~~~
-----BEGIN OCSP REQUEST-----
MIICNDCCAeKhHaQbMBkxFzAVBgNVBAMMDm9jc3AtcmVxdWVzdG9yMIIBnDBlMGMw
CwYJYIZIAWUDBAIBBCAyU450hb03rkVPHw0rl1XXWLkfbo46evOXoPQAYFxv+AQg
zBHIdAoFCexNoUzliG5yNkwPY7YO1jR/E8Fu5yW3ZqICEBI0EjQSNBI0EjQSNBI0
EjQwZTBjMAsGCWCGSAFlAwQCAQQgMlOOdIW9N65FTx8NK5dV11i5H26OOnrzl6D0
AGBcb/gEIMwRyHQKBQnsTaFM5YhucjZMD2O2DtY0fxPBbuclt2aiAhA0VjRWNFY0
VjRWNFY0VjRWMGUwYzALBglghkgBZQMEAgEEIDJTjnSFvTeuRU8fDSuXVddYuR9u
jjp685eg9ABgXG/4BCDMEch0CgUJ7E2hTOWIbnI2TA9jtg7WNH8TwW7nJbdmogIQ
VnhWeFZ4VnhWeFZ4VnhWeDBlMGMwCwYJYIZIAWUDBAIBBCAzMzMzMzMzMzMzMzMz
MzMzMzMzMzMzMzMzMzMzMzMzMwQgRERERERERERERERERERERERERERERERERERE
REREREQCECIzIjMiMyIzIjMiMyIzIjOiITAfMB0GCSsGAQUFBzABAgQQERERERER
EREREREREREREaBMMEowBQYDK2VwA0EA8JJx8V13unm3pbvjsR7RwmW76DhGyJSt
gMQVfiWeUpRj0I2byLGVImNkkcT4/Ap7T/FRlyaLAiDD10NHdbuyBA==
-----END OCSP REQUEST-----
~~~~~

#### C509 OCSP Request

[comment]: <> (replace-size:ocspreq/signed-ocspreq/ocspreq.hex)
Plain Hex (217 bytes):

[comment]: <> (replace-data:ocspreq/signed-ocspreq/ocspreq.hex)
~~~~~
89010C2F5011111111111111111111111111111111808650A01C73A5F3B063344257
D02693059DED80865012341234123412341234123412341234805034563456345634
56345634563456345680505678567856785678567856785678567880502222222222
222222222222222222222280825022332233223322332233223322332233805044F0
528B56F35AD998049B306FF9A8B0F65840510D01C9BAEBCEFC4A95A184A976919214
380629192B2254C690F8FB17C8A150056B8320871B5A8A4596CCA47BB27B6F243315
CC1638BB99DDE8E2A28243B404
~~~~~

Textual Representation

[comment]: <> (replace-data:ocspreq/signed-ocspreq/ocspreq.txt)
~~~~~
C509BasicOCSPRequest
  Type: BasicOCSPRequest (1)
  Signature Algorithm: Ed25519 (12)
  Hash Algorithm: SHA256 (-16)
  Nonce
    11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11
  Extensions: <empty>
  Requests
    OcspPerIssuerRequest
      issuerCertHash
        a0:1c:73:a5:f3:b0:63:34:42:57:d0:26:93:05:9d:ed
      extensions: <empty>
      singleRequests
        SingleCertRequest
          SerialNumber:
            12:34:12:34:12:34:12:34:12:34:12:34:12:34:12:34
          Extensions: <empty>
        SingleCertRequest
          SerialNumber:
            34:56:34:56:34:56:34:56:34:56:34:56:34:56:34:56
          Extensions: <empty>
        SingleCertRequest
          SerialNumber:
            56:78:56:78:56:78:56:78:56:78:56:78:56:78:56:78
          Extensions: <empty>
    OcspPerIssuerRequest
      issuerCertHash
        22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22
      extensions: <empty>
      singleRequests
        SingleCertRequest
          SerialNumber:
            22:33:22:33:22:33:22:33:22:33:22:33:22:33:22:33
          Extensions: <empty>
  RequestorCertHash
    44:f0:52:8b:56:f3:5a:d9:98:04:9b:30:6f:f9:a8:b0
  Requestor Certs: null
  signatureValue
    51:0d:01:c9:ba:eb:ce:fc:4a:95:a1:84:a9:76:91:92:
    14:38:06:29:19:2b:22:54:c6:90:f8:fb:17:c8:a1:50:
    05:6b:83:20:87:1b:5a:8a:45:96:cc:a4:7b:b2:7b:6f:
    24:33:15:cc:16:38:bb:99:dd:e8:e2:a2:82:43:b4:04
~~~~~

Annotated hex

[comment]: <> (replace-data:ocspreq/signed-ocspreq/ocspreq.diag)
~~~~~
  0: 89             # C509OCSPRequest=array[9]
  1:   01             # [0]. ocspRequestType=BasicOCSPRequest (1)
  2:   0C             # [1]. signatureAlgorithm=Ed25519 (12)
  3:   2F             # [2]. hashAlgorithm=SHA256 (-16)
  4:   50             # [3]. nonce=byte[16]
  5:     11111111111111111111111111111111
 21:   80             # [4]. extensions=array[0]
 22:   86             # [5]. requests=array[6]
                        #---PerIssuerRequests[0]---
 23:     50             # [0]. issuerCertHash=byte[16]
 24:       A01C73A5F3B063344257D02693059DED
 40:     80             # [1]. extensions=array[0]
 41:     86             # [2]. singleRequests=array[6]
                          #---SingleCertRequests[0]---
 42:       50             # [0]. serialNumber=byte[16]
 43:         12341234123412341234123412341234
 59:       80             # [1]. extensions=array[0]
                          #---SingleCertRequests[1]---
 60:       50             # [2]. serialNumber=byte[16]
 61:         34563456345634563456345634563456
 77:       80             # [3]. extensions=array[0]
                          #---SingleCertRequests[2]---
 78:       50             # [4]. serialNumber=byte[16]
 79:         56785678567856785678567856785678
 95:       80             # [5]. extensions=array[0]
                        #---PerIssuerRequests[1]---
 96:     50             # [3]. issuerCertHash=byte[16]
 97:       22222222222222222222222222222222
113:     80             # [4]. extensions=array[0]
114:     82             # [5]. singleRequests=array[2]
                          #---SingleCertRequests[0]---
115:       50             # [0]. serialNumber=byte[16]
116:         22332233223322332233223322332233
132:       80             # [1]. extensions=array[0]
133:   50             # [6]. requestorCertHash=byte[16]
134:     44F0528B56F35AD998049B306FF9A8B0
150:   F6             # [7]. requestorCerts=<null>
151:   58 40          # [8]. signatureValue=byte[64]
153:     510D01C9BAEBCEFC4A95A184A976919214380629192B2254C690F8FB17
182:     C8A150056B8320871B5A8A4596CCA47BB27B6F243315CC1638BB99DDE8
211:     E2A28243B404
~~~~~

### Signed Basic OCSP Request Example With Requestor's Certificate {#exam-signed-ocsp-req-withcert}

[comment]: <> (replace-reduction:ocspreq/signed-ocspreq-with-cert/ocspreq.hex % ocspreq/signed-ocspreq-with-cert/x509ocspreq.pem)
- Size reduction: 58%
- Verifiable with certificate in {{ocsp-requestor-cert}}
- Signed Basic OCSP Request (`C509BasicOCSPRequest`) with embedded requestor's certificate
- Note that the X.509 OCSP Request and the C509 OCSP Request are not convertible.

#### X.509 OCSP Request

[comment]: <> (replace-size:ocspreq/signed-ocspreq-with-cert/x509ocspreq.pem)
PEM content (1019 bytes):

[comment]: <> (replace-data:ocspreq/signed-ocspreq-with-cert/x509ocspreq.pem)
~~~~~
-----BEGIN OCSP REQUEST-----
MIID9zCCAmGhHaQbMBkxFzAVBgNVBAMMDm9jc3AtcmVxdWVzdG9yMIIBnDBlMGMw
CwYJYIZIAWUDBAIBBCAyU450hb03rkVPHw0rl1XXWLkfbo46evOXoPQAYFxv+AQg
zBHIdAoFCexNoUzliG5yNkwPY7YO1jR/E8Fu5yW3ZqICEBI0EjQSNBI0EjQSNBI0
EjQwZTBjMAsGCWCGSAFlAwQCAQQgMlOOdIW9N65FTx8NK5dV11i5H26OOnrzl6D0
AGBcb/gEIMwRyHQKBQnsTaFM5YhucjZMD2O2DtY0fxPBbuclt2aiAhA0VjRWNFY0
VjRWNFY0VjRWMGUwYzALBglghkgBZQMEAgEEIDJTjnSFvTeuRU8fDSuXVddYuR9u
jjp685eg9ABgXG/4BCDMEch0CgUJ7E2hTOWIbnI2TA9jtg7WNH8TwW7nJbdmogIQ
VnhWeFZ4VnhWeFZ4VnhWeDBlMGMwCwYJYIZIAWUDBAIBBCAzMzMzMzMzMzMzMzMz
MzMzMzMzMzMzMzMzMzMzMzMzMwQgRERERERERERERERERERERERERERERERERERE
REREREQCECIzIjMiMyIzIjMiMyIzIjOigZ8wgZwwGgYJKwYBBQUHMAEEBA0wCwYJ
KwYBBQUHMAEBMF8GCSsGAQUFBzABCARSMFAwBzAFBgMrZXAwITAKBggqhkjOPQQD
AjATBgcqhkjOPQIBBggqhkjOPQMBBzAiMAoGCCqGSM49BAMCMBQGByqGSM49AgEG
CSskAwMCCAEBBzAdBgkrBgEFBQcwAQIEEBERERERERERERERERERERGgggGOMIIB
ijAFBgMrZXADQQDoiFWrafZrXIE8LIF+q1hlfRS09scypApZ89OemC1cURYa4cfp
KJwBTJOAdTUk/4Rb+YM7kNpZd0MUNmJfca0EoIIBPDCCATgwggE0MIHnoAMCAQIC
AhI2MAUGAytlcDAaMRgwFgYDVQQDDA90ZXN0IGNybG9jc3AtY2EwHhcNMjUwMTAy
MDAwMDAwWhcNMjYwMTAyMDAwMDAwWjAZMRcwFQYDVQQDDA5vY3NwLXJlcXVlc3Rv
cjAqMAUGAytlcAMhAARTCxdk7dS04zq0SvD4OJYcAHF210tqNUbst/1XMg3To1Iw
UDAdBgNVHQ4EFgQUsTbUWYobG2qG2mUQrqVk2BKX5PkwDgYDVR0PAQH/BAQDAgeA
MB8GA1UdIwQYMBaAFNl9d+Y0wvcAMAylj8h3NlsVUAeiMAUGAytlcANBAJj5kiFe
kcWb6v8et+o+/Suqfh29AdErA3eBmFnJZ5A/+c/q9jFbvdahCBJJteLJhUIc0BJ0
GlmWOBLI0no1fQI=
-----END OCSP REQUEST-----
~~~~~

#### C509 OCSP Request

[comment]: <> (replace-size:ocspreq/signed-ocspreq-with-cert/ocspreq.hex)
Plain Hex (430 bytes):

[comment]: <> (replace-data:ocspreq/signed-ocspreq-with-cert/ocspreq.hex)
~~~~~
89010C2F50111111111111111111111111111111118418818200011882840CF60082
0118188650A01C73A5F3B063344257D02693059DED80865012341234123412341234
12341234123480503456345634563456345634563456345680505678567856785678
56785678567856788050222222222222222222222222222222228082502233223322
3322332233223322332233805044F0528B56F35AD998049B306FF9A8B0820458C38B
024212360C6F746573742063726C6F6373702D63611A6775D7001A69570A806E6F63
73702D726571756573746F720C582004530B1764EDD4B4E33AB44AF0F838961C0071
76D74B6A3546ECB7FD57320DD3860154DD51BDB2A2C791C062D4027856DBACF52607
F0BE210107542F45E78D2CAEDF368CDF53C39005D492450E10565840F8C6183ECF8C
3EFD50DD4942D172814C46EC0FC01DD586A597178DF864A0D9DA86B7CA17FC9F772F
F04C80E98B60D5B4B62408A277A5B70D0D2A3F5ED5442D075840A35F16CECA647427
345BFF6BE9502F903DB7B4F8E23A7DB288FA88E52F2426FF36D42C2B5298C7834E2D
3364929518502F190C7EE10C37E9EA3F78C07856440F
~~~~~

Textual Representation

[comment]: <> (replace-data:ocspreq/signed-ocspreq-with-cert/ocspreq.txt)
~~~~~
C509BasicOCSPRequest
  Type: BasicOCSPRequest (1)
  Signature Algorithm: Ed25519 (12)
  Hash Algorithm: SHA256 (-16)
  Nonce
    11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11
  Extensions
    AcceptOCSPResponseTypes (129)
      C509ErrorOCSPResponse (0)
      C509BasicOCSPResponse (1)
    preferredSignatureAlgorithms (130)
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
        a0:1c:73:a5:f3:b0:63:34:42:57:d0:26:93:05:9d:ed
      extensions: <empty>
      singleRequests
        SingleCertRequest
          SerialNumber:
            12:34:12:34:12:34:12:34:12:34:12:34:12:34:12:34
          Extensions: <empty>
        SingleCertRequest
          SerialNumber:
            34:56:34:56:34:56:34:56:34:56:34:56:34:56:34:56
          Extensions: <empty>
        SingleCertRequest
          SerialNumber:
            56:78:56:78:56:78:56:78:56:78:56:78:56:78:56:78
          Extensions: <empty>
    OcspPerIssuerRequest
      issuerCertHash
        22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22
      extensions: <empty>
      singleRequests
        SingleCertRequest
          SerialNumber:
            22:33:22:33:22:33:22:33:22:33:22:33:22:33:22:33
          Extensions: <empty>
  RequestorCertHash
    44:f0:52:8b:56:f3:5a:d9:98:04:9b:30:6f:f9:a8:b0
  Requestor Certs
    Type: C509
    Chain
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
  signatureValue
    a3:5f:16:ce:ca:64:74:27:34:5b:ff:6b:e9:50:2f:90:
    3d:b7:b4:f8:e2:3a:7d:b2:88:fa:88:e5:2f:24:26:ff:
    36:d4:2c:2b:52:98:c7:83:4e:2d:33:64:92:95:18:50:
    2f:19:0c:7e:e1:0c:37:e9:ea:3f:78:c0:78:56:44:0f
~~~~~

Annotated hex

[comment]: <> (replace-data:ocspreq/signed-ocspreq-with-cert/ocspreq.diag)
~~~~~
  0: 89             # C509OCSPRequest=array[9]
  1:   01             # [0]. ocspRequestType=BasicOCSPRequest (1)
  2:   0C             # [1]. signatureAlgorithm=Ed25519 (12)
  3:   2F             # [2]. hashAlgorithm=SHA256 (-16)
  4:   50             # [3]. nonce=byte[16]
  5:     11111111111111111111111111111111
 21:   84             # [4]. extensions=array[4]
                        #---extension[0]---
 22:     18 81          # [0]. type=AcceptOCSPResponseTypes (129)
 24:     82             # [1]. value=array[2]
 25:       00             # [0]. C509ErrorOCSPResponse (0)
 26:       01             # [1]. C509BasicOCSPResponse (1)
                        #---extension[1]---
 27:     18 82          # [2]. type=preferredSignatureAlgorithms
                        #      (130)
 29:     84             # [3]. value=array[4]
                          #---preferredSignatureAlgorithms[0]---
 30:       0C             # [0]. sigIdentifier=Ed25519 (12)
 31:       F6             # [1]. pubKeyAlgIdentifiers=<null>
                          #---preferredSignatureAlgorithms[1]---
 32:       00             # [2]. sigIdentifier=ecdsa-with-sha256 (0)
 33:       82             # [3]. pubKeyAlgIdentifiers=array[2]
 34:         01             # [0]. pubKeyAlgIdentifier=EC public key
                            #      on curve secp256r1 (1)
 35:         18 18          # [1]. pubKeyAlgIdentifier=EC public key
                            #      on curve brainpoolp256r1 (24)
 37:   86             # [5]. requests=array[6]
                        #---PerIssuerRequests[0]---
 38:     50             # [0]. issuerCertHash=byte[16]
 39:       A01C73A5F3B063344257D02693059DED
 55:     80             # [1]. extensions=array[0]
 56:     86             # [2]. singleRequests=array[6]
                          #---SingleCertRequests[0]---
 57:       50             # [0]. serialNumber=byte[16]
 58:         12341234123412341234123412341234
 74:       80             # [1]. extensions=array[0]
                          #---SingleCertRequests[1]---
 75:       50             # [2]. serialNumber=byte[16]
 76:         34563456345634563456345634563456
 92:       80             # [3]. extensions=array[0]
                          #---SingleCertRequests[2]---
 93:       50             # [4]. serialNumber=byte[16]
 94:         56785678567856785678567856785678
110:       80             # [5]. extensions=array[0]
                        #---PerIssuerRequests[1]---
111:     50             # [3]. issuerCertHash=byte[16]
112:       22222222222222222222222222222222
128:     80             # [4]. extensions=array[0]
129:     82             # [5]. singleRequests=array[2]
                          #---SingleCertRequests[0]---
130:       50             # [0]. serialNumber=byte[16]
131:         22332233223322332233223322332233
147:       80             # [1]. extensions=array[0]
148:   50             # [6]. requestorCertHash=byte[16]
149:     44F0528B56F35AD998049B306FF9A8B0
165:   82             # [7]. requestorCerts=array[2]
166:     04             # Type=C509 (4)
167:     58 C3          # Chain(COSE_C509)=byte[195]
169:       8B024212360C6F746573742063726C6F6373702D63611A6775D7001A
197:       69570A806E6F6373702D726571756573746F720C582004530B1764ED
225:       D4B4E33AB44AF0F838961C007176D74B6A3546ECB7FD57320DD38601
253:       54DD51BDB2A2C791C062D4027856DBACF52607F0BE210107542F45E7
281:       8D2CAEDF368CDF53C39005D492450E10565840F8C6183ECF8C3EFD50
309:       DD4942D172814C46EC0FC01DD586A597178DF864A0D9DA86B7CA17FC
337:       9F772FF04C80E98B60D5B4B62408A277A5B70D0D2A3F5ED5442D07
364:   58 40          # [8]. signatureValue=byte[64]
366:     A35F16CECA647427345BFF6BE9502F903DB7B4F8E23A7DB288FA88E52F
395:     2426FF36D42C2B5298C7834E2D3364929518502F190C7EE10C37E9EA3F
424:     78C07856440F
~~~~~

### Signed Basic OCSP Request Example With Requestor's Certificate Chain {#exam-signed-ocsp-req-withcertchain}

[comment]: <> (replace-reduction:ocspreq/signed-ocspreq-with-certchain/ocspreq.hex % ocspreq/signed-ocspreq-with-certchain/x509ocspreq.pem)
- Size reduction: 53%
- Verifiable with certificate in {{ocsp-requestor-cert}}
- Signed Basic OCSP Request (`C509BasicOCSPRequest`) with embedded requestor's certificate chain (2 certificates)
- Note that the X.509 OCSP Request and the C509 OCSP Request are not convertible.

#### X.509 OCSP Request

[comment]: <> (replace-size:ocspreq/signed-ocspreq-with-certchain/x509ocspreq.pem)
PEM content (1355 bytes):

[comment]: <> (replace-data:ocspreq/signed-ocspreq-with-certchain/x509ocspreq.pem)
~~~~~
-----BEGIN OCSP REQUEST-----
MIIFRzCCAmGhHaQbMBkxFzAVBgNVBAMMDm9jc3AtcmVxdWVzdG9yMIIBnDBlMGMw
CwYJYIZIAWUDBAIBBCAyU450hb03rkVPHw0rl1XXWLkfbo46evOXoPQAYFxv+AQg
zBHIdAoFCexNoUzliG5yNkwPY7YO1jR/E8Fu5yW3ZqICEBI0EjQSNBI0EjQSNBI0
EjQwZTBjMAsGCWCGSAFlAwQCAQQgMlOOdIW9N65FTx8NK5dV11i5H26OOnrzl6D0
AGBcb/gEIMwRyHQKBQnsTaFM5YhucjZMD2O2DtY0fxPBbuclt2aiAhA0VjRWNFY0
VjRWNFY0VjRWMGUwYzALBglghkgBZQMEAgEEIDJTjnSFvTeuRU8fDSuXVddYuR9u
jjp685eg9ABgXG/4BCDMEch0CgUJ7E2hTOWIbnI2TA9jtg7WNH8TwW7nJbdmogIQ
VnhWeFZ4VnhWeFZ4VnhWeDBlMGMwCwYJYIZIAWUDBAIBBCAzMzMzMzMzMzMzMzMz
MzMzMzMzMzMzMzMzMzMzMzMzMwQgRERERERERERERERERERERERERERERERERERE
REREREQCECIzIjMiMyIzIjMiMyIzIjOigZ8wgZwwGgYJKwYBBQUHMAEEBA0wCwYJ
KwYBBQUHMAEBMF8GCSsGAQUFBzABCARSMFAwBzAFBgMrZXAwITAKBggqhkjOPQQD
AjATBgcqhkjOPQIBBggqhkjOPQMBBzAiMAoGCCqGSM49BAMCMBQGByqGSM49AgEG
CSskAwMCCAEBBzAdBgkrBgEFBQcwAQIEEBERERERERERERERERERERGgggLeMIIC
2jAFBgMrZXADQQDoiFWrafZrXIE8LIF+q1hlfRS09scypApZ89OemC1cURYa4cfp
KJwBTJOAdTUk/4Rb+YM7kNpZd0MUNmJfca0EoIICjDCCAogwggE0MIHnoAMCAQIC
AhI2MAUGAytlcDAaMRgwFgYDVQQDDA90ZXN0IGNybG9jc3AtY2EwHhcNMjUwMTAy
MDAwMDAwWhcNMjYwMTAyMDAwMDAwWjAZMRcwFQYDVQQDDA5vY3NwLXJlcXVlc3Rv
cjAqMAUGAytlcAMhAARTCxdk7dS04zq0SvD4OJYcAHF210tqNUbst/1XMg3To1Iw
UDAdBgNVHQ4EFgQUsTbUWYobG2qG2mUQrqVk2BKX5PkwDgYDVR0PAQH/BAQDAgeA
MB8GA1UdIwQYMBaAFNl9d+Y0wvcAMAylj8h3NlsVUAeiMAUGAytlcANBAJj5kiFe
kcWb6v8et+o+/Suqfh29AdErA3eBmFnJZ5A/+c/q9jFbvdahCBJJteLJhUIc0BJ0
GlmWOBLI0no1fQIwggFMMIH/oAMCAQICAQEwBQYDK2VwMB4xHDAaBgNVBAMME3Rl
c3QgY3Jsb2NzcC1yb290Y2EwHhcNMjUwMTAxMDAwMDAwWhcNMjYxMjMxMjM1OTU5
WjAaMRgwFgYDVQQDDA90ZXN0IGNybG9jc3AtY2EwKjAFBgMrZXADIQBe+KNVoAGn
xQ0jSUcBIIExpLsquSDUC/sO4farKP90AKNmMGQwHQYDVR0OBBYEFNl9d+Y0wvcA
MAylj8h3NlsVUAeiMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEB
MB8GA1UdIwQYMBaAFJEjnPr554Nssp9R4TGR2xDTrhaTMAUGAytlcANBANZeAdfL
+kF/sXuZ95ftaSevVi/2Po01s+On04FgzGRnQBBNjzkYl92rEZjz0FomGSBDYqb4
PDOIIRs2vFY9QQI=
-----END OCSP REQUEST-----
~~~~~

#### C509 OCSP Request

[comment]: <> (replace-size:ocspreq/signed-ocspreq-with-certchain/ocspreq.hex)
Plain Hex (635 bytes):

[comment]: <> (replace-data:ocspreq/signed-ocspreq-with-certchain/ocspreq.hex)
~~~~~
89010C2F50111111111111111111111111111111118418818200011882840CF60082
0118188650A01C73A5F3B063344257D02693059DED80865012341234123412341234
12341234123480503456345634563456345634563456345680505678567856785678
56785678567856788050222222222222222222222222222222228082502233223322
3322332233223322332233805044F0528B56F35AD998049B306FF9A8B082048258C3
8B024212360C6F746573742063726C6F6373702D63611A6775D7001A69570A806E6F
6373702D726571756573746F720C582004530B1764EDD4B4E33AB44AF0F838961C00
7176D74B6A3546ECB7FD57320DD3860154DD51BDB2A2C791C062D4027856DBACF526
07F0BE210107542F45E78D2CAEDF368CDF53C39005D492450E10565840F8C6183ECF
8C3EFD50DD4942D172814C46EC0FC01DD586A597178DF864A0D9DA86B7CA17FC9F77
2FF04C80E98B60D5B4B62408A277A5B70D0D2A3F5ED5442D0758CA8B0241010C7374
6573742063726C6F6373702D726F6F7463611A677485801A6B36EC7F6F7465737420
63726C6F6373702D63610C58205EF8A355A001A7C50D23494701208131A4BB2AB920
D40BFB0EE1F6AB28FF74008801542F45E78D2CAEDF368CDF53C39005D492450E1056
211860230107542DA3A403F7D2F4E0B3D8031A73BA8A839F557F0F5840E50465D60C
02A2111EF3FC6E44F2A36008765B552351F9A3F5B2AA7C76F1F05D259847A4F4250B
2E4B0AE2099762A2596D3CC1DB2CCD180AA0A2D0E191310B0F5840A533371BBBC0C4
155D2DA33E948D1DCBB63070EB5F69AA6FCFD0720B050FE7650EACAE7D714237B03B
1F795A789C28140E250EEA9D86D53C59AC998C03BAE305
~~~~~

Textual Representation

[comment]: <> (replace-data:ocspreq/signed-ocspreq-with-certchain/ocspreq.txt)
~~~~~
C509BasicOCSPRequest
  Type: BasicOCSPRequest (1)
  Signature Algorithm: Ed25519 (12)
  Hash Algorithm: SHA256 (-16)
  Nonce
    11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11
  Extensions
    AcceptOCSPResponseTypes (129)
      C509ErrorOCSPResponse (0)
      C509BasicOCSPResponse (1)
    preferredSignatureAlgorithms (130)
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
        a0:1c:73:a5:f3:b0:63:34:42:57:d0:26:93:05:9d:ed
      extensions: <empty>
      singleRequests
        SingleCertRequest
          SerialNumber:
            12:34:12:34:12:34:12:34:12:34:12:34:12:34:12:34
          Extensions: <empty>
        SingleCertRequest
          SerialNumber:
            34:56:34:56:34:56:34:56:34:56:34:56:34:56:34:56
          Extensions: <empty>
        SingleCertRequest
          SerialNumber:
            56:78:56:78:56:78:56:78:56:78:56:78:56:78:56:78
          Extensions: <empty>
    OcspPerIssuerRequest
      issuerCertHash
        22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22
      extensions: <empty>
      singleRequests
        SingleCertRequest
          SerialNumber:
            22:33:22:33:22:33:22:33:22:33:22:33:22:33:22:33
          Extensions: <empty>
  RequestorCertHash
    44:f0:52:8b:56:f3:5a:d9:98:04:9b:30:6f:f9:a8:b0
  Requestor Certs
    Type: C509
    Chain
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
  signatureValue
    a5:33:37:1b:bb:c0:c4:15:5d:2d:a3:3e:94:8d:1d:cb:
    b6:30:70:eb:5f:69:aa:6f:cf:d0:72:0b:05:0f:e7:65:
    0e:ac:ae:7d:71:42:37:b0:3b:1f:79:5a:78:9c:28:14:
    0e:25:0e:ea:9d:86:d5:3c:59:ac:99:8c:03:ba:e3:05
~~~~~

Annotated hex

[comment]: <> (replace-data:ocspreq/signed-ocspreq-with-certchain/ocspreq.diag)
~~~~~
  0: 89             # C509OCSPRequest=array[9]
  1:   01             # [0]. ocspRequestType=BasicOCSPRequest (1)
  2:   0C             # [1]. signatureAlgorithm=Ed25519 (12)
  3:   2F             # [2]. hashAlgorithm=SHA256 (-16)
  4:   50             # [3]. nonce=byte[16]
  5:     11111111111111111111111111111111
 21:   84             # [4]. extensions=array[4]
                        #---extension[0]---
 22:     18 81          # [0]. type=AcceptOCSPResponseTypes (129)
 24:     82             # [1]. value=array[2]
 25:       00             # [0]. C509ErrorOCSPResponse (0)
 26:       01             # [1]. C509BasicOCSPResponse (1)
                        #---extension[1]---
 27:     18 82          # [2]. type=preferredSignatureAlgorithms
                        #      (130)
 29:     84             # [3]. value=array[4]
                          #---preferredSignatureAlgorithms[0]---
 30:       0C             # [0]. sigIdentifier=Ed25519 (12)
 31:       F6             # [1]. pubKeyAlgIdentifiers=<null>
                          #---preferredSignatureAlgorithms[1]---
 32:       00             # [2]. sigIdentifier=ecdsa-with-sha256 (0)
 33:       82             # [3]. pubKeyAlgIdentifiers=array[2]
 34:         01             # [0]. pubKeyAlgIdentifier=EC public key
                            #      on curve secp256r1 (1)
 35:         18 18          # [1]. pubKeyAlgIdentifier=EC public key
                            #      on curve brainpoolp256r1 (24)
 37:   86             # [5]. requests=array[6]
                        #---PerIssuerRequests[0]---
 38:     50             # [0]. issuerCertHash=byte[16]
 39:       A01C73A5F3B063344257D02693059DED
 55:     80             # [1]. extensions=array[0]
 56:     86             # [2]. singleRequests=array[6]
                          #---SingleCertRequests[0]---
 57:       50             # [0]. serialNumber=byte[16]
 58:         12341234123412341234123412341234
 74:       80             # [1]. extensions=array[0]
                          #---SingleCertRequests[1]---
 75:       50             # [2]. serialNumber=byte[16]
 76:         34563456345634563456345634563456
 92:       80             # [3]. extensions=array[0]
                          #---SingleCertRequests[2]---
 93:       50             # [4]. serialNumber=byte[16]
 94:         56785678567856785678567856785678
110:       80             # [5]. extensions=array[0]
                        #---PerIssuerRequests[1]---
111:     50             # [3]. issuerCertHash=byte[16]
112:       22222222222222222222222222222222
128:     80             # [4]. extensions=array[0]
129:     82             # [5]. singleRequests=array[2]
                          #---SingleCertRequests[0]---
130:       50             # [0]. serialNumber=byte[16]
131:         22332233223322332233223322332233
147:       80             # [1]. extensions=array[0]
148:   50             # [6]. requestorCertHash=byte[16]
149:     44F0528B56F35AD998049B306FF9A8B0
165:   82             # [7]. requestorCerts=array[2]
166:     04             # Type=C509 (4)
167:     82             # Chain(COSE_C509)=array[2]
168:       58 C3          # [0]. C509CertData=byte[195]
170:         8B024212360C6F746573742063726C6F6373702D63611A6775D700
197:         1A69570A806E6F6373702D726571756573746F720C582004530B17
224:         64EDD4B4E33AB44AF0F838961C007176D74B6A3546ECB7FD57320D
251:         D3860154DD51BDB2A2C791C062D4027856DBACF52607F0BE210107
278:         542F45E78D2CAEDF368CDF53C39005D492450E10565840F8C6183E
305:         CF8C3EFD50DD4942D172814C46EC0FC01DD586A597178DF864A0D9
332:         DA86B7CA17FC9F772FF04C80E98B60D5B4B62408A277A5B70D0D2A
359:         3F5ED5442D07
365:       58 CA          # [1]. C509CertData=byte[202]
367:         8B0241010C73746573742063726C6F6373702D726F6F7463611A67
394:         7485801A6B36EC7F6F746573742063726C6F6373702D63610C5820
421:         5EF8A355A001A7C50D23494701208131A4BB2AB920D40BFB0EE1F6
448:         AB28FF74008801542F45E78D2CAEDF368CDF53C39005D492450E10
475:         56211860230107542DA3A403F7D2F4E0B3D8031A73BA8A839F557F
502:         0F5840E50465D60C02A2111EF3FC6E44F2A36008765B552351F9A3
529:         F5B2AA7C76F1F05D259847A4F4250B2E4B0AE2099762A2596D3CC1
556:         DB2CCD180AA0A2D0E191310B0F
569:   58 40          # [8]. signatureValue=byte[64]
571:     A533371BBBC0C4155D2DA33E948D1DCBB63070EB5F69AA6FCFD0720B05
600:     0FE7650EACAE7D714237B03B1F795A789C28140E250EEA9D86D53C59AC
629:     998C03BAE305
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
- Size reduction: 54%
- Verifiable with certificate in {{ocsp-responder-cert}}
- Simple OCSP Response (`C509SimpleOCSPResponse`) without responder's certificate
- Note that the X.509 OCSP Response and the C509 OCSP Response are not convertible.

#### X.509 OCSP Response

[comment]: <> (replace-size:ocspresp/simple-ocspresp/x509ocspresp.pem)
PEM content (332 bytes):

[comment]: <> (replace-data:ocspresp/simple-ocspresp/x509ocspresp.pem)
~~~~~
-----BEGIN OCSP RESPONSE-----
MIIBSAoBAKCCAUEwggE9BgkrBgEFBQcwAQEEggEuMIIBKjCB3aIWBBTq5ZqK6ar0
EEsV5Q6O4BcVF3QYrxgPMjAyNTAzMDMwMDAwMDBaMIGOMIGLMGMwCwYJYIZIAWUD
BAIBBCAyU450hb03rkVPHw0rl1XXWLkfbo46evOXoPQAYFxv+AQgzBHIdAoFCexN
oUzliG5yNkwPY7YO1jR/E8Fu5yW3ZqICEBI0EjQSNBI0EjQSNBI0EjSAABgPMjAy
NTAzMDIxNjAwMDBaoBEYDzIwMjUwMzAzMDcwMDAwWqEhMB8wHQYJKwYBBQUHMAEC
BBARERERERERERERERERERERMAUGAytlcANBAFhdl3GGrAQ4qbLb6GlNS6RIDW7v
9xd49FR/zdtbQ1Sd+HneQ/Q3Z4Udcj85XGJXy62uoZ+4AG37wzzQCyTHhg4=
-----END OCSP RESPONSE-----
~~~~~

#### C509 OCSP Response

[comment]: <> (replace-size:ocspresp/simple-ocspresp/ocspresp.hex)
Plain Hex (152 bytes):

[comment]: <> (replace-data:ocspresp/simple-ocspresp/ocspresp.hex)
~~~~~
8E020C2F5011111111111111111111111111111111500600867838E3311AA78B9ED6
0C631C8650A01C73A5F3B063344257D02693059DED50123412341234123412341234
12341234001A67C4F10039707F19627080F658404D74460A8F59A1B2A27A558A0809
7AA0B3A825702393061ABC20D627C7FB4BD391FE921CA16E9CA8F3BA53694ABAFC02
0E702DC975A34FF97D8444909F4A770C
~~~~~

Textual Representation

[comment]: <> (replace-data:ocspresp/simple-ocspresp/ocspresp.txt)
~~~~~
C509SimpleOCSPResponse
  TBSSimpleOCSPResponse
    Type: C509SimpleOCSPResponse (2)
    Signature Algorithm: Ed25519 (12)
    Hash Algorithm: SHA256 (-16)
    Nonce
      11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11
    ResponderCertHash
      06:00:86:78:38:e3:31:1a:a7:8b:9e:d6:0c:63:1c:86
    IssuerCertHash
      a0:1c:73:a5:f3:b0:63:34:42:57:d0:26:93:05:9d:ed
    SerialNumber
      12:34:12:34:12:34:12:34:12:34:12:34:12:34:12:34
    Cert Status: good
    ProducedAt: 2025-03-03T00:00:00Z
    This Update: -28800, 2025-03-02T16:00:00Z
    Next Update: 25200, 2025-03-03T07:00:00Z
    Extensions: <empty>
    Responder Certs: null
  Signature Value
    4d:74:46:0a:8f:59:a1:b2:a2:7a:55:8a:08:09:7a:a0:
    b3:a8:25:70:23:93:06:1a:bc:20:d6:27:c7:fb:4b:d3:
    91:fe:92:1c:a1:6e:9c:a8:f3:ba:53:69:4a:ba:fc:02:
    0e:70:2d:c9:75:a3:4f:f9:7d:84:44:90:9f:4a:77:0c
~~~~~

Annotated hex

[comment]: <> (replace-data:ocspresp/simple-ocspresp/ocspresp.diag)
~~~~~
  0: 8E             # C509OCSPResponse=array[14]
  1:   02             # [0]. ocspResponseType=C509SimpleOCSPResponse
                      #      (2)
  2:   0C             # [1]. signatureAlgorithm=Ed25519 (12)
  3:   2F             # [2]. hashAlgorithm=SHA256 (-16)
  4:   50             # [3]. nonce=byte[16]
  5:     11111111111111111111111111111111
 21:   50             # [4]. responderCertHash=byte[16]
 22:     0600867838E3311AA78B9ED60C631C86
 38:   50             # [5]. issuerCertHash=byte[16]
 39:     A01C73A5F3B063344257D02693059DED
 55:   50             # [6]. serialNumber=byte[16]
 56:     12341234123412341234123412341234
 72:   00             # [7]. certStatus=good (0)
 73:   1A 67C4F100    # [8]. producedAt=1740960000:
                      #      2025-03-03T00:00:00Z
 78:   39 707F        # [9]. thisUpdate=-28800: 2025-03-02T16:00:00Z
 81:   19 6270        # [10]. nextUpdate=25200: 2025-03-03T07:00:00Z
 84:   80             # [11]. extensions=array[0]
 85:   F6             # [12]. responderCerts=<null>
 86:   58 40          # [13]. signatureValue=byte[64]
 88:     4D74460A8F59A1B2A27A558A08097AA0B3A825702393061ABC20D627C7
117:     FB4BD391FE921CA16E9CA8F3BA53694ABAFC020E702DC975A34FF97D84
146:     44909F4A770C
~~~~~


### Basic OCSP Response Example Without Responder's Certificate {#exam-basic-ocsp-resp}

[comment]: <> (replace-reduction:ocspresp/basic-ocspresp/ocspresp.hex % ocspresp/basic-ocspresp/x509ocspresp.pem)
- Size reduction: 69%
- Verifiable with certificate in {{ocsp-responder-cert}}
- Basic OCSP Response (`C509BasicOCSPResponse`) without responder's certificate
- Note that the X.509 OCSP Response and the C509 OCSP Response are not convertible.

#### X.509 OCSP Response

[comment]: <> (replace-size:ocspresp/basic-ocspresp/x509ocspresp.pem)
PEM content (821 bytes):

[comment]: <> (replace-data:ocspresp/basic-ocspresp/x509ocspresp.pem)
~~~~~
-----BEGIN OCSP RESPONSE-----
MIIDMQoBAKCCAyowggMmBgkrBgEFBQcwAQEEggMXMIIDEzCCAsWiFgQU6uWaiumq
9BBLFeUOjuAXFRd0GK8YDzIwMjUwMzAzMDAwMDAwWjCCAmQwgYswYzALBglghkgB
ZQMEAgEEIDJTjnSFvTeuRU8fDSuXVddYuR9ujjp685eg9ABgXG/4BCDMEch0CgUJ
7E2hTOWIbnI2TA9jtg7WNH8TwW7nJbdmogIQEjQSNBI0EjQSNBI0EjQSNIAAGA8y
MDI1MDMwMjE2MDAwMFqgERgPMjAyNTAzMDMwNzAwMDBaMIGhMGMwCwYJYIZIAWUD
BAIBBCAyU450hb03rkVPHw0rl1XXWLkfbo46evOXoPQAYFxv+AQgzBHIdAoFCexN
oUzliG5yNkwPY7YO1jR/E8Fu5yW3ZqICEDRWNFY0VjRWNFY0VjRWNFahFhgPMTk3
MDAxMDEwMDAwMDBaoAMKAQYYDzIwMjUwMzAyMTYwMDAwWqARGA8yMDI1MDMwMzA3
MDAwMFowgaEwYzALBglghkgBZQMEAgEEIDJTjnSFvTeuRU8fDSuXVddYuR9ujjp6
85eg9ABgXG/4BCDMEch0CgUJ7E2hTOWIbnI2TA9jtg7WNH8TwW7nJbdmogIQVnhW
eFZ4VnhWeFZ4VnhWeKEWGA8yMDI1MDMwMTE2MDAwMFqgAwoBBBgPMjAyNTAzMDIx
NjAwMDBaoBEYDzIwMjUwMzAzMDcwMDAwWjCBizBjMAsGCWCGSAFlAwQCAQQgMzMz
MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMEIERERERERERERERERERERERE
REREREREREREREREREREAhAiMyIzIjMiMyIzIjMiMyIzggAYDzIwMjUwMzAyMTYw
MDAwWqARGA8yMDI1MDMwMzA3MDAwMFqhMjAwMB0GCSsGAQUFBzABAgQQERERERER
ERERERERERERETAPBgkrBgEFBQcwAQkEAgUAMAUGAytlcANBALKIGJiV0kmaGmKy
Ua9w9mtRMnsfVGU/nEXLzAQv7UuAnZogejVCdy+JhYMxVb8LwLr67lDNqguqoxBC
61Wg8Qg=
-----END OCSP RESPONSE-----
~~~~~

#### C509 OCSP Response

[comment]: <> (replace-size:ocspresp/basic-ocspresp/ocspresp.hex)
Plain Hex (256 bytes):

[comment]: <> (replace-data:ocspresp/basic-ocspresp/ocspresp.hex)
~~~~~
8A010C2F5011111111111111111111111111111111500600867838E3311AA78B9ED6
0C631C861A67C4F100808650A01C73A5F3B063344257D02693059DED808F50123412
341234123412341234123412340039707F1962708050345634563456345634563456
345634560139707F196270805056785678567856785678567856785678821A67C32F
000439707F1962708050222222222222222222222222222222228085502233223322
33223322332233223322330239707F19627080F65840786BF27C05B6B315CEF0443E
E6B495E776AE758377E90B27CE7984AEF2E4118E9075CE9D87E82A60FD902E3A4478
525EC0A5E92C53B32097E58C46B88D1B3006
~~~~~

Textual Representation

[comment]: <> (replace-data:ocspresp/basic-ocspresp/ocspresp.txt)
~~~~~
C509BasicOCSPResponse
  TBSBasicOCSPResponse
    Type: C509BasicOCSPResponse (1)
    Signature Algorithm: Ed25519 (12)
    Hash Algorithm: SHA256 (-16)
    Nonce
      11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11
    ResponderCertHash
      06:00:86:78:38:e3:31:1a:a7:8b:9e:d6:0c:63:1c:86
    ProducedAt: 2025-03-03T00:00:00Z
    Extensions: <empty>
    Responses
      OcspPerIssuerResponse
        IssuerCertHash
          a0:1c:73:a5:f3:b0:63:34:42:57:d0:26:93:05:9d:ed
        Extensions: <empty>
        SingleResponses
          SingleCertResponse
            SerialNumber:
              12:34:12:34:12:34:12:34:12:34:12:34:12:34:12:34
            Cert Status: good
            This Update: -28800, 2025-03-02T16:00:00Z
            Next Update: 25200, 2025-03-03T07:00:00Z
            Extensions: <empty>
          SingleCertResponse
            SerialNumber:
              34:56:34:56:34:56:34:56:34:56:34:56:34:56:34:56
            Cert Status: not-issued
            This Update: -28800, 2025-03-02T16:00:00Z
            Next Update: 25200, 2025-03-03T07:00:00Z
            Extensions: <empty>
          SingleCertResponse
            SerialNumber:
              56:78:56:78:56:78:56:78:56:78:56:78:56:78:56:78
            Cert Status: revoked (superseded)
              Revoked at 2025-03-01T16:00:00Z
            This Update: -28800, 2025-03-02T16:00:00Z
            Next Update: 25200, 2025-03-03T07:00:00Z
            Extensions: <empty>
      OcspPerIssuerResponse
        IssuerCertHash
          22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22
        Extensions: <empty>
        SingleResponses
          SingleCertResponse
            SerialNumber:
              22:33:22:33:22:33:22:33:22:33:22:33:22:33:22:33
            Cert Status: unknown
            This Update: -28800, 2025-03-02T16:00:00Z
            Next Update: 25200, 2025-03-03T07:00:00Z
            Extensions: <empty>
    Responder Certs: null
  Signature Value
    78:6b:f2:7c:05:b6:b3:15:ce:f0:44:3e:e6:b4:95:e7:
    76:ae:75:83:77:e9:0b:27:ce:79:84:ae:f2:e4:11:8e:
    90:75:ce:9d:87:e8:2a:60:fd:90:2e:3a:44:78:52:5e:
    c0:a5:e9:2c:53:b3:20:97:e5:8c:46:b8:8d:1b:30:06
~~~~~

Annotated hex

[comment]: <> (replace-data:ocspresp/basic-ocspresp/ocspresp.diag)
~~~~~
  0: 8A             # C509OCSPResponse=array[10]
  1:   01             # [0]. ocspResponseType=C509BasicOCSPResponse
                      #      (1)
  2:   0C             # [1]. signatureAlgorithm=Ed25519 (12)
  3:   2F             # [2]. hashAlgorithm=SHA256 (-16)
  4:   50             # [3]. nonce=byte[16]
  5:     11111111111111111111111111111111
 21:   50             # [4]. responderCertHash=byte[16]
 22:     0600867838E3311AA78B9ED60C631C86
 38:   1A 67C4F100    # [5]. producedAt=1740960000:
                      #      2025-03-03T00:00:00Z
 43:   80             # [6]. extensions=array[0]
 44:   86             # [7]. responses=array[6]
                        #---PerIssuerResponses[0]---
 45:     50             # [0]. issuerCertHash=byte[16]
 46:       A01C73A5F3B063344257D02693059DED
 62:     80             # [1]. extensions=array[0]
 63:     8F             # [2]. singleResponses=array[15]
                          #---SingleCertResponses[0]---
 64:       50             # [0]. serialNumber=byte[16]
 65:         12341234123412341234123412341234
 81:       00             # [1]. certStatus=good (0)
 82:       39 707F        # [2]. thisUpdate=-28800:
                          #      2025-03-02T16:00:00Z
 85:       19 6270        # [3]. nextUpdate=25200:
                          #      2025-03-03T07:00:00Z
 88:       80             # [4]. extensions=array[0]
                          #---SingleCertResponses[1]---
 89:       50             # [5]. serialNumber=byte[16]
 90:         34563456345634563456345634563456
106:       01             # [6]. certStatus=not-issued (1)
107:       39 707F        # [7]. thisUpdate=-28800:
                          #      2025-03-02T16:00:00Z
110:       19 6270        # [8]. nextUpdate=25200:
                          #      2025-03-03T07:00:00Z
113:       80             # [9]. extensions=array[0]
                          #---SingleCertResponses[2]---
114:       50             # [10]. serialNumber=byte[16]
115:         56785678567856785678567856785678
131:       82             # [11]. certStatus=array[2]
132:         1A 67C32F00    # [0]. revocationTime=1740844800:
                            #      2025-03-01T16:00:00Z
137:         04             # [1]. revocationReason=superseded (4)
138:       39 707F        # [12]. thisUpdate=-28800:
                          #       2025-03-02T16:00:00Z
141:       19 6270        # [13]. nextUpdate=25200:
                          #       2025-03-03T07:00:00Z
144:       80             # [14]. extensions=array[0]
                        #---PerIssuerResponses[1]---
145:     50             # [3]. issuerCertHash=byte[16]
146:       22222222222222222222222222222222
162:     80             # [4]. extensions=array[0]
163:     85             # [5]. singleResponses=array[5]
                          #---SingleCertResponses[0]---
164:       50             # [0]. serialNumber=byte[16]
165:         22332233223322332233223322332233
181:       02             # [1]. certStatus=unknown (2)
182:       39 707F        # [2]. thisUpdate=-28800:
                          #      2025-03-02T16:00:00Z
185:       19 6270        # [3]. nextUpdate=25200:
                          #      2025-03-03T07:00:00Z
188:       80             # [4]. extensions=array[0]
189:   F6             # [8]. responderCerts=<null>
190:   58 40          # [9]. signature value=byte[64]
192:     786BF27C05B6B315CEF0443EE6B495E776AE758377E90B27CE7984AEF2
221:     E4118E9075CE9D87E82A60FD902E3A4478525EC0A5E92C53B32097E58C
250:     46B88D1B3006
~~~~~

### Basic OCSP Response Example With Responder's Certificate {#exam-basic-ocsp-resp-withcert}

[comment]: <> (replace-reduction:ocspresp/basic-ocspresp-with-cert/ocspresp.hex % ocspresp/basic-ocspresp-with-cert/x509ocspresp.pem)
- Size reduction: 61%
- Verifiable with certificate in {{ocsp-responder-cert}}
- Basic OCSP Response (`C509BasicOCSPResponse`) with embedded responder's certificate
- Note that the X.509 OCSP Response and the C509 OCSP Response are not convertible.

#### X.509 OCSP Response

[comment]: <> (replace-size:ocspresp/basic-ocspresp-with-cert/x509ocspresp.pem)
PEM content (1165 bytes):

[comment]: <> (replace-data:ocspresp/basic-ocspresp-with-cert/x509ocspresp.pem)
~~~~~
-----BEGIN OCSP RESPONSE-----
MIIEiQoBAKCCBIIwggR+BgkrBgEFBQcwAQEEggRvMIIEazCCAsWiFgQU6uWaiumq
9BBLFeUOjuAXFRd0GK8YDzIwMjUwMzAzMDAwMDAwWjCCAmQwgYswYzALBglghkgB
ZQMEAgEEIDJTjnSFvTeuRU8fDSuXVddYuR9ujjp685eg9ABgXG/4BCDMEch0CgUJ
7E2hTOWIbnI2TA9jtg7WNH8TwW7nJbdmogIQEjQSNBI0EjQSNBI0EjQSNIAAGA8y
MDI1MDMwMjE2MDAwMFqgERgPMjAyNTAzMDMwNzAwMDBaMIGhMGMwCwYJYIZIAWUD
BAIBBCAyU450hb03rkVPHw0rl1XXWLkfbo46evOXoPQAYFxv+AQgzBHIdAoFCexN
oUzliG5yNkwPY7YO1jR/E8Fu5yW3ZqICEDRWNFY0VjRWNFY0VjRWNFahFhgPMTk3
MDAxMDEwMDAwMDBaoAMKAQYYDzIwMjUwMzAyMTYwMDAwWqARGA8yMDI1MDMwMzA3
MDAwMFowgaEwYzALBglghkgBZQMEAgEEIDJTjnSFvTeuRU8fDSuXVddYuR9ujjp6
85eg9ABgXG/4BCDMEch0CgUJ7E2hTOWIbnI2TA9jtg7WNH8TwW7nJbdmogIQVnhW
eFZ4VnhWeFZ4VnhWeKEWGA8yMDI1MDMwMTE2MDAwMFqgAwoBBBgPMjAyNTAzMDIx
NjAwMDBaoBEYDzIwMjUwMzAzMDcwMDAwWjCBizBjMAsGCWCGSAFlAwQCAQQgMzMz
MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMEIERERERERERERERERERERERE
REREREREREREREREREREAhAiMyIzIjMiMyIzIjMiMyIzggAYDzIwMjUwMzAyMTYw
MDAwWqARGA8yMDI1MDMwMzA3MDAwMFqhMjAwMB0GCSsGAQUFBzABAgQQERERERER
ERERERERERERETAPBgkrBgEFBQcwAQkEAgUAMAUGAytlcANBALKIGJiV0kmaGmKy
Ua9w9mtRMnsfVGU/nEXLzAQv7UuAnZogejVCdy+JhYMxVb8LwLr67lDNqguqoxBC
61Wg8QigggFUMIIBUDCCAUwwgf+gAwIBAgICEjUwBQYDK2VwMBoxGDAWBgNVBAMM
D3Rlc3QgY3Jsb2NzcC1jYTAeFw0yNTAxMDIwMDAwMDBaFw0yNjAxMDIwMDAwMDBa
MBkxFzAVBgNVBAMMDm9jc3AtcmVzcG9uZGVyMCowBQYDK2VwAyEAgZR7vCSKrHlz
ghGo11v5LLd32ZQHPfI64GOA7yxXOXajajBoMB0GA1UdDgQWBBTq5ZqK6ar0EEsV
5Q6O4BcVF3QYrzAOBgNVHQ8BAf8EBAMCB4AwHwYDVR0jBBgwFoAU2X135jTC9wAw
DKWPyHc2WxVQB6IwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwkwBQYDK2VwA0EAE6Mo
4UW6t2eMBWxsYX3UvhUJnaoXUOH7fAspqSPXK/f3h5+FSrkt0RCxXzct4Flmgi+H
ToCGEf1F3T0sXCiHCA==
-----END OCSP RESPONSE-----
~~~~~

#### C509 OCSP Response

[comment]: <> (replace-size:ocspresp/basic-ocspresp-with-cert/ocspresp.hex)
Plain Hex (456 bytes):

[comment]: <> (replace-data:ocspresp/basic-ocspresp-with-cert/ocspresp.hex)
~~~~~
8A010C2F5011111111111111111111111111111111500600867838E3311AA78B9ED6
0C631C861A67C4F100808650A01C73A5F3B063344257D02693059DED808F50123412
341234123412341234123412340039707F1962708050345634563456345634563456
345634560139707F196270805056785678567856785678567856785678821A67C32F
000439707F1962708050222222222222222222222222222222228085502233223322
33223322332233223322330239707F19627080820458C58B024212350C6F74657374
2063726C6F6373702D63611A6775D7001A69570A806E6F6373702D726573706F6E64
65720C582081947BBC248AAC79738211A8D75BF92CB777D994073DF23AE06380EF2C
573976880154B5B4CAF35401D06151DF9629DB579DC8CCA453A8210107542F45E78D
2CAEDF368CDF53C39005D492450E105627095840A01B0CBF3E34A4762D05404FD08A
7AEC103035358314686D72B6159078C76E1D88597F37531886A3F52F256FD722192B
289D6844014467F1F17F05ACBB7B660A584062B7066C43464C370CD22D50D7F7573C
FE8E3472DC95C345EA8596F66B796AEB07E7A6914F54D8DEC4984BF9782A166E6C82
D9D8100BD30BE590D5B0A3BA3309
~~~~~

Textual Representation

[comment]: <> (replace-data:ocspresp/basic-ocspresp-with-cert/ocspresp.txt)
~~~~~
C509BasicOCSPResponse
  TBSBasicOCSPResponse
    Type: C509BasicOCSPResponse (1)
    Signature Algorithm: Ed25519 (12)
    Hash Algorithm: SHA256 (-16)
    Nonce
      11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11
    ResponderCertHash
      06:00:86:78:38:e3:31:1a:a7:8b:9e:d6:0c:63:1c:86
    ProducedAt: 2025-03-03T00:00:00Z
    Extensions: <empty>
    Responses
      OcspPerIssuerResponse
        IssuerCertHash
          a0:1c:73:a5:f3:b0:63:34:42:57:d0:26:93:05:9d:ed
        Extensions: <empty>
        SingleResponses
          SingleCertResponse
            SerialNumber:
              12:34:12:34:12:34:12:34:12:34:12:34:12:34:12:34
            Cert Status: good
            This Update: -28800, 2025-03-02T16:00:00Z
            Next Update: 25200, 2025-03-03T07:00:00Z
            Extensions: <empty>
          SingleCertResponse
            SerialNumber:
              34:56:34:56:34:56:34:56:34:56:34:56:34:56:34:56
            Cert Status: not-issued
            This Update: -28800, 2025-03-02T16:00:00Z
            Next Update: 25200, 2025-03-03T07:00:00Z
            Extensions: <empty>
          SingleCertResponse
            SerialNumber:
              56:78:56:78:56:78:56:78:56:78:56:78:56:78:56:78
            Cert Status: revoked (superseded)
              Revoked at 2025-03-01T16:00:00Z
            This Update: -28800, 2025-03-02T16:00:00Z
            Next Update: 25200, 2025-03-03T07:00:00Z
            Extensions: <empty>
      OcspPerIssuerResponse
        IssuerCertHash
          22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22
        Extensions: <empty>
        SingleResponses
          SingleCertResponse
            SerialNumber:
              22:33:22:33:22:33:22:33:22:33:22:33:22:33:22:33
            Cert Status: unknown
            This Update: -28800, 2025-03-02T16:00:00Z
            Next Update: 25200, 2025-03-03T07:00:00Z
            Extensions: <empty>
    Responder Certs
      Type: C509
      Chain
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
    62:b7:06:6c:43:46:4c:37:0c:d2:2d:50:d7:f7:57:3c:
    fe:8e:34:72:dc:95:c3:45:ea:85:96:f6:6b:79:6a:eb:
    07:e7:a6:91:4f:54:d8:de:c4:98:4b:f9:78:2a:16:6e:
    6c:82:d9:d8:10:0b:d3:0b:e5:90:d5:b0:a3:ba:33:09
~~~~~

Annotated hex

[comment]: <> (replace-data:ocspresp/basic-ocspresp-with-cert/ocspresp.diag)
~~~~~
  0: 8A             # C509OCSPResponse=array[10]
  1:   01             # [0]. ocspResponseType=C509BasicOCSPResponse
                      #      (1)
  2:   0C             # [1]. signatureAlgorithm=Ed25519 (12)
  3:   2F             # [2]. hashAlgorithm=SHA256 (-16)
  4:   50             # [3]. nonce=byte[16]
  5:     11111111111111111111111111111111
 21:   50             # [4]. responderCertHash=byte[16]
 22:     0600867838E3311AA78B9ED60C631C86
 38:   1A 67C4F100    # [5]. producedAt=1740960000:
                      #      2025-03-03T00:00:00Z
 43:   80             # [6]. extensions=array[0]
 44:   86             # [7]. responses=array[6]
                        #---PerIssuerResponses[0]---
 45:     50             # [0]. issuerCertHash=byte[16]
 46:       A01C73A5F3B063344257D02693059DED
 62:     80             # [1]. extensions=array[0]
 63:     8F             # [2]. singleResponses=array[15]
                          #---SingleCertResponses[0]---
 64:       50             # [0]. serialNumber=byte[16]
 65:         12341234123412341234123412341234
 81:       00             # [1]. certStatus=good (0)
 82:       39 707F        # [2]. thisUpdate=-28800:
                          #      2025-03-02T16:00:00Z
 85:       19 6270        # [3]. nextUpdate=25200:
                          #      2025-03-03T07:00:00Z
 88:       80             # [4]. extensions=array[0]
                          #---SingleCertResponses[1]---
 89:       50             # [5]. serialNumber=byte[16]
 90:         34563456345634563456345634563456
106:       01             # [6]. certStatus=not-issued (1)
107:       39 707F        # [7]. thisUpdate=-28800:
                          #      2025-03-02T16:00:00Z
110:       19 6270        # [8]. nextUpdate=25200:
                          #      2025-03-03T07:00:00Z
113:       80             # [9]. extensions=array[0]
                          #---SingleCertResponses[2]---
114:       50             # [10]. serialNumber=byte[16]
115:         56785678567856785678567856785678
131:       82             # [11]. certStatus=array[2]
132:         1A 67C32F00    # [0]. revocationTime=1740844800:
                            #      2025-03-01T16:00:00Z
137:         04             # [1]. revocationReason=superseded (4)
138:       39 707F        # [12]. thisUpdate=-28800:
                          #       2025-03-02T16:00:00Z
141:       19 6270        # [13]. nextUpdate=25200:
                          #       2025-03-03T07:00:00Z
144:       80             # [14]. extensions=array[0]
                        #---PerIssuerResponses[1]---
145:     50             # [3]. issuerCertHash=byte[16]
146:       22222222222222222222222222222222
162:     80             # [4]. extensions=array[0]
163:     85             # [5]. singleResponses=array[5]
                          #---SingleCertResponses[0]---
164:       50             # [0]. serialNumber=byte[16]
165:         22332233223322332233223322332233
181:       02             # [1]. certStatus=unknown (2)
182:       39 707F        # [2]. thisUpdate=-28800:
                          #      2025-03-02T16:00:00Z
185:       19 6270        # [3]. nextUpdate=25200:
                          #      2025-03-03T07:00:00Z
188:       80             # [4]. extensions=array[0]
189:   82             # [8]. responderCerts=array[2]
190:     04             # Type=C509 (4)
191:     58 C5          # Chain(COSE_C509)=byte[197]
193:       8B024212350C6F746573742063726C6F6373702D63611A6775D7001A
221:       69570A806E6F6373702D726573706F6E6465720C582081947BBC248A
249:       AC79738211A8D75BF92CB777D994073DF23AE06380EF2C5739768801
277:       54B5B4CAF35401D06151DF9629DB579DC8CCA453A8210107542F45E7
305:       8D2CAEDF368CDF53C39005D492450E105627095840A01B0CBF3E34A4
333:       762D05404FD08A7AEC103035358314686D72B6159078C76E1D88597F
361:       37531886A3F52F256FD722192B289D6844014467F1F17F05ACBB7B66
389:       0A
390:   58 40          # [9]. signature value=byte[64]
392:     62B7066C43464C370CD22D50D7F7573CFE8E3472DC95C345EA8596F66B
421:     796AEB07E7A6914F54D8DEC4984BF9782A166E6C82D9D8100BD30BE590
450:     D5B0A3BA3309
~~~~~

### Basic OCSP Response Example With Responder's Certificate Chain {#exam-basic-ocsp-resp-withcertchain}

[comment]: <> (replace-reduction:ocspresp/basic-ocspresp-with-certchain/ocspresp.hex % ocspresp/basic-ocspresp-with-certchain/x509ocspresp.pem)
- Size reduction: 56%
- Verifiable with certificate in {{ocsp-responder-cert}}
- Basic OCSP Response (`C509BasicOCSPResponse`) with embedded responder's certificate chain (2 certificates)
- Note that the X.509 OCSP Response and the C509 OCSP Response are not convertible.

#### X.509 OCSP Response

[comment]: <> (replace-size:ocspresp/basic-ocspresp-with-certchain/x509ocspresp.pem)
PEM content (1501 bytes):

[comment]: <> (replace-data:ocspresp/basic-ocspresp-with-certchain/x509ocspresp.pem)
~~~~~
-----BEGIN OCSP RESPONSE-----
MIIF2QoBAKCCBdIwggXOBgkrBgEFBQcwAQEEggW/MIIFuzCCAsWiFgQU6uWaiumq
9BBLFeUOjuAXFRd0GK8YDzIwMjUwMzAzMDAwMDAwWjCCAmQwgYswYzALBglghkgB
ZQMEAgEEIDJTjnSFvTeuRU8fDSuXVddYuR9ujjp685eg9ABgXG/4BCDMEch0CgUJ
7E2hTOWIbnI2TA9jtg7WNH8TwW7nJbdmogIQEjQSNBI0EjQSNBI0EjQSNIAAGA8y
MDI1MDMwMjE2MDAwMFqgERgPMjAyNTAzMDMwNzAwMDBaMIGhMGMwCwYJYIZIAWUD
BAIBBCAyU450hb03rkVPHw0rl1XXWLkfbo46evOXoPQAYFxv+AQgzBHIdAoFCexN
oUzliG5yNkwPY7YO1jR/E8Fu5yW3ZqICEDRWNFY0VjRWNFY0VjRWNFahFhgPMTk3
MDAxMDEwMDAwMDBaoAMKAQYYDzIwMjUwMzAyMTYwMDAwWqARGA8yMDI1MDMwMzA3
MDAwMFowgaEwYzALBglghkgBZQMEAgEEIDJTjnSFvTeuRU8fDSuXVddYuR9ujjp6
85eg9ABgXG/4BCDMEch0CgUJ7E2hTOWIbnI2TA9jtg7WNH8TwW7nJbdmogIQVnhW
eFZ4VnhWeFZ4VnhWeKEWGA8yMDI1MDMwMTE2MDAwMFqgAwoBBBgPMjAyNTAzMDIx
NjAwMDBaoBEYDzIwMjUwMzAzMDcwMDAwWjCBizBjMAsGCWCGSAFlAwQCAQQgMzMz
MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMEIERERERERERERERERERERERE
REREREREREREREREREREAhAiMyIzIjMiMyIzIjMiMyIzggAYDzIwMjUwMzAyMTYw
MDAwWqARGA8yMDI1MDMwMzA3MDAwMFqhMjAwMB0GCSsGAQUFBzABAgQQERERERER
ERERERERERERETAPBgkrBgEFBQcwAQkEAgUAMAUGAytlcANBALKIGJiV0kmaGmKy
Ua9w9mtRMnsfVGU/nEXLzAQv7UuAnZogejVCdy+JhYMxVb8LwLr67lDNqguqoxBC
61Wg8QigggKkMIICoDCCAUwwgf+gAwIBAgICEjUwBQYDK2VwMBoxGDAWBgNVBAMM
D3Rlc3QgY3Jsb2NzcC1jYTAeFw0yNTAxMDIwMDAwMDBaFw0yNjAxMDIwMDAwMDBa
MBkxFzAVBgNVBAMMDm9jc3AtcmVzcG9uZGVyMCowBQYDK2VwAyEAgZR7vCSKrHlz
ghGo11v5LLd32ZQHPfI64GOA7yxXOXajajBoMB0GA1UdDgQWBBTq5ZqK6ar0EEsV
5Q6O4BcVF3QYrzAOBgNVHQ8BAf8EBAMCB4AwHwYDVR0jBBgwFoAU2X135jTC9wAw
DKWPyHc2WxVQB6IwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwkwBQYDK2VwA0EAE6Mo
4UW6t2eMBWxsYX3UvhUJnaoXUOH7fAspqSPXK/f3h5+FSrkt0RCxXzct4Flmgi+H
ToCGEf1F3T0sXCiHCDCCAUwwgf+gAwIBAgIBATAFBgMrZXAwHjEcMBoGA1UEAwwT
dGVzdCBjcmxvY3NwLXJvb3RjYTAeFw0yNTAxMDEwMDAwMDBaFw0yNjEyMzEyMzU5
NTlaMBoxGDAWBgNVBAMMD3Rlc3QgY3Jsb2NzcC1jYTAqMAUGAytlcAMhAF74o1Wg
AafFDSNJRwEggTGkuyq5INQL+w7h9qso/3QAo2YwZDAdBgNVHQ4EFgQU2X135jTC
9wAwDKWPyHc2WxVQB6IwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8C
AQEwHwYDVR0jBBgwFoAUkSOc+vnng2yyn1HhMZHbENOuFpMwBQYDK2VwA0EA1l4B
18v6QX+xe5n3l+1pJ69WL/Y+jTWz46fTgWDMZGdAEE2PORiX3asRmPPQWiYZIENi
pvg8M4ghGza8Vj1BAg==
-----END OCSP RESPONSE-----
~~~~~

#### C509 OCSP Response

[comment]: <> (replace-size:ocspresp/basic-ocspresp-with-certchain/ocspresp.hex)
Plain Hex (661 bytes):

[comment]: <> (replace-data:ocspresp/basic-ocspresp-with-certchain/ocspresp.hex)
~~~~~
8A010C2F5011111111111111111111111111111111500600867838E3311AA78B9ED6
0C631C861A67C4F100808650A01C73A5F3B063344257D02693059DED808F50123412
341234123412341234123412340039707F1962708050345634563456345634563456
345634560139707F196270805056785678567856785678567856785678821A67C32F
000439707F1962708050222222222222222222222222222222228085502233223322
33223322332233223322330239707F1962708082048258C58B024212350C6F746573
742063726C6F6373702D63611A6775D7001A69570A806E6F6373702D726573706F6E
6465720C582081947BBC248AAC79738211A8D75BF92CB777D994073DF23AE06380EF
2C573976880154B5B4CAF35401D06151DF9629DB579DC8CCA453A8210107542F45E7
8D2CAEDF368CDF53C39005D492450E105627095840A01B0CBF3E34A4762D05404FD0
8A7AEC103035358314686D72B6159078C76E1D88597F37531886A3F52F256FD72219
2B289D6844014467F1F17F05ACBB7B660A58CA8B0241010C73746573742063726C6F
6373702D726F6F7463611A677485801A6B36EC7F6F746573742063726C6F6373702D
63610C58205EF8A355A001A7C50D23494701208131A4BB2AB920D40BFB0EE1F6AB28
FF74008801542F45E78D2CAEDF368CDF53C39005D492450E1056211860230107542D
A3A403F7D2F4E0B3D8031A73BA8A839F557F0F5840E50465D60C02A2111EF3FC6E44
F2A36008765B552351F9A3F5B2AA7C76F1F05D259847A4F4250B2E4B0AE2099762A2
596D3CC1DB2CCD180AA0A2D0E191310B0F5840F8B3DCBAF5016BC3AFF85E53FD0C25
B341FBBF730ACCEF355C57A5B932D52D07B1FF967AA7980C40C5DD793C4FA649C16C
19AF34D0D03498DF758454B7AC2506
~~~~~

Textual Representation

[comment]: <> (replace-data:ocspresp/basic-ocspresp-with-certchain/ocspresp.txt)
~~~~~
C509BasicOCSPResponse
  TBSBasicOCSPResponse
    Type: C509BasicOCSPResponse (1)
    Signature Algorithm: Ed25519 (12)
    Hash Algorithm: SHA256 (-16)
    Nonce
      11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11
    ResponderCertHash
      06:00:86:78:38:e3:31:1a:a7:8b:9e:d6:0c:63:1c:86
    ProducedAt: 2025-03-03T00:00:00Z
    Extensions: <empty>
    Responses
      OcspPerIssuerResponse
        IssuerCertHash
          a0:1c:73:a5:f3:b0:63:34:42:57:d0:26:93:05:9d:ed
        Extensions: <empty>
        SingleResponses
          SingleCertResponse
            SerialNumber:
              12:34:12:34:12:34:12:34:12:34:12:34:12:34:12:34
            Cert Status: good
            This Update: -28800, 2025-03-02T16:00:00Z
            Next Update: 25200, 2025-03-03T07:00:00Z
            Extensions: <empty>
          SingleCertResponse
            SerialNumber:
              34:56:34:56:34:56:34:56:34:56:34:56:34:56:34:56
            Cert Status: not-issued
            This Update: -28800, 2025-03-02T16:00:00Z
            Next Update: 25200, 2025-03-03T07:00:00Z
            Extensions: <empty>
          SingleCertResponse
            SerialNumber:
              56:78:56:78:56:78:56:78:56:78:56:78:56:78:56:78
            Cert Status: revoked (superseded)
              Revoked at 2025-03-01T16:00:00Z
            This Update: -28800, 2025-03-02T16:00:00Z
            Next Update: 25200, 2025-03-03T07:00:00Z
            Extensions: <empty>
      OcspPerIssuerResponse
        IssuerCertHash
          22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22
        Extensions: <empty>
        SingleResponses
          SingleCertResponse
            SerialNumber:
              22:33:22:33:22:33:22:33:22:33:22:33:22:33:22:33
            Cert Status: unknown
            This Update: -28800, 2025-03-02T16:00:00Z
            Next Update: 25200, 2025-03-03T07:00:00Z
            Extensions: <empty>
    Responder Certs
      Type: C509
      Chain
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
    f8:b3:dc:ba:f5:01:6b:c3:af:f8:5e:53:fd:0c:25:b3:
    41:fb:bf:73:0a:cc:ef:35:5c:57:a5:b9:32:d5:2d:07:
    b1:ff:96:7a:a7:98:0c:40:c5:dd:79:3c:4f:a6:49:c1:
    6c:19:af:34:d0:d0:34:98:df:75:84:54:b7:ac:25:06
~~~~~

Annotated hex

[comment]: <> (replace-data:ocspresp/basic-ocspresp-with-certchain/ocspresp.diag)
~~~~~
  0: 8A             # C509OCSPResponse=array[10]
  1:   01             # [0]. ocspResponseType=C509BasicOCSPResponse
                      #      (1)
  2:   0C             # [1]. signatureAlgorithm=Ed25519 (12)
  3:   2F             # [2]. hashAlgorithm=SHA256 (-16)
  4:   50             # [3]. nonce=byte[16]
  5:     11111111111111111111111111111111
 21:   50             # [4]. responderCertHash=byte[16]
 22:     0600867838E3311AA78B9ED60C631C86
 38:   1A 67C4F100    # [5]. producedAt=1740960000:
                      #      2025-03-03T00:00:00Z
 43:   80             # [6]. extensions=array[0]
 44:   86             # [7]. responses=array[6]
                        #---PerIssuerResponses[0]---
 45:     50             # [0]. issuerCertHash=byte[16]
 46:       A01C73A5F3B063344257D02693059DED
 62:     80             # [1]. extensions=array[0]
 63:     8F             # [2]. singleResponses=array[15]
                          #---SingleCertResponses[0]---
 64:       50             # [0]. serialNumber=byte[16]
 65:         12341234123412341234123412341234
 81:       00             # [1]. certStatus=good (0)
 82:       39 707F        # [2]. thisUpdate=-28800:
                          #      2025-03-02T16:00:00Z
 85:       19 6270        # [3]. nextUpdate=25200:
                          #      2025-03-03T07:00:00Z
 88:       80             # [4]. extensions=array[0]
                          #---SingleCertResponses[1]---
 89:       50             # [5]. serialNumber=byte[16]
 90:         34563456345634563456345634563456
106:       01             # [6]. certStatus=not-issued (1)
107:       39 707F        # [7]. thisUpdate=-28800:
                          #      2025-03-02T16:00:00Z
110:       19 6270        # [8]. nextUpdate=25200:
                          #      2025-03-03T07:00:00Z
113:       80             # [9]. extensions=array[0]
                          #---SingleCertResponses[2]---
114:       50             # [10]. serialNumber=byte[16]
115:         56785678567856785678567856785678
131:       82             # [11]. certStatus=array[2]
132:         1A 67C32F00    # [0]. revocationTime=1740844800:
                            #      2025-03-01T16:00:00Z
137:         04             # [1]. revocationReason=superseded (4)
138:       39 707F        # [12]. thisUpdate=-28800:
                          #       2025-03-02T16:00:00Z
141:       19 6270        # [13]. nextUpdate=25200:
                          #       2025-03-03T07:00:00Z
144:       80             # [14]. extensions=array[0]
                        #---PerIssuerResponses[1]---
145:     50             # [3]. issuerCertHash=byte[16]
146:       22222222222222222222222222222222
162:     80             # [4]. extensions=array[0]
163:     85             # [5]. singleResponses=array[5]
                          #---SingleCertResponses[0]---
164:       50             # [0]. serialNumber=byte[16]
165:         22332233223322332233223322332233
181:       02             # [1]. certStatus=unknown (2)
182:       39 707F        # [2]. thisUpdate=-28800:
                          #      2025-03-02T16:00:00Z
185:       19 6270        # [3]. nextUpdate=25200:
                          #      2025-03-03T07:00:00Z
188:       80             # [4]. extensions=array[0]
189:   82             # [8]. responderCerts=array[2]
190:     04             # Type=C509 (4)
191:     82             # Chain(COSE_C509)=array[2]
192:       58 C5          # [0]. C509CertData=byte[197]
194:         8B024212350C6F746573742063726C6F6373702D63611A6775D700
221:         1A69570A806E6F6373702D726573706F6E6465720C582081947BBC
248:         248AAC79738211A8D75BF92CB777D994073DF23AE06380EF2C5739
275:         76880154B5B4CAF35401D06151DF9629DB579DC8CCA453A8210107
302:         542F45E78D2CAEDF368CDF53C39005D492450E105627095840A01B
329:         0CBF3E34A4762D05404FD08A7AEC103035358314686D72B6159078
356:         C76E1D88597F37531886A3F52F256FD722192B289D6844014467F1
383:         F17F05ACBB7B660A
391:       58 CA          # [1]. C509CertData=byte[202]
393:         8B0241010C73746573742063726C6F6373702D726F6F7463611A67
420:         7485801A6B36EC7F6F746573742063726C6F6373702D63610C5820
447:         5EF8A355A001A7C50D23494701208131A4BB2AB920D40BFB0EE1F6
474:         AB28FF74008801542F45E78D2CAEDF368CDF53C39005D492450E10
501:         56211860230107542DA3A403F7D2F4E0B3D8031A73BA8A839F557F
528:         0F5840E50465D60C02A2111EF3FC6E44F2A36008765B552351F9A3
555:         F5B2AA7C76F1F05D259847A4F4250B2E4B0AE2099762A2596D3CC1
582:         DB2CCD180AA0A2D0E191310B0F
595:   58 40          # [9]. signature value=byte[64]
597:     F8B3DCBAF5016BC3AFF85E53FD0C25B341FBBF730ACCEF355C57A5B932
626:     D52D07B1FF967AA7980C40C5DD793C4FA649C16C19AF34D0D03498DF75
655:     8454B7AC2506
~~~~~

# Document Updates # {#sec-document-updates}
{:removeinrfc}

## Version -01 to -02 ## {#sec-01-02}

* Replaced `serialNumberHash` in OCSP requests and responses with the plain serial number (`serialNumber`).

* Replaced `HashId8` with `HashedId`, the leading 8 to 64 bytes of the hash value, for the certificate hashes `issuerCertHash`, `requestorCertHash`, and `responderCertHash`, and discussed the collision probability in the Security Considerations.

* Merged `C509UnsignedOCSPRequest` and `C509SignedOCSPRequest` into `C509BasicOCSPRequest` (type 1).

* Renamed `C509CRL` to `C509CertificateList`, aligned with `CertificateList` in {{RFC5280}}, and named CRL type 0 "Basic".

* Introduced `NameVariant` for the CRL fields `authoritySubject` and `issuer`, replacing `Name / #6.121(bytes)`.  The name type is taken from the "TLS Certificate Types" registry.

* Introduced `CertChainVariant` for the OCSP fields `requestorCerts` and `responderCerts`, replacing `COSE_C509 / #6.121(COSE_X509)`.

* Added the section "Conformance Requirements" for C509 OCSP clients and responders.

* Restricted TLS OCSP stapling to `C509SimpleOCSPResponse`.

## Version -00 to -01 ## {#sec-00-01}

* Added the section "Alternative Certificate Status Checking Mechanisms".

* Constrained the value ranges of integer fields in the CDDL.

* Replaced the "C509 Hash Algorithms" registry with the "COSE Algorithms" registry.

* Specified the PEM representation of C509 CRL and C509 OCSP messages.

* Added the registries for C509 CRL types and C509 OCSP request and response types.

* Added the section "Implementation Status".

* Added the section "Security Considerations".

* Clarifications and editorial improvements.

# Acknowledgments # {#acknowledgments}
{:numbered="false"}

The authors thank xxx for reviewing and commenting on intermediate versions of the draft.

---
title: "Transparency Service"
category: info

docname: draft-steele-transparency-service-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
keyword:
 - cose
 - transparency
 - service
venue:
  github: "OR13/draft-steele-transparency-service"
  latest: "https://OR13.github.io/draft-steele-transparency-service/draft-steele-transparency-service.html"

author:
 -
    fullname: "Orie Steele"
    email: "orie@or13.io"

normative:
  IANA.media-types:
  RFC9052: COSE
  RFC8693: TOKEN-EXCHANGE
  I-D.draft-ietf-cose-merkle-tree-proofs: COSE-RECEIPTS
  I-D.draft-demarco-nonce-endpoint: NONCE-ENDPOINT

informative:
  RFC9162: CERTIFICATE-TRANSPARENCY
  I-D.draft-ietf-keytrans-architecture: KEY-TRANSPARENCY
  I-D.draft-ietf-scitt-architecture: SCITT-ARCHITECTURE

--- abstract

This document describes an http service and interaction patterns for obtaining receipts for signatures, that can be used to provide transparency.

--- middle

# Introduction

Transparency Services have been adopted for use cases including {{-CERTIFICATE-TRANSPARENCY}}, {{-KEY-TRANSPARENCY}},  {{-SCITT-ARCHITECTURE}}.

This document describes a generic COSE and HTTP based service, which can be applied to any use case that build on top of HTTP and COSE.

Producers create content, which they then sign and submit transparency services.

Transparency services act as a kind of notary, authenticating signed content from issuers, and providing receipts, which can be used to convince a verifier that an issuer is legitimate, based on mutual trust in the notary.

The identity layer is not bound to a specific PKI, but is compatible with credentialing systems based on public key cryptography that are supported by {{-COSE}}.

We use the term "Identity Document" as a placeholder for "x509 certificate" or a name and a "cose-key", "cose-key-set", "jwk", or "jwk-set".

~~~aasvg
                         .------------.                   +----------+
Content   -->           |  Payload     +----------------->+ Content  |
Producers                '----------+-'                   | Storage  |
                 .----------.       |                     +----+-----+
Issuers  -->    |  Identity  |      |                          |
                |  Document  +------)-----------------+        +------+
                 '----+-----'       |                 |               |
                      |             |                 |               |
                      | Identifiers |                 |               |
                      |             |                 |               |
                      v             v                 |               |
                 .----+----.  .-----+----.            |               |
                | Headers   || Payload    |           |               |
                 '----+----'  '-----+----'            |               |
                      |             |                 |               |
                       '----. .----'                  |               |
                             |                        |               |
                             v                        |               |
                        .----+----.                   |               |
                       | Opaque    |                  |               |
                       | Signature |                  |               |
                        '----+----'                   |               |
                             |                        v               |
                             |                +-------+------+        |
                          .-' '-------------->+ Transparency |        |
                         |   .----------.     |              |        |
Transparency    -->      |  | Receipt 1  +<---+   Service 1  +----+   |
Provider 1               |   '---+------'     +-------+------+    |   |
                         |       |                    |           |   |
    ...                  |       |           +--------------+     |   |
                      .-' '------)---------->+ Transparency |     |   |
                     |   .----------.        |              |     |   |
Transparency  -->    |  | Receipt 2  +<------+   Service 2  +--+  |   |
Provider 2           |   '----+-----'        +----+---------+  |  |   |
                     |        |  |                |   |        |  |   |
    ...               '-. .--'   |                |   |        |  |   |
                         |       |                |   |        |  |   |
                          '-. .-'                 |   |        |  |   |
                             |                    |   |        |  |   |
                             v                    v   v        |  |   |
                       .-----+------.        .----+---+---.    |  |   |
                      | Transparent  |      | Identity     |   |  |   |
                      | Signatures   |      | Documents    |   |  |   |
                       '-----+------'        '------+-----'    |  |   |
                             |                      |          |  |   |
                             |'--------.     .-----'           |  |   |
                             |          |   |                  |  |   |
                             v          v   v                  v  v   |
                    .--------+--. .-----+---+----------. .-----+--+-. |
Verifiers -->      / Review    / / Verify Transparent / / Analyze  /  |
                  /  Receipts / /  Signatures        / /  Logs    /   |
                 '-----------' '----------+---------' '----------'    |
                                          |                           |
                                          v                           |
                              .-----------+-------.                   |
                             / Verify Content    /<-------------------+
Relying Parties    -->      /  Transparency     /
                           '-------------------'
~~~

# Terminology

{::boilerplate bcp14-tagged}

The terms "cose-sign1" and "cose-key", and "cose-key-set" are defined in {{-COSE}}.

issuer:
: A name for the entity that produces a cose-sign1.
  Issuers are identified by Identity Documents.

opaque-signature:
: A cose-sign1 as decribed in {{-COSE}}.

receipt:
: A cose-sign1, with an inclusion, consistency or other proof type as described in {{-COSE-RECEIPTS}}.

transparent-signature:
: A cose-sign1, opaque-signature, with one or more receipts included in its unprotected header.

notary:
: A name for the entity that produces a receipt.
  A notary is an issuer of receipts.
  Notaries are identified by Identity Documents.

# Messages

This section describes the conceptual messages supported by transparency services.

Each message is a cose-sign1, and MAY be described with the media type `application/cose; cose-type="cose-sign1"` as defined in {{-COSE}}.

To provide additional clarity, we define new media types for each conceptual message.

## Opaque Signature

An opaque signature MUST be a cose-sign1 produced according to {{-COSE}}.

The unprotected header MAY contain arbitrary data, as described in {{Section 3 of RFC9052}}.

The payload MAY be detached, as described in {{Section 4.1 of RFC9052}}.

There are no changes to the protected header requirements described in {{Section 4 of RFC9052}}.

The media type `application/opaque-signature+cose` SHOULD be used to distinguish opaque signatures from other forms of cose-sign1.

~~~ cddl
Opaque_Signature = #6.18(COSE_Sign1)

COSE_Sign1 = [
  protected   : bstr .cbor Opaque_Signature_Protected_Header,
  unprotected : Opaque_Signature_Unprotected_Header,
  payload     : bstr,
  signature   : bstr
]

Opaque_Signature_Protected_Header = {

  ; Algorithm Identifier,
  ? (alg: 1)   => int

  ; Key Identifier,
  ? (kid: 4)   => bstr

  ; CBOR Web Token Claims,
  ? (cwt-claims: 15)  => Opaque_Signature_CWT_Claims

  ; Payload Content Type
  ? (content-type: 3)   => tstr

  ; X.509 Certificate Thumbprint
  ? (x509-thumbprint: 34)  => COSE_CertHash

  * cose-label => cose-value

}

COSE_X509 = bstr / [ 2*certs: bstr ]
COSE_CertHash = [ hashAlg: (int / tstr), hashValue: bstr ]


Opaque_Signature_CWT_Claims = {

  ; Issuer
  ? (iss: 1) => tstr,

  ; Subject
  ? (sub: 2) => tstr,

  ; Audience
  ? (aud: 3) => tstr,

  ; Expiration
  ? (exp: 4) => uint .within (~time),

  ; Issued At
  ? (iat: 6) => uint .within (~time),

  ; label MUST be less than -65536
  * label => value

}

Opaque_Signature_Unprotected_Header = {
  * cose-label => cose-value
}
~~~

## Receipt

A receipt MUST be a cose-sign1 produced according to {{-COSE}}.

The unprotected header MAY contain arbitrary data, as described in {{Section 3 of RFC9052}}.

The unprotected header MUST include an a proof as described in {{-COSE-RECEIPTS}}.

The payload MAY be detached, as described in {{Section 4.1 of RFC9052}}.

There are no changes to the protected header requirements described in {{Section 4 of RFC9052}}, and {{-COSE-RECEIPTS}}.

The media type `application/receipt+cose` SHOULD be used to distinguish receipts from other forms of cose-sign1.


~~~ cddl

Receipt = #6.18(Receipt_as_COSE_Sign1)

Receipt_as_COSE_Sign1 = [
    protected : bstr .cbor Receipt_Protected_Header,
    unprotected : Receipt_Unprotected_Header,
    payload: nil,
    signature : bstr
]

Receipt_Protected_Header = {

  ; Algorithm Identifier,
  ? (alg: 1)   => int

  ; Key Identifier,
  ? (kid: 4)   => bstr

  ; CBOR Web Token Claims,
  ? (cwt-claims: 15)  => Opaque_Signature_CWT_Claims

  ; Payload Content Type
  ? (content-type: 3)   => tstr

  ; X.509 Certificate Thumbprint
  ? (x509-thumbprint: 34)  => COSE_CertHash

  ; Verifiable Data Structure
  &(verifiable-data-structure: -111) => int,

  * cose-label => cose-value
}

COSE_X509 = bstr / [ 2*certs: bstr ]
COSE_CertHash = [ hashAlg: (int / tstr), hashValue: bstr ]

Receipt_CWT_Claims = {
  ; Issuer
  ? (iss: 1) => tstr,

  ; Subject
  ? (sub: 2) => tstr,

  ; Audience
  ? (aud: 3) => tstr,

  ; Expiration
  ? (exp: 4) => uint .within (~time),

  ; Issued At
  ? (iat: 6) => uint .within (~time),

  ; label MUST be less than -65536
  * label => value
}

Receipt_Unprotected_Header = {
  &(verifiable-data-proof: -222) => Verifiable_Proofs
  * cose-label => cose-value
}

Verifiable_Proofs = {
  &(inclusion-proofs: -1) => Inclusion_Proofs
}

Inclusion_Proofs = [ + Inclusion_Proof ]

Inclusion_Proof = bstr .cbor
~~~

## Transparent Signature

A transparent signature MUST be a cose-sign1 produced according to {{-COSE}}.

The unprotected header MAY contain arbitrary data, as described in {{Section 3 of RFC9052}}.

The unprotected header MUST include an a receipt as described in this document.

The payload MAY be detached, as described in {{Section 4.1 of RFC9052}}.

There are no changes to the protected header requirements described in {{Section 4 of RFC9052}}, and this document.

The media type `application/transparent-signature+cose` SHOULD be used to distinguish transparent signatures from other forms of cose-sign1.

~~~ cddl
Transparent_Signature = #6.18(Transparent_Signature)

Transparent_Signature_as_COSE_Sign1 = [
  protected   : bstr .cbor Opaque_Signature_Protected_Header,
  unprotected : Transparent_Signature_Unprotected_Header,
  payload     : bstr,
  signature   : bstr
]

Transparent_Signature_Unprotected_Header = {
  (receipts: 394) => [+ Receipt],
  * cose-label => cose-value
}
~~~

# Message URNs

This section describes deterministic names for the conceptual messages described in the previous section, and one new message type "payload" which is defined in {{RFC9052}}.

The following URI template is used produce URNs:

~~~
urn:ietf:params:{wg}:\
{message-type}:\
{hash-name}:{base-encoding}:\
{base64url-encoded-bytes-digest}
~~~

`wg` MUST be the name of an IETF Working Group.

`message-type` MUST be `payload`, `opaque-signature`, `receipt`, or `transparent-signature`.

`hash-name` MUST be `sha-256`.

`base-encoding` MUST be `base64url`.

`base64url-encoded-bytes-digest` MUST be the the base64url encoded sha-256 digest of the `payload`, `opaque-signature`, `receipt`, or `transparent-signature`.

Note that this identifier scheme is sensitive to changes in the unprotected header and signature of the cose-sign1.

The following informative examples are provided:

~~~
urn:ietf:params:cose:payload\
:sha-256:base64url:5i6UeRzg1...qnGmr1o
urn:ietf:params:cose:opaque-signature\
:sha-256:base64url:5i6UeRzg1...qnGmr1o
urn:ietf:params:cose:receipt\
:sha-256:base64url:5i6UeRzg1...qnGmr1o
urn:ietf:params:cose:transparent-signature\
:sha-256:base64url:5i6UeRzg1...qnGmr1o
~~~
{: #urn-identifier-examples align="left" title="URN Examples"}

Implementations MAY choose to shorten these identifiers by replacing the middle sections of these URNs, for example `ietf:params:cose:opaque-signature:sha-256:base64url`, with a vendor specific URL safe string.

The following informative examples are provided:

~~~
urn:payload.vendor.example:5i6UeRzg1...qnGmr1o
urn:opaque.vendor.example:5i6UeRzg1...qnGmr1o
urn:receipt.vendor.example:5i6UeRzg1...qnGmr1o
urn:transparent.vendor.example:5i6UeRzg1...qnGmr1o
~~~
{: #urn-vendor-specific-identifier-examples align="left" title="Vendor URN Examples"}

Implementations are cautioned that these vendor specific identifiers cannot be understood globablly.

# Message URLs

Identifiers MAY be prefixed with a URL base, such as `https://vendor.example`.

For example:

~~~
https://vendor.example/urn:...:5i6UeRzg1...qnGmr1o
~~~
{: #url-identifier-examples align="left" title="URL Examples"}

These identifiers MAY be used as values for `opaque-signature-reference`, `receipt-reference`, `transparent-signature-reference`, which are produced and consumed in the Operations section of this document.

# Operations

This section describes the operations associated with the conceptual messages described in this document.

Each operation is defined in terms on consuming inputs and producing outputs.

The operations defined in this section are abstract, but a concrete HTTP API for them is provided in Section TBD of this document.

## Register Opaque Signature

The register opaque signature operation takes an `opaque-signature` as input and produces a `receipt`, or `receipt-reference` as output.

Concrete instantiations of this operation MUST return a `receipt-reference` in case a `receipt` cannot be produced in under 100 seconds.

## Request Receipt

The request receipt operation takes an `receipt-reference` as input and produces a `receipt` as output.

Concrete instantiations of this operation MUST return a `receipt-reference` in case a `receipt` cannot be produced in under 100 seconds.

## Attach Receipt

The attach receipt operation takes an (`opaque-signature` or `transparent-signature`) and `receipt` as input and produces a `transparent-signature`, or `transparent-signature-reference` as output.

Concrete instantiations of this operation MUST be synchronous, and cannot exceed 100 seconds to complete.

## Detach Receipt

The detach receipt operation takes a `transparent-signature`, and index number as input and produces an (`opaque-signature`, `transparent-signature`, or `transparent-signature-reference`) as output.

Concrete instantiations of this operation MUST be synchronous, and cannot exceed 100 seconds to complete.

## Verify Opaque Signature

The verify opaque signature operation takes an `opaque-signature`, and optional (`payload` or `payload-reference`) as input and produces a boolean value `true` if the signature verifies as decribed in {{Section 4.4 of RFC9052}}.

The `payload` MUST be included for detached payload cose-sign1 and MUST NOT be included for attached payload cose-sign1, see {{Section 2 of RFC9052}} for detached regarding detached content.

In the case a `payload` is large, a `payload-reference` MAY be used instead.

Note that no public key or certificate is provided as input, because the verification key must be discoverable from the details of the protected header.

Key discovery, distribution, resolution and dereferencing are out of scope for this document.

## Verify Receipt

The verify receipt operation takes an optional (`payload` or `payload-reference`), `opaque-signature` and a `receipt` as input and produces a boolean value `true` if the following succeed and `false` otherwise:

- Verify Opaque Signature MUST return `true` for the `opaque-signature`.
- Verify Proof MUST return `true` for all proofs inside the `receipt` unprotected header.
- Verify must return `true` for the `receipt`, as described in {{Section 4.4 of RFC9052}}.

The `payload` MUST be included for detached payload cose-sign1 and MUST NOT be included for attached payload cose-sign1, see {{Section 2 of RFC9052}} for detached regarding detached content.

In the case a `payload` is large, a `payload-reference` MAY be used instead.

Note that no public key or certificate is provided as input, because the verification key must be discoverable from the details of the protected headers.

Key discovery, distribution, resolution and dereferencing are out of scope for this document.

## Verify Transparent Signature

The verify transparent signature operation takes an optional (`payload` or `payload-reference`) and `transparent-signature` as input and produces a boolean `true` as output when the following succeed and `false` otherwise:

For each `receipt` in the `transparent-signature` the Verify Receipt operation MUST return true.

The `payload` MUST be included for detached payload cose-sign1 and MUST NOT be included for attached payload cose-sign1, see {{Section 2 of RFC9052}} for detached regarding detached content.

In the case a `payload` is large, a `payload-reference` MAY be used instead.

Note that no public key or certificate is provided as input, because the verification key must be discoverable from the details of the protected headers.

Key discovery, distribution, resolution and dereferencing are out of scope for this document.

## Verify Issuer

The verify issuer operation takes an identifier for the issuer as input, and produces a set of verification keys for the issuer as output.

Producing an empty set of verification keys MUST be interpretted as the issuer being untrusted, and not verified.

The set of verification keys, combined with the issuer identifier, delivered from a trust store, is also called an Identity Document.

The content type of the output MUST be a registered media type in {{IANA.media-types}}.

Implementations MUST support "cose-key-set", and MAY support "jwk-set".

This operation MAY be called on issuers or notaries.

## Verify References

The verify references operation takes an identifier for a message ( `payload-reference`, `opaque-signature-reference`, `receipt-reference`, `transparent-signature-reference`) and an optional `payload` as input and produces a boolean `true` or `false` as output.

This operation requires the provider to be able to resolve a given identifier to a message, and then apply the Verify Opaque Signature, Verify Receipt or Verify Transparent Signature operations.

# HTTP API

This section proposes concrete http endpoints for the operations described in the previous section.

## Register Opaque Signature

Request:

~~~ http-message
NOTE: '\' line wrapping per RFC 8792

POST /register/opaque-signature HTTP/1.1
Host: transparency.service.example
Content-Type: \
  application/opaque-signature+cose
Body (in CBOR diagnostic notation):

18(                                 / COSE Sign 1                   /
    [
      h'a4013822...3a343536',       / Protected Header              /
      {},                           / Unprotected Header            /
      nil,                          / Detached Payload              /
      h'4be77803...65c72b2a'        / Signature                     /
    ]
)

~~~

Response:

~~~ http-message
NOTE: '\' line wrapping per RFC 8792

HTTP/1.1 200 Ok
Content-Type: \
  application/json
Body:
{
  "receipt": "https://.../receipts/urn:...qnGmr1o"
}
~~~

In some cases, the opaque signature may need to demonstrate proof of possession of a specific key.

For example, the `cnf` claim can be used to create an identity document, where an opaque signature is signed by the public key included in the identity document, and the signature is over some "nonce" or "challenge" provided by the transparency service.

Implementations MUST use the endpoints defined in {{-NONCE-ENDPOINT}} in cases where the "nonce" is made available from the transparency service, to an issuer over HTTP.

In cases where a transparency service maintains multiple independent logs under the same origin, the issuer MUST submit the opaque signature to the correct log.

This can be accomplished by providing unique identifiers for the logs, and basing the Register Opaque Signature endpoint on those identifiers.

The following informative examples are provided:

~~~
POST https://organization-1.transparency.example/register/opaque-signature
POST https://transparency.example/organization-2/register/opaque-signature
~~~

In case the authorization scheme used to protect the endpoints binds access to a specific log, for example using a JWT based access token, granting write ability to a specific log, the token can be used to convey the desired log, and the endpoint and host can ommit log specific identifiers, for example:

~~~ http-message

POST /register/opaque-signature HTTP/1.1
Host: transparency.service.example

Authorization: Bearer "{header}.\
{ 
  "iss": "https://issuer.transparency.example",
  "sub": "user@vendor.example",
  "client_id": "s6BhdRkqt3"
  "aud": [
    "https://log1.transparency.example", 
    "https://transparency.example/log2"
  ],
  "scope": [
    "opaque-signature:register",
    ...
  ],
}.{signature}"

Content-Type: application/opaque-signature+cose
Body: ...
~~~

For JWT based access tokens, see:

- "aud" as defined in {{ Section 3.1.3 of RFC8392 }}.
- "scope" as defined in {{ Section 4.2 of RFC8693 }}.
- "client_id" as defined in {{ Section 4.3 of RFC8693 }}.

For CWT based access tokens, see:

- "aud" as defined in {{ Section 4.1.3 of RFC7519 }}.
- "scope" as defined in {{ Section 4.2 of RFC8693 }}.
- "client_id" as defined in [NOT POSSIBLE?](https://mailarchive.ietf.org/arch/msg/oauth/aJk_fJd9n8oGVKEafM2zMQdyWb4/)

## Request Receipt

Request:

~~~ http-message
NOTE: '\' line wrapping per RFC 8792

GET /receipts/urn:...opaque-signature...:5i6UeRzg1...qnGmr1o HTTP/1.1
Host: transparency.service.example
Accept: \
  application/receipt+cose
~~~

Response:

~~~ http-message
NOTE: '\' line wrapping per RFC 8792

HTTP/1.1 200 Ok
Content-Type: \
  application/receipt+cose
Body (in CBOR diagnostic notation):

18(                                 / COSE Sign 1                   /
    [
      h'a4013822...3a616263',       / Protected                     /
      {                             / Unprotected                   /
        -222: {                     / Proofs                        /
          -1: [                     / Inclusion proofs (1)          /
            h'83040382...8628a031', / Inclusion proof 1             /
          ]
        },
      },
      h'',                          / Detached payload              /
      h'15280897...93ef39e5'        / Signature                     /
    ]
)
~~~

## Verify Issuer

Request:

~~~ http-message
NOTE: '\' line wrapping per RFC 8792

GET /issuer/vendor.example HTTP/1.1
Host: transparency.service.example
Accept: \
  application/jwk-set+json
~~~

Response:

~~~ http-message
NOTE: '\' line wrapping per RFC 8792

HTTP/1.1 200 Ok
Content-Type: \
  application/jwk-set+json
Body:

{
  "keys": [
    {
      "kid": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:Nz2...sXs"
      "kty": "EC",
      "crv": "P-256",
      "alg": "ES256",
      "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
      "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
      "x5t": "NTBGNTJEMDc3RUE3RUVEO...yOTY5NDNGOUQ4OEU5OA",
      "x5c": [
        "MIIDCzCCAfOgAwIBAgIJA...iwiJS+u/nSYvqCFt57+g3R+"
      ]
    }
  ]
}
~~~

## Verify References

Request:

~~~ http-message
NOTE: '\' line wrapping per RFC 8792

POST /verify/references HTTP/1.1
Host: transparency.service.example
Content-Type: \
  application/json
Body:
{

  "payload": "urn:...qnGmr1o",

  "transparent-signature": "urn:...qnGmr1o"

}

~~~

Response:

~~~ http-message
NOTE: '\' line wrapping per RFC 8792

HTTP/1.1 200 Ok
Content-Type: \
  application/json
Body:
{
  "verified": true
}
~~~

# Security Considerations

TODO Security


# IANA Considerations

TODO Request Registration of Media Types


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.

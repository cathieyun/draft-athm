---
title: "Anonymous Token with Hidden Metadata Privacy Pass Issuance and Authentication Protocols"
abbrev: "ATHM Privacy Pass Issuance and Authentication Protocols"
category: std

docname: draft-yun-privacypass-athm-latest
submissiontype: IETF
consensus: true
number:
date:
v: 3
venue:
  group: PRIVACYPASS
  type: Privacy Pass
  mail: WG@example.com
  arch: https://example.com/WG
  github: USER/REPO
  latest: https://example.com/LATEST

author:
 -
    ins: J. Appleseed
    name: Johnny Appleseed
    organization: Apple, Inc.
    email: johnny@apple.com

normative:
  AUTHSCHEME: RFC9577
  ARCHITECTURE: RFC9576
  ISSUANCE: RFC9578

informative:

--- abstract

TODO Abstract


--- middle

# Introduction

TODO Introduction


# Terminology

{::boilerplate bcp14-tagged}

This document uses the terms Origin, Client, Issuer, and Token as defined in
{{Section 2 of ARCHITECTURE}}. Moreover, the following additional terms are
used throughout this document.

- Issuer Public Key: The public key (from a private-public key pair) used by
  the Issuer for issuing and verifying Tokens.
- Issuer Private Key: The private key (from a private-public key pair) used by
  the Issuer for issuing and verifying Tokens.

Unless otherwise specified, this document encodes protocol messages in TLS
notation from {{Section 3 of !TLS13=RFC8446}}. Moreover, all constants are in
network byte order.

# Protocol Overview

The issuance and redemption protocols defined in this document are built on
an anonymous credential construction called ATHM, as specified in {{!ATHM-SPEC=I-D.yun-cfrg-athm}}.
ATHM is a privately verifiable token with support for n private metadata buckets.

Unlike the core Privacy Pass token types specified in {{ISSUANCE}}, ATHM tokens
are not cryptographically bound to TokenChallenge messages; see {{AUTHSCHEME}}
for details about how this binding typically works. Instead, with ATHM, Clients
can request tokens from an Issuer without a preceding TokenChallenge, and
present these tokens to the Origin during presentation. This interaction is
shown below.

~~~ aasvg
+--------+            +--------+         +----------+ +--------+
| Origin |            | Client |         | Attester | | Issuer |
+---+----+            +---+----+         +----+-----+ +---+----+
    |                     |                   |           |
    |                     |<== Attestation ==>|           |
    |                     |                   |           |
    |                     +--------- TokenRequest ------->|
    |                     |<------- TokenResponse --------+
    |<-- Request+Token ---+                   |           |
    |                     |                   |           |
~~~
{: #fig-overview title="Issuance and Redemption Overview"}

Unlike the core Privacy Pass protocols, TokenChallenge values
are not inputs to the issuance protocol or redemption protocols.
As such, ATHM tokens require their own Token format, which is specified
in {{redemption}}.

ATHM is only compatible with deployment models where the Issuer and Origin
are operated by the same entity (see {{Section 4 of ARCHITECTURE}}), as
tokens produced from a credential are not publicly verifiable. The details
of attestation are outside the scope of the issuance protocol; see
{{Section 4 of ARCHITECTURE}} for information about how attestation can
be implemented in each of the relevant deployment models.

# Configuration {#setup}

ATHM issuers are configured with key material used for issuance and credential
verification. Concretely, Issuers run the `KeyGen` function from {{ATHM-SPEC}}
to produce a secret and public key, denoted skI and pkI, respectively.

~~~
skI, pkI = KeyGen()
~~~

The Issuer Public Key ID, denoted `issuer_key_id`, is computed as the SHA-256
hash of the Verified Issuer Public Key, i.e., `issuer_key_id = SHA-256(Serialize(verifiedPublicKey))`.

# Token Issuance Protocol

Issuers provide a Issuer Private and Public Key, denoted `skI` and `pkI` respectively,
used to produce tokens as input to the protocol. See {{setup}} for how these keys are generated.

Clients provide the following as input to the issuance protocol:

- Issuer Request URL: A URL identifying the location to which issuance requests
  are sent. This can be a URL derived from the "issuer-request-uri" value in the
  Issuer's directory resource, or it can be another Client-configured URL. The value
  of this parameter depends on the Client configuration and deployment model.
  For example, in the 'Joint Origin and Issuer' deployment model, the Issuer
  Request URL might correspond to the Client's configured Attester, and the
  Attester is configured to relay requests to the Issuer.
- Issuer name: An identifier for the Issuer. This is typically a host name that
  can be used to construct HTTP requests to the Issuer.
- Issuer Public Key: `pkI`, with a key identifier `token_key_id` computed as
  described in {{setup}}.

Given this configuration and these inputs, the two messages exchanged in
this protocol to produce a credential are described below.

## Client-to-Issuer Request

Given Issuer Public Key `pkI`, the Client first verifies the public key to make
a verified public key:

~~~
verifiedPublicKey = VerifyPublicKeyProof(publicKey, pi)
~~~

Next, it creates a token request message using the `TokenRequest` function from
{{ATHM-SPEC}} as follows:

~~~
(context, request) = TokenRequest(verifiedPublicKey)
~~~

The Client then creates a TokenRequest structure as follows:

~~~
struct {
  uint16_t token_type = 0xC07E; /* Type ATHM(P-256) */
  uint8_t truncated_issuer_key_id;
  uint8_t encoded_request[Nrequest];
} TokenRequest;
~~~

The structure fields are defined as follows:

- "token_type" is a 2-octet integer.

- "truncated_issuer_key_id" is the least significant byte of the `issuer_key_id`,
  the Issuer Public Key ID corresponding to `pkI`, in network byte order (in other words, the last 8
  bits of `issuer_key_id`). This value is truncated so that Issuers cannot use
  `issuer_key_id` as a way of uniquely identifying Clients; see {{security}}
  and referenced information for more details.

- "encoded_request" is the Nrequest-octet request, computed as the serialization
  of the `request` value as defined in {{ATHM-SPEC}}.

The Client then generates an HTTP POST request to send to the Issuer Request URL,
with the TokenRequest as the content. The media type for this request is
"application/private-token-request". An example request for the Issuer Request URL
"https://issuer.example.net/request" is shown below.

[[QUESTION: Should we reuse the same content type for this request, or should we introduce a new content type?]]

~~~
POST /request HTTP/1.1
Host: issuer.example.net
Accept: application/private-token-response
Content-Type: application/private-token-request
Content-Length: <Length of TokenRequest>

<Bytes containing the TokenRequest>
~~~

## Issuer-to-Client Response

Upon receipt of the request, the Issuer validates the following conditions:

- The TokenRequest contains a supported token_type equal to value 0xC07E.
- The TokenRequest.truncated_token_key_id corresponds to the truncated key ID
  of an Issuer Public Key, with corresponding secret key `skI`, owned by
  the Issuer.
- The TokenRequest.encoded_request is of the correct size (`Nrequest`).

If any of these conditions is not met, the Issuer MUST return an HTTP 422
(Unprocessable Content) error to the client.

If these conditions are met, the Issuer then tries to deserialize
TokenRequest.encoded_request according to {{ATHM-SPEC}}, yielding `request`.
If this fails, the Issuer MUST return an HTTP 422 (Unprocessable Content)
error to the client. Otherwise, if the Issuer is willing to produce a token
for the Client with a hidden metadata bucket, denoted `hiddenMetadata`, the Issuer
completes the issuance flow by an issuance response as follows:

~~~
response = TokenResponse(skI, pkI, request, hiddenMetadata)
~~~

The Issuer then creates a TokenResponse structured as follows:

~~~
struct {
   uint8_t encoded_response[Nresponse];
} TokenResponse;
~~~

The structure fields are defined as follows:

- "encoded_response" is the Nresponse-octet encoded issuance response message, computed
  as the serialization of `response` as specified in {{ATHM-SPEC}}.

The Issuer generates an HTTP response with status code 200 whose content
consists of TokenResponse, with the content type set as
"application/private-token-response".

~~~
HTTP/1.1 200 OK
Content-Type: application/private-token-response
Content-Length: <Length of TokenResponse>

<Bytes containing the TokenResponse>
~~~

## Token Finalization

Upon receipt, the Client handles the response and, if successful, deserializes
the content values `TokenResponse.encoded_response` according to {{ATHM-SPEC}}
yielding `response`. If deserialization fails, the Client aborts the protocol.
Otherwise, the Client processes the response as follows:

~~~
token = FinalizeToken(context, verifiedPublicKey, request, response)
~~~

The Client then saves the resulting token structure for use with a future redemption.

# Token Redemption Protocol {#redemption}

The token redemption protocol presents a Token to the Origin for redemption. This section
describes how the Token values are encoded in the redemption protocol and then verified
by the Origin.

## Token Structure

~~~
struct {
    uint16_t token_type = 0xC07E; /* Type ATHM(P-256) */
    uint8_t issuer_key_id[Nid];
    uint8_t token[Ntoken];
} Token;
~~~

The structure fields are defined as follows:

- "token_type" is a 2-octet integer, in network byte order, equal to 0xC7D3.

- "issuer_key_id" is a Nid-octet identifier for the Issuer Public Key, computed
as defined in {{setup}}.

- "token" is a Ntoken-octet token, set to the serialized `token` value (see {{ATHM-SPEC}}
for serialization details); see {{verification}} for more information
about how this field is used in verifying a token.

## Token Verification {#verification}

Verifying a Token requires invoking the VerifyToken function from {{ATHM-SPEC}}
with input `skI`, `pkI`, and `token` in the following way:

~~~
hiddenMetadata = VerifyToken(skI, pkI, token)
~~~

This function will fail with an error if the token is invalid. Otherwise, it will
return an integer value corresponding to the bucket bound to the token during issuance.

# Security Considerations {#security}

TODO Security


# IANA Considerations

This document updates the "Privacy Pass Token Type" Registry with the
following entries.

* Value: 0xC07E
* Name: ATHM(P-256)
* Token Structure: As defined in {{Section 2.2 of AUTHSCHEME}}
* Token Key Encoding: Serialized as described in {{setup}}
* TokenChallenge Structure: As defined in {{Section 2.1 of AUTHSCHEME}}
* Public Verifiability: N
* Public Metadata: N
* Private Metadata: Y
* Nk: 48
* Nid: 32
* Reference: This document
* Notes: None


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.

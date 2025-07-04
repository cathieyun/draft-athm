---
title: "Anonymous Tokens with Hidden Metadata"
abbrev: "ATHM"
category: info

docname: draft-yun-cfrg-athm-latest
submissiontype: IRTF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "IRTF"
workgroup: "Crypto Forum"
keyword:
 - next generation
 - unicorn
 - sparkling distributed ledger
venue:
  group: "Crypto Forum"
  type: "Research Group"
  mail: "cfrg@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/cfrg"
  github: "cathieyun/draft-athm"
  latest: "https://cathieyun.github.io/draft-athm/draft-yun-cfrg-athm.html"

author:
 -
    ins: C. Yun
    name: Cathie Yun
    organization: Apple, Inc.
    email: cathieyun@gmail.com
 -
    ins: C. A. Wood
    name: Christopher A. Wood
    org: Apple, Inc.
    email: caw@heapingbits.net
 -
    ins: M. Raykova
    name: Mariana Raykova
    organization: Google
    email: marianar@google.com
 -
    ins: S. Schlesinger
    name: Samuel Schlesinger
    organization: Google
    email: sgschlesinger@gmail.com

normative:

informative:
  NISTCurves: DOI.10.6028/NIST.FIPS.186-4
  SEC1:
    title: "SEC 1: Elliptic Curve Cryptography"
    target: https://www.secg.org/sec1-v2.pdf
    date: false
    author:
      -
        ins: Standards for Efficient Cryptography Group (SECG)

--- abstract

This document specifies the Anonymous Tokens with Hidden Metadata (ATHM) protocol, a protocol
for constructing Privacy Pass like tokens with hidden metadata embedded within it unknown
to the client.

--- middle

# Introduction

TODO Introduction


# Conventions and Definitions

## Notation and Terminology

The following functions and notation are used throughout the document.

- For any object `x`, we write `len(x)` to denote its length in bytes.
- For two byte arrays `x` and `y`, write `x || y` to denote their
  concatenation.
- I2OSP(x, xLen): Converts a non-negative integer `x` into a byte array
  of specified length `xLen` as described in {{!RFC8017}}. Note that
  this function returns a byte array in big-endian byte order.
- The notation `T U[N]` refers to an array called U containing N items of type
  T. The type `opaque` means one single byte of uninterpreted data. Items of
  the array are zero-indexed and referred as `U[j]` such that 0 <= j < N.

All algorithms and procedures described in this document are laid out
in a Python-like pseudocode. Each function takes a set of inputs and parameters
and produces a set of output values. Parameters become constant values once the
protocol variant and the ciphersuite are fixed.

String values such as "CredentialRequest", "CredentialResponse", and "Presentation" are ASCII string literals.

The `PrivateInput` data type refers to inputs that are known only to the client
in the protocol, whereas the `PublicInput` data type refers to inputs that are
known to both client and server in the protocol.

The following terms are used throughout this document.

- Client: Protocol initiator. Creates an encrypted request, and uses the
corresponding server encrypted issuance to make a presentation.
- Server: Computes an encrypted issuance for an encrypted request, with its
server private keys. Later the server can verify the client's presentations
with its private keys. Learns nothing about the client's secret attributes,
and cannot link a client's issuance and presentation steps.

# Preliminaries

The construction in this document has two primary dependencies:

- `Group`: A prime-order group implementing the API described below in {{pog}}.
  See {{ciphersuites}} for specific instances of groups.
- `Hash`: A cryptographic hash function whose output length is `Nh` bytes.

{{ciphersuites}} specifies ciphersuites as combinations of `Group` and `Hash`.

## Prime-Order Group {#pog}

In this document, we assume the construction of an additive, prime-order
group `Group` for performing all mathematical operations. In prime-order groups,
any element (other than the identity) can generate the other elements of the
group. Usually, one element is fixed and defined as the group generator.
In the KVAC setting, there are two fixed generator elements (generatorG, generatorH).
Such groups are uniquely determined by the choice of the prime `p` that defines the
order of the group. (There may, however, exist different representations
of the group for a single `p`. {{ciphersuites}} lists specific groups which
indicate both order and representation.)

The fundamental group operation is addition `+` with identity element
`I`. For any elements `A` and `B` of the group, `A + B = B + A` is
also a member of the group. Also, for any `A` in the group, there exists an element
`-A` such that `A + (-A) = (-A) + A = I`. Scalar multiplication by `r` is
equivalent to the repeated application of the group operation on an
element A with itself `r-1` times, this is denoted as `r*A = A + ... + A`.
For any element `A`, `p*A=I`. The case when the scalar multiplication is
performed on the group generator is denoted as `ScalarMultGen(r)`.
Given two elements A and B, the discrete logarithm problem is to find
an integer k such that B = k*A. Thus, k is the discrete logarithm of
B with respect to the base A.
The set of scalars corresponds to `GF(p)`, a prime field of order p, and are
represented as the set of integers defined by `{0, 1, ..., p-1}`.
This document uses types
`Element` and `Scalar` to denote elements of the group and its set of
scalars, respectively.

We now detail a number of member functions that can be invoked on a
prime-order group.

- Order(): Outputs the order of the group (i.e. `p`).
- Identity(): Outputs the identity element of the group (i.e. `I`).
- Generators(): Outputs the generator elements of the group, (generatorG, generatorH)
  generatorG = Group.generator
  generatorH = HashToGroup(SerializeElement(generatorG), "generatorH"). The
  group member functions GeneratorG() and GeneratorH() are shorthand for
  returning generatorG and generatorH, respectively.
- HashToGroup(x, info): Deterministically maps
  an array of bytes `x` with domain separation value `info` to an element of `Group`. The map must ensure that,
  for any adversary receiving `R = HashToGroup(x, info)`, it is
  computationally difficult to reverse the mapping.
  Security properties of this function are described
  in {{!I-D.irtf-cfrg-hash-to-curve}}.
- HashToScalar(x, info): Deterministically maps
  an array of bytes `x` with domain separation value `info` to an element in GF(p).
  Security properties of this function are described in {{!I-D.irtf-cfrg-hash-to-curve, Section 10.5}}.
- RandomScalar(): Chooses at random a non-zero element in GF(p).
- ScalarInverse(s): Returns the inverse of input `Scalar` `s` on `GF(p)`.
- SerializeElement(A): Maps an `Element` `A`
  to a canonical byte array `buf` of fixed length `Ne`.
- DeserializeElement(buf): Attempts to map a byte array `buf` to
  an `Element` `A`, and fails if the input is not the valid canonical byte
  representation of an element of the group. This function can raise a
  DeserializeError if deserialization fails or `A` is the identity element of
  the group; see {{ciphersuites}} for group-specific input validation steps.
- SerializeScalar(s): Maps a `Scalar` `s` to a canonical
  byte array `buf` of fixed length `Ns`.
- DeserializeScalar(buf): Attempts to map a byte array `buf` to a `Scalar` `s`.
  This function can raise a DeserializeError if deserialization fails; see
  {{ciphersuites}} for group-specific input validation steps.

{{ciphersuites}} contains details for the implementation of this interface
for different prime-order groups instantiated over elliptic curves. In
particular, for some choices of elliptic curves, e.g., those detailed in
{{?RFC7748}}, which require accounting for cofactors, {{ciphersuites}}
describes required steps necessary to ensure the resulting group is of
prime order.

# Ciphersuites {#ciphersuites}

A ciphersuite (also referred to as 'suite' in this document) for the protocol
wraps the functionality required for the protocol to take place. The
ciphersuite should be available to both the client and server, and agreement
on the specific instantiation is assumed throughout.

A ciphersuite contains instantiations of the following functionalities:

- `Group`: A prime-order Group exposing the API detailed in {{pog}}, with the
  generator element defined in the corresponding reference for each group. Each
  group also specifies HashToGroup, HashToScalar, and serialization
  functionalities. For
  HashToGroup, the domain separation tag (DST) is constructed in accordance
  with the recommendations in {{!I-D.irtf-cfrg-hash-to-curve, Section 3.1}}.
  For HashToScalar, each group specifies an integer order that is used in
  reducing integer values to a member of the corresponding scalar field.
- `Hash`: A cryptographic hash function whose output length is Nh bytes long.

This section includes an initial set of ciphersuites with supported groups
and hash functions. It also includes implementation details for each ciphersuite,
focusing on input validation.

For each ciphersuite, `contextString` is that which is computed in the Setup functions.
Applications should take caution in using ciphersuites targeting P-256 and ristretto255.
<!-- See {{cryptanalysis}} for related discussion. -->

## ATHM(P-256, SHA-256)

This ciphersuite uses P-256 {{NISTCurves}} for the Group.
The value of the ciphersuite identifier is "P256". The value of
contextString is "ARCV1-P256".

- Group: P-256 (secp256r1) {{NISTCurves}}
  - Order(): Return 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551.
  - Identity(): As defined in {{NISTCurves}}.
  - Generator(): As defined in {{NISTCurves}}.
  - RandomScalar(): Implemented by returning a uniformly random Scalar in the range
    \[0, `G.Order()` - 1\]. Refer to {{random-scalar}} for implementation guidance.
  - HashToGroup(x, info): Use hash_to_curve with suite P256_XMD:SHA-256_SSWU_RO\_
    {{!I-D.irtf-cfrg-hash-to-curve}}, input `x`, and DST =
    "HashToGroup-" || contextString || info.
  - HashToScalar(x, info): Use hash_to_field from {{!I-D.irtf-cfrg-hash-to-curve}}
    using L = 48, `expand_message_xmd` with SHA-256, input `x` and
    DST = "HashToScalar-" || contextString || info, and
    prime modulus equal to `Group.Order()`.
  - ScalarInverse(s): Returns the multiplicative inverse of input Scalar `s` mod `Group.Order()`.
  - SerializeElement(A): Implemented using the compressed Elliptic-Curve-Point-to-Octet-String
    method according to {{SEC1}}; Ne = 33.
  - DeserializeElement(buf): Implemented by attempting to deserialize a 33-byte array to
    a public key using the compressed Octet-String-to-Elliptic-Curve-Point method according to {{SEC1}},
    and then performs partial public-key validation as defined in section 5.6.2.3.4 of
    {{!KEYAGREEMENT=DOI.10.6028/NIST.SP.800-56Ar3}}. This includes checking that the
    coordinates of the resulting point are in the correct range, that the point is on
    the curve, and that the point is not the point at infinity. Additionally, this function
    validates that the resulting element is not the group identity element.
    If these checks fail, deserialization returns an InputValidationError error.
  - SerializeScalar(s): Implemented using the Field-Element-to-Octet-String conversion
    according to {{SEC1}}; Ns = 32.
  - DeserializeScalar(buf): Implemented by attempting to deserialize a Scalar from a 32-byte
    string using Octet-String-to-Field-Element from {{SEC1}}. This function can fail if the
    input does not represent a Scalar in the range \[0, `G.Order()` - 1\].

## Random Scalar Generation {#random-scalar}

Two popular algorithms for generating a random integer uniformly distributed in
the range \[0, G.Order() -1\] are as follows:

### Rejection Sampling

Generate a random byte array with `Ns` bytes, and attempt to map to a Scalar
by calling `DeserializeScalar` in constant time. If it succeeds, return the
result. If it fails, try again with another random byte array, until the
procedure succeeds. Failure to implement `DeserializeScalar` in constant time
can leak information about the underlying corresponding Scalar.

As an optimization, if the group order is very close to a power of
2, it is acceptable to omit the rejection test completely.  In
particular, if the group order is p, and there is an integer b
such that |p - 2<sup>b</sup>| is less than 2<sup>(b/2)</sup>, then
`RandomScalar` can simply return a uniformly random integer of at
most b bits.

### Random Number Generation Using Extra Random Bits

Generate a random byte array with `L = ceil(((3 * ceil(log2(G.Order()))) / 2) / 8)`
bytes, and interpret it as an integer; reduce the integer modulo `G.Order()` and return the
result. See {{I-D.irtf-cfrg-hash-to-curve, Section 5}} for the underlying derivation of `L`.

# Anonymous Token with Hidden Metadata Protocol

TODO(caw): writeme

## Key Generation and Context Setup {#setup}

In the offline phase, the server generates a public and private key using the KeyGen routine below.
The type PublicKeyProof and the function CreatePublicKeyProof are specified in {{public-key-proof}}.

~~~
Input: None
Output:
- privateKey:
  - x: Scalar
  - y: Scalar
  - z: Scalar
  - r_x: Scalar
  - r_y: Scalar
- publicKey:
  - Z: Element
  - C_x: Element
  - C_y: Element
- pi: PublicKeyProof

Parameters
- Group G

def KeyGen():
  x = G.RandomScalar()
  y = G.RandomNonzeroScalar()
  z = G.RandomNonzeroScalar()
  r_x = G.RandomScalar()
  r_y = G.RandomScalar()

  Z = z * G.GeneratorG()
  C_x = (x * G.GeneratorG()) + (r_x * G.GeneratorH())
  C_y = (y * G.GeneratorG()) + (r_y * G.GeneratorH())
  pi = CreatePublicKeyProof(z, Z)

  return privateKey(x, y, z, r_x, r_y), publicKey(Z, C_x, C_y), pi)
~~~

<!-- TODO(caw): specify SerializePublicKey -->

### Public Key Proof {#public-key-proof}

The server public key carries with it a zero-knowledge proof of knowledge
of the corresponding private key. Clients verify this proof before using
the public key for token issuance. The procedures for creating and verifying
this proof, CreatePublicKeyProof and VerifyPublicKeyProof, are detailed below.

~~~
Input:
- z: Scalar
- Z: Element

Output:
- pi: PublicKeyProof
  - e: Scalar
  - a_z: Scalar

Parameters
- Group G

def CreatePublicKeyProof(z, Z):
  rho_z = G.RandomScalar()
  gamma_z = rho_z * G.GeneratorG()

  ser_genG = G.SerializeElement(G.GeneratorG())
  ser_Z = G.SerializeElement(Z)
  ser_gamma_z = G.SerializeElement(gamma_big_z)

  challenge_transcript =
    I2OSP(len(ser_genG), 2) + ser_genG +
    I2OSP(len(ser_Z), 2) + ser_Z +
    I2OSP(len(ser_gamma_z), 2) + ser_gamma_z

  e = G.HashToScalar(challenge_transcript, "KeyCommitments")
  a_z = rho_z - (e * z)

  return PublicKeyProof(e, a_z)
~~~

The output of CreatePublicKeyProof is a value of type PublicKeyProof,
which is wire-encoded as the concatenation of the `e` and `a_z` values,
both serialized using SerializeScalar, yielding the following format:

~~~
struct {
  uint8 e_enc[Ns];
  uint8 a_z_enc[Ns];
} PublicKeyProof;
~~~

The VerifyPublicKeyProof routine, which takes as input a server public key, is below.

~~~
Input:
- publicKey:
  - Z: Element
  - C_x: Element
  - C_y: Element
- pi: PublicKeyProof

Output:
- publicKey if valid, False otherwise

def VerifyPublicKeyProof(publicKey, pi):
  gamma_z = (pi.e * publicKey.Z) +
    (pi.a_z * G.GeneratorG())

  ser_genG = G.SerializeElement(G.GeneratorG())
  ser_Z = G.SerializeElement(Z)
  ser_gamma_z = G.SerializeElement(gamma_big_z)

  challenge_transcript =
    I2OSP(len(ser_genG), 2) + ser_genG +
    I2OSP(len(ser_Z), 2) + ser_Z +
    I2OSP(len(ser_gamma_z), 2) + ser_gamma_z

  e_verify = G.HashToScalar(challenge_transcript, "KeyCommitments")
  if e_verify == e:
    return publicKey
  return False
~~~

## ATHM Protocol

The ATHM Protocol is a two-party protocol between a client and server where
they interact to compute

~~~
token = F(privateKey, publicKey, hiddenMetadata)
~~~

where privateKey and publicKey contains the server's private and public keys, respectively
(and generated as described in {{setup}}), and hiddenMetadata is an application-specific value
known only to the server.

The protocol begins with the client making a token request using the verified server public key.

~~~
verifiedPublicKey = VerifyPublicKeyProof(publicKey, pi)
(context, request) = TokenRequest(verifiedPublicKey)
~~~

The client then sends `request` to the server. If the request is well-formed, the server computes a token response with the server private keys and hidden metadata. The response includes a proof that the token response is valid with respect to the server keys, and a maximum number of buckets for the hidden metadata.

~~~
response = CredentialResponse(privateKey, publicKey, request, hiddenMetadata, nBuckets)
~~~

The server sends the response to the client. The client processes the response by verifying the response proof. If the proof verifies correctly, the client computes a token from its context and the server response:

~~~
token = FinalizeToken(context, verifiedPublicKey, request, response, nBuckets)
~~~

When the client presents the token to the server for redemption, the server verifies it using its private keys, as follows:

~~~
hiddenMetadata = VerifyToken(privateKey, token, nBuckets)
~~~

This process fails if the token is invalid, and otherwise returns the hidden metadata associated with the token during issuance.

Shown graphically, the protocol runs as follows:

~~~

   Client(publicKey)                      Server(privateKey, publicKey, hiddenMetadata)
         ---                                                  ---
  verifiedPublicKey = VerifyPublicKeyProof(publicKey, pi)
  (context, request) = TokenRequest(verifiedPublicKey)

                                request
                            --------------->

                    response = TokenResponse(privateKey, publicKey, request, hiddenMetadata, nBuckets)

                                response
                            <---------------

  token = FinalizeToken(context, verifiedPublicKey, request, response, nBuckets)

     ....

                                  token
                            ------------------->

                    hiddenMetadata = VerifyToken(privateKey, token, nBuckets)
~~~

In the remainder of this section, we specify the TokenRequest, TokenResponse,
FinalizeToken, and VerifyToken functions that are used in this protocol.

## TokenRequest

The TokenRequest function is defined below.

~~~
Inputs:
- verifiedPublicKey:
  - Z: Element
  - C_x: Element
  - C_y: Element

Outputs:
- context:
  - r: Scalar
  - tc: Scalar
- request:
  - T: Element

Parameters:
- G: Group

def TokenRequest(client):
  r = G.RandomScalar()
  tc = G.RandomScalar()
  T = (r * G.GeneratorG()) + (tc * verifiedPublicKey.Z)
  return context(r, tc), request(T)
~~~

The output `request` from this function is wire-encoded into `Nrequest=Ne` bytes as follows:

~~~
struct {
  uint8 T_enc[Ne];
}
~~~

The `T_enc` field is the serialized representation of `request.T`.

## TokenResponse

The TokenResponse function is defined below.

~~~ pseudocode
Inputs:
- privateKey:
  - x: Scalar
  - y: Scalar
  - z: Scalar
  - r_x: Scalar
  - r_y: Scalar
- publicKey:
  - Z: Element
  - C_x: Element
  - C_y: Element
- request:
  - T: Element
- hiddenMetadata: Integer
- nBuckets: Integer

Outputs:
- response:
  - U: Element
  - V: Element
  - ts: Scalar
  - pi: IssuanceProof

Parameters:
- G: Group

def TokenResponse(privateKey, publicKey, request, hiddenMetadata, nBuckets):
  ts = G.RandomScalar()
  d = G.RandomNonzeroScalar()

  U = d * G.GeneratorG()
  X = privateKey.x * GeneratorG()
  Y = privateKey.y * GeneratorG()
  V = d * (X + (hiddenMetadata * Y) + (ts * publicKey.Z) + request.T)

  pi = CreateIssuanceProof(privateKey, publicKey, hiddenMetadata, nBuckets, d, U, V, ts, T)

  return response(U, V, ts, pi)
~~~

The output `response` from this function is wire-encoded into `Nresponse=Ne+Ne+Ns+Nproof` bytes as follows:

~~~
struct {
  uint8 U_enc[Ne];
  uint8 V_enc[Ne];
  uint8 ts_enc[Ns];
  uint8 pi_enc[Nproof];
}
~~~

The `U_enc`, `V_enc`, and `ts_enc` fields are the serialized representations
of `response.U`, `response.V`, and `response.ts`, respectively.
The `pi_enc` field is the serialized IssuanceProof, as defined below.

The CreateIssuanceProof function is defined below.

~~~ pseudocode
Inputs:
- privateKey:
  - x: Scalar
  - y: Scalar
  - z: Scalar
  - r_x: Scalar
  - r_y: Scalar
- publicKey:
  - Z: Element
  - C_x: Element
  - C_y: Element
- hiddenMetadata: Integer
- nBuckets: Integer
- d: Scalar
- U: Element
- V: Element
- ts: Scalar
- T: Element

Output:
- pi: IssuanceProof
  - C: Element
  - e: [Scalar]
  - a: [Scalar]
  - a_d: Scalar
  - a_rho: Scalar
  - a_w: Scalar

Parameters:
- G: Group

def CreateIssuanceProof(privateKey, publicKey, hiddenMetadata, nBuckets, d, U, V, ts, T):
  e_vec = [G.RandomScalar() for i in range(nBuckets)]
  e_vec[hiddenMetadata] = Scalar(0) # zero for now - will be calculated and set later.
  a_vec = [G.RandomScalar() for i in range(nBuckets)]
  a_vec[hiddenMetadata] = Scalar(0) # zero for now - will be calculated and set later.
  r_mu = G.RandomScalar()
  r_d = G.RandomScalar()
  r_rho = G.RandomScalar()
  r_w = G.RandomScalar()
  mu = G.RandomScalar()

  C = hiddenMetadata * publicKey.C_y + mu * G.GeneratorH()
  C_vec = []
  for i in range(nBuckets):
    if i == hiddenMetadata:
      # This is the actual C[i] value for the "correct" slot (i == hiddenMetadata)
      C_vec.append(r_mu * G.GeneratorH())
    else:
      # This is the simulated C[i] value for the "incorrect" slot (i != hiddenMetadata)
      C_vec.append(a_vec[i] * G.GeneratorH() - e_vec[i] * (C - (i * pk.C_y)))
  C_d = r_d * U
  C_rho = (r_d * V) + (r_rho * G.GeneratorH())
  C_w = (r_d * V) + (r_w * G.GeneratorG())

  ser_genG = G.SerializeElement(G.GeneratorG())
  ser_genH = G.SerializeElement(G.GeneratorH())
  ser_C_x = G.SerializeElement(publicKey.C_x)
  ser_C_y = G.SerializeElement(publicKey.C_y)
  ser_Z = G.SerializeElement(publicKey.Z)
  ser_U = G.SerializeElement(U)
  ser_V = G.SerializeElement(V)
  ser_ts = G.SerializeScalar(ts)
  ser_T = G.SerializeElement(T)
  ser_C = G.SerializeElement(C)
  ser_C_d = G.SerializeElement(C_d)
  ser_C_rho = G.SerializeElement(C_rho)
  ser_C_w = G.SerializeElement(C_w)

  challenge_transcript = \
    I2OSP(len(ser_genG), 2) + ser_genG + \
    I2OSP(len(ser_genH), 2) + ser_genH + \
    I2OSP(len(ser_C_x), 2) + ser_C_x + \
    I2OSP(len(ser_C_y), 2) + ser_C_y + \
    I2OSP(len(ser_Z), 2) + ser_Z + \
    I2OSP(len(ser_U), 2) + ser_U + \
    I2OSP(len(ser_V), 2) + ser_V + \
    I2OSP(len(ser_ts), 2) + ser_ts + \
    I2OSP(len(ser_T), 2) + ser_T + \
    I2OSP(len(ser_C), 2) + ser_C
  for i in range(nBuckets):
    ser_C_i = G.SerializeElement(C_vec[i])
    challenge_transcript.append(I2OSP(len(ser_C_i), 2) + ser_C_i)
  challenge_transcript.append( \
    I2OSP(len(ser_C_d), 2) + ser_C_d + \
    I2OSP(len(ser_C_rho), 2) + ser_C_rho + \
    I2OSP(len(ser_C_w), 2) + ser_C_w
  )

  e = G.HashToScalar(challenge_transcript, "TokenResponseProof")
  # Set the correct e_vec[hiddenMetadata] value.
  e_vec[hiddenMetadata] = e - sum(e_vec)

  d_inv = G.ScalarInverse(d)
  rho = -(privateKey.r_x + (hiddenMetadata * privateKey.r_y) + mu)
  w = privateKey.x + (hiddenMetadata * privateKey.y) + (ts * privateKey.z)

  # Set the correct a_vec[hiddenMetadata] value.
  a_vec[hiddenMetadata] = r_mu + (e_vec[hiddenMetadata] * mu)
  a_d = r_d - (e * d_inv)
  a_rho = r_rho + (e * rho)
  a_w = r_w + (e * w)

  return IssuanceProof(C, e_vec, a_vec, a_d, a_rho, a_w)
~~~

The output `pi` from this function is wire-encoded into `Nproof = Ne+(3+2*nBuckets)*Ns` bytes as follows:

~~~
struct {
  uint8 C_enc[Ne];
  [uint8] e_0_enc[Ns]...e_nBuckets_enc[Ns];
  [uint8] a_0_enc[Ns]...a_nBuckets_enc[Ns];
  uint8 a_d_enc[Ns];
  uint8 a_rho_enc[Ns];
  uint8 a_w_enc[Ns];
}
~~~

The fields in this structure are the serialized representations of the contents of `pi`,
e.g., `C_enc` is the serialized representation of `pi.C` and `e_0_enc` is the serialized representation of `e[0]`.

### FinalizeToken

The FinalizeToken function is defined below. Internally, the client
verifies the token response proof. FinalizeToken fails if this proof
is invalid.

~~~
Inputs:
- context:
  - r: Scalar
  - tc: Scalar
- verifiedPublicKey:
  - Z: Element
  - C_x: Element
  - C_y: Element
- request:
  - T: Element
- response:
  - U: Element
  - V: Element
  - ts: Scalar
  - pi: IssuanceProof
- nBuckets: Integer

Outputs:
- token:
  - t: Scalar
  - P: Element
  - Q: Element

Parameters:
- G: Group

Exceptions:
- VerifyError, raised when response proof verification fails

def FinalizeToken(context, verifiedPublicKey, request, response, nBuckets):
  if VerifyIssuanceProof(verifiedPublicKey, request, response, nBuckets) == false:
    raise VerifyError

  c = G.RandomNonzeroScalar()
  P = c * response.U
  Q = c * (response.V - (context.r * response.U))
  t = context.tc + response.ts

  return token(t, P, Q)
~~~

The resulting token can be serialized as the concatenation of `t`, `P`,
and `Q` serialized using their respective serialization functions, yielding
the following struct:

~~~
struct {
  uint8 t_enc[Ns];
  uint8 P_enc[Ne];
  uint8 Q_enc[Ne];
}
~~~

The VerifyIssuanceProof function is defined below.

~~~ pseudocode
Inputs:
- publicKey:
  - Z: Element
  - C_x: Element
  - C_y: Element
- T: Element
- response:
  - U: Element
  - V: Element
  - ts: Scalar
  - pi: IssuanceProof
- nBuckets: Integer

Output:
- True if valid, false otherwise

Parameters:
- G: Group

def VerifyIssuanceProof(publicKey, T, response, nBuckets):
  pi = response.pi

  C_vec = []
  for i in range(nBuckets):
    C_i = pi.a_vec[i] * G.GeneratorH - (pi.e_vec[i] * (pi.C - (i * publicKey.C_y))

  e = sum(pi.e_vec)

  C_d = (response.pi.a_d * response.U) + (e * G.GeneratorG())

  C_rho = (response.pi.a_d * response.V)
      + (response.pi.a_rho * G.GeneratorH())
      + (e * (publicKey.C_x + response.pi.C + (response.ts * publicKey.Z) + T))

  C_w = (response.pi.a_d * response.V)
      + (response.pi.a_w * G.GeneratorG())
      + (e * T)

  ser_genG = G.SerializeElement(G.GeneratorG())
  ser_genH = G.SerializeElement(G.GeneratorH())
  ser_C_x = G.SerializeElement(publicKey.C_x)
  ser_C_y = G.SerializeElement(publicKey.C_y)
  ser_Z = G.SerializeElement(publicKey.Z)
  ser_U = G.SerializeElement(response.U)
  ser_V = G.SerializeElement(response.V)
  ser_ts = G.SerializeScalar(response.ts)
  ser_T = G.SerializeElement(T)
  ser_C = G.SerializeElement(pi.C)
  ser_C_d = G.SerializeElement(C_d)
  ser_C_rho = G.SerializeElement(C_rho)
  ser_C_w = G.SerializeElement(C_w)

  challenge_transcript = \
    I2OSP(len(ser_genG), 2) + ser_genG + \
    I2OSP(len(ser_genH), 2) + ser_genH + \
    I2OSP(len(ser_C_x), 2) + ser_C_x + \
    I2OSP(len(ser_C_y), 2) + ser_C_y + \
    I2OSP(len(ser_Z), 2) + ser_Z + \
    I2OSP(len(ser_U), 2) + ser_U + \
    I2OSP(len(ser_V), 2) + ser_V + \
    I2OSP(len(ser_ts), 2) + ser_ts + \
    I2OSP(len(ser_T), 2) + ser_T + \
    I2OSP(len(ser_C), 2) + ser_C + \
  for i in range(nBuckets):
    ser_C_i = G.SerializeElement(pi.C_vec[i])
    challenge_transcript.append(I2OSP(len(ser_C_i), 2) + ser_C_i)
  challenge_transcript.append( \
    I2OSP(len(ser_C_d), 2) + ser_C_d + \
    I2OSP(len(ser_C_rho), 2) + ser_C_rho + \
    I2OSP(len(ser_C_w), 2) + ser_C_w
  )

  e_verify = G.HashToScalar(challenge_transcript, "TokenResponseProof")
  return e == e_verify
~~~

### VerifyToken

The VerifyToken token is defined below.

~~~
Inputs:
- privateKey:
  - x: Scalar
  - y: Scalar
  - z: Scalar
  - r_x: Scalar
  - r_y: Scalar
- token:
  - t: Scalar
  - P: Element
  - Q: Element
- nBuckets: Integer

Outputs:
- hiddenMetadata: Integer

Parameters:
- G: Group

Exceptions:
- VerifyError, raised when token verification fails

def VerifyToken(privateKey, token, nBuckets):
  if (token.P == token.P + token.P) || (token.Q == token.Q + token.Q):
    raise VerifyError # P and Q should not be zero

  iMatch = -1
  for i in range(nBuckets):
    Q_i = (privateKey.x + token.t * privateKey.z + i * privateKey.y) * token.P
    if token.Q == Q_i:
      if iMatch != -1:
        raise VerifyError # Multiple metadata values match
      iMatch = i

  if iMatch != -1:
    return iMatch
  else:
    raise VerifyError # No metadata values match
~~~

# Security Considerations

TODO

# IANA Considerations

This document has no IANA actions.

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.

# Test Vectors
{:numbered="false"}

[[TODO: update these test vectors to use P256 instead of P384, using the new multi-bit protocol. Also add an allVectors.txt file and link to that here.]]

This section contains test vectors for the ATHM ciphersuites specified in this document.

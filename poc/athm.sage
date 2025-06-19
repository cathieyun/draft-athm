from sagelib.athm_proofs import KeyCommitmentProof, Proof
from sagelib.athm_groups import G, GenG, GenH
from util import to_hex

class Token(object):
    def __init__(self, t, P, Q, c):
        self.t = t
        self.P = P
        self.Q = Q
        self.c = c
        self._vectors = {}
        self._vectors["c"] = to_hex(G.serialize_scalar(self.c))
        self._vectors["t"] = to_hex(G.serialize_scalar(self.t))
        self._vectors["P"] = to_hex(G.serialize(self.P))
        self._vectors["Q"] = to_hex(G.serialize(self.Q))

    def vectors(self):
        return self._vectors

    def serialize(self):
        return G.serialize_scalar(self.t) + \
            G.serialize(self.P) + \
            G.serialize(self.Q)

class TokenRequest(object):
    def __init__(self, t_big):
        self.t_big = t_big

    def serialize(self):
        return G.serialize(self.t_big)

class TokenRequestContext(object):
    def __init__(self, issuer_key, t_big, r, tc, rng):
        self.issuer_key = issuer_key
        self.t_big = t_big
        self.r = r
        self.tc = tc
        self.rng = rng

    def public(self):
        return TokenRequest(self.t_big)

    def finalize_token(self, token_response):
        if token_response.U == G.identity():
            raise Exception("invalid response")
        
        if not Proof.verify(self.issuer_key, self.t_big, token_response):
            raise Exception("invalid proof")
        
        c = G.random_nonzero_scalar(self.rng)
        P = c * token_response.U
        Q = c * (token_response.V - (self.r * token_response.U))
        t = self.tc + token_response.ts

        token = Token(t, P, Q, c)
        return token

class TokenResponse(object):
    def __init__(self, U, V, ts, pi):
        self.U = U
        self.V = V
        self.ts = ts
        self.pi = pi

    def serialize(self):
        return G.serialize(self.U) + G.serialize(self.V) + G.serialize_scalar(self.ts) + self.pi.serialize()

class Client(object):
    def __init__(self, issuer_key, rng):
        assert(KeyCommitmentProof.verify(issuer_key))

        self.issuer_key = issuer_key
        self.rng = rng
        self._vectors = {}

    def vectors(self):
        return self._vectors

    def request(self):
        r = G.random_scalar(self.rng)
        tc = G.random_scalar(self.rng)
        T = (r * GenG) + (tc * self.issuer_key.Z)

        context = TokenRequestContext(self.issuer_key, T, r, tc, self.rng)

        self._vectors["r"] = to_hex(G.serialize_scalar(r))
        self._vectors["tc"] = to_hex(G.serialize_scalar(tc))
        self._vectors["T"] = to_hex(G.serialize(T))

        return context

class IssuerPublicKey(object):
    def __init__(self, Z, C_x, C_y, pi):
        self.Z = Z
        self.C_x = C_x
        self.C_y = C_y
        self.pi = pi

    def vectors(self):
        return {
            "Z": to_hex(G.serialize(self.Z)),
            "C_x": to_hex(G.serialize(self.C_x)),
            "C_y": to_hex(G.serialize(self.C_y)),
            "pi": to_hex(self.pi.serialize()),
        }

    def serialize(self):
        return to_hex(G.serialize(self.Z)) + \
            to_hex(G.serialize(self.C_x)) + \
            to_hex(G.serialize(self.C_y)) + \
            to_hex(self.pi.serialize())

class IssuerPrivateKey(object):
    def __init__(self, x, y, z, r_x, r_y, X, Y):
        self.x = x
        self.y = y
        self.z = z
        self.r_x = r_x
        self.r_y = r_y
        self.X = X
        self.Y = Y

    def vectors(self):
        return {
            "x": to_hex(G.serialize_scalar(self.x)),
            "y": to_hex(G.serialize_scalar(self.y)),
            "z": to_hex(G.serialize_scalar(self.z)),
            "r_x": to_hex(G.serialize_scalar(self.r_x)),
            "r_y": to_hex(G.serialize_scalar(self.r_y)),
        }

    def serialize(self):
        return to_hex(G.serialize_scalar(self.x)) + \
            to_hex(G.serialize_scalar(self.y)) + \
            to_hex(G.serialize_scalar(self.z)) + \
            to_hex(G.serialize_scalar(self.r_x)) + \
            to_hex(G.serialize_scalar(self.r_y))

class Issuer(object):
    def keygen(self, rng):
        x = G.random_scalar(rng)
        y = G.random_scalar(rng)
        z = G.random_scalar(rng)
        r_x = G.random_scalar(rng)
        r_y = G.random_scalar(rng)

        X = x * GenG
        Y = y * GenG
        Z = z * GenG
        C_x = (x * GenG) + (r_x * GenH)
        C_y = (y * GenG) + (r_y * GenH)

        pi = KeyCommitmentProof(z, Z, rng)

        return IssuerPrivateKey(x, y, z, r_x, r_y, X, Y), IssuerPublicKey(Z, C_x, C_y, pi)

    def __init__(self, rng):
        self.private_key, self.public_key = self.keygen(rng)
        self.rng = rng
        self._vectors = {}

        self._vectors["private_key"] = self.private_key.vectors()
        self._vectors["public_key"] = self.public_key.vectors()

    def vectors(self):
        return self._vectors

    def issue(self, token_request, metadata_bit):
        assert(metadata_bit == 0 or metadata_bit == 1)
        scalar_b = int(metadata_bit)

        ts = G.random_scalar(self.rng)
        d = G.random_nonzero_scalar(self.rng)
        
        U = d * GenG
        V = d * (self.private_key.X + (scalar_b * self.private_key.Y) + (ts * self.public_key.Z) + token_request.t_big)

        pi = Proof(scalar_b, d, self.private_key, U, V, ts, self.public_key, token_request.t_big, self.rng)
        response = TokenResponse(U, V, ts, pi)

        self._vectors["ts"] = to_hex(G.serialize_scalar(ts))
        self._vectors["d"] = to_hex(G.serialize_scalar(d))
        self._vectors["U"] = to_hex(G.serialize(U))
        self._vectors["V"] = to_hex(G.serialize(V))
        self._vectors["pi"] = to_hex(pi.serialize())

        return response

class Origin(object):
    def __init__(self, private_key):
        self.private_key = private_key

    def verify_token(self, token):
        false_scalar = self.private_key.x + (token.t * self.private_key.z)
        true_scalar = false_scalar + self.private_key.y
        false_point = false_scalar * token.P
        true_point = true_scalar * token.P

        is_true = true_point == token.Q
        is_false = false_point == token.Q

        if not (is_true ^^ is_false):
            raise Exception("invalid token")
        
        return is_true


from sagelib.athm_groups import G, GenG, GenH, hash_to_scalar
from hash_to_field import I2OSP
from util import to_hex, to_bytes

class KeyCommitmentProof(object):
    def __init__(self, z, Z, rng):
        rho_z = G.random_scalar(rng)
        gamma_big_z = rho_z * GenG

        ser_genG = G.serialize(GenG)
        ser_Z = G.serialize(Z)
        ser_gamma_big_z = G.serialize(gamma_big_z)

        challenge_transcript = \
            I2OSP(len(ser_genG), 2) + ser_genG + \
            I2OSP(len(ser_Z), 2) + ser_Z + \
            I2OSP(len(ser_gamma_big_z), 2) + ser_gamma_big_z
        
        challenge = hash_to_scalar(challenge_transcript, to_bytes("KeyCommitments"))
        a_z = rho_z - (challenge * z)

        self.challenge = challenge
        self.a_z = a_z

    def vectors(self):
        return {
            "challenge": to_hex(G.serialize_scalar(self.challenge)),
            "a_z": to_hex(G.serialize_scalar(self.a_z)),
        }

    def serialize(self):
        return G.serialize_scalar(self.challenge) + G.serialize_scalar(self.a_z)

    @classmethod
    def verify(cls, pk):
        gamma_big_z = (pk.pi.challenge * pk.Z) + (pk.pi.a_z * GenG)

        ser_genG = G.serialize(GenG)
        ser_Z = G.serialize(pk.Z)
        ser_gamma_big_z = G.serialize(gamma_big_z)

        challenge_transcript = \
            I2OSP(len(ser_genG), 2) + ser_genG + \
            I2OSP(len(ser_Z), 2) + ser_Z + \
            I2OSP(len(ser_gamma_big_z), 2) + ser_gamma_big_z

        challenge_verify = hash_to_scalar(challenge_transcript, to_bytes("KeyCommitments"))
        return pk.pi.challenge == challenge_verify

class Proof(object):
    def __init__(self, scalar_b, d, sk, U, V, ts, pk, T, rng):
        e_one_minus_b = G.random_scalar(rng)
        a_one_minus_b = G.random_scalar(rng)
        r_mu = G.random_scalar(rng)
        r_d = G.random_scalar(rng)
        r_rho = G.random_scalar(rng)
        r_w = G.random_scalar(rng)

        mu = G.random_nonzero_scalar(rng)
        C = (scalar_b * pk.C_y) + (mu * GenH)

        C_b = r_mu * GenH
        C_one_minus_b = (a_one_minus_b * GenH) - (e_one_minus_b * (C - ((1 - scalar_b) * pk.C_y)))
        
        C_d = r_d * U
        C_rho = (r_d * V) + (r_rho * GenH)
        C_w = (r_d * V) + (r_w * GenG)

        C_zero = C_b
        C_one = C_one_minus_b
        if scalar_b != int(0):
            C_zero = C_one_minus_b
            C_one = C_b

        ser_genG = G.serialize(GenG)
        ser_genH = G.serialize(GenH)
        ser_C_x = G.serialize(pk.C_x)
        ser_C_y = G.serialize(pk.C_y)
        ser_Z = G.serialize(pk.Z)
        ser_U = G.serialize(U)
        ser_V = G.serialize(V)
        ser_ts = G.serialize_scalar(ts)
        ser_T = G.serialize(T)
        ser_C = G.serialize(C)
        ser_C_zero = G.serialize(C_zero)
        ser_C_one = G.serialize(C_one)
        ser_C_d = G.serialize(C_d)
        ser_C_rho = G.serialize(C_rho)
        ser_C_w = G.serialize(C_w)

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
            I2OSP(len(ser_C_zero), 2) + ser_C_zero + \
            I2OSP(len(ser_C_one), 2) + ser_C_one + \
            I2OSP(len(ser_C_d), 2) + ser_C_d + \
            I2OSP(len(ser_C_rho), 2) + ser_C_rho + \
            I2OSP(len(ser_C_w), 2) + ser_C_w

        e = hash_to_scalar(challenge_transcript, to_bytes("TokenResponseProof"))
        e_b = e - e_one_minus_b

        d_inv = inverse_mod(d, G.order())
        rho = -(sk.r_x + (scalar_b * sk.r_y) + mu)
        w = sk.x + (scalar_b * sk.y) + (ts * sk.z)

        a_b = r_mu + (e_b * mu)
        a_d = r_d - (e * d_inv)
        a_rho = r_rho + (e * rho)
        a_w = r_w + (e * w)

        e_zero = e_b
        e_one = e_one_minus_b
        a_zero = a_b
        a_one = a_one_minus_b
        if scalar_b != int(0):
            e_zero = e_one_minus_b
            e_one = e_b
            a_zero = a_one_minus_b
            a_one = a_b

        self.C = C
        self.e_zero = e_zero
        self.e_one = e_one
        self.a_zero = a_zero
        self.a_one = a_one
        self.a_d = a_d
        self.a_rho = a_rho
        self.a_w = a_w

    def serialize(self):
        return G.serialize(self.C) + \
            G.serialize_scalar(self.e_zero) + \
            G.serialize_scalar(self.e_one) + \
            G.serialize_scalar(self.a_zero) + \
            G.serialize_scalar(self.a_one) + \
            G.serialize_scalar(self.a_d) + \
            G.serialize_scalar(self.a_rho) + \
            G.serialize_scalar(self.a_w)

    @classmethod
    def verify(cls, pk, T, token_response):
        C_zero = (token_response.pi.a_zero * GenH) - (token_response.pi.e_zero * token_response.pi.C)
        C_one = (token_response.pi.a_one * GenH) - (token_response.pi.e_one * (token_response.pi.C - pk.C_y))

        e = token_response.pi.e_zero + token_response.pi.e_one

        C_d = (token_response.pi.a_d * token_response.U) + (e * GenG)

        C_rho = (token_response.pi.a_d * token_response.V) \
            + (token_response.pi.a_rho * GenH) \
            + (e * (pk.C_x + token_response.pi.C + (token_response.ts * pk.Z) + T))

        C_w = (token_response.pi.a_d * token_response.V) \
            + (token_response.pi.a_w * GenG) \
            + (e * T)

        ser_genG = G.serialize(GenG)
        ser_genH = G.serialize(GenH)
        ser_C_x = G.serialize(pk.C_x)
        ser_C_y = G.serialize(pk.C_y)
        ser_Z = G.serialize(pk.Z)
        ser_U = G.serialize(token_response.U)
        ser_V = G.serialize(token_response.V)
        ser_ts = G.serialize_scalar(token_response.ts)
        ser_T = G.serialize(T)
        ser_C = G.serialize(token_response.pi.C)
        ser_C_zero = G.serialize(C_zero)
        ser_C_one = G.serialize(C_one)
        ser_C_d = G.serialize(C_d)
        ser_C_rho = G.serialize(C_rho)
        ser_C_w = G.serialize(C_w)

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
            I2OSP(len(ser_C_zero), 2) + ser_C_zero + \
            I2OSP(len(ser_C_one), 2) + ser_C_one + \
            I2OSP(len(ser_C_d), 2) + ser_C_d + \
            I2OSP(len(ser_C_rho), 2) + ser_C_rho + \
            I2OSP(len(ser_C_w), 2) + ser_C_w

        e_verify = hash_to_scalar(challenge_transcript, to_bytes("TokenResponseProof"))
        return e_verify == e
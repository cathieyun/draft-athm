#!/usr/bin/sage
# vim: syntax=python

import sys
import json

try:
    from sagelib.test_drng import TestDRNG
    from sagelib.athm import Client, Issuer, Origin
    from sagelib.athm_groups import suite_identifier
    from util import to_hex
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

def wrap_write(fh, arg, *args):
    line_length = 68
    string = " ".join( [arg] + list(args))
    for hunk in (string[0+i:line_length+i] for i in range(0, len(string), line_length)):
        if hunk and len(hunk.strip()) > 0:
            fh.write(hunk + "\n")

def write_blob(fh, name, blob):
    wrap_write(fh, name + ' = ' + to_hex(blob))

def write_value(fh, name, value):
    wrap_write(fh, name + ' = ' + value)

def main(path="vectors"):
    rng = TestDRNG("seed".encode('utf-8'))

    vectors = []
    for metadata_bit in [False, True]:
        issuer = Issuer(rng)
        origin = Origin(issuer.private_key)
        client = Client(issuer.public_key, rng)

        request_context = client.request()
        token_request = request_context.public()
        token_response = issuer.issue(token_request, metadata_bit)
        token = request_context.finalize_token(token_response)

        token_bit = origin.verify_token(token)
        assert(token_bit == metadata_bit)

        vectors.append({
            "metadata": metadata_bit,
            "suite": str(suite_identifier),
            "issuer": issuer.vectors(),
            "client": client.vectors(),
            "token": token.vectors(),
        })

    with open(path + "/allVectors.json", 'wt') as f:
        json.dump(vectors, f, sort_keys=True, indent=2)
        f.write("\n")

if __name__ == "__main__":
    main()

from sagelib.groups import GroupP256
from util import to_bytes

G = GroupP256()

version_identifier = "ATHMV1-"
deployment_id = "4-test_vector_deployment_id"

def create_context_string(identifier):
  return version_identifier + identifier + deployment_id

suite_identifier = create_context_string("P256-")

def hash_to_group(x, info):
    dst = to_bytes("HashToGroup-") + to_bytes(suite_identifier) + info
    return G.hash_to_group(x, dst)

def hash_to_scalar(x, info):
    dst = to_bytes("HashToScalar-") + to_bytes(suite_identifier) + info
    return G.hash_to_scalar(x, dst)

GenG = G.generator()
GenH = hash_to_group(G.serialize(GenG), to_bytes("generatorH"))

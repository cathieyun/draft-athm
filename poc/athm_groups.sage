from sagelib.groups import GroupP384
from util import to_bytes

G = GroupP384()

version_identifier = "ATHMV1-"

def create_context_string(identifier):
  return version_identifier + identifier

suite_identifier = create_context_string("P384-SHA384-")

def hash_to_group(x, info):
    dst = to_bytes("HashToGroup-") + to_bytes(suite_identifier) + info
    return G.hash_to_group(x, dst)

def hash_to_scalar(x, info):
    dst = to_bytes("HashToScalar-") + to_bytes(suite_identifier) + info
    return G.hash_to_scalar(x, dst)

GenG = G.generator()
GenH = hash_to_group(G.serialize(GenG), to_bytes("generatorH"))

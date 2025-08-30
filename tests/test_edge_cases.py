import pytest
from sabotage import MerkleTree, verify_inclusion

def test_odd_leaf_duplication_and_all_targets():
    # 5 leaves to force duplication
    hexes = [
        "00"*32, "01"*32, "02"*32, "03"*32, "04"*32
    ]
    leaves = [bytes.fromhex(h) for h in hexes]
    t = MerkleTree(leaves)
    p = t.generate_proof(leaves)  # all leaves as targets → full expansion
    assert verify_inclusion(leaves, t.root, p)

def test_empty_tree_rejected():
    with pytest.raises(RuntimeError):
        MerkleTree([])  # merkle_root() would fail; ensure you guard usage

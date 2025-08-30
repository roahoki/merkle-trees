# Most of the code is taken from Jimmy Song's book 'Programming Bitcoin'
# All trees are constructed with hashes only, and not the raw data
# If you want to implement them with raw data, you just add one extra level

# ============================================================
# STEP 1 — PROJECT SCAFFOLD & DOCS (roadmap notes)
# ------------------------------------------------------------
# Docs:
# - docs/00_glossary.md
# - docs/01_merkle_basics.md
# - docs/02_partial_merkle_proof.md
# - docs/03_sorted_tree_non_inclusion.md
# - docs/04_decisiones_implementacion.md
# - docs/05_casos_prueba.md
#
# In code, we'll add:
# - CLI switch to test either the provided fixture or your generated proof
# - Clean helpers that avoid mutation
# ============================================================

from hash import *
import math
from typing import List, Tuple
import argparse
import sys

# ---------------------------
# Helpers (non-mutating)
# ---------------------------

def merkle_parent(hash1: bytes, hash2: bytes) -> bytes:
    """Takes two binary hashes and returns hash256"""
    return hash256(hash1 + hash2)

def _build_levels(leaves: List[bytes]) -> List[List[bytes]]:
    """Build all levels without mutating inputs.
       Returns levels with levels[0]=[root], levels[-1]=leaves."""
    if not leaves:
        raise ValueError("Empty leaves :(")
    cur = leaves[:]  # copy
    all_levels = [cur]
    while len(cur) > 1:
        nxt = []
        for i in range(0, len(cur), 2):
            left = cur[i]
            right = cur[i + 1] if i + 1 < len(cur) else cur[i]  # duplicate last
            nxt.append(merkle_parent(left, right))
        cur = nxt
        all_levels.append(cur)
    return list(reversed(all_levels))  # root level first

def _leaf_range(total_leaves: int, depth: int, index: int, max_depth: int) -> Tuple[int, int]:
    """Return [start, end) leaf indices covered by node (depth, index)."""
    width = 1 << (max_depth - depth)
    start = index * width
    end = min(start + width, total_leaves)
    return start, end

def merkle_parent_level(hashes: List[bytes]) -> List[bytes]:
    """Mutating parent-level builder (kept for compatibility)."""
    if len(hashes) == 1:
        raise RuntimeError('Cannot take a parent level with only 1 item')
    switch = 0
    if len(hashes) % 2 == 1:
        switch = 1
        hashes.append(hashes[-1])
    parent_level = []
    for i in range(0, len(hashes), 2):
        parent = merkle_parent(hashes[i], hashes[i + 1])
        parent_level.append(parent)
    if switch == 1:
        hashes.pop(-1)
    return parent_level

def merkle_root(hashes: List[bytes]) -> bytes:
    """Return Merkle root from a list of binary hashes."""
    current_level = hashes[:]
    while len(current_level) > 1:
        current_level = merkle_parent_level(current_level)
    return current_level[0]

class MerkleProof:
    """Container for Bitcoin-style partial merkle proof (flags + hashes).
       `meta` is optional and used for non-inclusion (neighbors, splits)."""
    def __init__(self, hashesOfInterest, nrLeaves=None, flags=None, hashes=None, meta=None):
        self.hashesOfInterest = hashesOfInterest
        self.nrLeaves = nrLeaves
        self.flags = flags
        self.hashes = hashes
        self.meta = meta or {}

# Unordered
class MerkleTree:
    """Full Merkle tree; hashes are the ordered leaves."""
    def __init__(self, hashes: List[bytes]):
        self.hashes = hashes
        self.root = merkle_root(hashes)

    def __str__(self) -> str:
        # NOTE: __str__ should not print; it returns a string.
        lines = []
        current_level = self.hashes[:]  # defensive copy
        # bottom level (leaves)
        leaf_line = ' '.join('None' if h is None else f'{h.hex()[:8]}...' for h in current_level)
        lines.append(leaf_line)
        # ascend to root
        while len(current_level) > 1:
            current_level = merkle_parent_level(current_level)
            line = ' '.join('None' if h is None else f'{h.hex()[:8]}...' for h in current_level)
            lines.append(line)
        # print from top to bottom
        return '\n'.join(reversed(lines))

    # ========================================================
    # STEP 3 — generate_proof(hashesOfInterest)
    # --------------------------------------------------------
    # - Validate targets are leaves
    # - Mark subtrees containing targets
    # - Preorder traversal to emit flags + minimal hashes
    # ========================================================
    def generate_proof(self, hashesOfInterest: List[bytes]) -> MerkleProof:
        """Return MerkleProof with flag bits + minimal hashes for target leaves.
           Assumes all targets are leaves; raises if any target not found."""
        n = len(self.hashes)
        if n == 0:
            raise RuntimeError("Empty tree")

        # 3.1 Validate targets & collect indices (all occurrences)
        leaves = self.hashes
        index_map = {}
        for i, h in enumerate(leaves):
            index_map.setdefault(h, []).append(i)

        target_indices: List[int] = []
        for h in hashesOfInterest:
            if h not in index_map:
                raise RuntimeError("Target not found in leaves")
            target_indices.extend(index_map[h])
        target_set = set(target_indices)

        # 3.2 Build levels
        levels = _build_levels(leaves)
        max_depth = len(levels) - 1  # 0=root, max_depth=leaves

        # 3.3 Mark subtrees containing targets
        contains = [[False] * len(level) for level in levels]
        for depth, level in enumerate(levels):
            for idx in range(len(level)):
                start, end = _leaf_range(n, depth, idx, max_depth)
                if any(k in target_set for k in range(start, end)):
                    contains[depth][idx] = True

        # 3.4 Preorder traversal to produce flags + hashes
        flags: List[int] = []
        proof_hashes: List[bytes] = []

        def right_exists(depth: int, idx: int) -> bool:
            return (idx * 2 + 1) < len(levels[depth + 1])

        def gen(depth: int, idx: int):
            if not contains[depth][idx]:
                flags.append(0)
                proof_hashes.append(levels[depth][idx])
                return
            flags.append(1)
            if depth == max_depth:
                # matching leaf
                proof_hashes.append(levels[depth][idx])
                return
            # internal node with interest → expand children
            gen(depth + 1, idx * 2)
            if right_exists(depth, idx):
                gen(depth + 1, idx * 2 + 1)
            # if right child doesn't exist, duplication is implied by verifier

        gen(0, 0)
        return MerkleProof(hashesOfInterest, nrLeaves=n, flags=flags, hashes=proof_hashes)

class PartialMerkleTree:
    """Verifier that reconstructs the root from (flags, hashes)."""
    def __init__(self, total: int):
        self.total = total
        self.max_depth = math.ceil(math.log(self.total, 2))
        self.nodes = []
        for depth in range(self.max_depth + 1):
            num_items = math.ceil(self.total / 2 ** (self.max_depth - depth))
            level_hashes = [None] * num_items
            self.nodes.append(level_hashes)
        self.current_depth = 0
        self.current_index = 0

    def __repr__(self):
        result = []
        for depth, level in enumerate(self.nodes):
            items = []
            for index, h in enumerate(level):
                short = 'None' if h is None else f'{h.hex()[:8]}...'
                if depth == self.current_depth and index == self.current_index:
                    items.insert(0, f'*{short[:-3]}*')  # show cursor (rough)
                else:
                    items.append(short)
            result.append(', '.join(items))
        return '\n'.join(result)

    def up(self):
        # reduce depth by 1 and halve the index
        self.current_depth -= 1
        self.current_index //= 2

    def left(self):
        # increase depth by 1 and double the index
        self.current_depth += 1
        self.current_index *= 2

    def right(self):
        # increase depth by 1 and double the index + 1
        self.current_depth += 1
        self.current_index = self.current_index * 2 + 1

    def root(self):
        return self.nodes[0][0]

    def set_current_node(self, value: bytes):
        self.nodes[self.current_depth][self.current_index] = value

    def get_left_node(self):
        return self.nodes[self.current_depth + 1][self.current_index * 2]

    def get_right_node(self):
        return self.nodes[self.current_depth + 1][self.current_index * 2 + 1]

    def is_leaf(self):
        return self.current_depth == self.max_depth

    def right_exists(self):
        return len(self.nodes[self.current_depth + 1]) > self.current_index * 2 + 1

    def populate_tree(self, flag_bits: List[int], hashes: List[bytes]):
        flag_bits = flag_bits[:]  # do not mutate the caller's arrays
        hashes = hashes[:]
        while self.root() is None:
            if self.is_leaf():
                flag_bits.pop(0)
                self.set_current_node(hashes.pop(0))
                self.up()
            else:
                left_hash = self.get_left_node()
                if left_hash is None:
                    if flag_bits.pop(0) == 0:
                        self.set_current_node(hashes.pop(0))
                        self.up()
                    else:
                        self.left()
                elif self.right_exists():
                    right_hash = self.get_right_node()
                    if right_hash is None:
                        self.right()
                    else:
                        self.set_current_node(merkle_parent(left_hash, right_hash))
                        self.up()
                else:
                    # duplicate left
                    self.set_current_node(merkle_parent(left_hash, left_hash))
                    self.up()
        if len(hashes) != 0:
            raise RuntimeError(f'hashes not all consumed {len(hashes)}')
        for flag_bit in flag_bits:
            if flag_bit != 0:
                raise RuntimeError('flag bits not all consumed')

# ---------------------------
# Verifiers
# ---------------------------

def verify_inclusion(hashesOfInterest: List[bytes], merkleRoot: bytes, proof: MerkleProof) -> bool:
    """Verify that hashesOfInterest belong to a Merkle tree (root = merkleRoot)."""
    tree = PartialMerkleTree(proof.nrLeaves)
    tree.populate_tree(proof.flags, proof.hashes)
    return tree.root() == merkleRoot

def verify_non_inclusion(hash_val: bytes, merkleRoot: bytes, proof: MerkleProof) -> bool:
    """Verify non-inclusion via neighbor proofs on a sorted tree.
       Strategy:
         1) Verify inclusion of left/right neighbors (if present) to the SAME root.
         2) Check ordering h is strictly between neighbors (or beyond extremes).
         3) Ensure h != neighbor(s).
    """
    if proof.meta is None:
        return False

    # 1) split concatenated flags/hashes back into neighbor subproofs
    F = proof.flags[:]
    H = proof.hashes[:]
    sf = proof.meta.get("split_flags", 0)
    sh = proof.meta.get("split_hashes", 0)

    left_flags, right_flags = F[:sf], F[sf:]
    left_hashes, right_hashes = H[:sh], H[sh:]

    ok_left = True
    ok_right = True

    # neighbors are stored in proof.hashesOfInterest (bytes) in order: [left?, right?]
    neighbors = proof.hashesOfInterest
    if len(neighbors) == 2:
        left_b, right_b = neighbors[0], neighbors[1]
    elif len(neighbors) == 1:
        # only one neighbor: either left or right depending on meta fields
        if proof.meta.get("left_hex") is not None:
            left_b, right_b = neighbors[0], None
        else:
            left_b, right_b = None, neighbors[0]
    else:
        return False  # malformed

    if left_b is not None:
        ok_left = verify_inclusion([left_b], merkleRoot,
                                   MerkleProof([left_b], nrLeaves=proof.nrLeaves,
                                               flags=left_flags, hashes=left_hashes))
    if right_b is not None:
        ok_right = verify_inclusion([right_b], merkleRoot,
                                    MerkleProof([right_b], nrLeaves=proof.nrLeaves,
                                                flags=right_flags, hashes=right_hashes))
    if not (ok_left and ok_right):
        return False

    # 2) strict ordering checks (by hex)
    h_hex = hash_val.hex()
    left_hex = proof.meta.get("left_hex")
    right_hex = proof.meta.get("right_hex")

    # h must not equal any neighbor
    if left_hex is not None and h_hex == left_hex:
        return False
    if right_hex is not None and h_hex == right_hex:
        return False

    if left_hex is not None and right_hex is not None:
        return (left_hex < h_hex < right_hex)
    elif left_hex is not None:
        # h is greater than max element → must be strictly greater than left
        return h_hex > left_hex
    elif right_hex is not None:
        # h is smaller than min element → must be strictly smaller than right
        return h_hex < right_hex
    else:
        # empty tree? not our case
        return False


# ============================================================
# STEP 4 — SortedTree (non-inclusion proof) — scaffolding
# ------------------------------------------------------------
# This will provide proofs of non-inclusion using neighbors (a,b).
# Fill in after inclusion path is solid.
# ============================================================

import bisect

class SortedTree(MerkleTree):
    """Sorted Merkle Tree to support non-inclusion proofs.
       Leaves are sorted lexicographically by hex for order proofs."""
    def __init__(self, leaves_hex):
        self.leaves_hex = sorted(leaves_hex)                 # keep for order checks
        leaves_bytes = [bytes.fromhex(h) for h in self.leaves_hex]
        super().__init__(leaves_bytes)

    def _index_of(self, h_hex: str):
        """Binary-search position of h_hex. Returns (found: bool, pos: int)."""
        pos = bisect.bisect_left(self.leaves_hex, h_hex)
        if pos < len(self.leaves_hex) and self.leaves_hex[pos] == h_hex:
            return True, pos
        return False, pos

    def proof_of_non_inclusion(self, h: bytes) -> MerkleProof:
        """Produce a non-inclusion proof using adjacent neighbors.
           If h is present, raises RuntimeError."""
        h_hex = h.hex()
        found, pos = self._index_of(h_hex)
        if found:
            raise RuntimeError("hash IS present; cannot prove non-inclusion")

        # neighbors by hex (optional at extremes)
        left_hex = self.leaves_hex[pos-1] if pos > 0 else None
        right_hex = self.leaves_hex[pos] if pos < len(self.leaves_hex) else None

        # Build inclusion proofs (flags+hashes) for the neighbors we have
        flags_concat, hashes_concat = [], []
        split_flags = split_hashes = 0

        neighbors = []
        if left_hex is not None:
            left_b = bytes.fromhex(left_hex)
            p_left = super().generate_proof([left_b])
            flags_concat += p_left.flags
            hashes_concat += p_left.hashes
            split_flags = len(flags_concat)
            split_hashes = len(hashes_concat)
            neighbors.append(left_b)

        if right_hex is not None:
            right_b = bytes.fromhex(right_hex)
            p_right = super().generate_proof([right_b])
            flags_concat += p_right.flags
            hashes_concat += p_right.hashes
            neighbors.append(right_b)

        meta = {
            "target_hex": h_hex,
            "left_hex": left_hex,
            "right_hex": right_hex,
            # boundaries to split concatenated arrays during verification
            "split_flags": split_flags,
            "split_hashes": split_hashes,
        }
        # hashesOfInterest holds the neighbor(s) we proved INCLUDED
        return MerkleProof(neighbors, nrLeaves=len(self.hashes),
                           flags=flags_concat, hashes=hashes_concat, meta=meta)


# ============================================================
# Test data (fixture from the starter)
# ============================================================

hex_hashes = [
    "9745f7173ef14ee4155722d1cbf13304339fd00d900b759c6f9d58579b5765fb",
    "5573c8ede34936c29cdfdfe743f7f5fdfbd4f54ba0705259e62f39917065cb9b",
    "82a02ecbb6623b4274dfcab82b336dc017a27136e08521091e443e62582e8f05",
    "507ccae5ed9b340363a0e6d765af148be9cb1c8766ccc922f83e4ae681658308",
    "a7a4aec28e7162e1e9ef33dfa30f0bc0526e6cf4b11a576f6c5de58593898330",
    "bb6267664bd833fd9fc82582853ab144fece26b7a8a5bf328f8a059445b59add",
    "ea6d7ac1ee77fbacee58fc717b990c4fcccf1b19af43103c090f601677fd8836",
    "457743861de496c429912558a106b810b0507975a49773228aa788df40730d41",
    "7688029288efc9e9a0011c960a6ed9e5466581abf3e3a6c26ee317461add619a",
    "b1ae7f15836cb2286cdd4e2c37bf9bb7da0a2846d06867a429f654b2e7f383c9",
    "9b74f89fa3f93e71ff2c241f32945d877281a6a50a6bf94adac002980aafe5ab",
    "b3a92b5b255019bdaf754875633c2de9fec2ab03e6b8ce669d07cb5b18804638",
    "b5c0b915312b9bdaedd2b86aa2d0f8feffc73a2d37668fd9010179261e25e263",
    "c9d52c5cb1e557b92c84c52e7c4bfbce859408bedffc8a5560fd6e35e10b8800",
    "c555bc5fc3bc096df0a0c9532f07640bfb76bfe4fc1ace214b8b228a1297a4c2",
    "f9dbfafc3af3400954975da24eb325e326960a25b87fffe23eef3e7ed2fb610e",
]
raw_hashes = [bytes.fromhex(h) for h in hex_hashes]
tree = MerkleTree(raw_hashes)

fixture_flags = [1,0,1,1,0,1,1,0,1,1,0,1,0]
fixture_hashes_hex = [
    "6382df3f3a0b1323ff73f4da50dc5e318468734d6054111481921d845c020b93",
    "3b67006ccf7fe54b6cb3b2d7b9b03fb0b94185e12d086a42eb2f32d29d535918",
    "9b74f89fa3f93e71ff2c241f32945d877281a6a50a6bf94adac002980aafe5ab",
    "b3a92b5b255019bdaf754875633c2de9fec2ab03e6b8ce669d07cb5b18804638",
    "b5c0b915312b9bdaedd2b86aa2d0f8feffc73a2d37668fd9010179261e25e263",
    "c9d52c5cb1e557b92c84c52e7c4bfbce859408bedffc8a5560fd6e35e10b8800",
    "8636b7a3935a68e49dd19fc224a8318f4ee3c14791b3388f47f9dc3dee2247d1"
]
fixture_hashes = [bytes.fromhex(h) for h in fixture_hashes_hex]

targets_hex = [
    "9b74f89fa3f93e71ff2c241f32945d877281a6a50a6bf94adac002980aafe5ab",
    "c9d52c5cb1e557b92c84c52e7c4bfbce859408bedffc8a5560fd6e35e10b8800",
]
targets = [bytes.fromhex(h) for h in targets_hex]

# ---------------------------
# CLI harness
# ---------------------------

def _tohex(arr: List[bytes]) -> List[str]:
    return [h.hex() for h in arr]

def run_fixture():
    proof = MerkleProof(targets, nrLeaves=16, flags=fixture_flags, hashes=fixture_hashes)
    ok = verify_inclusion(targets, tree.root, proof)
    print("Fixture verify_inclusion =", ok)
    if not ok:
        sys.exit(1)

def run_generated(verbose: bool = False):
    gen_proof = tree.generate_proof(targets)
    ok = verify_inclusion(targets, tree.root, gen_proof)
    print("Generated verify_inclusion =", ok)
    if verbose:
        print("nrLeaves:", gen_proof.nrLeaves)
        print("flags:", gen_proof.flags)
        print("hashes:", _tohex(gen_proof.hashes))
    if not ok:
        sys.exit(1)

def run_non_inclusion_demo():
    # pick a value not in the set: mutate one bit of an existing leaf
    candidate = bytearray(raw_hashes[0])  # reuse your test data
    candidate[0] ^= 0x01
    h = bytes(candidate)

    st = SortedTree(hex_hashes)  # sorted by hex internally
    proof = st.proof_of_non_inclusion(h)
    ok = verify_non_inclusion(h, st.root, proof)
    print("Non-inclusion demo =", ok)
    if not ok:
        sys.exit(1)


def run_both():
    run_fixture()
    run_generated(verbose=True)

# ============================================================
# STEP 2 — (docs) explain odd duplication & flags traversal
# STEP 3 — (in code) implemented generate_proof above
# STEP 4 — SortedTree + non-inclusion (TODOs placed)
# STEP 5 — verify_non_inclusion (TODO, after STEP 4)
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="Merkle Tree proof tester")
    parser.add_argument(
        "--mode",
        choices=["fixture", "generated", "both", "noninclusion"],
        default="both",
        help="fixture: use provided flags/hashes; generated: use tree.generate_proof; both: run both"
    )
    parser.add_argument("--verbose", action="store_true", help="Print proof details (generated mode)")
    args = parser.parse_args()

    if args.mode == "fixture":
        run_fixture()
    elif args.mode == "generated":
        run_generated(verbose=args.verbose)
    elif args.mode == "noninclusion":
        run_non_inclusion_demo()
    else:
        run_both()

if __name__ == "__main__":
    main()

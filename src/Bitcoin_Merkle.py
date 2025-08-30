# Most of the code is taken from Jimmy Song's book 'Programming Bitcoin'
# All trees are constructed with hashes only, and not the raw data
# If you want to implement them with raw data, you just add one extra level

from hash import *
import math

### developed functions ###
from typing import List, Tuple

def _build_levels(leaves: List[bytes]) -> List[List[bytes]]:
    """levels[0] = [root], levels[-1] = leaves (non-mutating)."""
    if not leaves:
        raise ValueError("Empty leaves")
    cur = leaves[:]  # copy
    all_levels = [cur]
    while len(cur) > 1:
        nxt = []
        for i in range(0, len(cur), 2):
            left = cur[i]
            right = cur[i+1] if i+1 < len(cur) else cur[i]  # duplicate last
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

### default functions ###

def merkle_parent(hash1, hash2):
    '''Takes the binary hashes and calculates the hash256'''
    return hash256(hash1 + hash2)

def merkle_parent_level(hashes):
    '''Takes a list of binary hashes and returns a list that's half
    the length'''
    if len(hashes) == 1:
        raise RuntimeError('Cannot take a parent level with only 1 item')
    # if the list has an odd number of elements, duplicate the last one
    # and put it at the end so it has an even number of elements
    switch = 0 # to signal if we append an extra value
    if len(hashes) % 2 == 1:
        switch = 1
        hashes.append(hashes[-1])
    # initialize next level
    parent_level = []
    # loop over every pair (use: for i in range(0, len(hashes), 2))
    for i in range(0, len(hashes), 2):
        # get the merkle parent of the hashes at index i and i+1
        parent = merkle_parent(hashes[i], hashes[i + 1])
        # append parent to parent level
        parent_level.append(parent)
    # return parent level, remove the extra stuff for consistency 
    if (switch == 1):
        hashes.pop(-1)
    return parent_level

def merkle_root(hashes):
    '''Takes a list of binary hashes and returns the merkle root
    '''
    # current level starts as hashes
    current_level = hashes
    # loop until there's exactly 1 element
    while len(current_level) > 1:
        # current level becomes the merkle parent level
        current_level = merkle_parent_level(current_level)
    # return the 1st item of the current level
    return current_level[0]

class MerkleTree:
    '''This is the full Merkle tree class
    As stated previously, we really just need to guard the hashes (ordered)
    To speed up accessing the root, we will also compute the root of the tree
    '''
    def __init__(self, hashes):
        self.hashes = hashes
        self.root = merkle_root(hashes)

    def __str__(self):
        tmp = ''
        print('\nPrinting the merkle tree level by level:')
        current_level = self.hashes[:]  # defensive copy
        # current_level = self.hashes

        items = ''

        for h in current_level:
            if (h == None):
                short = h
            else:
                short = '{}... '.format(h.hex()[:8])
            tmp = tmp + short
        items = tmp

        while len(current_level) > 1:
            tmp = ''
            current_level = merkle_parent_level(current_level)
            for h in current_level:
                if (h == None):
                    short = h
                else:
                    short = '{}... '.format(h.hex()[:8])
                tmp = tmp + short
            tmp = tmp + '\n'
            items = tmp + items
        
        return items          



    def generate_proof(self, hashesOfInterest: List[bytes]):
        
        """Return MerkleProof with flag bits + minimal hashes for the given target leaves.
        Assumes all targets are leaves; raises if any target not in self.hashes."""
        n = len(self.hashes)
        if n == 0:
            raise RuntimeError("Empty tree")
        # 1) validate + collect target indices
        #    (if duplicates appear in leaves, keep all indices)
        leaves = self.hashes
        index_map = {}
        for i, h in enumerate(leaves):
            index_map.setdefault(h, []).append(i)

        target_indices = []
        for h in hashesOfInterest:
            if h not in index_map:
                raise RuntimeError("Target not found in leaves")
            # include all occurrences of this hash
            target_indices.extend(index_map[h])

        target_set = set(target_indices)

        # 2) build levels
        levels = _build_levels(leaves)
        max_depth = len(levels) - 1  # 0 = root, max_depth = leaves

        # 3) contains_interest mask
        contains = [ [False]*len(level) for level in levels ]
        for depth, level in enumerate(levels):
            for idx in range(len(level)):
                start, end = _leaf_range(n, depth, idx, max_depth)
                # range [start, end) intersects target_set?
                if any(k in target_set for k in range(start, end)):
                    contains[depth][idx] = True

        flags: List[int] = []
        proof_hashes: List[bytes] = []

        def right_exists(depth: int, idx: int) -> bool:
            return (idx * 2 + 1) < len(levels[depth + 1])

        # 4) preorder traversal
        def gen(depth: int, idx: int):
            if not contains[depth][idx]:
                flags.append(0)
                proof_hashes.append(levels[depth][idx])
                return
            flags.append(1)
            if depth == max_depth:
                # leaf; must be a target leaf
                proof_hashes.append(levels[depth][idx])
                return
            # internal: expand children
            gen(depth + 1, idx * 2)
            if right_exists(depth, idx):
                gen(depth + 1, idx * 2 + 1)
            # if right doesn't exist, duplication is implied; nothing to append

        gen(0, 0)
        return MerkleProof(hashesOfInterest, nrLeaves=n, flags=flags, hashes=proof_hashes)

class MerkleProof:
    def __init__(self, hashesOfInterest, nrLeaves = None, flags = None, hashes = None):
        self.hashesOfInterest = hashesOfInterest
        self.nrLeaves = nrLeaves
        self.flags = flags
        self.hashes = hashes

class SortedTree:
    '''
    This will be a sorted Merkle Tree which will allow a proof of non-inclusion
    Copy/paste any method from the other classes that you will need

    '''

    def proof_of_non_inclusion(self,hash):
        '''
        HW1: Implement the function that generates a proof of non inclusion for a single hash
        !!!the hash is assumed to be a leaf of the Merkle tree!!! 
        '''
        return True

class PartialMerkleTree:

    def __init__(self, total):
        self.total = total
        # compute max depth math.ceil(math.log(self.total, 2))
        self.max_depth = math.ceil(math.log(self.total, 2))
        # initialize the nodes property to hold the actual tree
        self.nodes = []
        # loop over the number of levels (max_depth+1)
        for depth in range(self.max_depth + 1):
            # the number of items at this depth is
            # math.ceil(self.total / 2**(self.max_depth - depth))
            num_items = math.ceil(self.total / 2**(self.max_depth - depth))
            # create this level's hashes list with the right number of items
            level_hashes = [None] * num_items
            # append this level's hashes to the merkle tree
            self.nodes.append(level_hashes)
        # set the pointer to the root (depth=0, index=0)
        self.current_depth = 0
        self.current_index = 0

    def __repr__(self):
        result = []
        for depth, level in enumerate(self.nodes):
            items = []
            for index, h in enumerate(level):
                if h is None:
                    short = 'None'
                else:
                    short = '{}...'.format(h.hex()[:8])
                if depth == self.current_depth and index == self.current_index:
                    items.insert('*{}*'.format(short[:-2]))
                else:
                    items.append('{}'.format(short))
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

    def set_current_node(self, value):
        self.nodes[self.current_depth][self.current_index] = value

    def get_current_node(self):
        return self.nodes[self.current_depth][self.current_index]

    def get_left_node(self):
        return self.nodes[self.current_depth + 1][self.current_index * 2]

    def get_right_node(self):
        return self.nodes[self.current_depth + 1][self.current_index * 2 + 1]

    def is_leaf(self):
        return self.current_depth == self.max_depth

    def right_exists(self):
        return len(self.nodes[self.current_depth + 1]) > self.current_index * 2 + 1

    def populate_tree(self, flag_bits, hashes):
        # populate until we have the root
        while self.root() is None:
            # if we are a leaf, we know this position's hash
            if self.is_leaf():
                # get the next bit from flag_bits: flag_bits.pop(0)
                flag_bits.pop(0)
                # set the current node in the merkle tree to the next hash: hashes.pop(0)
                self.set_current_node(hashes.pop(0))
                # go up a level
                self.up()
            else:
                # get the left hash
                left_hash = self.get_left_node()
                # if we don't have the left hash
                if left_hash is None:
                    # if the next flag bit is 0, the next hash is our current node
                    if flag_bits.pop(0) == 0:
                        # set the current node to be the next hash
                        self.set_current_node(hashes.pop(0))
                        # sub-tree doesn't need calculation, go up
                        self.up()
                    else:
                        # go to the left node
                        self.left()
                elif self.right_exists():
                    # get the right hash
                    right_hash = self.get_right_node()
                    # if we don't have the right hash
                    if right_hash is None:
                        # go to the right node
                        self.right()
                    else:
                        # combine the left and right hashes
                        self.set_current_node(merkle_parent(left_hash, right_hash))
                        # we've completed this sub-tree, go up
                        self.up()
                else:
                    # combine the left hash twice
                    self.set_current_node(merkle_parent(left_hash, left_hash))
                    # we've completed this sub-tree, go up
                    self.up()
        if len(hashes) != 0:
            raise RuntimeError('hashes not all consumed {}'.format(len(hashes)))
        for flag_bit in flag_bits:
            if flag_bit != 0:
                raise RuntimeError('flag bits not all consumed')

def verify_inclusion(hashesOfInterest, merkleRoot, proof):
    ''' Verifies if hashesOfInterest belong to a Merkle Tree with the root merkleRoot using the proof
    '''
    leaves = proof.nrLeaves
    flags = proof.flags
    hashes = proof.hashes

    tree = PartialMerkleTree(leaves)
    tree.populate_tree(flags,hashes)

    return (tree.root() == merkleRoot)

def verify_non_inclusion(hash, merkleRoot, proof):
    '''
    The method receives a hash, a Merkle root, and a proof that hash does not belong to this Merkle root
    the proof is of type MerkleProof
    '''
    return True

	
## Data for testing:

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

flags=[1,0,1,1,0,1,1,0,1,1,0,1,0]
hashes = ["6382df3f3a0b1323ff73f4da50dc5e318468734d6054111481921d845c020b93",
"3b67006ccf7fe54b6cb3b2d7b9b03fb0b94185e12d086a42eb2f32d29d535918",
"9b74f89fa3f93e71ff2c241f32945d877281a6a50a6bf94adac002980aafe5ab",
"b3a92b5b255019bdaf754875633c2de9fec2ab03e6b8ce669d07cb5b18804638",
"b5c0b915312b9bdaedd2b86aa2d0f8feffc73a2d37668fd9010179261e25e263",
"c9d52c5cb1e557b92c84c52e7c4bfbce859408bedffc8a5560fd6e35e10b8800",
"8636b7a3935a68e49dd19fc224a8318f4ee3c14791b3388f47f9dc3dee2247d1"
]

r_hashes = [bytes.fromhex(h) for h in hashes]

hashesOfInterest = ["9b74f89fa3f93e71ff2c241f32945d877281a6a50a6bf94adac002980aafe5ab",
"c9d52c5cb1e557b92c84c52e7c4bfbce859408bedffc8a5560fd6e35e10b8800"
]

r_interest = [bytes.fromhex(h) for h in hashesOfInterest]

proof = MerkleProof(r_interest,16,flags,r_hashes)

print(verify_inclusion(r_interest, tree.root, proof))

if __name__ == "__main__":
    print("here i want to add the options to use the hardcoded provided way to test or the option to use the developed functions and actions")
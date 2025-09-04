# Key Words and Concepts

> **hash**  
A fixed-length digest produced by a hash function from arbitrary input. In Bitcoin-style Merkle trees we use **double-SHA256** (`hash256(x) = SHA256(SHA256(x))`). In code you’ll handle two common encodings:
- **bytes**: raw 32-byte values used for concatenation and hashing (e.g., `b"\x12..."`).
- **hex**: human-readable hex strings (64 chars, lowercase usually) used for logging/IO (e.g., `"9745f7..."`).  
**Rule of thumb:** do all cryptographic operations on **bytes**; convert to/from hex only at the edges.

> **flag bits**  
A preorder traversal control stream (list of bits) used to rebuild a **Partial Merkle Tree**:
- `1` (expand): “This subtree **contains** at least one match → descend into its children (or it’s a matching leaf).”
- `0` (use hash): “This subtree **does not** contain a match → do **not** descend; consume one hash from the provided list and assign it to this node.”  
During verification, the verifier walks the implicit tree guided by `flag_bits`, pulling node hashes from the provided `hashes` array when a `0` tells it a whole subtree is summarized by one hash.

> **partial merkle tree**  
A compact proof structure that contains *only* the information needed to recompute the Merkle root for a subset of leaves (“leaves of interest”). It includes:
- `flag_bits`: which nodes to expand vs. summarize.
- `hashes`: the minimal set of node hashes required to reconstruct all necessary internal nodes up to the root.  
Properties:
- Verifies inclusion of the target leaves **without** revealing all other leaves.
- Handles odd node counts by duplicating the last hash when needed (same rule as the full tree).

> **proof of non-inclusion**  
A proof that a given hash **is not** a member of a set, assuming the Merkle tree is built over **sorted leaves** (total order by hex). Standard strategy:
1. Binary-search the position of `x` among sorted leaves. If `x` isn’t present, identify its adjacent neighbors `a` (predecessor) and `b` (successor) such that `a < x < b`.  
2. Provide **authentication path(s)** (Merkle sibling hashes) for `a` and/or `b` so the verifier can recompute the same Merkle root.  
3. The verifier checks:
   - The reconstructed root(s) equal the advertised Merkle root.
   - Ordering holds (`a < x < b` in hex; single-neighbor checks for extremes).
   - `x ≠ a` and `x ≠ b`.  
If these pass, `x` cannot be in the set—there would be no place to insert it without breaking order or changing the root.

---

## ⚠️ Gotchas (Common Pitfalls)

- **Bytes vs. Hex:**  
  Always do concatenation and hashing on raw **bytes**. Only convert to **hex strings** for logging, printing, or sorting leaves in `SortedTree`. Mixing them up is the #1 source of subtle bugs.

- **Odd number of nodes:**  
  When a level has an odd count of hashes, the last one must be **duplicated** to form a pair. If you forget this, your root won’t match Bitcoin’s rules.  

  **Diagram:** (5 leaves → duplication of last leaf before hashing)  

```
Level 2 (root):       [R]
                    /     \
Level 1:         [P1]     [P2]
                 /  \     /   \
Level 0:     [L1][L2] [L3][L4] [L5][L5]

```




- `L1...L5` are leaf hashes.  
- Notice how `L5` is **duplicated** to make an even pair.  
- Then `P1 = H(L1+L2)`, `P2 = H(H(L3+L4) + H(L5+L5))`.  
- Root `R = H(P1 + P2)`.

- **Mutable lists:**  
Functions like `merkle_parent_level` in the starter code modify the input list (they `append` and later `pop`). If you reuse the same list elsewhere, you may get corrupted state. Use defensive copies (`hashes[:]`) whenever building new levels.

- **Flags/hashes alignment:**  
When generating proofs, the order in which you append to `flag_bits` and `hashes` must mirror exactly what the verifier (`populate_tree`) expects. Off-by-one errors here are super easy to introduce.

- **Sorted vs. unsorted trees:**  
Standard Merkle proofs assume leaves are in their original order. For **proof of non-inclusion**, you must first sort the leaves lexicographically by hex. If you forget to sort before building, your non-inclusion proofs are meaningless.

- **Extremes in non-inclusion:**  
When proving that a hash is smaller than the minimum or larger than the maximum leaf, you only have one neighbor. Make sure your verification code handles these edge cases explicitly.

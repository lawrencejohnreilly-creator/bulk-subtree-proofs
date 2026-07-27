"""
Reference implementation for draft-reilly-plants-bulk-subtree-proofs-00.

Implements, from first principles:
  * RFC 9162 Section 2.1 Merkle Tree Hash
  * draft-ietf-plants-merkle-tree-certs Section 4.1 subtree definition
  * draft-ietf-plants-merkle-tree-certs Section 4.5 interval covering
  * draft-ietf-plants-merkle-tree-certs Section 4.4.1 subtree consistency proof
    (generation only, used for size baselines)
  * draft-ietf-plants-merkle-tree-certs Section 6.3 landmark allocation
  * The bulk subtree consistency proof under specification

The correctness oracle for subtree hashes is direct recomputation from the log,
so the bulk verifier is never checked against another implementation of the
same idea.
"""

import hashlib
from dataclasses import dataclass, field
from typing import List, Tuple, Optional, Dict

Range = Tuple[int, int]

HASH_SIZE = 32


def HASH(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


# ---------------------------------------------------------------------------
# Integer helpers (RFC 9162 / MTC Section 2 notation)
# ---------------------------------------------------------------------------

def bit_width(n: int) -> int:
    return n.bit_length()


def bit_ceil(n: int) -> int:
    """Smallest power of two >= n."""
    if n <= 1:
        return 1
    return 1 << (n - 1).bit_length()


def largest_pow2_less(n: int) -> int:
    """Largest power of two strictly less than n. Requires n > 1."""
    assert n > 1
    return 1 << ((n - 1).bit_length() - 1)


def is_valid_subtree(start: int, end: int) -> bool:
    """MTC Section 4.1: start must be a multiple of BIT_CEIL(end - start)."""
    if not (0 <= start < end):
        return False
    return start % bit_ceil(end - start) == 0


def children_split(start: int, end: int) -> Optional[int]:
    """Index at which node [start, end) splits into its two children.

    Follows the RFC 9162 Section 2.1.1 recursion: split at the largest power
    of two strictly less than the node size.
    """
    size = end - start
    if size <= 1:
        return None
    return start + largest_pow2_less(size)


def are_siblings(a: Range, b: Range) -> bool:
    """True if a and b are exactly the two children of a valid subtree."""
    (s1, e1), (s2, e2) = a, b
    if e1 != s2:
        return False
    if not is_valid_subtree(s1, e2):
        return False
    return children_split(s1, e2) == e1


# ---------------------------------------------------------------------------
# Merkle log
# ---------------------------------------------------------------------------

class MerkleLog:
    """An append-only log of opaque entries, hashed per RFC 9162 Section 2.1."""

    def __init__(self, entries: List[bytes]):
        self.entries = list(entries)
        self._memo: Dict[Range, bytes] = {}

    @property
    def size(self) -> int:
        return len(self.entries)

    def node(self, start: int, end: int) -> bytes:
        """MTH(D[start:end]). This is the correctness oracle."""
        assert 0 <= start < end <= self.size, (start, end, self.size)
        key = (start, end)
        memo = self._memo.get(key)
        if memo is not None:
            return memo
        if end - start == 1:
            h = HASH(b"\x00" + self.entries[start])
        else:
            k = children_split(start, end)
            h = HASH(b"\x01" + self.node(start, k) + self.node(k, end))
        self._memo[key] = h
        return h

    def root(self) -> bytes:
        if self.size == 0:
            return HASH(b"")
        return self.node(0, self.size)


# ---------------------------------------------------------------------------
# MTC Section 4.5: covering an arbitrary interval with one or two subtrees
# ---------------------------------------------------------------------------

def find_subtrees(start: int, end: int) -> List[Range]:
    """Verbatim port of the procedure in MTC Section 4.5."""
    assert start < end
    if end - start == 1:
        return [(start, end)]
    last = end - 1
    split = (start ^ last).bit_length() - 1
    mask = (1 << split) - 1
    mid = last & ~mask
    left_split = (~start & mask).bit_length()
    left_start = start & ~((1 << left_split) - 1)
    return [(left_start, mid), (mid, end)]


# ---------------------------------------------------------------------------
# Frontier decomposition (draft Section 4.3)
# ---------------------------------------------------------------------------

def frontier(s: int, e: int) -> List[Range]:
    """Canonical full subtrees covering [s, e), ascending by start."""
    nodes: List[Range] = []
    while s < e:
        size = 1
        while s % (size * 2) == 0 and s + size * 2 <= e:
            size *= 2
        nodes.append((s, s + size))
        s += size
    return nodes


# ---------------------------------------------------------------------------
# MTC Section 4.4.1: subtree consistency proof generation (size baseline)
# ---------------------------------------------------------------------------

def subtree_consistency_proof(log: MerkleLog, start: int, end: int) -> List[bytes]:
    """SUBTREE_PROOF(start, end, D_n) from MTC Section 4.4.1."""
    return _subproof(log, start, end, 0, log.size, True)


def _subproof(log: MerkleLog, start: int, end: int,
              lo: int, hi: int, known: bool) -> List[bytes]:
    if start == lo and end == hi:
        return [] if known else [log.node(lo, hi)]
    mid = children_split(lo, hi)
    assert mid is not None
    if end <= mid:
        return _subproof(log, start, end, lo, mid, known) + [log.node(mid, hi)]
    if start >= mid:
        return _subproof(log, start, end, mid, hi, known) + [log.node(lo, mid)]
    # start < mid < end, which implies start == lo
    return _subproof(log, mid, end, mid, hi, False) + [log.node(lo, mid)]


# ---------------------------------------------------------------------------
# MTC Section 6.3: landmarks
# ---------------------------------------------------------------------------

@dataclass
class LandmarkSequence:
    """Landmark tree sizes, index 0 always tree size 0 (MTC Section 6.3.1)."""
    sizes: List[int] = field(default_factory=lambda: [0])
    max_active_landmarks: int = 169

    def append(self, tree_size: int) -> None:
        if tree_size > self.sizes[-1]:
            self.sizes.append(tree_size)

    @property
    def last(self) -> int:
        return len(self.sizes) - 1

    def active_indices(self) -> List[int]:
        first = max(1, self.last - self.max_active_landmarks + 1)
        return list(range(first, self.last + 1))

    def active_subtrees(self) -> List[Range]:
        """Active landmark subtrees, deduplicated, in canonical order."""
        out: List[Range] = []
        for i in self.active_indices():
            prev, cur = self.sizes[i - 1], self.sizes[i]
            if prev >= cur:
                continue
            out.extend(find_subtrees(prev, cur))
        return canonical_order(dedupe(out))


def dedupe(rs: List[Range]) -> List[Range]:
    return list(dict.fromkeys(rs))


def canonical_order(rs: List[Range]) -> List[Range]:
    """Ascending by start, ties broken by descending end (draft Section 4.2)."""
    return sorted(rs, key=lambda r: (r[0], -r[1]))


# ---------------------------------------------------------------------------
# Laminar family helpers (draft Section 3.2)
# ---------------------------------------------------------------------------

def contains(outer: Range, inner: Range) -> bool:
    return outer[0] <= inner[0] and inner[1] <= outer[1]


def properly_contains(outer: Range, inner: Range) -> bool:
    return contains(outer, inner) and outer != inner


def partially_overlaps(a: Range, b: Range) -> bool:
    lo = max(a[0], b[0])
    hi = min(a[1], b[1])
    if lo >= hi:
        return False  # disjoint
    return not (contains(a, b) or contains(b, a))


def maximal_elements(rs: List[Range]) -> List[Range]:
    """The antichain A: elements not properly contained in any other."""
    return [r for r in rs if not any(properly_contains(o, r) for o in rs)]


# ---------------------------------------------------------------------------
# Bulk subtree consistency proof
# ---------------------------------------------------------------------------

@dataclass
class NestedSubtreeProof:
    contained_in: Range
    inclusion_proof: List[bytes]


@dataclass
class BulkSubtreeProof:
    tree_size: int
    subtrees: List[Tuple[int, int, bytes]]
    left_frontier: List[bytes]
    right_frontier: List[bytes]
    nested_proofs: List[NestedSubtreeProof]

    def hash_count(self) -> int:
        """Hashes carried, excluding the subtree hashes the RP holds anyway."""
        return (len(self.left_frontier) + len(self.right_frontier)
                + sum(len(p.inclusion_proof) for p in self.nested_proofs))

    def wire_bytes(self, include_subtree_hashes: bool = False) -> int:
        n = self.hash_count() * HASH_SIZE
        if include_subtree_hashes:
            n += len(self.subtrees) * HASH_SIZE
        return n


def interior_inclusion_proof(log: MerkleLog, target: Range,
                             ancestor: Range) -> List[bytes]:
    """Sibling hashes from target up to ancestor, ordered bottom-up."""
    path: List[bytes] = []
    s, e = ancestor
    while (s, e) != target:
        m = children_split(s, e)
        if m is None:
            raise ValueError("target is not a descendant of ancestor")
        if target[1] <= m:
            path.append(log.node(m, e))
            s, e = s, m
        elif target[0] >= m:
            path.append(log.node(s, m))
            s, e = m, e
        else:
            raise ValueError("target straddles a split")
    path.reverse()
    return path


def descent_sides(target: Range, ancestor: Range) -> Optional[List[str]]:
    """Which child the target lies in at each step, bottom-up.

    Derived from ranges alone, so a verifier never trusts proof-supplied
    structure.
    """
    sides: List[str] = []
    s, e = ancestor
    while (s, e) != target:
        m = children_split(s, e)
        if m is None:
            return None
        if target[1] <= m:
            sides.append("L")
            s, e = s, m
        elif target[0] >= m:
            sides.append("R")
            s, e = m, e
        else:
            return None
    sides.reverse()
    return sides


def generate_bulk_proof(log: MerkleLog, subtrees: List[Range],
                        tree_size: Optional[int] = None) -> BulkSubtreeProof:
    if tree_size is None:
        tree_size = log.size
    subs = canonical_order(dedupe(subtrees))
    if not subs:
        raise ValueError("no subtrees")
    a = min(s for s, _ in subs)
    b = max(e for _, e in subs)
    A = maximal_elements(subs)

    left_nodes = frontier(0, a)
    right_nodes = frontier(b, tree_size)

    nested: List[NestedSubtreeProof] = []
    for r in subs:
        if r in A:
            continue
        anc = next(o for o in A if contains(o, r))
        nested.append(NestedSubtreeProof(anc, interior_inclusion_proof(log, r, anc)))

    return BulkSubtreeProof(
        tree_size=tree_size,
        subtrees=[(s, e, log.node(s, e)) for s, e in subs],
        left_frontier=[log.node(s, e) for s, e in left_nodes],
        right_frontier=[log.node(s, e) for s, e in right_nodes],
        nested_proofs=nested,
    )


@dataclass
class VerifyResult:
    ok: bool
    reason: str = ""
    stage: int = 0
    merge_steps: int = 0

    def __bool__(self) -> bool:
        return self.ok


def verify_bulk_proof(proof: BulkSubtreeProof, root_hash: bytes,
                      tree_size: int) -> VerifyResult:
    """Verify a bulk subtree consistency proof (draft Section 4.4)."""

    # ---- Stage 1: structural checks ----
    if proof.tree_size != tree_size:
        return VerifyResult(False, "tree_size mismatch", 1)
    subs = proof.subtrees
    if not subs:
        return VerifyResult(False, "empty subtree list", 1)

    ranges = [(s, e) for s, e, _ in subs]
    if ranges != canonical_order(ranges):
        return VerifyResult(False, "subtrees not in canonical order", 1)
    if len(set(ranges)) != len(ranges):
        return VerifyResult(False, "duplicate subtree", 1)

    for s, e in ranges:
        if not is_valid_subtree(s, e) or e > tree_size:
            return VerifyResult(False, f"invalid subtree {(s, e)}", 1)

    for i, r1 in enumerate(ranges):
        for r2 in ranges[i + 1:]:
            if partially_overlaps(r1, r2):
                return VerifyResult(False, f"partial overlap {r1} {r2}", 1)

    hash_of = {(s, e): h for s, e, h in subs}
    A = maximal_elements(ranges)
    a = min(s for s, _ in ranges)
    b = max(e for _, e in ranges)

    # A must be a gapless, disjoint cover of [a, b). This is the check that
    # makes the optimization safe (draft Section 6).
    cover = sorted(A)
    if cover[0][0] != a or cover[-1][1] != b:
        return VerifyResult(False, "antichain does not span [a,b)", 1)
    for (s1, e1), (s2, e2) in zip(cover, cover[1:]):
        if e1 != s2:
            return VerifyResult(False, f"gap or overlap in antichain at {e1}", 1)

    nested_ranges = [r for r in ranges if r not in A]
    if len(proof.nested_proofs) != len(nested_ranges):
        return VerifyResult(False, "nested_proofs count mismatch", 1)

    # ---- Stage 2: root reconstruction ----
    left_nodes = frontier(0, a)
    right_nodes = frontier(b, tree_size)
    if len(proof.left_frontier) != len(left_nodes):
        return VerifyResult(False, "left_frontier length mismatch", 2)
    if len(proof.right_frontier) != len(right_nodes):
        return VerifyResult(False, "right_frontier length mismatch", 2)

    working: List[Tuple[Range, bytes]] = []
    working += list(zip(left_nodes, proof.left_frontier))
    working += [(r, hash_of[r]) for r in cover]
    working += list(zip(right_nodes, proof.right_frontier))

    # Adjacency sanity: the working list must tile [0, tree_size).
    if working[0][0][0] != 0 or working[-1][0][1] != tree_size:
        return VerifyResult(False, "working list does not tile the tree", 2)
    for (r1, _), (r2, _) in zip(working, working[1:]):
        if r1[1] != r2[0]:
            return VerifyResult(False, "working list not adjacent", 2)

    steps = 0
    while len(working) > 1:
        merged = False
        for i in range(len(working) - 1):
            (r1, h1), (r2, h2) = working[i], working[i + 1]
            if are_siblings(r1, r2):
                parent = (r1[0], r2[1])
                working[i:i + 2] = [(parent, HASH(b"\x01" + h1 + h2))]
                merged = True
                steps += 1
                break
        if not merged:
            return VerifyResult(False, "no mergeable sibling pair", 2, steps)

    if working[0][0] != (0, tree_size):
        return VerifyResult(False, "reduced to wrong range", 2, steps)
    if working[0][1] != root_hash:
        return VerifyResult(False, "root hash mismatch", 2, steps)

    # ---- Stage 3: nested subtrees ----
    for r, np_ in zip(nested_ranges, proof.nested_proofs):
        anc = np_.contained_in
        if anc not in A or not contains(anc, r):
            return VerifyResult(False, f"bad ancestor for {r}", 3, steps)
        sides = descent_sides(r, anc)
        if sides is None or len(sides) != len(np_.inclusion_proof):
            return VerifyResult(False, f"bad nested proof length for {r}", 3, steps)
        h = hash_of[r]
        for side, p in zip(sides, np_.inclusion_proof):
            h = HASH(b"\x01" + h + p) if side == "L" else HASH(b"\x01" + p + h)
        if h != hash_of[anc]:
            return VerifyResult(False, f"nested hash mismatch for {r}", 3, steps)

    return VerifyResult(True, "ok", 3, steps)


# ---------------------------------------------------------------------------
# Baseline: per-subtree consistency proofs (what the draft replaces)
# ---------------------------------------------------------------------------

def baseline_hash_count(log: MerkleLog, subtrees: List[Range]) -> int:
    return sum(len(subtree_consistency_proof(log, s, e))
               for s, e in canonical_order(dedupe(subtrees)))


def baseline_wire_bytes(log: MerkleLog, subtrees: List[Range]) -> int:
    return baseline_hash_count(log, subtrees) * HASH_SIZE

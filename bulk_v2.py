"""
Corrected bulk subtree consistency proof.

The -00 construction assumed the active landmark subtrees are nodes of the
reference checkpoint's Merkle Tree, and could therefore be folded upward into
the root. That is false. Per MTC Section 4.2, a *partial* subtree is directly
contained in MTH(D_n) only when n equals its end; in any larger tree it is not
a node at all. find_subtrees explicitly returns a possibly-partial right
subtree, so landmark sets routinely contain such subtrees.

This module replaces that construction with one that holds:

  1. Take the breakpoints: 0, the reference tree size, and every landmark
     subtree endpoint.
  2. Tile [0, n) by decomposing each inter-breakpoint gap with frontier().
     Every resulting tile is a FULL subtree, hence a genuine node of the
     reference tree, and the tiling refines every landmark subtree boundary.
  3. The proof carries exactly the tile hashes. Ranges are derived by the
     verifier from the claimed subtree list, never transmitted.
  4. The verifier recomputes the root by descending the reference tree and
     stopping at tiles, then recomputes each claimed subtree hash the same
     way. Descent follows children_split, so there is no merge-order
     ambiguity.

Both partial subtrees and nested/overlapping subtrees fall out for free; the
separate nested-proof machinery of the -00 draft is not needed.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from mtc_bulk import (
    HASH, HASH_SIZE, MerkleLog, Range, canonical_order, children_split,
    dedupe, frontier, is_valid_subtree,
)


def breakpoints(subtrees: List[Range], tree_size: int) -> List[int]:
    pts = {0, tree_size}
    for s, e in subtrees:
        pts.add(s)
        pts.add(e)
    return sorted(p for p in pts if 0 <= p <= tree_size)


def tiling(subtrees: List[Range], tree_size: int) -> List[Range]:
    """Full subtrees tiling [0, tree_size), refined at every subtree boundary."""
    bps = breakpoints(subtrees, tree_size)
    tiles: List[Range] = []
    for p, q in zip(bps, bps[1:]):
        tiles.extend(frontier(p, q))
    return tiles


@dataclass
class BulkProofV2:
    tree_size: int
    subtrees: List[Tuple[int, int, bytes]]
    tile_hashes: List[bytes]

    def hash_count(self) -> int:
        return len(self.tile_hashes)

    def wire_bytes(self) -> int:
        return len(self.tile_hashes) * HASH_SIZE


def generate(log: MerkleLog, subtrees: List[Range],
             tree_size: Optional[int] = None) -> BulkProofV2:
    if tree_size is None:
        tree_size = log.size
    subs = canonical_order(dedupe(subtrees))
    if not subs:
        raise ValueError("no subtrees")
    tiles = tiling(subs, tree_size)
    return BulkProofV2(
        tree_size=tree_size,
        subtrees=[(s, e, log.node(s, e)) for s, e in subs],
        tile_hashes=[log.node(s, e) for s, e in tiles],
    )


@dataclass
class Result:
    ok: bool
    reason: str = ""

    def __bool__(self) -> bool:
        return self.ok


def verify(proof: BulkProofV2, root_hash: bytes, tree_size: int) -> Result:
    if proof.tree_size != tree_size:
        return Result(False, "tree_size mismatch")
    if not proof.subtrees:
        return Result(False, "empty subtree list")

    ranges = [(s, e) for s, e, _ in proof.subtrees]
    if ranges != canonical_order(ranges):
        return Result(False, "subtrees not in canonical order")
    if len(set(ranges)) != len(ranges):
        return Result(False, "duplicate subtree")
    for s, e in ranges:
        if not is_valid_subtree(s, e) or e > tree_size:
            return Result(False, f"invalid subtree {(s, e)}")

    # Ranges are derived, never accepted from the proof.
    tiles = tiling(ranges, tree_size)
    if len(proof.tile_hashes) != len(tiles):
        return Result(False, "tile count mismatch")
    tile_map: Dict[Range, bytes] = dict(zip(tiles, proof.tile_hashes))
    if len(tile_map) != len(tiles):
        return Result(False, "duplicate tile range")

    memo: Dict[Range, bytes] = {}

    def compute(s: int, e: int) -> Optional[bytes]:
        key = (s, e)
        if key in memo:
            return memo[key]
        got = tile_map.get(key)
        if got is None:
            m = children_split(s, e)
            if m is None:
                return None
            left = compute(s, m)
            right = compute(m, e)
            if left is None or right is None:
                return None
            got = HASH(b"\x01" + left + right)
        memo[key] = got
        return got

    if compute(0, tree_size) != root_hash:
        return Result(False, "root hash mismatch")

    for s, e, h in proof.subtrees:
        if compute(s, e) != h:
            return Result(False, f"subtree hash mismatch at {(s, e)}")

    return Result(True, "ok")

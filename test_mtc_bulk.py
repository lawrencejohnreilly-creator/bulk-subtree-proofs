"""Validation suite for the bulk subtree consistency proof construction."""

import os
import random
import sys

from mtc_bulk import (
    HASH, HASH_SIZE, MerkleLog, LandmarkSequence, BulkSubtreeProof,
    NestedSubtreeProof, bit_ceil, is_valid_subtree, children_split,
    find_subtrees, frontier, maximal_elements, canonical_order, dedupe,
    generate_bulk_proof, verify_bulk_proof, baseline_hash_count,
    baseline_wire_bytes, subtree_consistency_proof, contains,
)

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    mark = "PASS" if cond else "FAIL"
    line = f"  [{mark}] {name}"
    if detail and not cond:
        line += f"  <- {detail}"
    print(line)
    return cond


def make_log(n, seed=0):
    rnd = random.Random(seed)
    return MerkleLog([rnd.randbytes(16) for _ in range(n)])


# ---------------------------------------------------------------------------
print("\n=== 1. Spec conformance: fixtures from draft-ietf-plants-mtc-04 ===")

check("bit_ceil(5) == 8", bit_ceil(5) == 8)
check("[4,8) is a valid subtree", is_valid_subtree(4, 8))
check("[8,13) is a valid subtree", is_valid_subtree(8, 13))
check("[7,9) is NOT a valid subtree (Section 4.5 Figure 10)",
      not is_valid_subtree(7, 9))

# Section 4.5, Figure 9: [5,13) is covered by [4,8) and [8,13).
check("find_subtrees(5,13) == [(4,8),(8,13)] (Figure 9)",
      find_subtrees(5, 13) == [(4, 8), (8, 13)],
      str(find_subtrees(5, 13)))

# Section 4.5: [7,9) is covered by [7,8) and [8,9).
check("find_subtrees(7,9) == [(7,8),(8,9)] (Figure 10 text)",
      find_subtrees(7, 9) == [(7, 8), (8, 9)],
      str(find_subtrees(7, 9)))

# Section 4.3.1: inclusion proof for entry 10 of [8,13) has 3 hashes.
log13 = make_log(13, seed=1)
from mtc_bulk import interior_inclusion_proof
p = interior_inclusion_proof(log13, (10, 11), (8, 13))
check("inclusion proof for entry 10 in [8,13) has 3 hashes (Section 4.3.1)",
      len(p) == 3, f"got {len(p)}")
check("  and its hashes are MTH(d[11]), MTH(D[8:10]), MTH(d[12])",
      p == [log13.node(11, 12), log13.node(8, 10), log13.node(12, 13)])

# Section 4.4.2: consistency proof for [4,8) in a tree of 14 has 2 hashes.
log14 = make_log(14, seed=2)
cp = subtree_consistency_proof(log14, 4, 8)
check("subtree consistency proof for [4,8) in n=14 has 2 hashes (Section 4.4.2)",
      len(cp) == 2, f"got {len(cp)}")
check("  and equals MTH(D[0:4]), MTH(D[8:14])",
      set(cp) == {log14.node(0, 4), log14.node(8, 14)})

# Section 4.4.2: consistency proof for [8,13) in n=14 has 4 hashes.
cp2 = subtree_consistency_proof(log14, 8, 13)
check("subtree consistency proof for [8,13) in n=14 has 4 hashes (Section 4.4.2)",
      len(cp2) == 4, f"got {len(cp2)}")

# frontier decomposition matches the tree structure
check("frontier(0,13) == [(0,8),(8,12),(12,13)]",
      frontier(0, 13) == [(0, 8), (8, 12), (12, 13)], str(frontier(0, 13)))

# Every node produced by frontier is a valid subtree.
ok = all(is_valid_subtree(s, e)
         for n in range(1, 300) for s, e in frontier(0, n))
check("frontier() only emits valid subtrees for n in 1..299", ok)

ok = all(sum(e - s for s, e in frontier(x, y)) == y - x
         for x in range(0, 60) for y in range(x + 1, 61))
check("frontier(s,e) exactly covers [s,e) for all s<e<=60", ok)


# ---------------------------------------------------------------------------
print("\n=== 2. Root reconstruction: does the stage 2 fold work? ===")

def fold_check(n, seed=3):
    """Reconstruct the root from the frontier of [0,n) using stage-2 merging."""
    log = make_log(n, seed)
    proof = generate_bulk_proof(log, [(0, n)] if is_valid_subtree(0, n) else
                               frontier(0, n))
    return verify_bulk_proof(proof, log.root(), n)

sizes = [1, 2, 3, 4, 5, 7, 8, 9, 13, 14, 16, 17, 31, 32, 33, 63, 100, 127, 128, 129]
bad = [n for n in sizes if not fold_check(n)]
check("stage-2 fold reconstructs the root for assorted tree sizes",
      not bad, f"failed at n={bad}")

# Naive right-to-left folding, which the -00 draft text falls back to.
def naive_rtl_fold(log, nodes):
    work = [(r, log.node(*r)) for r in nodes]
    while len(work) > 1:
        (s1, e1), h1 = work[-2]
        (s2, e2), h2 = work[-1]
        work[-2:] = [((s1, e2), HASH(b"\x01" + h1 + h2))]
    return work[0][1]

log13b = make_log(13, seed=4)
rtl_ok = naive_rtl_fold(log13b, frontier(0, 13)) == log13b.root()
check("naive right-to-left fold happens to work for the canonical frontier",
      rtl_ok)

# But not for a non-canonical (still valid) partition.
partition = [(0, 4), (4, 8), (8, 13)]
rtl_bad = naive_rtl_fold(log13b, partition) != log13b.root()
check("naive right-to-left fold FAILS on partition [(0,4),(4,8),(8,13)]",
      rtl_bad,
      "right-to-left fold produced the correct root, contradiction expected")

# The sibling-merge rule handles it.
proof_p = generate_bulk_proof(log13b, partition)
check("sibling-merge rule handles the same partition correctly",
      bool(verify_bulk_proof(proof_p, log13b.root(), 13)))


# ---------------------------------------------------------------------------
print("\n=== 3. Differential: bulk proof vs. direct recomputation ===")

rnd = random.Random(1234)
fails = []
for trial in range(400):
    n = rnd.randint(1, 400)
    log = make_log(n, seed=rnd.randint(0, 10 ** 6))
    # Build a landmark sequence over this log.
    seq = LandmarkSequence(max_active_landmarks=rnd.randint(2, 12))
    t = 0
    while t < n:
        t = min(n, t + rnd.randint(1, max(1, n // 4)))
        seq.append(t)
    subs = seq.active_subtrees()
    if not subs:
        continue
    proof = generate_bulk_proof(log, subs, n)
    res = verify_bulk_proof(proof, log.root(), n)
    if not res:
        fails.append((n, subs, res.reason))
        continue
    # Oracle: every asserted subtree hash must equal direct recomputation.
    for s, e, h in proof.subtrees:
        if h != log.node(s, e):
            fails.append((n, (s, e), "oracle mismatch"))

check("400 random logs x landmark sequences: bulk proof verifies and every "
      "asserted hash matches direct recomputation",
      not fails, f"{len(fails)} failures, first: {fails[:2]}")

# Confirm the nested-subtree path is actually being exercised.
nested_seen = 0
for trial in range(200):
    n = rnd.randint(20, 400)
    log = make_log(n, seed=rnd.randint(0, 10 ** 6))
    seq = LandmarkSequence(max_active_landmarks=rnd.randint(3, 10))
    t = 0
    while t < n:
        t = min(n, t + rnd.randint(1, max(1, n // 6)))
        seq.append(t)
    subs = seq.active_subtrees()
    if not subs:
        continue
    proof = generate_bulk_proof(log, subs, n)
    nested_seen += len(proof.nested_proofs)
check(f"nested-subtree branch exercised ({nested_seen} nested proofs generated)",
      nested_seen > 0,
      "stage 3 never ran; the differential test says nothing about it")


# ---------------------------------------------------------------------------
print("\n=== 4. Adversarial: the attacks Security Considerations claims to stop ===")

n = 200
log = make_log(n, seed=77)
seq = LandmarkSequence(max_active_landmarks=8)
for t in range(20, n + 1, 20):
    seq.append(t)
subs = seq.active_subtrees()
good = generate_bulk_proof(log, subs, n)
check("baseline: honest proof verifies", bool(verify_bulk_proof(good, log.root(), n)))

# (a) Corrupt one subtree hash.
import copy
bad1 = copy.deepcopy(good)
s, e, h = bad1.subtrees[len(bad1.subtrees) // 2]
bad1.subtrees[len(bad1.subtrees) // 2] = (s, e, HASH(b"forged"))
check("(a) corrupted subtree hash is rejected",
      not verify_bulk_proof(bad1, log.root(), n))

# (b) Omit a subregion from the antichain, absorbing it into a frontier hash.
#     Drop a maximal element and see whether the cover check catches the gap.
A = maximal_elements([(x, y) for x, y, _ in good.subtrees])
if len(A) >= 2:
    drop = A[len(A) // 2]
    bad2 = copy.deepcopy(good)
    bad2.subtrees = [(x, y, hh) for x, y, hh in bad2.subtrees if (x, y) != drop]
    bad2.nested_proofs = []
    res2 = verify_bulk_proof(bad2, log.root(), n)
    check("(b) omitted subregion is rejected by the antichain cover check",
          not res2 and "antichain" in res2.reason or "gap" in res2.reason,
          f"reason: {res2.reason}")

# (c) Substitute frontier ranges by lying about the covered range.
bad3 = copy.deepcopy(good)
bad3.left_frontier = bad3.left_frontier + [HASH(b"extra")]
check("(c) frontier length tampering is rejected",
      not verify_bulk_proof(bad3, log.root(), n))

# (d) Swap two frontier hashes.
if len(good.left_frontier) >= 2:
    bad4 = copy.deepcopy(good)
    bad4.left_frontier[0], bad4.left_frontier[1] = (
        bad4.left_frontier[1], bad4.left_frontier[0])
    check("(d) reordered frontier hashes are rejected",
          not verify_bulk_proof(bad4, log.root(), n))

# (e) Wrong root.
check("(e) proof against a different root is rejected",
      not verify_bulk_proof(good, HASH(b"other root"), n))

# (f) Partially overlapping subtrees (violates laminarity).
bad6 = copy.deepcopy(good)
bad6.subtrees.append((3, 5, HASH(b"x")))
bad6.subtrees = canonical_order([(x, y) for x, y, _ in bad6.subtrees]) and sorted(
    bad6.subtrees, key=lambda r: (r[0], -r[1]))
res6 = verify_bulk_proof(bad6, log.root(), n)
check("(f) partially-overlapping subtree is rejected", not res6, res6.reason)

# (g) Forged nested proof.
nested_case = None
for trial in range(300):
    nn = rnd.randint(50, 300)
    lg = make_log(nn, seed=rnd.randint(0, 10 ** 6))
    sq = LandmarkSequence(max_active_landmarks=6)
    t = 0
    while t < nn:
        t = min(nn, t + rnd.randint(3, 25))
        sq.append(t)
    sb = sq.active_subtrees()
    pf = generate_bulk_proof(lg, sb, nn)
    if pf.nested_proofs:
        nested_case = (lg, pf, nn)
        break
if nested_case:
    lg, pf, nn = nested_case
    bad7 = copy.deepcopy(pf)
    idx = 0
    A7 = maximal_elements([(x, y) for x, y, _ in bad7.subtrees])
    nested_ranges = [(x, y) for x, y, _ in bad7.subtrees if (x, y) not in A7]
    tgt = nested_ranges[idx]
    pos = next(i for i, (x, y, _) in enumerate(bad7.subtrees) if (x, y) == tgt)
    bad7.subtrees[pos] = (tgt[0], tgt[1], HASH(b"forged nested"))
    res7 = verify_bulk_proof(bad7, lg.root(), nn)
    check("(g) forged nested subtree hash is rejected (stage 3)",
          not res7, res7.reason)
else:
    check("(g) forged nested subtree hash is rejected (stage 3)", False,
          "could not construct a case with nested subtrees")


# ---------------------------------------------------------------------------
print("\n=== 5. Size measurement at draft Section 6 parameters ===")

def measure(n_entries, landmark_every, max_active):
    log = make_log(n_entries, seed=9)
    seq = LandmarkSequence(max_active_landmarks=max_active)
    t = 0
    while t < n_entries:
        t = min(n_entries, t + landmark_every)
        seq.append(t)
    subs = seq.active_subtrees()
    proof = generate_bulk_proof(log, subs, n_entries)
    assert verify_bulk_proof(proof, log.root(), n_entries), "proof failed"
    base = baseline_wire_bytes(log, subs)
    bulk = proof.wire_bytes()
    return {
        "entries": n_entries,
        "subtrees": len(subs),
        "nested": len(proof.nested_proofs),
        "baseline_bytes": base,
        "bulk_bytes": bulk,
        "ratio": base / bulk if bulk else float("inf"),
        "held_anyway_bytes": len(subs) * HASH_SIZE,
    }

print(f"  {'entries':>9} {'subtrees':>9} {'nested':>7} "
      f"{'baseline':>10} {'bulk':>8} {'ratio':>7}")
rows = []
for n_e, every, ma in [
    (5_000, 30, 169),
    (20_000, 120, 169),
    (100_000, 600, 169),
    (500_000, 3_000, 169),
]:
    r = measure(n_e, every, ma)
    rows.append(r)
    print(f"  {r['entries']:>9,} {r['subtrees']:>9} {r['nested']:>7} "
          f"{r['baseline_bytes']:>9,}B {r['bulk_bytes']:>7,}B "
          f"{r['ratio']:>6.1f}x")

check("bulk proof is smaller than the per-subtree baseline in all cases",
      all(r["ratio"] > 1 for r in rows))
check("bulk proof material stays roughly constant as the log grows",
      max(r["bulk_bytes"] for r in rows) < 4 * min(r["bulk_bytes"] for r in rows),
      str([r["bulk_bytes"] for r in rows]))


# ---------------------------------------------------------------------------
print("\n=== Summary ===")
print(f"  {len(PASS)} passed, {len(FAIL)} failed")
if FAIL:
    print("\n  Failures:")
    for f in FAIL:
        print(f"    - {f}")
sys.exit(1 if FAIL else 0)

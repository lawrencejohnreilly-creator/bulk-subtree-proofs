import random, copy, sys
from mtc_bulk import *
import bulk_v2 as V2

PASS, FAIL = [], []
def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  <- {detail}" if detail and not cond else ""))
    return cond

def make_log(n, seed=0):
    r = random.Random(seed); return MerkleLog([r.randbytes(16) for _ in range(n)])

print("\n=== Differential: corrected construction vs. direct recomputation ===")
rnd = random.Random(4321); fails = []; trials = 0; nested_or_partial = 0
for _ in range(600):
    n = rnd.randint(1, 600)
    log = make_log(n, seed=rnd.randint(0, 10**6))
    seq = LandmarkSequence(max_active_landmarks=rnd.randint(2, 15))
    t = 0
    while t < n:
        t = min(n, t + rnd.randint(1, max(1, n // 4))); seq.append(t)
    subs = seq.active_subtrees()
    if not subs: continue
    trials += 1
    # count subtrees that are NOT nodes of the reference tree (the -00 killer)
    def is_node(s, e, n):
        if e - s == 1: return True
        cur = (0, n)
        while cur != (s, e):
            m = children_split(*cur)
            if m is None: return False
            if e <= m: cur = (cur[0], m)
            elif s >= m: cur = (m, cur[1])
            else: return False
        return True
    nested_or_partial += sum(0 if is_node(s, e, n) else 1 for s, e in subs)
    p = V2.generate(log, subs, n)
    r = V2.verify(p, log.root(), n)
    if not r: fails.append((n, r.reason)); continue
    for s, e, h in p.subtrees:
        if h != log.node(s, e): fails.append((n, "oracle mismatch"))

check(f"{trials} random logs x landmark sequences verify, all hashes match oracle",
      not fails, f"{len(fails)} failures, first: {fails[:3]}")
check(f"non-node (partial) subtrees exercised: {nested_or_partial} instances",
      nested_or_partial > 0, "the -00 failure mode was never hit")

print("\n=== Adversarial ===")
n = 400; log = make_log(n, seed=99)
seq = LandmarkSequence(max_active_landmarks=8)
for t in range(37, n+1, 37): seq.append(t)
seq.append(n)
subs = seq.active_subtrees()
good = V2.generate(log, subs, n)
check("honest proof verifies", bool(V2.verify(good, log.root(), n)))

b = copy.deepcopy(good); i = len(b.subtrees)//2
s,e,_ = b.subtrees[i]; b.subtrees[i] = (s,e,HASH(b"forged"))
check("corrupted subtree hash rejected", not V2.verify(b, log.root(), n))

b = copy.deepcopy(good); b.tile_hashes[0] = HASH(b"forged tile")
check("corrupted tile hash rejected", not V2.verify(b, log.root(), n))

b = copy.deepcopy(good); b.tile_hashes = b.tile_hashes[:-1]
check("dropped tile rejected (count check)", not V2.verify(b, log.root(), n))

b = copy.deepcopy(good)
if len(b.tile_hashes) >= 2: b.tile_hashes[0], b.tile_hashes[1] = b.tile_hashes[1], b.tile_hashes[0]
check("reordered tiles rejected", not V2.verify(b, log.root(), n))

b = copy.deepcopy(good); b.subtrees = [x for x in b.subtrees if x != b.subtrees[len(b.subtrees)//2]]
r = V2.verify(b, log.root(), n)
check("dropping a subtree changes the derived tiling and is rejected", not r, r.reason)

check("proof against a different root rejected", not V2.verify(good, HASH(b"other"), n))

print("\n=== Size: corrected bulk vs. per-subtree baseline ===")
print(f"  {'entries':>10} {'subs':>5} {'baseline':>11} {'bulk':>9} {'ratio':>7}")
rows=[]
for n_e, every, ma in [(5_000,30,169),(50_000,300,169),(500_000,3_000,169),(4_400_000,26_000,169)]:
    log = make_log(n_e, seed=7)
    seq = LandmarkSequence(max_active_landmarks=ma)
    t=0
    while t < n_e:
        t = min(n_e, t+every); seq.append(t)
    subs = seq.active_subtrees()
    p = V2.generate(log, subs, n_e)
    assert V2.verify(p, log.root(), n_e), "FAILED"
    base = baseline_wire_bytes(log, subs); bulk = p.wire_bytes()
    rows.append((n_e,len(subs),base,bulk,base/bulk))
    print(f"  {n_e:>10,} {len(subs):>5} {base:>10,}B {bulk:>8,}B {base/bulk:>6.2f}x")

check("bulk is smaller than baseline in all measured cases", all(r[4]>1 for r in rows))

print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
for f in FAIL: print(f"    - {f}")
sys.exit(1 if FAIL else 0)

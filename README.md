# Bulk subtree consistency proofs — reference implementation

Reference implementation and interactive verifier for
[draft-reilly-plants-bulk-subtree-proofs-01](https://datatracker.ietf.org/doc/draft-reilly-plants-bulk-subtree-proofs/),
a companion optimization to
[draft-ietf-plants-merkle-tree-certs](https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/)
(IETF PLANTS working group).

## What this is

Merkle Tree Certificates require a relying party to verify a set of active
landmark subtrees against a reference checkpoint before it can accept
landmark-relative certificates. As specified in §7.4 of the base draft, that is
one subtree consistency proof per landmark subtree — up to 338 of them at the
example parameters, refreshed periodically over a broadcast channel.

The base draft records the possibility of a single proof covering the whole set
but does not define one. This is a definition, plus code that runs it.

## Files

| File | Purpose |
|---|---|
| `index.html` | Interactive verifier. Generates and checks proofs live in the browser; no backend, no precomputation. |
| `mtc_bulk.py` | RFC 9162 §2.1 Merkle trees, MTC §4 subtree definitions, §4.5 covering, §4.4.1 consistency proofs, §6.3 landmarks. |
| `bulk_v2.py` | The construction in `-01`: breakpoint tiling and verification by descent. |
| `test_mtc_bulk.py` | Spec conformance against fixtures from the base draft, and a demonstration of why the `-00` construction fails. |
| `test_v2.py` | Differential correctness, adversarial cases, and size measurement. |

## Running the tests

No dependencies beyond the standard library.

```
python3 test_mtc_bulk.py     # spec conformance + -00 failure demonstration
python3 test_v2.py           # differential, adversarial, sizes
```

## What the tests establish

**Spec conformance.** Fixtures taken directly from the base draft: `[7,9)` is
not a valid subtree; `find_subtrees(5,13)` returns `[(4,8),(8,13)]` per Figure 9;
the inclusion proof for entry 10 of `[8,13)` has three hashes per §4.3.1; the
consistency proofs in §4.4.2 have the stated lengths and contents.

**Differential correctness.** 600 randomized combinations of log size and
landmark allocation. Every subtree hash the proof asserts is compared against
direct recomputation of `MTH(D[start:end])` from the log — not against another
implementation of the same proof technique. Partial, nested, and overlapping
landmark subtrees are confirmed to occur in the sample (2,353 partial instances).

**Adversarial cases.** Corrupted subtree hash, corrupted tile hash, dropped
tile, reordered tiles, dropped subtree entry, and verification against an
unrelated root are each confirmed rejected.

**Size.** Measured, not estimated. Baseline is one consistency proof per
landmark subtree; bulk is the tile count. Both at 32 bytes per hash:

| Log entries | Subtrees | Baseline | Bulk | Reduction |
|---|---|---|---|---|
| 5,000 | 334 | 107,776 B | 21,344 B | 5.05× |
| 50,000 | 334 | 119,680 B | 33,024 B | 3.62× |
| 500,000 | 334 | 129,056 B | 45,184 B | 2.86× |
| 4,400,000 | 338 | 150,080 B | 57,184 B | 2.62× |

## Note on -00

The construction published in `-00` was incorrect and was withdrawn after being
implemented. It assumed the active landmark subtrees are nodes of the reference
checkpoint's tree; partial subtrees are not, since a partial subtree is
contained in `MTH(D_n)` only when `n` equals its end. `test_mtc_bulk.py`
demonstrates the failure. `-01` §A records the errors in full.

## Deploying the page

`index.html` is self-contained and needs no server-side code. Static hosting is
sufficient. A `Dockerfile` is included for platforms that expect a container.

## Status

Independent submission, not adopted by any working group. Test vectors have not
yet been extracted into citable form; that is tracked in the draft's Open
Questions.

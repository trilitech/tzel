# TzEL v2: Design Rationale

This document is informative, not normative. The canonical protocol rules and encodings are in `specs/spec.md`.

## Owner Tags and Nullifier Binding

The note commitment includes:

```text
owner_tag = H_owner(auth_root, pub_seed, nk_tag)
cm        = H_commit(d_j, v, rcm, owner_tag)
```

This is the mechanism that binds the commitment to the nullifier key material.

Without owner tags, the commitment could look like:

```text
cm = H_commit(d_j, v, rcm)
```

In that weaker design, an attacker observing `cm` could choose an arbitrary nullifier key and try to spend the same commitment under a fresh nullifier. The owner-tag chain:

```text
nk_spend -> nk_tag -> owner_tag(auth_root, pub_seed, nk_tag) -> cm
```

forces the commitment to be tied to the spender's nullifier derivation path. The spending proof then has to be consistent with the same bound commitment.

## Position-Dependent Nullifiers

The nullifier includes the Merkle position:

```text
nf = H_nf(nk_spend, H_nf(cm, pos))
```

The purpose is to ensure that two equal commitments inserted at different tree positions do not collapse to the same nullifier. This avoids aliasing between duplicated commitments and makes nullifier uniqueness a function of both note ownership and concrete tree placement.

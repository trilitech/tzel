(* Note structure for TzEL v2.
   rseed       — random per-note seed
   rcm         = H(H("rcm"), rseed)
   owner_tag   = H_owner(auth_root, auth_pub_seed, nk_tag)
   cm          = H_commit(d_j, v, rcm, owner_tag)
   nf          = H_nf(nk_spend, H_nf(cm, pos)) *)

type t = {
  d_j : Felt.t;
  v : int64;
  rseed : Felt.t;
  rcm : Felt.t;
  owner_tag : Felt.t;
  cm : Felt.t;
}

let create (addr : Keys.address) (v : int64) (rseed : Felt.t) =
  let rcm = Hash.derive_rcm rseed in
  let owner_tag = Keys.owner_tag addr in
  let cm = Hash.hash_commit addr.d_j (Felt.of_u64 (Int64.to_int v)) rcm owner_tag in
  { d_j = addr.d_j; v; rseed; rcm; owner_tag; cm }

let create_from_parts ~d_j ~auth_root ~auth_pub_seed ~nk_tag ~v ~rseed =
  let rcm = Hash.derive_rcm rseed in
  let owner_tag = Hash.hash_owner auth_root auth_pub_seed nk_tag in
  let cm = Hash.hash_commit d_j (Felt.of_u64 (Int64.to_int v)) rcm owner_tag in
  { d_j; v; rseed; rcm; owner_tag; cm }

(* Compute nullifier for a note at a given position *)
let nullifier (nk_spend : Felt.t) (cm : Felt.t) (pos : int) =
  let inner = Hash.hash_nf cm (Felt.of_int pos) in
  Hash.hash_nf nk_spend inner

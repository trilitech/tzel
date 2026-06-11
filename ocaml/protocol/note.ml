(* Note structure for TzEL v2.
   rseed       — random per-note seed
   rcm         = H(H("rcm"), rseed)
   owner_tag   = H_owner(auth_root, auth_pub_seed, nk_tag)
   cm          = H_commit(d_j, v, asset, rcm, owner_tag)
   nf          = H_nf(nk_spend, H_nf(cm, pos))

   Multiasset: each note carries an [asset] tag (the L2 asset_id) bound
   into its commitment. [asset = Felt.zero] is ASSET_TEZ; nonzero asset
   ids name FA2 tokens (see Asset_registry.derive_asset_id). The
   constructors default [asset] to ASSET_TEZ so tez-only callers are
   unchanged. *)

type t = {
  d_j : Felt.t;
  v : int64;
  asset : Felt.t;
  rseed : Felt.t;
  rcm : Felt.t;
  owner_tag : Felt.t;
  cm : Felt.t;
}

let create ?(asset = Asset_registry.asset_tez) (addr : Keys.address) (v : int64)
    (rseed : Felt.t) =
  let rcm = Hash.derive_rcm rseed in
  let owner_tag = Keys.owner_tag addr in
  let cm =
    Hash.hash_commit addr.d_j (Felt.of_u64 (Int64.to_int v)) asset rcm owner_tag
  in
  { d_j = addr.d_j; v; asset; rseed; rcm; owner_tag; cm }

let create_from_parts ?(asset = Asset_registry.asset_tez) ~d_j ~auth_root
    ~auth_pub_seed ~nk_tag ~v ~rseed () =
  let rcm = Hash.derive_rcm rseed in
  let owner_tag = Hash.hash_owner auth_root auth_pub_seed nk_tag in
  let cm =
    Hash.hash_commit d_j (Felt.of_u64 (Int64.to_int v)) asset rcm owner_tag
  in
  { d_j; v; asset; rseed; rcm; owner_tag; cm }

(* Compute nullifier for a note at a given position *)
let nullifier (nk_spend : Felt.t) (cm : Felt.t) (pos : int) =
  let inner = Hash.hash_nf cm (Felt.of_int pos) in
  Hash.hash_nf nk_spend inner

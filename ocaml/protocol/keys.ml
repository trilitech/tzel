(* Key hierarchy for TzEL v2.
   Spend authorization uses an XMSS-style depth-16 WOTS+ tree with explicit
   auth_pub_seed and L-tree leaf compression. *)

let auth_depth = 16
let auth_tree_size = 1 lsl auth_depth
let tag_xmss_tree = 0x0072742d73736d78L

type account_keys = {
  nk : Felt.t;
  ask_base : Felt.t;
  dsk : Felt.t;
  incoming_seed : Felt.t;
  view_root : Felt.t;
  detect_root : Felt.t;
}

type address = {
  index : int;
  d_j : Felt.t;
  auth_root : Felt.t;
  auth_pub_seed : Felt.t;
  nk_tag : Felt.t;
  nk_spend : Felt.t;
  ask_j : Felt.t;
  ek_v : Mlkem.encapsulation_key;
  dk_v : Mlkem.decapsulation_key;
  ek_d : Mlkem.encapsulation_key;
  dk_d : Mlkem.decapsulation_key;
}

type payment_address = {
  pa_d_j : Felt.t;
  pa_auth_root : Felt.t;
  pa_auth_pub_seed : Felt.t;
  pa_nk_tag : Felt.t;
  pa_ek_v : Mlkem.encapsulation_key;
  pa_ek_d : Mlkem.encapsulation_key;
}

let derive master_sk =
  let spend_seed = Hash.hash2 Hash.tag_spend master_sk in
  let incoming_seed = Hash.hash2 Hash.tag_incoming master_sk in
  let nk = Hash.hash2 Hash.tag_nk spend_seed in
  let ask_base = Hash.hash2 Hash.tag_ask spend_seed in
  let dsk = Hash.hash2 Hash.tag_dsk incoming_seed in
  let view_root = Hash.hash2 Hash.tag_view incoming_seed in
  let detect_root = Hash.hash2 Hash.tag_detect view_root in
  { nk; ask_base; dsk; incoming_seed; view_root; detect_root }

let derive_diversifier keys j =
  Hash.hash2 keys.dsk (Felt.of_int j)

let derive_ask keys j =
  Hash.hash2 keys.ask_base (Felt.of_int j)

let derive_nk_spend keys d_j =
  Hash.hash_nk_spend keys.nk d_j

let derive_nk_tag nk_spend =
  Hash.hash_nk_tag nk_spend

let derive_auth_key_seed ask_j i =
  Hash.hash3 Hash.tag_xmss_sk ask_j (Felt.of_u32 i)

let derive_wots_seed ask_j i =
  derive_auth_key_seed ask_j i

let derive_auth_pub_seed ask_j =
  Hash.hash2 Hash.tag_xmss_ps ask_j

let xmss_node_hash pub_seed key_idx level node_idx left right =
  let adrs = Wots.pack_adrs tag_xmss_tree key_idx level node_idx 0 in
  Hash.hash4 pub_seed adrs left right

let wots_pk ask_j key_idx =
  let pub_seed = derive_auth_pub_seed ask_j in
  let seed = derive_auth_key_seed ask_j key_idx in
  Wots.keygen ~seed ~pub_seed ~key_idx

let auth_leaf_hash ask_j key_idx =
  let pub_seed = derive_auth_pub_seed ask_j in
  let pk = wots_pk ask_j key_idx in
  Wots.pk_to_leaf ~pub_seed ~key_idx pk

let rec xmss_subtree_root ask_j pub_seed start height =
  if height = 0 then
    let pk = wots_pk ask_j start in
    Wots.pk_to_leaf ~pub_seed ~key_idx:start pk
  else
    let split = 1 lsl (height - 1) in
    let left = xmss_subtree_root ask_j pub_seed start (height - 1) in
    let right = xmss_subtree_root ask_j pub_seed (start + split) (height - 1) in
    xmss_node_hash pub_seed 0 (height - 1) (start lsr height) left right

let rec xmss_root_and_path_inner ask_j pub_seed start height target =
  if height = 0 then
    let leaf = auth_leaf_hash ask_j start in
    let path = if start = target then Some [] else None in
    (leaf, path)
  else
    let split = 1 lsl (height - 1) in
    let mid = start + split in
    let (left, left_path) =
      if target < mid then
        xmss_root_and_path_inner ask_j pub_seed start (height - 1) target
      else
        (xmss_subtree_root ask_j pub_seed start (height - 1), None)
    in
    let (right, right_path) =
      if target >= mid then
        xmss_root_and_path_inner ask_j pub_seed mid (height - 1) target
      else
        (xmss_subtree_root ask_j pub_seed mid (height - 1), None)
    in
    let root = xmss_node_hash pub_seed 0 (height - 1) (start lsr height) left right in
    let path =
      match left_path, right_path with
      | Some p, _ -> Some (p @ [right])
      | None, Some p -> Some (p @ [left])
      | None, None -> None
    in
    (root, path)

let build_auth_tree ask_j =
  let pub_seed = derive_auth_pub_seed ask_j in
  xmss_subtree_root ask_j pub_seed 0 auth_depth

let auth_tree_path ask_j index =
  let pub_seed = derive_auth_pub_seed ask_j in
  let (_root, path) = xmss_root_and_path_inner ask_j pub_seed 0 auth_depth index in
  Array.of_list (Option.get path)

let auth_root_and_path ask_j index =
  let pub_seed = derive_auth_pub_seed ask_j in
  let (root, path) = xmss_root_and_path_inner ask_j pub_seed 0 auth_depth index in
  (root, Array.of_list (Option.get path))

let derive_address keys j =
  let d_j = derive_diversifier keys j in
  let ask_j = derive_ask keys j in
  let auth_pub_seed = derive_auth_pub_seed ask_j in
  let nk_spend = derive_nk_spend keys d_j in
  let nk_tag = derive_nk_tag nk_spend in
  let auth_root = build_auth_tree ask_j in
  let (ek_v, dk_v) = Mlkem.derive_view_keypair keys.view_root j in
  let (ek_d, dk_d) = Mlkem.derive_detect_keypair keys.detect_root j in
  { index = j; d_j; auth_root; auth_pub_seed; nk_tag; nk_spend; ask_j;
    ek_v; dk_v; ek_d; dk_d }

let to_payment_address addr =
  { pa_d_j = addr.d_j;
    pa_auth_root = addr.auth_root;
    pa_auth_pub_seed = addr.auth_pub_seed;
    pa_nk_tag = addr.nk_tag;
    pa_ek_v = addr.ek_v;
    pa_ek_d = addr.ek_d }

let owner_tag addr =
  Hash.hash_owner addr.auth_root addr.auth_pub_seed addr.nk_tag

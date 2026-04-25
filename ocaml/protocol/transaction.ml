(* Transaction types for TzEL.

   NOTE on protocol drift vs the canonical Rust circuit / kernel:
   This module models the *original* TzEL v1 public output shapes
     - transfer: 2 output notes (cm_1, cm_2)
     - unshield: optional change note (cm_change) only
   The current canonical protocol additionally publishes a per-tx
   DAL-producer fee note in both transfer (cm_3 / memo_ct_hash_3) and
   unshield (cm_fee / memo_ct_hash_fee). These extra fields are NOT
   modelled here; the test_interop scenario compensates by appending
   the producer-fee commitment to the OCaml tree manually after each
   apply_transfer / apply_unshield call. As a consequence the OCaml
   sighash defined below differs from the canonical Rust sighash —
   this implementation cannot verify a Rust-signed sighash without
   the missing fields. *)

(* Transaction types for TzEL v2:
   - Shield (public -> private)
   - Transfer (N->2 private)
   - Unshield (N->withdrawal + optional change) *)

(* Shield public outputs: [v_pub, cm_new, sender_id, memo_ct_hash] *)
type shield_public = {
  v_pub : int64;
  cm_new : Felt.t;
  sender_id : Felt.t;
  memo_ct_hash : Felt.t;
}

(* Transfer public outputs:
   [auth_domain, root, nf_0..nf_{N-1}, cm_1, cm_2, memo_ct_hash_1, memo_ct_hash_2] *)
type transfer_public = {
  auth_domain : Felt.t;
  root : Felt.t;
  nullifiers : Felt.t list;
  cm_1 : Felt.t;
  cm_2 : Felt.t;
  memo_ct_hash_1 : Felt.t;
  memo_ct_hash_2 : Felt.t;
}

(* Unshield public outputs:
   [auth_domain, root, nf_0..nf_{N-1}, v_pub, recipient_id, cm_change, memo_ct_hash_change] *)
type unshield_public = {
  auth_domain : Felt.t;
  root : Felt.t;
  nullifiers : Felt.t list;
  v_pub : int64;
  recipient_id : Felt.t;
  cm_change : Felt.t;
  memo_ct_hash_change : Felt.t;
}

(* Per-input spend witness *)
type spend_input = {
  note : Note.t;
  pos : int;
  nk_spend : Felt.t;
  auth_root : Felt.t;
  auth_pub_seed : Felt.t;
  ask_j : Felt.t;
  key_idx : int;
  commitment_path : Felt.t array;
}

(* Per-output witness *)
type output_desc = {
  d_j : Felt.t;
  auth_root : Felt.t;
  auth_pub_seed : Felt.t;
  nk_tag : Felt.t;
  v : int64;
  rseed : Felt.t;
  memo_ct_hash : Felt.t;
}

(* Compute sighash for transfer:
   fold(0x01, auth_domain, root, nf_0..nf_{N-1}, cm_1, cm_2, mh_1, mh_2) *)
let transfer_sighash (pub : transfer_public) =
  let items =
    [Felt.of_int 0x01; pub.auth_domain; pub.root]
    @ pub.nullifiers
    @ [pub.cm_1; pub.cm_2; pub.memo_ct_hash_1; pub.memo_ct_hash_2]
  in
  Hash.sighash_fold items

(* Compute sighash for unshield:
   fold(0x02, auth_domain, root, nf_0..nf_{N-1}, v_pub, recipient_id, cm_change, mh_change) *)
let unshield_sighash (pub : unshield_public) =
  let items =
    [Felt.of_int 0x02; pub.auth_domain; pub.root]
    @ pub.nullifiers
    @ [Felt.of_u64 (Int64.to_int pub.v_pub); pub.recipient_id;
       pub.cm_change; pub.memo_ct_hash_change]
  in
  Hash.sighash_fold items

(* Build a shield transaction *)
let build_shield ~sender_string ~(recipient : Keys.address)
    ~(v : int64) ~(rseed : Felt.t) ~memo_ct_hash =
  let note = Note.create recipient v rseed in
  let sender_id = Hash.account_id sender_string in
  let pub = { v_pub = v; cm_new = note.cm; sender_id; memo_ct_hash } in
  (pub, note)

(* Build output notes for transfer *)
let build_output ~(d_j : Felt.t) ~(auth_root : Felt.t) ~(auth_pub_seed : Felt.t) ~(nk_tag : Felt.t)
    ~(v : int64) ~(rseed : Felt.t) =
  Note.create_from_parts ~d_j ~auth_root ~auth_pub_seed ~nk_tag ~v ~rseed

(* Build transfer public outputs and sighash *)
let build_transfer_public ~auth_domain ~root ~nullifiers
    ~(out1 : Note.t) ~(out2 : Note.t) ~memo_ct_hash_1 ~memo_ct_hash_2 =
  let pub = {
    auth_domain; root; nullifiers;
    cm_1 = out1.cm; cm_2 = out2.cm;
    memo_ct_hash_1; memo_ct_hash_2;
  } in
  let sighash = transfer_sighash pub in
  (pub, sighash)

(* Build unshield public outputs and sighash *)
let build_unshield_public ~auth_domain ~root ~nullifiers
    ~v_pub ~recipient_string ~change_note ~memo_ct_hash_change =
  let recipient_id = Hash.account_id recipient_string in
  let cm_change = match change_note with
    | Some n -> n.Note.cm
    | None -> Felt.zero in
  let memo_ct_hash_change = match change_note with
    | Some _ -> memo_ct_hash_change
    | None -> Felt.zero in
  let pub = {
    auth_domain; root; nullifiers;
    v_pub; recipient_id; cm_change; memo_ct_hash_change;
  } in
  let sighash = unshield_sighash pub in
  (pub, sighash)

(* Sign all inputs with WOTS+ *)
let sign_inputs (inputs : spend_input list) sighash =
  List.map (fun inp ->
    let wots_seed = Keys.derive_auth_key_seed inp.ask_j inp.key_idx in
    let sig_vals = Wots.sign ~seed:wots_seed ~pub_seed:inp.auth_pub_seed ~key_idx:inp.key_idx sighash in
    (inp, sig_vals)
  ) inputs

(* Verify a single WOTS+ input signature *)
let verify_input_sig (inp : spend_input) (sig_vals : Felt.t array) sighash =
  let leaf = Keys.auth_leaf_hash inp.ask_j inp.key_idx in
  Wots.verify ~pub_seed:inp.auth_pub_seed ~key_idx:inp.key_idx sig_vals sighash leaf

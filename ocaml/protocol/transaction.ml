(* Transaction types for TzEL — canonical (multiasset, post pubkey_hash
   redesign).

   Public-output shapes match the Rust circuit / kernel EXACTLY (see
   core::{shield,transfer,unshield}_sighash in core/src/lib.rs and the
   in-circuit folds in cairo/src/{shield,transfer,unshield}.cairo):
   - Shield:   [auth_domain, pubkey_hash, v_pub, fee, producer_fee,
                asset_new, asset_producer, cm_new, cm_producer,
                memo_ct_hash, producer_memo_ct_hash]
   - Transfer: [auth_domain, root, nf_0..nf_{N-1}, fee,
                cm_1, cm_2, cm_3, cm_4,
                memo_ct_hash_1, memo_ct_hash_2, memo_ct_hash_3, memo_ct_hash_4]
     where slot 1 = recipient, 2 = change_1, 3 = change_2, 4 = producer-fee.
   - Unshield: [auth_domain, root, nf_0..nf_{N-1}, v_pub, asset_pub, fee,
                recipient_id, cm_change, memo_ct_hash_change,
                cm_change_2, memo_ct_hash_change_2, cm_fee, memo_ct_hash_fee]

   This port is tez-only (notes commit with asset = Felt.zero), so the
   multiasset asset fields are always ASSET_TEZ (Felt.zero) and the unused
   change/output slots are Felt.zero here — but the FIELDS and their fold
   ORDER are present so the sighashes are byte-identical to the deployed
   circuit's, which folds those zeros too.  The asset fields and the extra
   slots were added in the multiasset change; an earlier version of this
   file silently dropped them, which the per-flow sighash conformance test
   (test below) now catches.

   Sighashes use the sighash_fold primitive (BLAKE2s with personalization
   "sighSP__"). The leading type tag is 0x01 / 0x02 / 0x03 respectively
   for transfer / unshield / shield, providing cross-construction domain
   separation. *)

(* Canonical tez asset tag (matches Cairo ASSET_TEZ / Rust ASSET_TEZ). *)
let asset_tez : Felt.t = Felt.zero

type shield_public = {
  auth_domain : Felt.t;
  pubkey_hash : Felt.t;
  v_pub : int64;
  fee : int64;
  producer_fee : int64;
  asset_new : Felt.t;
  asset_producer : Felt.t;
  cm_new : Felt.t;
  cm_producer : Felt.t;
  memo_ct_hash : Felt.t;
  producer_memo_ct_hash : Felt.t;
}

type transfer_public = {
  auth_domain : Felt.t;
  root : Felt.t;
  nullifiers : Felt.t list;
  fee : int64;
  cm_1 : Felt.t;
  cm_2 : Felt.t;
  cm_3 : Felt.t;
  cm_4 : Felt.t;
  memo_ct_hash_1 : Felt.t;
  memo_ct_hash_2 : Felt.t;
  memo_ct_hash_3 : Felt.t;
  memo_ct_hash_4 : Felt.t;
}

type unshield_public = {
  auth_domain : Felt.t;
  root : Felt.t;
  nullifiers : Felt.t list;
  v_pub : int64;
  asset_pub : Felt.t;
  fee : int64;
  recipient_id : Felt.t;
  cm_change : Felt.t;
  memo_ct_hash_change : Felt.t;
  cm_change_2 : Felt.t;
  memo_ct_hash_change_2 : Felt.t;
  cm_fee : Felt.t;
  memo_ct_hash_fee : Felt.t;
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

(* Compute the deposit-pool pubkey_hash.
   pubkey_hash = fold(0x04, auth_domain, auth_root, auth_pub_seed, blind) *)
let deposit_pubkey_hash ~auth_domain ~auth_root ~auth_pub_seed ~blind =
  let items =
    [
      Felt.of_int 0x04;
      auth_domain;
      auth_root;
      auth_pub_seed;
      blind;
    ]
  in
  Hash.sighash_fold items

(* Compute the in-circuit shield sighash bound by the WOTS+ signature.
   sighash = fold(0x03, auth_domain, pubkey_hash, v_pub, fee, producer_fee,
                  asset_new, asset_producer, cm_new, cm_producer,
                  memo_ct_hash, producer_memo_ct_hash)
   The two asset fields are bound because they are public at the L1 bridge
   boundary; they match core::shield_sighash. *)
let shield_sighash ~auth_domain ~pubkey_hash ~(v_pub : int64) ~(fee : int64)
    ~(producer_fee : int64) ~asset_new ~asset_producer ~cm_new ~cm_producer
    ~memo_ct_hash ~producer_memo_ct_hash =
  let items =
    [
      Felt.of_int 0x03;
      auth_domain;
      pubkey_hash;
      Felt.of_u64 (Int64.to_int v_pub);
      Felt.of_u64 (Int64.to_int fee);
      Felt.of_u64 (Int64.to_int producer_fee);
      asset_new;
      asset_producer;
      cm_new;
      cm_producer;
      memo_ct_hash;
      producer_memo_ct_hash;
    ]
  in
  Hash.sighash_fold items

(* Compute sighash for transfer:
   fold(0x01, auth_domain, root, nf_0..nf_{N-1}, fee,
        cm_1, cm_2, cm_3, cm_4, mh_1, mh_2, mh_3, mh_4) *)
let transfer_sighash (pub : transfer_public) =
  let items =
    [Felt.of_int 0x01; pub.auth_domain; pub.root]
    @ pub.nullifiers
    @ [
        Felt.of_u64 (Int64.to_int pub.fee);
        pub.cm_1; pub.cm_2; pub.cm_3; pub.cm_4;
        pub.memo_ct_hash_1; pub.memo_ct_hash_2;
        pub.memo_ct_hash_3; pub.memo_ct_hash_4;
      ]
  in
  Hash.sighash_fold items

(* Compute sighash for unshield:
   fold(0x02, auth_domain, root, nf_0..nf_{N-1}, v_pub, asset_pub, fee,
        recipient_id, cm_change, mh_change, cm_change_2, mh_change_2,
        cm_fee, mh_fee) *)
let unshield_sighash (pub : unshield_public) =
  let items =
    [Felt.of_int 0x02; pub.auth_domain; pub.root]
    @ pub.nullifiers
    @ [
        Felt.of_u64 (Int64.to_int pub.v_pub);
        pub.asset_pub;
        Felt.of_u64 (Int64.to_int pub.fee);
        pub.recipient_id;
        pub.cm_change; pub.memo_ct_hash_change;
        pub.cm_change_2; pub.memo_ct_hash_change_2;
        pub.cm_fee; pub.memo_ct_hash_fee;
      ]
  in
  Hash.sighash_fold items

(* Build a shield transaction. The pubkey_hash names the deposit-balance
   pool the shield drains; the recipient and producer notes are picked at
   shield time and bound by the in-circuit WOTS+ signature (not modeled in
   this OCaml mirror — it trusts that the corresponding STARK has already
   validated). *)
let build_shield ~auth_domain ~pubkey_hash ~(recipient : Keys.address)
    ~(v_pub : int64) ~(fee : int64) ~(producer_fee : int64)
    ~(rseed : Felt.t) ~memo_ct_hash
    ~(producer : Keys.address) ~(producer_rseed : Felt.t) ~producer_memo_ct_hash =
  let note = Note.create recipient v_pub rseed in
  let producer_note = Note.create producer producer_fee producer_rseed in
  let pub = {
    auth_domain;
    pubkey_hash;
    v_pub; fee; producer_fee;
    (* tez-only port: both notes are tez (asset = ASSET_TEZ). *)
    asset_new = asset_tez; asset_producer = asset_tez;
    cm_new = note.cm; cm_producer = producer_note.cm;
    memo_ct_hash; producer_memo_ct_hash;
  } in
  (pub, note, producer_note)

(* Build output notes for transfer *)
let build_output ~(d_j : Felt.t) ~(auth_root : Felt.t) ~(auth_pub_seed : Felt.t) ~(nk_tag : Felt.t)
    ~(v : int64) ~(rseed : Felt.t) =
  Note.create_from_parts ~d_j ~auth_root ~auth_pub_seed ~nk_tag ~v ~rseed

(* Build transfer public outputs and sighash.
   [out1] = recipient (slot 1), [out2] = change_1 (slot 2),
   [out3] = producer-fee (slot 4).  This tez-only port has no second-asset
   change, so slot 3 (change_2) is empty (Felt.zero). *)
let build_transfer_public ~auth_domain ~root ~nullifiers ~(fee : int64)
    ~(out1 : Note.t) ~(out2 : Note.t) ~(out3 : Note.t)
    ~memo_ct_hash_1 ~memo_ct_hash_2 ~memo_ct_hash_3 =
  let pub = {
    auth_domain; root; nullifiers; fee;
    cm_1 = out1.cm; cm_2 = out2.cm; cm_3 = Felt.zero; cm_4 = out3.cm;
    memo_ct_hash_1; memo_ct_hash_2;
    memo_ct_hash_3 = Felt.zero; memo_ct_hash_4 = memo_ct_hash_3;
  } in
  let sighash = transfer_sighash pub in
  (pub, sighash)

(* Build unshield public outputs and sighash *)
let build_unshield_public ~auth_domain ~root ~nullifiers
    ~(v_pub : int64) ~(fee : int64) ~recipient_string
    ~change_note ~memo_ct_hash_change
    ~(fee_note : Note.t) ~memo_ct_hash_fee =
  let recipient_id = Hash.account_id recipient_string in
  let (cm_change, memo_ct_hash_change) = match change_note with
    | Some (n : Note.t) -> (n.cm, memo_ct_hash_change)
    | None -> (Felt.zero, Felt.zero) in
  let pub = {
    auth_domain; root; nullifiers;
    (* tez-only port: the public exit and change are tez; no second-asset
       change slot is used. *)
    v_pub; asset_pub = asset_tez; fee; recipient_id;
    cm_change; memo_ct_hash_change;
    cm_change_2 = Felt.zero; memo_ct_hash_change_2 = Felt.zero;
    cm_fee = fee_note.cm; memo_ct_hash_fee;
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

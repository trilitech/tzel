(* Transaction types for TzEL — canonical (post pubkey_hash redesign).

   Public-output shapes match the Rust circuit exactly:
   - Shield: [auth_domain, pubkey_hash, v_pub, fee, producer_fee,
             cm_new, cm_producer, memo_ct_hash, producer_memo_ct_hash]
   - Transfer: [auth_domain, root, nf_0..nf_{N-1}, fee, cm_1, cm_2, cm_3,
               memo_ct_hash_1, memo_ct_hash_2, memo_ct_hash_3]
   - Unshield: [auth_domain, root, nf_0..nf_{N-1}, v_pub, fee, recipient_id,
               cm_change, memo_ct_hash_change, cm_fee, memo_ct_hash_fee]

   Sighashes use the sighash_fold primitive (BLAKE2s with personalization
   "sighSP__"). The leading type tag is 0x01 / 0x02 / 0x03 respectively
   for transfer / unshield / shield, providing cross-construction domain
   separation. The shield circuit additionally verifies an in-circuit
   WOTS+ signature under the recipient's auth tree (matching pubkey_hash
   = H_pubkey(auth_domain, auth_root, auth_pub_seed, blind)). *)

(* Shield public outputs:
   [auth_domain, pubkey_hash, v_pub, fee, producer_fee, cm_new, cm_producer,
    memo_ct_hash, producer_memo_ct_hash] *)
type shield_public = {
  auth_domain : Felt.t;
  pubkey_hash : Felt.t;
  v_pub : int64;
  fee : int64;
  producer_fee : int64;
  cm_new : Felt.t;
  cm_producer : Felt.t;
  memo_ct_hash : Felt.t;
  producer_memo_ct_hash : Felt.t;
}

(* Transfer public outputs:
   [auth_domain, root, nf_0..nf_{N-1}, fee, cm_1, cm_2, cm_3,
    memo_ct_hash_1, memo_ct_hash_2, memo_ct_hash_3] *)
type transfer_public = {
  auth_domain : Felt.t;
  root : Felt.t;
  nullifiers : Felt.t list;
  fee : int64;
  cm_1 : Felt.t;
  cm_2 : Felt.t;
  cm_3 : Felt.t;
  memo_ct_hash_1 : Felt.t;
  memo_ct_hash_2 : Felt.t;
  memo_ct_hash_3 : Felt.t;
}

(* Unshield public outputs:
   [auth_domain, root, nf_0..nf_{N-1}, v_pub, fee, recipient_id,
    cm_change, memo_ct_hash_change, cm_fee, memo_ct_hash_fee] *)
type unshield_public = {
  auth_domain : Felt.t;
  root : Felt.t;
  nullifiers : Felt.t list;
  v_pub : int64;
  fee : int64;
  recipient_id : Felt.t;
  cm_change : Felt.t;
  memo_ct_hash_change : Felt.t;
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
                  cm_new, cm_producer, memo_ct_hash, producer_memo_ct_hash) *)
let shield_sighash ~auth_domain ~pubkey_hash ~(v_pub : int64) ~(fee : int64)
    ~(producer_fee : int64) ~cm_new ~cm_producer ~memo_ct_hash
    ~producer_memo_ct_hash =
  let items =
    [
      Felt.of_int 0x03;
      auth_domain;
      pubkey_hash;
      Felt.of_u64 (Int64.to_int v_pub);
      Felt.of_u64 (Int64.to_int fee);
      Felt.of_u64 (Int64.to_int producer_fee);
      cm_new;
      cm_producer;
      memo_ct_hash;
      producer_memo_ct_hash;
    ]
  in
  Hash.sighash_fold items

(* Compute sighash for transfer:
   fold(0x01, auth_domain, root, nf_0..nf_{N-1}, fee,
        cm_1, cm_2, cm_3, mh_1, mh_2, mh_3) *)
let transfer_sighash (pub : transfer_public) =
  let items =
    [Felt.of_int 0x01; pub.auth_domain; pub.root]
    @ pub.nullifiers
    @ [
        Felt.of_u64 (Int64.to_int pub.fee);
        pub.cm_1; pub.cm_2; pub.cm_3;
        pub.memo_ct_hash_1; pub.memo_ct_hash_2; pub.memo_ct_hash_3;
      ]
  in
  Hash.sighash_fold items

(* Compute sighash for unshield:
   fold(0x02, auth_domain, root, nf_0..nf_{N-1}, v_pub, fee, recipient_id,
        cm_change, mh_change, cm_fee, mh_fee) *)
let unshield_sighash (pub : unshield_public) =
  let items =
    [Felt.of_int 0x02; pub.auth_domain; pub.root]
    @ pub.nullifiers
    @ [
        Felt.of_u64 (Int64.to_int pub.v_pub);
        Felt.of_u64 (Int64.to_int pub.fee);
        pub.recipient_id;
        pub.cm_change; pub.memo_ct_hash_change;
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
    cm_new = note.cm; cm_producer = producer_note.cm;
    memo_ct_hash; producer_memo_ct_hash;
  } in
  (pub, note, producer_note)

(* Build output notes for transfer *)
let build_output ~(d_j : Felt.t) ~(auth_root : Felt.t) ~(auth_pub_seed : Felt.t) ~(nk_tag : Felt.t)
    ~(v : int64) ~(rseed : Felt.t) =
  Note.create_from_parts ~d_j ~auth_root ~auth_pub_seed ~nk_tag ~v ~rseed

(* Build transfer public outputs and sighash *)
let build_transfer_public ~auth_domain ~root ~nullifiers ~(fee : int64)
    ~(out1 : Note.t) ~(out2 : Note.t) ~(out3 : Note.t)
    ~memo_ct_hash_1 ~memo_ct_hash_2 ~memo_ct_hash_3 =
  let pub = {
    auth_domain; root; nullifiers; fee;
    cm_1 = out1.cm; cm_2 = out2.cm; cm_3 = out3.cm;
    memo_ct_hash_1; memo_ct_hash_2; memo_ct_hash_3;
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
    v_pub; fee; recipient_id;
    cm_change; memo_ct_hash_change;
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

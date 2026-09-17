(* Reference ledger state machine.
   Maintains:
   - Append-only commitment Merkle tree (depth 48)
   - Global nullifier set
   - Historical root set (anchors)
   - Pending withdrawals

   NOTE on protocol drift:
   This OCaml ledger does NOT enforce the canonical DAL-producer fee
   note that the current Rust circuit publishes for every transfer and
   unshield. See the comment in protocol/transaction.ml for details.
   The interop scenario compensates by manually appending the producer-fee
   commitment to the tree after the call. A future change should add
   cm_fee / memo_ct_hash_fee to unshield_public and cm_3 / memo_ct_hash_3
   to transfer_public, fold them into the sighash, and tighten
   apply_unshield / apply_transfer to verify and append them in-place. *)

let tree_depth = 48
let max_valid_roots = 4096

(* Per-pool aggregated deposit balance, indexed first by hex(asset_id)
   then by hex(deposit_pubkey_hash). Each L1 ticket addressed to
   `deposit:<hex(pubkey_hash)>` for a given asset increments the inner
   balance; shield decrements it. Pools scoped by asset so an FA2 deposit
   cannot be drawn down by a tez shield (and vice versa). Inner pools at
   zero balance are removed (and the outer asset entry too once empty) to
   bound storage. Mirrors the Rust `Ledger.deposit_balances:
   HashMap<asset_id, HashMap<pubkey_hash, u64>>`. *)
type t = {
  tree : Merkle.tree_with_leaves;
  nullifier_set : (string, unit) Hashtbl.t;
  root_set : (string, unit) Hashtbl.t;
  root_history : string Queue.t;
  (* (asset_id, recipient, amount) — mirrors Rust WithdrawalRecord. *)
  withdrawals : (Felt.t * string * int64) Queue.t;
  auth_domain : Felt.t;
  deposit_balances : (string, (string, int64) Hashtbl.t) Hashtbl.t;
  (* Replay-protection set for shield commitments. Each successful
     apply_shield records its `cm_new` here; a subsequent shield
     carrying the same `cm_new` is rejected. Without this, anyone
     could top up a drained pool and resubmit a victim's old proof,
     minting a duplicate of the recipient's note at a fresh tree
     position (independently spendable, since nullifiers are per-
     position). *)
  applied_shield_cms : (string, unit) Hashtbl.t;
}

let record_root_with_limit ledger ~max_roots root_hex =
  if Hashtbl.mem ledger.root_set root_hex then begin
    if Queue.is_empty ledger.root_history then Queue.push root_hex ledger.root_history
  end else begin
    Hashtbl.replace ledger.root_set root_hex ();
    Queue.push root_hex ledger.root_history;
    while Queue.length ledger.root_history > max_roots do
      let oldest = Queue.pop ledger.root_history in
      Hashtbl.remove ledger.root_set oldest
    done
  end

let create ~auth_domain =
  let tree = Merkle.create_with_leaves ~depth:tree_depth in
  let nullifier_set = Hashtbl.create 1024 in
  let root_set = Hashtbl.create 256 in
  let root_history = Queue.create () in
  let withdrawals = Queue.create () in
  let deposit_balances = Hashtbl.create 64 in
  let applied_shield_cms = Hashtbl.create 256 in
  let initial_root = Merkle.root_with_leaves tree in
  let initial_root_hex = Felt.to_hex initial_root in
  Hashtbl.replace root_set initial_root_hex ();
  Queue.push initial_root_hex root_history;
  {
    tree; nullifier_set; root_set; root_history;
    withdrawals; auth_domain;
    deposit_balances;
    applied_shield_cms;
  }

(* Current balance of the pool keyed by `(asset_id, pubkey_hash)`, or None
   if it has never been credited. [asset_id] defaults to ASSET_TEZ. *)
let deposit_balance ledger ?(asset_id = Asset_registry.asset_tez) ~pubkey_hash () =
  match Hashtbl.find_opt ledger.deposit_balances (Felt.to_hex asset_id) with
  | None -> None
  | Some inner -> Hashtbl.find_opt inner (Felt.to_hex pubkey_hash)

(* Credit an L1 bridge deposit to the pool keyed by `(asset_id, pubkey_hash)`.
   Multiple deposits to the same key aggregate (top-up). [asset_id] defaults
   to ASSET_TEZ for tez callers. *)
let credit_deposit ledger ?(asset_id = Asset_registry.asset_tez) ~pubkey_hash ~amount () =
  let akey = Felt.to_hex asset_id in
  let inner =
    match Hashtbl.find_opt ledger.deposit_balances akey with
    | Some inner -> inner
    | None ->
        let inner = Hashtbl.create 16 in
        Hashtbl.replace ledger.deposit_balances akey inner;
        inner
  in
  let key = Felt.to_hex pubkey_hash in
  let current =
    match Hashtbl.find_opt inner key with None -> 0L | Some n -> n
  in
  Hashtbl.replace inner key (Int64.add current amount)

(* Debit `amount` from the pool keyed by `(asset_id, pubkey_hash)`. Returns
   Error if the pool does not exist or its balance is below `amount`. When
   the resulting balance is zero the inner entry is removed (and the outer
   asset entry too once its last pool drains) to bound storage. *)
let debit_deposit ledger ?(asset_id = Asset_registry.asset_tez) ~pubkey_hash ~amount () =
  let akey = Felt.to_hex asset_id in
  let key = Felt.to_hex pubkey_hash in
  match Hashtbl.find_opt ledger.deposit_balances akey with
  | None ->
      Error (Printf.sprintf "deposit pool (asset %s, %s) does not exist" akey key)
  | Some inner ->
    match Hashtbl.find_opt inner key with
    | None ->
        Error (Printf.sprintf "deposit pool (asset %s, %s) does not exist" akey key)
    | Some current when Int64.compare current amount < 0 ->
        Error (Printf.sprintf
                 "deposit pool (asset %s, %s) balance %Ld too small to debit %Ld"
                 akey key current amount)
    | Some current ->
        let next = Int64.sub current amount in
        if Int64.compare next 0L = 0 then begin
          Hashtbl.remove inner key;
          if Hashtbl.length inner = 0 then Hashtbl.remove ledger.deposit_balances akey
        end else
          Hashtbl.replace inner key next;
        Ok ()

(* Drain the withdrawal queue as full (asset_id, recipient, amount) records
   (mirrors Rust `WithdrawalRecord`). *)
let withdrawal_records ledger =
  let copy = Queue.copy ledger.withdrawals in
  let rec drain acc =
    if Queue.is_empty copy then List.rev acc
    else drain (Queue.pop copy :: acc)
  in
  drain []

(* (recipient, amount) projection of the withdrawal queue, dropping the
   asset_id. Kept for tez-only callers/tests; the asset-aware view is
   [withdrawal_records]. *)
let withdrawals ledger =
  List.map (fun (_asset, recipient, amount) -> (recipient, amount))
    (withdrawal_records ledger)

let base58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

let base58_value c =
  match String.index_opt base58_alphabet c with
  | Some idx -> Ok idx
  | None -> Error "invalid base58 character"

let tezos_prefixes = [
  Bytes.of_string "\x06\xa1\x9f";  (* tz1 *)
  Bytes.of_string "\x06\xa1\xa1";  (* tz2 *)
  Bytes.of_string "\x06\xa1\xa4";  (* tz3 *)
  Bytes.of_string "\x02\x5a\x79";  (* KT1 *)
]

let starts_with_bytes bytes prefix =
  let prefix_len = Bytes.length prefix in
  Bytes.length bytes >= prefix_len
  && (
    let rec loop idx =
      if idx = prefix_len then true
      else if Bytes.get bytes idx <> Bytes.get prefix idx then false
      else loop (idx + 1)
    in
    loop 0
  )

let equal_bytes a b =
  let len = Bytes.length a in
  len = Bytes.length b
  && (
    let rec loop idx =
      if idx = len then true
      else if Bytes.get a idx <> Bytes.get b idx then false
      else loop (idx + 1)
    in
    loop 0
  )

let decode_base58 value =
  let len = String.length value in
  let zeroes = ref 0 in
  while !zeroes < len && value.[!zeroes] = '1' do
    incr zeroes
  done;
  let size = (len * 733 / 1000) + 1 in
  let b256 = Bytes.make size '\x00' in
  let used = ref 0 in
  let decode_char idx =
    match base58_value value.[idx] with
    | Ok digit -> digit
    | Error _ -> raise Exit
  in
  try
    for idx = !zeroes to len - 1 do
      let carry = ref (decode_char idx) in
      let pos = ref (size - 1) in
      let span = ref 0 in
      while (!carry <> 0 || !span < !used) && !pos >= 0 do
        let acc = (Char.code (Bytes.get b256 !pos) * 58) + !carry in
        Bytes.set b256 !pos (Char.chr (acc land 0xff));
        carry := acc lsr 8;
        decr pos;
        incr span
      done;
      if !carry <> 0 then raise Exit;
      if !span > !used then used := !span
    done;
    let start = size - !used in
    let out_len = !zeroes + (size - start) in
    let decoded = Bytes.make out_len '\x00' in
    for idx = 0 to size - start - 1 do
      Bytes.set decoded (!zeroes + idx) (Bytes.get b256 (start + idx))
    done;
    Ok decoded
  with Exit ->
    Error "invalid base58 character"

let double_sha256 bytes =
  let first =
    Digestif.SHA256.(digest_bytes bytes |> to_raw_string)
  in
  Digestif.SHA256.(digest_string first |> to_raw_string |> Bytes.of_string)

let is_l1_withdrawal_payload payload =
  let payload_len = Bytes.length payload in
  List.exists (fun prefix ->
    payload_len = Bytes.length prefix + 20
    && starts_with_bytes payload prefix
  ) tezos_prefixes

let normalize_l1_withdrawal_recipient value =
  let value = String.trim value in
  if value = "" then Error "L1 withdrawal recipient must not be empty"
  else
    match decode_base58 value with
    | Error _ -> Error ("invalid L1 withdrawal recipient: " ^ value)
    | Ok decoded ->
      let decoded_len = Bytes.length decoded in
      if decoded_len < 5 then
        Error ("invalid L1 withdrawal recipient: " ^ value)
      else
        let payload_len = decoded_len - 4 in
        let payload = Bytes.sub decoded 0 payload_len in
        let checksum = Bytes.sub decoded payload_len 4 in
        let expected = Bytes.sub (double_sha256 payload) 0 4 in
        if not (equal_bytes checksum expected) || not (is_l1_withdrawal_payload payload) then
          Error ("invalid L1 withdrawal recipient: " ^ value)
        else
          Ok value

let current_root ledger = Merkle.root_with_leaves ledger.tree

let tree_size ledger = Merkle.size_with_leaves ledger.tree

let append_commitment ledger cm =
  let new_root = Merkle.append_with_leaves ledger.tree cm in
  record_root_with_limit ledger ~max_roots:max_valid_roots (Felt.to_hex new_root)

let is_valid_root ledger root =
  Hashtbl.mem ledger.root_set (Felt.to_hex root)

let validate_nullifiers ledger nullifiers =
  let seen = Hashtbl.create (List.length nullifiers) in
  let dup = List.exists (fun nf ->
    let hex = Felt.to_hex nf in
    if Hashtbl.mem seen hex then true
    else (Hashtbl.replace seen hex (); false)
  ) nullifiers in
  if dup then Error "duplicate nullifier within transaction"
  else
    let already_spent = List.exists (fun nf ->
      Hashtbl.mem ledger.nullifier_set (Felt.to_hex nf)
    ) nullifiers in
    if already_spent then Error "nullifier already spent" else Ok ()

let insert_nullifiers ledger nullifiers =
  List.iter (fun nf ->
    Hashtbl.replace ledger.nullifier_set (Felt.to_hex nf) ()
  ) nullifiers

let check_and_insert_nullifiers ledger nullifiers =
  match validate_nullifiers ledger nullifiers with
  | Error e -> Error e
  | Ok () ->
    insert_nullifiers ledger nullifiers;
    Ok ()

(* Pool-bound shield. The shield message names a `pubkey_hash` identifying
   a deposit-balance pool; the kernel decrements it by `v + fee +
   producer_fee` and appends both notes. The in-circuit WOTS+ signature
   under the recipient's auth tree binds (v, fee, producer_fee, cm_recipient,
   cm_producer, mh_recipient, mh_producer); this OCaml mirror trusts the
   STARK has already validated those bindings. *)
let apply_shield ledger ~(pub : Transaction.shield_public)
    ~memo_ct_hash ~producer_memo_ct_hash =
  if not (Felt.equal pub.auth_domain ledger.auth_domain) then
    Error "auth_domain mismatch"
  else if not (Felt.equal memo_ct_hash pub.memo_ct_hash) then
    Error "memo_ct_hash mismatch"
  else if not (Felt.equal producer_memo_ct_hash pub.producer_memo_ct_hash) then
    Error "producer_memo_ct_hash mismatch"
  else if Int64.compare pub.producer_fee 0L <= 0 then
    Error "producer_fee must be positive"
  else begin
    let cm_key = Felt.to_hex pub.cm_new in
    if Hashtbl.mem ledger.applied_shield_cms cm_key then
      Error (Printf.sprintf "shield replay: cm %s already applied" cm_key)
    else begin
      (* Dual-pool debit (mirrors core::{prepare,commit_prepared}_shield):
         the (asset_new, pubkey) pool funds the recipient note + kernel
         fee (v + fee); the (ASSET_TEZ, pubkey) pool funds producer_fee,
         which is PERMANENTLY a tez output regardless of asset_new. For a
         tez shield both debits collapse onto the one tez pool. We
         validate every pool balance BEFORE mutating so a partial debit
         can never strand funds. *)
      let asset_new = pub.asset_new in
      let asset_debit = Int64.add pub.v_pub pub.fee in
      let producer_fee = pub.producer_fee in
      let is_tez = Felt.equal asset_new Asset_registry.asset_tez in
      let validation =
        if is_tez then begin
          let required = Int64.add asset_debit producer_fee in
          match deposit_balance ledger ~asset_id:asset_new ~pubkey_hash:pub.pubkey_hash () with
          | None ->
              Error (Printf.sprintf "no deposit pool for pubkey_hash %s; submit an L1 bridge deposit first"
                       (Felt.to_hex pub.pubkey_hash))
          | Some bal when Int64.compare bal required < 0 ->
              Error (Printf.sprintf "deposit pool balance (%Ld) too small for v + fee + producer_fee (%Ld)"
                       bal required)
          | Some _ -> Ok ()
        end else begin
          (* FA2: the asset pool must cover v + fee, and a SEPARATE tez
             pool at the same pubkey_hash must cover producer_fee. *)
          match deposit_balance ledger ~asset_id:asset_new ~pubkey_hash:pub.pubkey_hash () with
          | None ->
              Error (Printf.sprintf "no deposit pool for (asset_id %s, pubkey_hash %s); submit an L1 bridge deposit first"
                       (Felt.to_hex asset_new) (Felt.to_hex pub.pubkey_hash))
          | Some bal when Int64.compare bal asset_debit < 0 ->
              Error (Printf.sprintf "deposit pool balance (%Ld) too small for v + fee (%Ld)" bal asset_debit)
          | Some _ ->
            match deposit_balance ledger ~asset_id:Asset_registry.asset_tez ~pubkey_hash:pub.pubkey_hash () with
            | None ->
                Error (Printf.sprintf "no tez deposit pool at pubkey_hash %s — non-tez shields require a separate tez pool to fund producer_fee (%Ld)"
                         (Felt.to_hex pub.pubkey_hash) producer_fee)
            | Some tez_bal when Int64.compare tez_bal producer_fee < 0 ->
                Error (Printf.sprintf "tez deposit pool balance (%Ld) too small for producer_fee (%Ld) — required because producer fees are permanently tez"
                         tez_bal producer_fee)
            | Some _ -> Ok ()
        end
      in
      match validation with
      | Error e -> Error e
      | Ok () ->
        (* Balances validated above; these debits cannot fail. *)
        (if is_tez then
           ignore (debit_deposit ledger ~asset_id:asset_new ~pubkey_hash:pub.pubkey_hash
                     ~amount:(Int64.add asset_debit producer_fee) ())
         else begin
           ignore (debit_deposit ledger ~asset_id:asset_new ~pubkey_hash:pub.pubkey_hash
                     ~amount:asset_debit ());
           ignore (debit_deposit ledger ~asset_id:Asset_registry.asset_tez ~pubkey_hash:pub.pubkey_hash
                     ~amount:producer_fee ())
         end);
        Hashtbl.replace ledger.applied_shield_cms cm_key ();
        append_commitment ledger pub.cm_new;
        append_commitment ledger pub.cm_producer;
        Ok ()
    end
  end

let apply_transfer ledger (pub : Transaction.transfer_public)
    ~memo_ct_hash_1 ~memo_ct_hash_2 ~memo_ct_hash_3 =
  if not (Felt.equal pub.auth_domain ledger.auth_domain) then
    Error "auth_domain mismatch"
  else if not (is_valid_root ledger pub.root) then
    Error "unknown root"
  else if not (Felt.equal memo_ct_hash_1 pub.memo_ct_hash_1) then
    Error "memo_ct_hash_1 mismatch"
  else if not (Felt.equal memo_ct_hash_2 pub.memo_ct_hash_2) then
    Error "memo_ct_hash_2 mismatch"
  (* Multiasset slot layout: slot 1 = recipient, 2 = change_1,
     3 = change_2 (the second-asset change, unused by single-asset
     transfers), 4 = producer-fee. The caller's [memo_ct_hash_3] is the
     producer memo (record slot 4). *)
  else if not (Felt.equal memo_ct_hash_3 pub.memo_ct_hash_4) then
    Error "memo_ct_hash_3 (producer) mismatch"
  else
    match check_and_insert_nullifiers ledger pub.nullifiers with
    | Error e -> Error e
    | Ok () ->
      append_commitment ledger pub.cm_1;
      append_commitment ledger pub.cm_2;
      (* slot 3 (change_2) is empty for single-asset transfers; skip the
         zero leaf. (cm_3 is always Felt.zero here.) *)
      append_commitment ledger pub.cm_4;
      Ok ()

let apply_unshield ledger ~recipient_string (pub : Transaction.unshield_public)
    ~memo_ct_hash_change ~memo_ct_hash_fee =
  match normalize_l1_withdrawal_recipient recipient_string with
  | Error e -> Error e
  | Ok recipient_string ->
  if not (Felt.equal pub.auth_domain ledger.auth_domain) then
    Error "auth_domain mismatch"
  else if not (is_valid_root ledger pub.root) then
    Error "unknown root"
  else if not (Felt.equal memo_ct_hash_fee pub.memo_ct_hash_fee) then
    Error "memo_ct_hash_fee mismatch"
  else
    let expected_recipient_id = Hash.account_id recipient_string in
    if not (Felt.equal expected_recipient_id pub.recipient_id) then
      Error "recipient_id mismatch"
    else
      match validate_nullifiers ledger pub.nullifiers with
      | Error e -> Error e
      | Ok () ->
        if not (Felt.is_zero pub.cm_change) then begin
          if not (Felt.equal memo_ct_hash_change pub.memo_ct_hash_change) then
            Error "memo_ct_hash_change mismatch"
          else begin
            insert_nullifiers ledger pub.nullifiers;
            append_commitment ledger pub.cm_change;
            append_commitment ledger pub.cm_fee;
            (* The withdrawal is routed at the L1 outbox by asset_pub: the
               matching ticketer burns it (ASSET_TEZ for tez). *)
            Queue.push (pub.asset_pub, recipient_string, pub.v_pub) ledger.withdrawals;
            Ok ()
          end
        end else begin
          insert_nullifiers ledger pub.nullifiers;
          append_commitment ledger pub.cm_fee;
          Queue.push (pub.asset_pub, recipient_string, pub.v_pub) ledger.withdrawals;
          Ok ()
        end

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

(* Per-pool aggregated deposit balance, keyed by the hex-encoded
   `deposit_pubkey_hash`. Each L1 ticket addressed to
   `deposit:<hex(pubkey_hash)>` increments the balance; shield
   decrements it. Pools at zero balance are removed to bound storage. *)
type t = {
  tree : Merkle.tree_with_leaves;
  nullifier_set : (string, unit) Hashtbl.t;
  root_set : (string, unit) Hashtbl.t;
  root_history : string Queue.t;
  withdrawals : (string * int64) Queue.t;
  auth_domain : Felt.t;
  deposit_balances : (string, int64) Hashtbl.t;
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

(* Credit an L1 bridge deposit to the pool keyed by `pubkey_hash`. Multiple
   deposits to the same `pubkey_hash` aggregate (top-up). *)
let credit_deposit ledger ~pubkey_hash ~amount =
  let key = Felt.to_hex pubkey_hash in
  let current =
    match Hashtbl.find_opt ledger.deposit_balances key with
    | None -> 0L
    | Some n -> n
  in
  Hashtbl.replace ledger.deposit_balances key (Int64.add current amount)

(* Debit `amount` from the pool keyed by `pubkey_hash`. Returns Error if the
   pool does not exist or its balance is below `amount`. When the resulting
   balance is zero the entry is removed to bound storage. *)
let debit_deposit ledger ~pubkey_hash ~amount =
  let key = Felt.to_hex pubkey_hash in
  match Hashtbl.find_opt ledger.deposit_balances key with
  | None ->
      Error (Printf.sprintf "deposit pool %s does not exist" key)
  | Some current when Int64.compare current amount < 0 ->
      Error (Printf.sprintf
               "deposit pool %s balance %Ld too small to debit %Ld"
               key current amount)
  | Some current ->
      let next = Int64.sub current amount in
      if Int64.compare next 0L = 0 then
        Hashtbl.remove ledger.deposit_balances key
      else
        Hashtbl.replace ledger.deposit_balances key next;
      Ok ()


let withdrawals ledger =
  let copy = Queue.copy ledger.withdrawals in
  let rec drain acc =
    if Queue.is_empty copy then List.rev acc
    else drain (Queue.pop copy :: acc)
  in
  drain []

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
    else
      let debit =
        Int64.add pub.v_pub (Int64.add pub.fee pub.producer_fee)
      in
      match debit_deposit ledger ~pubkey_hash:pub.pubkey_hash ~amount:debit with
      | Error e -> Error e
      | Ok () ->
        Hashtbl.replace ledger.applied_shield_cms cm_key ();
        append_commitment ledger pub.cm_new;
        append_commitment ledger pub.cm_producer;
        Ok ()
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
  else if not (Felt.equal memo_ct_hash_3 pub.memo_ct_hash_3) then
    Error "memo_ct_hash_3 mismatch"
  else
    match check_and_insert_nullifiers ledger pub.nullifiers with
    | Error e -> Error e
    | Ok () ->
      append_commitment ledger pub.cm_1;
      append_commitment ledger pub.cm_2;
      append_commitment ledger pub.cm_3;
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
            Queue.push (recipient_string, pub.v_pub) ledger.withdrawals;
            Ok ()
          end
        end else begin
          insert_nullifiers ledger pub.nullifiers;
          append_commitment ledger pub.cm_fee;
          Queue.push (recipient_string, pub.v_pub) ledger.withdrawals;
          Ok ()
        end

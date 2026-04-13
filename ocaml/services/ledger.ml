(* Reference ledger state machine.
   Maintains:
   - Append-only commitment Merkle tree (depth 48)
   - Global nullifier set
   - Historical root set (anchors)
   - Public balance accounts *)

let tree_depth = 48
let max_valid_roots = 4096

type t = {
  tree : Merkle.tree_with_leaves;
  nullifier_set : (string, unit) Hashtbl.t;
  root_set : (string, unit) Hashtbl.t;
  root_history : string Queue.t;
  balances : (string, int64) Hashtbl.t;
  auth_domain : Felt.t;
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
  let balances = Hashtbl.create 64 in
  let initial_root = Merkle.root_with_leaves tree in
  let initial_root_hex = Felt.to_hex initial_root in
  Hashtbl.replace root_set initial_root_hex ();
  Queue.push initial_root_hex root_history;
  { tree; nullifier_set; root_set; root_history; balances; auth_domain }

let get_balance ledger account =
  match Hashtbl.find_opt ledger.balances account with
  | Some b -> b
  | None -> 0L

let set_balance ledger account balance =
  Hashtbl.replace ledger.balances account balance

let current_root ledger = Merkle.root_with_leaves ledger.tree

let tree_size ledger = Merkle.size_with_leaves ledger.tree

let append_commitment ledger cm =
  let new_root = Merkle.append_with_leaves ledger.tree cm in
  record_root_with_limit ledger ~max_roots:max_valid_roots (Felt.to_hex new_root)

let is_valid_root ledger root =
  Hashtbl.mem ledger.root_set (Felt.to_hex root)

let check_and_insert_nullifiers ledger nullifiers =
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
    if already_spent then Error "nullifier already spent"
    else begin
      List.iter (fun nf ->
        Hashtbl.replace ledger.nullifier_set (Felt.to_hex nf) ()
      ) nullifiers;
      Ok ()
    end

let apply_shield ledger ~sender_string ~(pub : Transaction.shield_public)
    ~memo_ct_hash =
  let expected_sender_id = Hash.account_id sender_string in
  if not (Felt.equal expected_sender_id pub.sender_id) then
    Error "sender_id mismatch"
  else if not (Felt.equal memo_ct_hash pub.memo_ct_hash) then
    Error "memo_ct_hash mismatch"
  else begin
    let v = pub.v_pub in
    let bal = get_balance ledger sender_string in
    if Int64.compare bal v < 0 then
      Error "insufficient balance"
    else begin
      set_balance ledger sender_string (Int64.sub bal v);
      append_commitment ledger pub.cm_new;
      Ok ()
    end
  end

let apply_transfer ledger (pub : Transaction.transfer_public)
    ~memo_ct_hash_1 ~memo_ct_hash_2 =
  if not (Felt.equal pub.auth_domain ledger.auth_domain) then
    Error "auth_domain mismatch"
  else if not (is_valid_root ledger pub.root) then
    Error "unknown root"
  else if not (Felt.equal memo_ct_hash_1 pub.memo_ct_hash_1) then
    Error "memo_ct_hash_1 mismatch"
  else if not (Felt.equal memo_ct_hash_2 pub.memo_ct_hash_2) then
    Error "memo_ct_hash_2 mismatch"
  else
    match check_and_insert_nullifiers ledger pub.nullifiers with
    | Error e -> Error e
    | Ok () ->
      append_commitment ledger pub.cm_1;
      append_commitment ledger pub.cm_2;
      Ok ()

let apply_unshield ledger ~recipient_string (pub : Transaction.unshield_public)
    ~memo_ct_hash_change =
  if not (Felt.equal pub.auth_domain ledger.auth_domain) then
    Error "auth_domain mismatch"
  else if not (is_valid_root ledger pub.root) then
    Error "unknown root"
  else
    let expected_recipient_id = Hash.account_id recipient_string in
    if not (Felt.equal expected_recipient_id pub.recipient_id) then
      Error "recipient_id mismatch"
    else
      match check_and_insert_nullifiers ledger pub.nullifiers with
      | Error e -> Error e
      | Ok () ->
        let bal = get_balance ledger recipient_string in
        set_balance ledger recipient_string (Int64.add bal pub.v_pub);
        if not (Felt.is_zero pub.cm_change) then begin
          if not (Felt.equal memo_ct_hash_change pub.memo_ct_hash_change) then
            Error "memo_ct_hash_change mismatch"
          else begin
            append_commitment ledger pub.cm_change;
            Ok ()
          end
        end else
          Ok ()

(* tzel.mligo — Phase 2: the TzEL Michelson contract skeleton.

   Implements architecture doc §2.1 (storage), §2.2 (the 5 entrypoints) and
   §2.3 (the 5 binding/precondition checks), with the Layer-1 primitives
   STUBBED at clearly-marked seams:

     * VERIFY_SNARK  — `verify_snark` below returns true (placeholder for the
                       enshrined `VERIFY_SNARK :: bytes -> bytes -> list bytes
                       -> bool` runtime instruction, arch §1.1).
     * BLAKE2S       — provided by OutHash.blake2s, itself stubbed via a
                       lookup table (arch §1.2). The OutHash M31/QM31 PACKING
                       around it is REAL LIGO (Phase-1 derisk, all golden
                       vectors pass + compiles to Michelson).

   Value custody uses native Michelson tickets (decision 4): deposit JOINs a
   ticket into the held balance; unshield SPLITs + sends to the ticketer's
   %burn. Because storage mutation and the emitted internal op are one atomic
   Michelson operation, the rollup-era emit-before-mutate hazard vanishes. *)

#include "out_hash.mligo"
#include "merkle.mligo"
module O = OutHash
module M = Merkle

(* ── storage (arch §2.1) ─────────────────────────────────────────────── *)

type program_hashes = {
  shield   : bytes ;
  transfer : bytes ;
  unshield : bytes ;
}

(* `ledger` is the fully-DUPLICABLE part of the storage — no ticket — so
   `{ l with ... }` is legal everywhere. The custodied XTZ `ticket` is LINEAR
   (cannot be DUP'd), so it lives OUTSIDE this record (`storage.held`) and is
   threaded explicitly. This split is forced by Michelson ticket semantics:
   putting the ticket in a record that the entrypoints rebuild with
   `{ s with ... }` duplicates the ticket and the compiler rejects it. *)
type ledger = {
  (* identity / config (write-once, admin) *)
  admin           : address ;
  configured      : bool ;
  verifier_vk     : bytes ;                 (* Groth16 wrap vk (VERIFY_SNARK input) *)
  auth_domain     : bytes ;                 (* 32B — domain-separates this ledger *)
  program_hashes  : program_hashes ;
  bridge_ticketer : address ;              (* KT1 minting/burning XTZ tickets *)
  blake_table     : O.blake_table ;        (* BLAKE2S (OutHash) seam (prototype only) *)
  blake_mrkl      : M.blake_mrkl ;         (* BLAKE2S(mrklSP__) seam (prototype only) *)
  zero_hashes     : (nat, bytes) map ;     (* zero_hashes[0..DEPTH], empty-subtree nodes *)

  (* shielded ledger *)
  commitment_root : bytes ;
  commitment_size : nat ;
  frontier        : M.frontier ;           (* level -> filled frontier node (DEPTH=48) *)
  notes           : (nat, bytes) big_map ;  (* index -> encrypted note payload *)
  nullifiers      : (bytes, unit) big_map ;
  roots           : (bytes, unit) big_map ;
  roots_fifo      : bytes list ;
  applied_shields : (bytes, unit) big_map ;  (* client_cm -> replay marker *)

  (* bridge *)
  deposits        : (bytes, nat) big_map ;   (* pubkey_hash -> escrowed mutez *)
}

type storage = {
  l    : ledger ;
  held : bytes ticket option ;   (* custodied XTZ ticket (linear) *)
}

(* ── operation publics (arch §2.2) ───────────────────────────────────────
   `op_publics` is the bootloader output_preimage + the proof envelope's
   public part. For the prototype we carry the fields the 5 checks need;
   the exact felt layout is parsed by the wallet/circuit and re-derived here. *)

type op_publics = {
  output_preimage  : bytes list ;   (* felts (32-byte BE each) — OutHash input *)
  program_hash     : bytes ;        (* circuit identity, in the preimage *)
  auth_domain      : bytes ;        (* ledger identity, in the preimage *)
  tree_root0       : bytes ;        (* TreeRoots[0], 32 raw bytes *)
  out_hash_lanes   : nat list ;     (* the 8 OutHash lanes the proof attests *)
  root             : bytes ;        (* merkle root the op was proved against *)
  nullifiers       : bytes list ;   (* spent-note markers (transfer/unshield) *)
  commitments      : bytes list ;   (* new note commitments *)
  client_cm        : bytes ;        (* shield replay marker *)
  pubkey_hash      : bytes ;        (* deposit account (shield) *)
  value            : nat ;          (* shield/unshield amount *)
  fee              : nat ;
  recipient        : address ;      (* unshield L1 recipient *)
  memo_hashes      : bytes list ;   (* per-enc-note memo bindings *)
}

type shield_param   = { proof : bytes ; publics : op_publics ; enc_notes : bytes list }
type transfer_param = { proof : bytes ; publics : op_publics ; enc_notes : bytes list }
type unshield_param = { proof : bytes ; publics : op_publics ; enc_notes : bytes list }

type configure_param = {
  vk             : bytes ;
  auth_domain    : bytes ;
  program_hashes : program_hashes ;
  ticketer       : address ;
  blake_table    : O.blake_table ;
  blake_mrkl     : M.blake_mrkl ;
}

(* ── Layer-1 VERIFY_SNARK seam (arch §1.1) ───────────────────────────────
   STUB. Returns true. The real deploy replaces this with the enshrined
   `VERIFY_SNARK` instruction:
     VERIFY_SNARK verifier_vk proof [tree_roots ‖ out_hash]  : bool
   Here we only model its signature/seam so the surrounding state machine —
   the least-certain part of the feasibility study — can be exercised. *)
let verify_snark (_vk : bytes) (_proof : bytes) (_publics : bytes list) : bool =
  true   (* <<< VERIFY_SNARK PRECOMPILE SEAM — replace with runtime instruction *)

(* ── the 5 checks (arch §2.3) ────────────────────────────────────────── *)

(* Check 1 — SNARK verify. Public inputs = 4 tree roots ‖ 8 OutHash lanes
   (each lane as 32-byte BE field element). *)
let check_snark (l : ledger) (p : op_publics) (proof : bytes) : unit =
  let lane_be (x : nat) : bytes = O.pad_left 32n (bytes x) in
  let lane_inputs = List.map lane_be p.out_hash_lanes in
  let inputs = p.tree_root0 :: lane_inputs in
  if verify_snark l.verifier_vk proof inputs then ()
  else failwith "TzEL: SNARK verification failed"

(* Check 2 — proof<->operation binding: recompute OutHash from op_publics via
   the Phase-1 chain and assert it equals the proof's OutHash lanes.
   Single-op v1 = depth-1 mv tree; here we use the leaf-mode derivation
   (felt preimage -> leaf output -> wrap OutHash). *)
let rec nat_list_eq (a : nat list) (b : nat list) : bool =
  match a, b with
  | [], [] -> true
  | x :: xs, y :: ys -> if x = y then nat_list_eq xs ys else false
  | _, _ -> false

let check_out_hash_binding (l : ledger) (p : op_publics) : unit =
  let leaf = O.compute_output_hash_values l.blake_table p.output_preimage in
  let expected = O.compute_expected_out_hash l.blake_table p.tree_root0 leaf in
  if nat_list_eq expected p.out_hash_lanes then ()
  else failwith "TzEL: output_preimage does not match proof OutHash"

(* Check 3 — circuit binding: program_hash matches this entrypoint's pinned
   hash, and auth_domain matches this ledger. *)
let check_circuit_binding (l : ledger) (p : op_publics) (expected_program : bytes) : unit =
  let () = if p.program_hash = expected_program then ()
           else failwith "TzEL: wrong circuit (program_hash mismatch)" in
  if p.auth_domain = l.auth_domain then ()
  else failwith "TzEL: wrong ledger (auth_domain mismatch)"

(* Check 4 — memo binding: BLAKE2S(enc_note) = proof's memo hash, per note. *)
let check_memo_binding (l : ledger) (p : op_publics) (enc_notes : bytes list) : unit =
  let tbl = l.blake_table in
  let rec go (memos : bytes list) (encs : bytes list) : unit =
    match memos, encs with
    | [], [] -> ()
    | mh :: mt, en :: et ->
        if O.blake2s tbl en = mh then go mt et
        else failwith "TzEL: enc_note memo hash mismatch"
    | _, _ -> failwith "TzEL: memo/enc_note count mismatch"
  in go p.memo_hashes enc_notes

(* nullifier preconditions (check 4, transfer/unshield): each absent and
   unique within the batch. *)
let check_nullifiers_fresh (l : ledger) (nfs : bytes list) : unit =
  let rec go (seen : (bytes, unit) map) (xs : bytes list) : unit =
    match xs with
    | [] -> ()
    | nf :: rest ->
        let () = if Big_map.mem nf l.nullifiers
                 then failwith "TzEL: nullifier already spent" else () in
        let () = if Map.mem nf seen
                 then failwith "TzEL: duplicate nullifier in batch" else () in
        go (Map.add nf () seen) rest
  in go (Map.empty : (bytes, unit) map) nfs

(* ── ledger mutation helpers (check 5 commit) — all on `ledger` (no ticket,
   freely duplicable) ──────────────────────────────────────────────────── *)

let insert_nullifiers (l : ledger) (nfs : bytes list) : ledger =
  let nullifiers =
    List.fold_left (fun (m, nf : (bytes, unit) big_map * bytes) -> Big_map.add nf () m)
      l.nullifiers nfs in
  { l with nullifiers }

(* Append commitments: REAL incremental Merkle frontier (merkle.mligo, mirroring
   kernel append_note). Each commitment is appended at the running tree index;
   the frontier slots, root and size advance exactly as the Rust kernel. The
   enc_notes are stored at the matching leaf index (1:1 with commitments).
   The new root is snapshotted into the valid-roots set + fifo history. *)
let append_commitments (l : ledger) (cms : bytes list) (enc_notes : bytes list) : ledger =
  let tbl = l.blake_mrkl in
  let zh = l.zero_hashes in
  (* fold over (commitment, enc_note) pairs, threading frontier/root/size/notes.
     The two lists must be 1:1 (one note per new commitment). *)
  let rec go
      (frontier : M.frontier) (root : bytes) (size : nat)
      (notes : (nat, bytes) big_map)
      (cs : bytes list) (es : bytes list)
      : M.frontier * bytes * nat * (nat, bytes) big_map =
    match cs, es with
    | [], [] -> (frontier, root, size, notes)
    | cm :: cs, en :: es ->
        let notes = Big_map.add size en notes in
        let (frontier, root, size) = M.append_one tbl zh frontier size cm in
        go frontier root size notes cs es
    | _, _ -> (failwith "TzEL: commitment/enc_note count mismatch" :
                 M.frontier * bytes * nat * (nat, bytes) big_map)
  in
  let (frontier, new_root, size, notes) =
    go l.frontier l.commitment_root l.commitment_size l.notes cms enc_notes in
  let roots = Big_map.add new_root () l.roots in
  { l with frontier ; notes ; commitment_size = size ;
           commitment_root = new_root ;
           roots ; roots_fifo = new_root :: l.roots_fifo }

(* ── entrypoints (arch §2.2) ─────────────────────────────────────────── *)

[@entry]
let configure (cfg : configure_param) (s : storage) : operation list * storage =
  let { l ; held } = s in
  let () = if Tezos.get_sender () <> l.admin then failwith "TzEL: not admin" else () in
  let () = if l.configured then failwith "TzEL: already configured" else () in
  (* re-derive zero_hashes + the empty-tree root from the supplied mrkl table,
     and reset the commitment tree to empty (configure is write-once admin). *)
  let zero_hashes = M.zero_hashes cfg.blake_mrkl in
  let empty_root = M.empty_root zero_hashes in
  let l = { l with configured = true ;
                   verifier_vk = cfg.vk ;
                   auth_domain = cfg.auth_domain ;
                   program_hashes = cfg.program_hashes ;
                   bridge_ticketer = cfg.ticketer ;
                   blake_table = cfg.blake_table ;
                   blake_mrkl = cfg.blake_mrkl ;
                   zero_hashes ;
                   frontier = (Map.empty : M.frontier) ;
                   commitment_size = 0n ;
                   commitment_root = empty_root ;
                   roots = Big_map.add empty_root () l.roots ;
                   roots_fifo = empty_root :: l.roots_fifo } in
  ([] : operation list), { l ; held }

(* %deposit — bridge ticketer delivers (pubkey_hash, ticket); join into held,
   credit deposits[pubkey_hash] += amount (decision 4). *)
[@entry]
let deposit (param : bytes * bytes ticket) (s : storage) : operation list * storage =
  let { l ; held } = s in
  let (pubkey_hash, tkt) = param in
  let ((ticketer, (_payload, amount)), tkt) = Tezos.read_ticket tkt in
  let () = if ticketer <> l.bridge_ticketer then failwith "TzEL: ticket not from bridge" else () in
  let held =
    match held with
    | None -> Some tkt
    | Some h -> Tezos.join_tickets (h, tkt) in
  let prev = match Big_map.find_opt pubkey_hash l.deposits with Some n -> n | None -> 0n in
  let deposits = Big_map.add pubkey_hash (prev + amount) l.deposits in
  ([] : operation list), { l = { l with deposits } ; held }

[@entry]
let shield (param : shield_param) (s : storage) : operation list * storage =
  let { l ; held } = s in
  let p = param.publics in
  (* checks 1-3 *)
  let () = check_snark l p param.proof in
  let () = check_out_hash_binding l p in
  let () = check_circuit_binding l p l.program_hashes.shield in
  (* check 4: deposit sufficiency + replay + memo *)
  let deposited = match Big_map.find_opt p.pubkey_hash l.deposits with Some n -> n | None -> 0n in
  let () = if deposited >= p.value + p.fee then ()
           else failwith "TzEL: insufficient deposit" in
  let () = if Big_map.mem p.client_cm l.applied_shields
           then failwith "TzEL: shield replay" else () in
  let () = check_memo_binding l p param.enc_notes in
  (* check 5: commit — debit deposit, mark replay, append commitments *)
  let deposits = Big_map.add p.pubkey_hash (abs (deposited - (p.value + p.fee))) l.deposits in
  let applied_shields = Big_map.add p.client_cm () l.applied_shields in
  let l = { l with deposits ; applied_shields } in
  let l = append_commitments l p.commitments param.enc_notes in
  ([] : operation list), { l ; held }

[@entry]
let transfer (param : transfer_param) (s : storage) : operation list * storage =
  let { l ; held } = s in
  let p = param.publics in
  let () = check_snark l p param.proof in
  let () = check_out_hash_binding l p in
  let () = check_circuit_binding l p l.program_hashes.transfer in
  (* check 4: valid (possibly stale) root + fresh nullifiers + memo *)
  let () = if Big_map.mem p.root l.roots then () else failwith "TzEL: unknown root" in
  let () = check_nullifiers_fresh l p.nullifiers in
  let () = check_memo_binding l p param.enc_notes in
  (* check 5: insert nullifiers, append commitments *)
  let l = insert_nullifiers l p.nullifiers in
  let l = append_commitments l p.commitments param.enc_notes in
  ([] : operation list), { l ; held }

[@entry]
let unshield (param : unshield_param) (s : storage) : operation list * storage =
  let { l ; held } = s in
  let p = param.publics in
  let () = check_snark l p param.proof in
  let () = check_out_hash_binding l p in
  let () = check_circuit_binding l p l.program_hashes.unshield in
  let () = if Big_map.mem p.root l.roots then () else failwith "TzEL: unknown root" in
  let () = check_nullifiers_fresh l p.nullifiers in
  let () = check_memo_binding l p param.enc_notes in
  (* check 5: SPLIT held ticket for v_pub, emit burn FIRST (atomic in
     Michelson), then mutate the tree. Decision 4. *)
  let tkt = match held with Some h -> h | None -> (failwith "TzEL: no custody" : bytes ticket) in
  let ((_, (_, total)), tkt) = Tezos.read_ticket tkt in
  let () = if total >= p.value then () else failwith "TzEL: custody underflow" in
  let (out_tkt, rest) =
    match Tezos.split_ticket tkt (p.value, abs (total - p.value)) with
    | Some pair -> pair
    | None -> (failwith "TzEL: split failed" : bytes ticket * bytes ticket) in
  let burn : (bytes * bytes ticket) contract =
    Tezos.get_entrypoint "%burn" l.bridge_ticketer in
  let op = Tezos.transaction (Bytes.pack p.recipient, out_tkt) 0mutez burn in
  let l = insert_nullifiers l p.nullifiers in
  let l = append_commitments l p.commitments param.enc_notes in
  [op], { l ; held = Some rest }

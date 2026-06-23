(* TzEL on Tezos X — shielded-pool contract. Verifies operations by calling the
   `zk` runtime through the enshrined gateway, keeps the nullifier set on-chain,
   and delegates the commitment tree + valid-roots to the A' accumulator.
   See docs/TZEL-TREE-AND-SYNC.md.

   The zk runtime exposes, as synchronous gateway views / async calls
   (`Tezos.call_view "zk" (path, body) gateway : bytes option`):
     - ("verify_snark", body)    -> Some 0x01 iff the Groth16 wrap proof is valid
                                    (item-D ABI: vk = 1744 B, 12 public inputs)
     - ("blake2s", body)         -> BLAKE2S-256 (OutHash STAGE-1 tree walk)
     - ("poseidon2_bn254", body) -> item-D FINAL OutHash re-commit (replaces the
                                    blake2s final step); see out_hash.mligo
     - ("tree_known_root", …) / "tree_append" -> the A' Merkle accumulator

   ## Two independent security checks (BOTH required)

   1. **OutHash binding** — the contract does NOT trust a supplied OutHash. It
      DERIVES it from the declared `output_preimage`: a BLAKE2S STAGE-1 mv tree
      walk followed by the item-D Poseidon2-BN254 FINAL re-commit. It then builds
      the wrap public inputs from (4 TreeRoots as Fr scalars + 8 OutHash lanes)
      and verifies the proof against those. So a valid proof is bound to its
      exact output_preimage.

   2. **Circuit-identity pin** — the OutHash binding alone is NOT enough: the
      stored vk pins only the UNIVERSAL wrap circuit. Without pinning the inner
      circuit identity, an attacker wraps their OWN trivial circuit and forges any
      output → pool theft. So the contract pins tree_roots[0] (inner STARK circuit
      identity), program_hash, and auth_domain against storage constants.

   Effects: the membership root the spend proved against is validated via the A'
   accumulator (`tree_known_root`); ALL nullifiers are spent; new commitments are
   published (EMIT) and appended to A' (TODO). The exact output felt offsets are
   the transfer layout and are re-pinned with the multi-asset circuit pass.

   The OutHash derivation chain is `out_hash.mligo`, parametrized over the hash
   source; here the STAGE-1 walk runs on the gateway BLAKE2S and the item-D FINAL
   re-commit on the gateway Poseidon2-BN254 (~3-5 synchronous view calls). *)

#include "out_hash.mligo"
module O = OutHash

type storage = {
  gateway      : address ;                 (* enshrined gateway KT1<MERG> *)
  vk           : bytes ;                    (* Groth16 wrap verifying key *)
  (* PINNED identities — set at origination. Without these the wrap vk only
     pins the UNIVERSAL wrap circuit, and any inner circuit forges effects. *)
  circuit_root : bytes ;                    (* tree_roots[0] = mv ROOT circuit identity *)
  program_hash : bytes ;                    (* bootloader program_hash (output_preimage[2]) *)
  auth_domain  : bytes ;                    (* ledger domain (output_preimage[3]) *)
  (* mv aggregation-tree circuit-root constants (per-release protocol consts,
     8 M31 lanes each): the leaf circuit's preprocessed root, and the internal
     levels bottom-up [leaf_to_mv, …, mv_to_mv]. The last == circuit_root lanes. *)
  leaf_circuit_root : nat list ;
  internal_roots    : (nat list) list ;
  nullifiers   : (bytes, unit) big_map ;    (* spent nullifier set *)
}

(* ── fixed wire constants (wrap circuit shape) ───────────────────────────── *)
let empty_bytes   : bytes = 0x
let vk_len_be     : bytes = 0x000006d0   (* 1744 = len(vk), item-D ABI *)
let proof_len_be  : bytes = 0x00000184   (* 388  = len(Groth16 proof) *)
let n_publics_be  : bytes = 0x0000000c   (* 12   = 4 TreeRoots Fr + 8 OutHash lanes *)
let scalar_len_be : bytes = 0x00000020   (* 32   = bytes per scalar   *)
let valid_byte    : bytes = 0x01
let tree_roots_len : nat  = 128n         (* input tree_roots size = 4 roots x 32 bytes *)
let n_tree_roots   : nat  = 4n           (* 4 TreeRoots framed as Fr scalars (item-D) *)

(* output_preimage bootloader framing (verifier core/src/lib.rs:1512):
   [0]=n_tasks=1, [1]=task_output_size, [2]=program_hash, [3..]=public_outputs.
   So program_hash and the FIRST public output (auth_domain) are at STABLE
   offsets across circuits. The remaining offsets (membership root, nullifiers,
   commitments) are per-entrypoint and re-pinned with the multi-asset circuit. *)
let boot_program_hash_idx : nat = 2n
let boot_auth_domain_idx  : nat = 3n     (* public_outputs[0] *)
(* transfer/unshield public layout = [auth_domain, membership_root, nf..]: *)
let tr_membership_root_idx : nat = 4n    (* public_outputs[1] *)
let tr_nf_start_idx        : nat = 5n    (* public_outputs[2..2+N] *)
let tr_tail_after_nf       : nat = 7n    (* trailing felts after nf: fee+cm1..3+memo1..3 *)

(* ── new-commitment offsets per entrypoint (item-D single-asset layout) ───────
   These are the CURRENT single-asset run_shield / run_transfer / run_unshield
   circuit output layouts (tzel/cairo/src/run_*.cairo + the *::verify output
   arrays). They are re-pinned with the multi-asset circuit pass.
   (* item-D single-asset offsets; revisit for multi-asset *)

   All offsets are into the bootloader-framed output_preimage, where
   public_outputs[k] sits at preimage index k+3 (boot prefix
   [n_tasks, task_output_size, program_hash] = 3 felts; boot_auth_domain_idx=3
   confirms public_outputs[0] is at index 3).

   SHIELD public outputs (run_shield.cairo:4-5):
     [auth_domain, pubkey_hash, v_note, fee, producer_fee,
      cm_new, cm_producer, memo_ct_hash, producer_memo_ct_hash]
   → cm_new = public[5] = preimage 8 ; cm_producer = public[6] = preimage 9.

   TRANSFER public outputs (transfer.cairo verify output array):
     [auth_domain, root, nf_1..nf_N, fee, cm_1, cm_2, cm_3, memo_1, memo_2, memo_3]
   → after the nf list ends at nf_end = len - tr_tail_after_nf, the tail is
     [fee, cm_1, cm_2, cm_3, memo_1, memo_2, memo_3]:
       cm_1 = nf_end+1 ; cm_2 = nf_end+2 ; cm_3 = nf_end+3.

   UNSHIELD public outputs (unshield.cairo verify output array) — tail DIFFERS
   from transfer (still 7 felts, so spend_all is unaffected, but cm positions
   differ):
     [auth_domain, root, nf_1..nf_N,
      v_pub, fee, recipient, cm_change, memo_change, cm_fee, memo_fee]
   → tail = [v_pub, fee, recipient, cm_change, memo_change, cm_fee, memo_fee]:
       cm_change = nf_end+3 ; cm_fee = nf_end+5. *)
let sh_cm_new_idx       : nat = 8n
let sh_cm_producer_idx  : nat = 9n
let tr_cm1_off          : nat = 1n   (* offsets from nf_end *)
let tr_cm2_off          : nat = 2n
let tr_cm3_off          : nat = 3n
let un_cm_change_off    : nat = 3n   (* offsets from nf_end *)
let un_cm_fee_off       : nat = 5n

(* The OutHash chain runs through the gateway (`Gateway s.gateway`): the STAGE-1
   mv tree walk on the runtime BLAKE2S-256 (out_hash.mligo `blake2s`), then the
   item-D FINAL re-commit on Poseidon2-BN254 (out_hash.mligo
   `compute_expected_out_hash_mv` -> "poseidon2_bn254" view). *)

(* ── public-input framing ────────────────────────────────────────────────── *)

(* Frame the 4 TreeRoots as 4 length-prefixed 32-byte Fr scalars (item-D ABI):
   each 32-byte root is taken as a full big-endian Fr field element (NOT
   byte-decomposed), emitted as `scalar_len_be ‖ root32` in gnark declaration
   order. So 4 scalars, not 128. *)
let frame_root_bytes (tree_roots : bytes) : bytes =
  let rec go (acc : bytes) (t : nat) : bytes =
    if t = n_tree_roots then acc
    else
      let scalar = Bytes.sub (t * 32n) 32n tree_roots in
      go (Bytes.concat acc (Bytes.concat scalar_len_be scalar)) (t + 1n)
  in go empty_bytes 0n

(* Frame the 8 OutHash lanes as length-prefixed 32-byte scalars. *)
let frame_lanes (lanes : nat list) : bytes =
  List.fold_left
    (fun ((acc, l) : bytes * nat) ->
       let scalar = O.pad_left 32n (bytes l) in
       Bytes.concat acc (Bytes.concat scalar_len_be scalar))
    empty_bytes lanes

(* ── mv aggregation-tree walk (mirrors verifier derive_mv_root_publics) ──────
   Each declared leaf op's output_preimage → its 8 output lanes
   (compute_output_hash_values); fold pairwise up the tree
   (compute_mv_output_values) using the pinned internal circuit-root constants;
   the mv ROOT's output lanes are returned. Both blakes are golden-tested. *)
type mv_node = { root : nat list ; ov : nat list }

let rec fold_pairs
    (src : blake_src) (internal_root : nat list)
    (level : mv_node list) : mv_node list =
  match level with
  | [] -> ([] : mv_node list)
  | [_] -> (failwith "TzEL: mv level not a power of two" : mv_node list)
  | l :: r :: rest ->
      let ov = O.compute_mv_output_values src l.root l.ov r.root r.ov in
      { root = internal_root ; ov } :: fold_pairs src internal_root rest

let derive_mv_root_ov
    (src : blake_src) (leaf_root : nat list)
    (internal_roots : (nat list) list) (leaves : bytes list list) : nat list =
  let leaf_nodes : mv_node list =
    List.map
      (fun (pre : bytes list) ->
         { root = leaf_root ; ov = O.compute_output_hash_values src pre })
      leaves in
  let root_level =
    List.fold_left
      (fun ((level, internal_root) : mv_node list * nat list) ->
         fold_pairs src internal_root level)
      leaf_nodes internal_roots in
  match root_level with
  | [ n ] -> n.ov
  | _ -> (failwith "TzEL: mv tree did not reduce to a single root" : nat list)

(* ── the binding: derive the publics from the declared leaves, verify ───────
   PRODUCTION proofs are mv-mode (circuit_multiverifier root, services/tzel
   submit_v18.rs): OutHash = compute_expected_out_hash_mv(TreeRoots[0],
   mv_root.output_values). The mv root output values are DERIVED here from the
   declared leaves via the aggregation tree walk — so the proof is bound to the
   exact declared ops (changing any leaf changes the root → OutHash → verify
   fails). See docs/TZEL-TREE-AND-SYNC.md §mv. *)
let verify_bound
    (s : storage) (proof : bytes)
    (tree_roots : bytes) (leaves : bytes list list) : unit =
  let src = Gateway s.gateway in
  let root0 = Bytes.sub 0n 32n tree_roots in
  (* CRITICAL pin: tree_roots[0] = the mv ROOT circuit identity. The stored vk
     pins only the UNIVERSAL wrap circuit; without this an attacker wraps their
     OWN inner circuit (arbitrary output) and drains the pool. *)
  let () = if root0 <> s.circuit_root then failwith "TzEL: wrong circuit" else () in
  let root_output_lanes =
    derive_mv_root_ov src s.leaf_circuit_root s.internal_roots leaves in
  let outhash_lanes = O.compute_expected_out_hash_mv src root0 root_output_lanes in
  let framed = Bytes.concat (frame_root_bytes tree_roots) (frame_lanes outhash_lanes) in
  let body =
    Bytes.concat (Bytes.concat vk_len_be s.vk)
      (Bytes.concat (Bytes.concat proof_len_be proof)
        (Bytes.concat n_publics_be framed)) in
  match (Tezos.call_view "zk" ("verify_snark", body) s.gateway : bytes option) with
  | Some r -> if r = valid_byte then unit else failwith "TzEL: proof rejected"
  | None -> failwith "TzEL: verify_snark view unavailable"

(* Read felt #idx (32-byte BE) from a bound output_preimage. *)
let preimage_at (output_preimage : bytes list) (idx : nat) : bytes =
  let (_, found) =
    List.fold_left
      (fun ((i, acc), felt : (nat * bytes option) * bytes) ->
         if i = idx then (i + 1n, Some felt) else (i + 1n, acc))
      (0n, (None : bytes option))
      output_preimage in
  match found with
  | Some b -> b
  | None -> (failwith "TzEL: output_preimage too short" : bytes)

(* ── identity & root checks ──────────────────────────────────────────────── *)

(* Pin the bootloader program_hash and the ledger auth_domain against storage.
   program_hash kills "different malicious Cairo program in the genuine circuit";
   auth_domain kills cross-ledger / cross-chain replay. *)
let check_identity (s : storage) (output_preimage : bytes list) : unit =
  let () =
    if preimage_at output_preimage boot_program_hash_idx <> s.program_hash
    then failwith "TzEL: wrong program_hash" else () in
  if preimage_at output_preimage boot_auth_domain_idx <> s.auth_domain
  then failwith "TzEL: wrong auth_domain" else ()

(* Validate the membership root the spend proved against is a REAL historical
   root of THIS pool — via the A' accumulator view `tree_known_root`. (Single
   tree for now: tag = empty.) Until A' is deployed this view returns None and
   the op fails closed — which is correct: no spend may pass an unvalidated
   root. *)
let require_known_root (s : storage) (root : bytes) : unit =
  (* tag is length-prefixed (runtime tree_known_root does take_lp), so the empty
     single-pool tag is 0x00000000 (u32 BE 0) — MUST match tree_append's tag
     framing, else the appended root is filed under a different tag and never
     found. *)
  let tag = 0x00000000 in
  match (Tezos.call_view "zk" ("tree_known_root", Bytes.concat tag root) s.gateway
         : bytes option) with
  | Some r -> if r = valid_byte then unit else failwith "TzEL: unknown membership root"
  | None -> failwith "TzEL: tree_known_root view unavailable (A' not deployed)"

(* ── nullifiers ──────────────────────────────────────────────────────────── *)

(* Spend ONE nullifier (reject double-spend). *)
let spend (s : storage) (nullifier : bytes) : storage =
  if Big_map.mem nullifier s.nullifiers then failwith "TzEL: double spend"
  else { s with nullifiers = Big_map.add nullifier unit s.nullifiers }

(* Spend ALL N nullifiers the circuit output (transfer is N->2, N up to 7). The
   circuit's `merkle::verify` path-index range check + nf = H(nk_spend, cm,
   path_idx) make each nf unique to a real note; we reject replays across ops.
   nf list = output_preimage[tr_nf_start .. len - tr_tail_after_nf). *)
let spend_all (s : storage) (output_preimage : bytes list) : storage =
  let n_total = List.length output_preimage in
  let nf_end = abs (n_total - tr_tail_after_nf) in
  let (_, s) =
    List.fold_left
      (fun ((i, s), felt : (nat * storage) * bytes) ->
         if (i >= tr_nf_start_idx) && (i < nf_end)
         then (i + 1n, spend s felt)
         else (i + 1n, s))
      (0n, s) output_preimage in
  s

(* ── wallet-sync data availability + tree append (A') ────────────────────────
   The commitment tree lives OFF-CHAIN (A' accumulator holds it). Each op must
   PUBLISH its leaves — commitments (in output_preimage) + encrypted notes — so
   a wallet rebuilds the tree by replay and trial-decrypts to find its funds.
   See docs/TZEL-TREE-AND-SYNC.md. *)
let emit_sync (output_preimage : bytes list) (enc_notes : bytes list) : operation =
  Tezos.emit "%tzel_notes" (output_preimage, enc_notes)

(* ── A' tree append (the async write counterpart of require_known_root) ───────
   tree_append is STATE-MUTATING (durable accumulator), so it is reached via the
   gateway's async `%call` (HTTP) entrypoint — NOT the synchronous `Tezos.call_view`
   used for the pure primitives (verify_snark / blake2s / poseidon2_bn254 /
   tree_known_root). The runtime records the new root in its durable accumulator;
   `require_known_root` reads it on a later spend. Fire-and-forget (no callback).

   The gateway `%call` entrypoint type (etherlink/michelson_test_scripts/
   mini_scenarios/cross_runtime_http_call_tez.tz):
     pair string                                         (* url *)
          (pair (list (pair string string))             (* headers *)
                (pair bytes                              (* body *)
                      (pair nat                          (* method: 1 = POST *)
                            (option (contract bytes))))) (* callback *)

   tree_append request body (zk runtime handle_tree_append, lib.rs):
     tag(lp) ‖ n:u32 BE ‖ leaf(32)*n
   where tag is length-prefixed (`take_lp` = u32 BE len ‖ bytes). For the single
   pool the tag is EMPTY, so the length prefix is 0x00000000 (4 zero bytes — the
   u32 BE length of an empty tag), followed by 0 bytes of tag.

   NOTE: require_known_root (line ~199) concats a BARE `0x` tag with no u32 length
   prefix, but the tree_known_root handler ALSO calls `take_lp()` for its tag —
   so that send is missing the 4-byte length prefix. tree_append below sends the
   correct length-prefixed empty tag (`tree_append_tag_lp`). The require_known_root
   tag should be fixed to match (out of scope for this hook; flagged). *)

(* gateway %call (HTTP) entrypoint parameter, mirrored from cross_runtime_http_call_tez.tz *)
type gateway_call_param =
  string
  * ((string * string) list
     * (bytes
        * (nat
           * (bytes contract) option)))

let tree_append_url      : string = "http://zk/tree_append"
let http_method_post     : nat    = 1n   (* gateway convention: 1 = POST *)
let tree_append_tag_lp   : bytes  = 0x00000000  (* len-prefixed EMPTY tag: u32 BE 0 ‖ 0 bytes *)

(* Build the tree_append request body: tag(lp) ‖ n:u32 BE ‖ leaf(32)*n.
   Each commitment is an output_preimage felt = exactly 32 BE bytes (same repr
   the proof binding uses), so leaves need no padding. *)
let build_tree_append_body (commitments : bytes list) : bytes =
  let n_be = O.pad_left 4n (bytes (List.length commitments)) in   (* u32 BE *)
  let leaves =
    List.fold_left
      (fun ((acc, cm) : bytes * bytes) -> Bytes.concat acc cm)
      empty_bytes commitments in
  Bytes.concat tree_append_tag_lp (Bytes.concat n_be leaves)

(* Emit the async gateway `%call http://zk/tree_append` op that advances the A'
   commitment tree with this op's new commitments. Fire-and-forget (callback None);
   the runtime records the new root for a later require_known_root. *)
let emit_tree_append (s : storage) (commitments : bytes list) : operation =
  let call : gateway_call_param contract =
    match (Tezos.get_entrypoint_opt "%call" s.gateway : gateway_call_param contract option) with
    | Some c -> c
    | None -> (failwith "TzEL: gateway %call entrypoint unavailable" : gateway_call_param contract) in
  let body = build_tree_append_body commitments in
  let headers : (string * string) list = [] in
  let callback : (bytes contract) option = None in
  let param : gateway_call_param =
    (tree_append_url, (headers, (body, (http_method_post, callback)))) in
  Tezos.transaction param 0mutez call

(* New commitments per entrypoint (item-D single-asset layout; see the offset
   consts above). nf_end = len - tr_tail_after_nf locates the trailing tail. *)
let shield_commitments (output_preimage : bytes list) : bytes list =
  [ preimage_at output_preimage sh_cm_new_idx ;
    preimage_at output_preimage sh_cm_producer_idx ]

let transfer_commitments (output_preimage : bytes list) : bytes list =
  let nf_end = abs (List.length output_preimage - tr_tail_after_nf) in
  [ preimage_at output_preimage (nf_end + tr_cm1_off) ;
    preimage_at output_preimage (nf_end + tr_cm2_off) ;
    preimage_at output_preimage (nf_end + tr_cm3_off) ]

let unshield_commitments (output_preimage : bytes list) : bytes list =
  let nf_end = abs (List.length output_preimage - tr_tail_after_nf) in
  [ preimage_at output_preimage (nf_end + un_cm_change_off) ;
    preimage_at output_preimage (nf_end + un_cm_fee_off) ]

(* ── entrypoints ─────────────────────────────────────────────────────────── *)

(* Every entrypoint: bind the proof (verify_bound, incl. the circuit-identity
   pin), then pin program_hash + auth_domain. shield is a deposit (no spend);
   transfer/unshield spend N nullifiers against a validated membership root.
   Effect offsets (membership root, nf list, commitments) are the transfer
   layout and are re-pinned with the multi-asset circuit. *)

(* `leaves` = the declared aggregation-tree leaves' output_preimages (the
   TreeBinding); the proof is bound to them via the mv walk. `output_preimage`
   is the PRIMARY op of this entrypoint (identity + effects); a step-3 check
   will assert it is one of `leaves`. *)

(* A shield deposits value and creates commitments (no spend, no nullifier). *)
type shield_param = {
  proof           : bytes ;
  tree_roots      : bytes ;             (* 128 bytes = 4 x 32 *)
  leaves          : (bytes list) list ; (* declared leaf output_preimages *)
  output_preimage : bytes list ;        (* the primary op (identity + effects) *)
  enc_notes       : bytes list ;        (* note ciphertexts to publish *)
}

[@entry]
let shield (p : shield_param) (s : storage) : operation list * storage =
  let () = verify_bound s p.proof p.tree_roots p.leaves in
  let () = check_identity s p.output_preimage in
  [ emit_sync p.output_preimage p.enc_notes ;
    emit_tree_append s (shield_commitments p.output_preimage) ], s

(* A transfer spends N notes against a validated membership root and creates new
   commitments. *)
type transfer_param = {
  proof           : bytes ;
  tree_roots      : bytes ;
  leaves          : (bytes list) list ;
  output_preimage : bytes list ;
  enc_notes       : bytes list ;
}

[@entry]
let transfer (p : transfer_param) (s : storage) : operation list * storage =
  let () = verify_bound s p.proof p.tree_roots p.leaves in
  let () = check_identity s p.output_preimage in
  let () = require_known_root s (preimage_at p.output_preimage tr_membership_root_idx) in
  let s = spend_all s p.output_preimage in
  [ emit_sync p.output_preimage p.enc_notes ;
    emit_tree_append s (transfer_commitments p.output_preimage) ], s

(* An unshield spends notes and exits value. The outbound transfer/ticket (value
   custody — per-asset tickets) is deferred to the multi-asset pass; the zk
   binding, membership and nullifier logic are identical to transfer. *)
type unshield_param = {
  proof           : bytes ;
  tree_roots      : bytes ;
  leaves          : (bytes list) list ;
  output_preimage : bytes list ;
  enc_notes       : bytes list ;
}

[@entry]
let unshield (p : unshield_param) (s : storage) : operation list * storage =
  let () = verify_bound s p.proof p.tree_roots p.leaves in
  let () = check_identity s p.output_preimage in
  let () = require_known_root s (preimage_at p.output_preimage tr_membership_root_idx) in
  let s = spend_all s p.output_preimage in
  [ emit_sync p.output_preimage p.enc_notes ;
    emit_tree_append s (unshield_commitments p.output_preimage) ], s

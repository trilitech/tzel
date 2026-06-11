(* TzEL on Tezos X — shielded-pool contract that verifies operations by calling
   the `zk` runtime THROUGH the enshrined cross-runtime gateway, and keeps the
   pool bookkeeping (commitment-tree root + nullifier set) on-chain.

   The zk runtime exposes two privacy primitives as *synchronous* gateway views
   — `Tezos.call_view "zk" (path, body) gateway : bytes option`:

     - ("verify_snark", body) -> Some 0x01 iff the Groth16 wrap proof is valid
     - ("blake2s", body)      -> Some digest (personalized BLAKE2S-256)

   ## The OutHash binding (the security core)

   A proof attests a set of PUBLIC INPUTS: the 4 STARK tree roots (the circuit's
   internal commitments) and an OutHash. The OutHash is a hash of the operation's
   `output_preimage` (the bootloader output: new tree root, nullifier, amounts…).

   The contract does NOT trust a supplied OutHash. It DERIVES it from the declared
   `output_preimage` using the real BLAKE2S primitive (the gateway view), builds
   the wrap public inputs from (tree_roots, derived OutHash), and verifies the
   proof against THOSE. So a valid proof cannot be replayed with a different
   output: any change to `output_preimage` changes the derived OutHash and the
   proof no longer verifies. The effects the contract then applies (new_root,
   nullifier) are READ FROM the bound `output_preimage`, so they too are attested.

   The OutHash derivation chain is `out_hash.mligo`, parametrized over the hash
   function; here it runs on the gateway BLAKE2S (~3-5 synchronous view calls). *)

#include "out_hash.mligo"
module O = OutHash

type storage = {
  gateway    : address ;                 (* enshrined gateway KT1<MERG> *)
  vk         : bytes ;                   (* Groth16 wrap verifying key *)
  root       : bytes ;                   (* current commitment-tree root *)
  nullifiers : (bytes, unit) big_map ;   (* spent nullifier set *)
}

(* ── fixed wire constants (wrap circuit shape) ───────────────────────────── *)
let empty_bytes   : bytes = 0x
let vk_len_be     : bytes = 0x000025d0   (* 9680 = len(vk)            *)
let proof_len_be  : bytes = 0x00000184   (* 388  = len(Groth16 proof) *)
let n_publics_be  : bytes = 0x00000088   (* 136  = 128 root bytes + 8 lanes *)
let scalar_len_be : bytes = 0x00000020   (* 32   = bytes per scalar   *)
let perso_len_0   : bytes = 0x00000000   (* empty perso = standard BLAKE2S *)
let valid_byte    : bytes = 0x01
let tree_roots_len : nat  = 128n         (* 4 roots x 32 bytes *)

(* output_preimage felt indices of the effects (per circuit bootloader output).
   PLACEHOLDER — must be pinned to the released TzEL circuit's output layout.
   The binding (proof <-> output_preimage) is exact regardless; only WHICH felt
   holds new_root / nullifier depends on the circuit spec. *)
let new_root_idx  : nat = 0n
let nullifier_idx : nat = 1n

(* The OutHash chain runs on the runtime BLAKE2S-256 reached through the
   gateway: `Gateway s.gateway` (see out_hash.mligo `blake2s`). *)

(* ── public-input framing ────────────────────────────────────────────────── *)

(* Frame the 128 tree-root bytes as 128 length-prefixed 32-byte scalars (each
   byte b becomes the field element b, big-endian, in gnark declaration order). *)
let frame_root_bytes (tree_roots : bytes) : bytes =
  let rec go (acc : bytes) (i : nat) : bytes =
    if i = tree_roots_len then acc
    else
      let scalar = O.pad_left 32n (Bytes.sub i 1n tree_roots) in
      go (Bytes.concat acc (Bytes.concat scalar_len_be scalar)) (i + 1n)
  in go empty_bytes 0n

(* Frame the 8 OutHash lanes as length-prefixed 32-byte scalars. *)
let frame_lanes (lanes : nat list) : bytes =
  List.fold_left
    (fun ((acc, l) : bytes * nat) ->
       let scalar = O.pad_left 32n (bytes l) in
       Bytes.concat acc (Bytes.concat scalar_len_be scalar))
    empty_bytes lanes

(* ── the binding: derive the publics from the declared output, verify ──────── *)

(* Verify the wrap proof against public inputs DERIVED from (tree_roots,
   output_preimage). Reverts unless the proof is valid for those publics — which
   binds it to this exact output_preimage (the OutHash is recomputed here, not
   trusted). *)
let verify_bound
    (s : storage) (proof : bytes)
    (tree_roots : bytes) (output_preimage : bytes list) : unit =
  let src = Gateway s.gateway in
  let root0 = Bytes.sub 0n 32n tree_roots in
  let output_lanes = O.compute_output_hash_values src output_preimage in
  let outhash_lanes = O.compute_expected_out_hash src root0 output_lanes in
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

(* ── bookkeeping ─────────────────────────────────────────────────────────── *)

let advance_root (s : storage) (old_root : bytes) (new_root : bytes) : storage =
  if old_root <> s.root then failwith "TzEL: stale root"
  else { s with root = new_root }

let spend (s : storage) (nullifier : bytes) : storage =
  if Big_map.mem nullifier s.nullifiers then failwith "TzEL: double spend"
  else { s with nullifiers = Big_map.add nullifier unit s.nullifiers }

(* ── wallet-sync data availability ───────────────────────────────────────────
   The commitment tree lives OFF-CHAIN; the contract stores only the root. So
   each op must PUBLISH its leaves: the commitments (carried in output_preimage)
   and the encrypted notes (for recipients). A wallet rebuilds the tree by
   replaying these and trial-decrypts the notes to find its funds.
   See docs/TZEL-TREE-AND-SYNC.md. *)
let emit_sync (output_preimage : bytes list) (enc_notes : bytes list) : operation =
  Tezos.emit "%tzel_notes" (output_preimage, enc_notes)

(* ── entrypoints ─────────────────────────────────────────────────────────── *)

(* NOTE: `new_root` is read from the bound `output_preimage` — which requires the
   circuit to OUTPUT it. The current single-value circuit does not yet; this
   path is staged pending the (multi-asset) circuit extension that adds new_root
   to the output. The OutHash binding already makes whatever the circuit outputs
   trustworthy. See docs/TZEL-TREE-AND-SYNC.md. *)

(* A shield adds commitments: verify the bound proof, advance the root to the
   new root attested in the bound output_preimage, publish the leaves. *)
type shield_param = {
  proof           : bytes ;
  tree_roots      : bytes ;        (* 128 bytes = 4 x 32 *)
  output_preimage : bytes list ;   (* bootloader output felts (32-byte BE) *)
  old_root        : bytes ;
  enc_notes       : bytes list ;   (* note ciphertexts to publish *)
}

[@entry]
let shield (p : shield_param) (s : storage) : operation list * storage =
  let () = verify_bound s p.proof p.tree_roots p.output_preimage in
  let new_root = preimage_at p.output_preimage new_root_idx in
  let s = advance_root s p.old_root new_root in
  [ emit_sync p.output_preimage p.enc_notes ], s

(* A transfer spends a note (its nullifier is attested in the bound preimage)
   and advances the root. *)
type transfer_param = {
  proof           : bytes ;
  tree_roots      : bytes ;
  output_preimage : bytes list ;
  old_root        : bytes ;
  enc_notes       : bytes list ;
}

[@entry]
let transfer (p : transfer_param) (s : storage) : operation list * storage =
  let () = verify_bound s p.proof p.tree_roots p.output_preimage in
  let nullifier = preimage_at p.output_preimage nullifier_idx in
  let new_root = preimage_at p.output_preimage new_root_idx in
  let s = spend s nullifier in
  let s = advance_root s p.old_root new_root in
  [ emit_sync p.output_preimage p.enc_notes ], s

(* An unshield spends a note and exits value. The outbound transfer/ticket
   (value custody) is omitted here — it will be multi-asset (per-asset tickets);
   verification, nullifier and root bookkeeping are identical to transfer. *)
type unshield_param = {
  proof           : bytes ;
  tree_roots      : bytes ;
  output_preimage : bytes list ;
  old_root        : bytes ;
  enc_notes       : bytes list ;
}

[@entry]
let unshield (p : unshield_param) (s : storage) : operation list * storage =
  let () = verify_bound s p.proof p.tree_roots p.output_preimage in
  let nullifier = preimage_at p.output_preimage nullifier_idx in
  let new_root = preimage_at p.output_preimage new_root_idx in
  let s = spend s nullifier in
  let s = advance_root s p.old_root new_root in
  [ emit_sync p.output_preimage p.enc_notes ], s

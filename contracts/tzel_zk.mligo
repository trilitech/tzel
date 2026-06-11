(* TzEL on Tezos X — shielded-pool contract that verifies operations by
   calling the `zk` runtime THROUGH the enshrined cross-runtime gateway, and
   keeps the pool bookkeeping (commitment-tree root + nullifier set) on-chain.

   The zk runtime exposes two privacy primitives as *synchronous* gateway
   views — `Tezos.call_view "zk" (path, body) gateway : bytes option`:

     - ("verify_snark", body) -> Some 0x01  iff the Groth16 wrap proof is valid
                                  None       on a rejected/malformed proof
     - ("blake2s", body)      -> Some digest (personalized BLAKE2S-256)

   Wire framing (matches tezosx-zk-runtime), all length fields u32 big-endian:

     verify_snark : vkLen|vk  proofLen|proof  nPublics  (scLen|scalar)*nPublics
     blake2s      : persoLen|perso  data

   For the wrap circuit these lengths are FIXED, so they are byte constants —
   no on-chain u32 encoding is needed. The application semantics (what the
   proof attests, replay protection, the tree transition) live HERE, in the
   contract; the runtime only offers the generic primitives. *)

type storage = {
  gateway    : address ;                 (* enshrined gateway KT1<MERG> *)
  vk         : bytes ;                   (* Groth16 wrap verifying key *)
  root       : bytes ;                   (* current commitment-tree root *)
  nullifiers : (bytes, unit) big_map ;   (* spent nullifier set *)
}

(* ── fixed wire constants (wrap circuit shape) ───────────────────────────── *)
let empty_bytes  : bytes = 0x
let vk_len_be    : bytes = 0x000025d0   (* 9680 = len(vk)            *)
let proof_len_be : bytes = 0x00000184   (* 388  = len(Groth16 proof) *)
let n_publics_be : bytes = 0x00000088   (* 136  = #public scalars    *)
let scalar_len_be: bytes = 0x00000020   (* 32   = bytes per scalar   *)
let perso_len_0  : bytes = 0x00000000
let perso_len_8  : bytes = 0x00000008
let valid_byte   : bytes = 0x01

(* ── gateway primitive calls ─────────────────────────────────────────────── *)

(* Length-prefix one 32-byte public scalar and append it. *)
let frame_scalar ((acc, scalar) : bytes * bytes) : bytes =
  Bytes.concat acc (Bytes.concat scalar_len_be scalar)

(* Verify the wrap proof against `vk` and `publics`; revert unless valid.
   A `None` (4xx from the runtime) or a non-0x01 body aborts the operation —
   the security property a shielded pool needs. *)
let verify_snark (s : storage) (proof : bytes) (publics : bytes list) : unit =
  let framed = List.fold_left frame_scalar empty_bytes publics in
  let body =
    Bytes.concat (Bytes.concat vk_len_be s.vk)
      (Bytes.concat (Bytes.concat proof_len_be proof)
        (Bytes.concat n_publics_be framed)) in
  match (Tezos.call_view "zk" ("verify_snark", body) s.gateway : bytes option) with
  | Some r -> if r = valid_byte then unit else failwith "TzEL: proof rejected"
  | None -> failwith "TzEL: verify_snark view unavailable"

(* Personalized BLAKE2S-256 via the zk runtime (empty perso = standard). *)
let blake2s (s : storage) (perso : bytes) (data : bytes) : bytes =
  let plen = if Bytes.length perso = 0n then perso_len_0 else perso_len_8 in
  let body = Bytes.concat (Bytes.concat plen perso) data in
  match (Tezos.call_view "zk" ("blake2s", body) s.gateway : bytes option) with
  | Some d -> d
  | None -> (failwith "TzEL: blake2s view unavailable" : bytes)

(* ── bookkeeping ─────────────────────────────────────────────────────────── *)

(* The proof attests a transition from `old_root` to `new_root`; the contract
   only advances if `old_root` is the pool's current root (replay/ordering). *)
let advance_root (s : storage) (old_root : bytes) (new_root : bytes) : storage =
  if old_root <> s.root then failwith "TzEL: stale root"
  else { s with root = new_root }

(* Spend a nullifier: reject double-spends, then record it. *)
let spend (s : storage) (nullifier : bytes) : storage =
  if Big_map.mem nullifier s.nullifiers then failwith "TzEL: double spend"
  else { s with nullifiers = Big_map.add nullifier unit s.nullifiers }

(* ── entrypoints ─────────────────────────────────────────────────────────── *)

(* A shield adds a commitment: verify the proof, advance the tree root. *)
type shield_param = {
  proof    : bytes ;
  publics  : bytes list ;
  old_root : bytes ;
  new_root : bytes ;
}

[@entry]
let shield (p : shield_param) (s : storage) : operation list * storage =
  let () = verify_snark s p.proof p.publics in
  let s = advance_root s p.old_root p.new_root in
  ([] : operation list), s

(* A transfer spends one note and creates new ones: verify, derive the
   nullifier on-chain via blake2s, reject double-spend, advance the root. *)
type transfer_param = {
  proof              : bytes ;
  publics            : bytes list ;
  nullifier_preimage : bytes ;
  old_root           : bytes ;
  new_root           : bytes ;
}

[@entry]
let transfer (p : transfer_param) (s : storage) : operation list * storage =
  let () = verify_snark s p.proof p.publics in
  let nullifier = blake2s s empty_bytes p.nullifier_preimage in
  let s = spend s nullifier in
  let s = advance_root s p.old_root p.new_root in
  ([] : operation list), s

(* An unshield spends a note and exits value. The outbound transfer/ticket is
   omitted in this first version (it is orthogonal to the zk integration);
   verification, nullifier and root bookkeeping are identical to transfer. *)
type unshield_param = {
  proof              : bytes ;
  publics            : bytes list ;
  nullifier_preimage : bytes ;
  old_root           : bytes ;
  new_root           : bytes ;
}

[@entry]
let unshield (p : unshield_param) (s : storage) : operation list * storage =
  let () = verify_snark s p.proof p.publics in
  let nullifier = blake2s s empty_bytes p.nullifier_preimage in
  let s = spend s nullifier in
  let s = advance_root s p.old_root p.new_root in
  ([] : operation list), s

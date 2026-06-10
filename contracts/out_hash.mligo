(* out_hash.mligo — Phase 1 derisk: the TzEL proof->operation OutHash binding,
   mirrored bit-for-bit from the Rust reference in CameLIGO.

   Reference (mirrored line-by-line):
     verifier/src/out_hash.rs  : compute_output_hash_values  (STAGE 1)
     verifier/src/snark.rs     : compute_expected_out_hash{,_mv} / compute_mv_output_values (STAGE 2)
     starknet-types-core blake2s.rs : encode_felt252_data_and_calc_blake_hash
     stwo-circuits circuits/src/blake.rs : blake_qm31 / qm31 lane (LE u32) framing
     stwo core/vcs/blake2_hash.rs : reduce_to_m31

   The ONE primitive LIGO lacks today is BLAKE2S. Layer-1 must enshrine a
   `BLAKE2S :: bytes -> bytes` instruction (architecture doc 1.2). Until it
   lands we stub it (see `blake2s` below) so the SURROUNDING M31/QM31 packing
   logic — the actual empirical unknown of decision 2 — is validated against
   the golden vectors. Everything except the blake call is real LIGO. *)

module OutHash = struct

  (* ── field/word constants ─────────────────────────────────────────── *)

  (* M31 prime P = 2^31 - 1 (stwo m31.rs:14). reduce_to_m31 lane = lane mod P. *)
  let m31_p : nat = 2147483647n
  (* 2^9 - 1 mask for the 9-bit felt limbs (out_hash.rs FELT252_BITS_PER_WORD). *)
  let limb_mask : nat = 511n
  (* Starknet field prime: 2^251 + 17*2^192 + 1 (pack_256_le_to_felt reduces
     the 256-bit LE digest into this field).
     NOTE: large nat literals must be encoded as `nat 0x..` (bytes->nat at
     runtime). A 251-bit DECIMAL literal in any arithmetic op makes the LIGO
     compiler's optimizer throw `Z.Overflow` (Z.to_int on the literal) at
     `ligo compile contract` time — a toolchain quirk, see Phase-1 report.
     The bytes form is pushed and converted by the Michelson `NAT` op, so the
     optimizer never folds it. The 2^63 threshold is handled byte-wise
     (`felt_is_small`) for the same reason. *)
  let stark_p : nat =
    nat 0x0800000000000011000000000000000000000000000000000000000000000001

  (* ── BLAKE2S SEAM (Layer-1 primitive `BLAKE2S :: bytes -> bytes`) ─────
     STUB. LIGO/Michelson has BLAKE2B but no BLAKE2S today. The real deploy
     replaces this body with the enshrined BLAKE2S instruction. For the
     prototype we resolve the few preimages that appear in the golden-vector
     tests to their known blake2s-256 digests (computed off-chain by the
     reference). This isolates the derisk to the M31/QM31 packing around the
     hash — which IS real LIGO below. *)
  type blake_table = (bytes, bytes) map

  let blake2s (table : blake_table) (input : bytes) : bytes =
    match Map.find_opt input table with
    | Some d -> d
    | None ->
        (* In production this is the BLAKE2S runtime instruction. The stub
           must never be asked for an unknown preimage in the prototype. *)
        (failwith "BLAKE2S seam: unknown preimage (replace with runtime BLAKE2S)" : bytes)

  (* ── byte/word helpers (all real LIGO) ───────────────────────────────
     `bytes n` (nat->bytes) and `nat b` (bytes->nat) are BIG-ENDIAN and
     minimal-width. The reference uses fixed-width LE u32 lanes, so we build
     LE encoders / fixed-width helpers on top. *)

  (* Left-pad a byte string to `width` bytes (prepend 0x00). *)
  let pad_left (width : nat) (b : bytes) : bytes =
    let len = Bytes.length b in
    if len >= width then b
    else
      let rec go (acc : bytes) (n : nat) : bytes =
        if n = 0n then acc else go (Bytes.concat 0x00 acc) (abs (n - 1))
      in go b (abs (width - len))

  (* Reverse a byte string (BE <-> LE). *)
  let reverse_bytes (b : bytes) : bytes =
    let len = Bytes.length b in
    let rec go (acc : bytes) (i : nat) : bytes =
      if i = 0n then acc
      else
        let j = abs (i - 1) in
        go (Bytes.concat acc (Bytes.sub j 1n b)) j
    in go 0x (len)

  (* Encode a u32 (nat < 2^32) as 4 little-endian bytes. *)
  let le32 (n : nat) : bytes =
    (* `bytes n` is minimal big-endian; pad to 4, then reverse to LE. *)
    let be4 = pad_left 4n (bytes n) in
    reverse_bytes be4

  (* Decode 4 little-endian bytes (offset i) of `b` as a nat. *)
  let le32_at (b : bytes) (i : nat) : nat =
    let chunk = Bytes.sub i 4n b in
    nat (reverse_bytes chunk)   (* reverse LE->BE, then nat is BE *)

  (* reduce_to_m31 on one u32 lane: lane mod P (blake2_hash.rs:111). *)
  let reduce_m31 (lane : nat) : nat = lane mod m31_p

  (* ── STAGE 1a: encode_felt252_data_and_calc_blake_hash inner preimage ──
     blake2s.rs encode_felts_to_u32s: per felt, if < 2^63 emit 2 BE u32 words
     (bytes 24..32 of the 32-byte BE repr); else 8 BE u32 words with MSB of
     word0 set. Then serialise each u32 word LITTLE-endian (the LE byte
     stream that is blake2s-hashed). A felt is given as a 32-byte BE bytes. *)
  (* felt < 2^63 (Blake2Felt252::SMALL_THRESHOLD) tested byte-wise on the
     32-byte BE repr: top 24 bytes all zero AND bit 63 (high bit of byte 24)
     clear. Avoids a `nat < 2^63n` comparison (large-literal optimizer bug). *)
  let felt_is_small (felt_be32 : bytes) : bool =
    let hi24 = nat (Bytes.sub 0n 24n felt_be32) in
    let b24  = nat (Bytes.sub 24n 1n felt_be32) in
    (hi24 = 0n) && (b24 < 128n)

  let encode_one_felt_le (felt_be32 : bytes) : bytes =
    if felt_is_small felt_be32 then
      (* small: words = [BE(24..28), BE(28..32)], each serialised LE *)
      let w_hi = Bytes.sub 24n 4n felt_be32 in
      let w_lo = Bytes.sub 28n 4n felt_be32 in
      Bytes.concat (reverse_bytes w_hi) (reverse_bytes w_lo)
    else
      (* big: 8 BE u32 words, word0 |= 2^31; each serialised LE *)
      let rec emit (acc : bytes) (i : nat) : bytes =
        if i = 8n then acc
        else
          let w_be = Bytes.sub (i * 4n) 4n felt_be32 in
          let w = nat w_be in
          let w = if i = 0n then Bitwise.or w 2147483648n else w in
          let w_le = reverse_bytes (pad_left 4n (bytes w)) in
          emit (Bytes.concat acc w_le) (i + 1n)
      in emit 0x 0n

  (* Build the full inner blake2s preimage from a list of felts (each 32-byte
     BE bytes). *)
  let encode_felts_le_stream (felts : bytes list) : bytes =
    List.fold_left
      (fun (acc, f : bytes * bytes) -> Bytes.concat acc (encode_one_felt_le f))
      0x felts

  (* pack_256_le_to_felt: interpret the 32-byte LE blake2s digest as a nat,
     reduce mod the Starknet prime -> the inner felt (out_hash.rs uses this as
     the value fed to felt252_to_m31_words). *)
  let digest_le_to_felt (digest_le : bytes) : nat =
    let v = nat (reverse_bytes digest_le) in   (* LE bytes -> nat *)
    v mod stark_p

  (* ── STAGE 1b: felt252_to_m31_words — 28 x 9-bit limbs (out_hash.rs:24) ──
     The reference reads 4 little-endian u64 limbs; limb `index` is 9 bits
     starting at bit 9*index. Working on the felt as a single nat, this is
     exactly (felt >> (9*index)) & 0x1ff. (The u64-limb gymnastics in Rust are
     just a 64-bit-word reimplementation of that shift; on an arbitrary-width
     nat it collapses to a single shift+mask.) *)
  let felt_to_28_limbs (felt : nat) : nat list =
    let rec go (acc : nat list) (i : int) : nat list =
      if i < 0 then acc
      else
        let idx = abs i in
        let limb = Bitwise.and (Bitwise.shift_right felt (idx * 9n)) limb_mask in
        go (limb :: acc) (i - 1)
    in go ([] : nat list) 27

  (* ── STAGE 1c: pack_into_qm31s + QM31::blake (out_hash.rs:44-47) ───────
     pack_into_qm31s groups the 28 limbs into 7 QM31s (4 lanes each), then
     QM31::blake hashes n_bytes = 7*16 = 112 bytes = the 28 lanes serialised
     as LE u32. So the outer-blake preimage is just the 28 limbs each as LE
     u32. We then reduce_to_m31 the 8 digest lanes. *)
  let lanes_to_le_stream (lanes : nat list) : bytes =
    List.fold_left
      (fun (acc, l : bytes * nat) -> Bytes.concat acc (le32 l)) 0x lanes

  (* reduce_to_m31 over the 8 lanes of a 32-byte LE blake2s digest. *)
  let digest_to_m31_lanes (digest_le : bytes) : nat list =
    let rec go (acc : nat list) (i : int) : nat list =
      if i < 0 then acc
      else
        let lane = le32_at digest_le ((abs i) * 4n) in
        go (reduce_m31 lane :: acc) (i - 1)
    in go ([] : nat list) 7

  (* blake_m31(data) = reduce_to_m31(blake2s256(data)) -> 8 lanes. *)
  let blake_m31 (table : blake_table) (data : bytes) : nat list =
    digest_to_m31_lanes (blake2s table data)

  (* STAGE 1 end-to-end: output_preimage (felts as 32-byte BE) -> 8 M31 lanes.
     = compute_output_hash_values / compute_leaf_output_lanes. *)
  let compute_output_hash_values (table : blake_table) (felts : bytes list) : nat list =
    let inner_stream = encode_felts_le_stream felts in
    let inner_digest = blake2s table inner_stream in        (* STAGE 1a blake *)
    let felt = digest_le_to_felt inner_digest in            (* pack_256_le_to_felt *)
    let limbs = felt_to_28_limbs felt in                    (* STAGE 1b *)
    let outer_stream = lanes_to_le_stream limbs in          (* pack -> LE lanes *)
    blake_m31 table outer_stream                            (* STAGE 1c blake_qm31 *)

  (* ── STAGE 2: the wrap OutHash (snark.rs) ─────────────────────────────
     compute_expected_out_hash_mv: blake_m31( root32 || 8 lanes as LE u32 ).
     compute_expected_out_hash (leaf shape): root32 || (8 output lanes) ||
     U_VALUE(0,0,1,0) as LE u32 -> blake_m31. *)
  let u_value_lanes : nat list = [0n; 0n; 1n; 0n]

  (* mv mode: root (32 raw bytes) || 2 output QM31s (8 lanes) -> OutHash. *)
  let compute_expected_out_hash_mv
      (table : blake_table) (root32 : bytes) (output_lanes : nat list) : nat list =
    let preimage = Bytes.concat root32 (lanes_to_le_stream output_lanes) in
    blake_m31 table preimage

  (* leaf mode: root || output_hash(8 lanes) || U_VALUE -> OutHash. *)
  let compute_expected_out_hash
      (table : blake_table) (root32 : bytes) (output_lanes : nat list) : nat list =
    let preimage =
      Bytes.concat root32
        (Bytes.concat (lanes_to_le_stream output_lanes)
                      (lanes_to_le_stream u_value_lanes)) in
    blake_m31 table preimage

  (* one mv tree fold: parent.output = blake_m31(rootL||ovL||rootR||ovR),
     each as 8 LE u32 lanes (snark.rs compute_mv_output_values). *)
  let compute_mv_output_values
      (table : blake_table)
      (left_root : nat list) (left_ov : nat list)
      (right_root : nat list) (right_ov : nat list) : nat list =
    let s =
      Bytes.concat
        (Bytes.concat (lanes_to_le_stream left_root) (lanes_to_le_stream left_ov))
        (Bytes.concat (lanes_to_le_stream right_root) (lanes_to_le_stream right_ov)) in
    blake_m31 table s

end

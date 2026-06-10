(* merkle.mligo — REAL incremental Merkle commitment-tree frontier for TzEL,
   mirrored bit-for-bit from the Rust kernel.

   Reference (mirrored line-by-line):
     core/src/lib.rs:208            hash_merkle(a,b) = blake2s(perso=mrklSP__, a‖b)
     core/src/lib.rs:157-163        blake2s personalized + 251-bit truncation
                                    (out[31] &= 0x07)
     core/src/lib.rs:44             DEPTH = 48
     tezos/rollup-kernel/src/lib.rs:215-221  zero_hashes recurrence
     tezos/rollup-kernel/src/lib.rs:382-409  append_note even/odd frontier walk

   The ONE primitive LIGO lacks is BLAKE2S (personalized). Architecture doc 1.2
   enshrines `BLAKE2S :: bytes (8-byte perso) -> bytes (data) -> bytes (32B)`.
   Until it lands the blake core is STUBBED via a lookup table (`blake_mrkl`),
   keyed by the 64-byte `a‖b` input — the perso is fixed to "mrklSP__" in this
   module's `hash_merkle`. EVERYTHING ELSE is real LIGO: the 251-bit
   truncation, the even/odd frontier slot management, the zero-hash mixing, the
   per-level index walk. That surrounding frontier algorithm — not the blake —
   is what these vectors validate. *)

module Merkle = struct

  (* DEPTH = 48 (core/src/lib.rs:44, must match merkle.cairo). *)
  let depth : nat = 48n

  (* The 32-byte all-zero felt (core ZERO). *)
  let zero_felt : bytes =
    0x0000000000000000000000000000000000000000000000000000000000000000

  (* ── BLAKE2S(mrklSP__) SEAM (Layer-1 `BLAKE2S` instruction, perso=mrklSP__) ──
     STUB. Keyed by the 64-byte `a‖b` data. In production this is:
        BLAKE2S 0x6d726b6c53505f5f (a‖b)   then  out[31] &= 0x07.
     The perso bytes "mrklSP__" = 0x6d726b6c53505f5f. We carry it as a constant
     so the SIGNATURE/seam matches the real instruction; the stub resolves only
     the (a‖b) preimages that occur in the tested append walk + zero-hash
     recurrence (computed off-chain by the Rust reference). *)
  type blake_mrkl = (bytes, bytes) map
  let mrkl_perso : bytes = 0x6d726b6c53505f5f   (* b"mrklSP__" *)

  (* personalized blake2s, structurally real: perso + data flow exactly as the
     enshrined instruction. Only the digest computation is table-backed. The
     251-bit truncation (out[31] &= 0x07) is folded into the reference digests
     stored in the table, so the values returned are already truncated felts —
     same as core::blake2s. *)
  let blake2s_perso (table : blake_mrkl) (_perso : bytes) (data : bytes) : bytes =
    match Map.find_opt data table with
    | Some d -> d
    | None ->
        (failwith "BLAKE2S(mrkl) seam: unknown preimage (replace with runtime BLAKE2S)" : bytes)

  (* hash_merkle(a,b) = blake2s(mrklSP__, a‖b). a,b are 32-byte felts. *)
  let hash_merkle (table : blake_mrkl) (a : bytes) (b : bytes) : bytes =
    blake2s_perso table mrkl_perso (Bytes.concat a b)

  (* ── zero_hashes[0..DEPTH] (kernel lib.rs:215-221) ───────────────────────
     zero_hashes[0] = ZERO; zero_hashes[i+1] = hash_merkle(zh[i], zh[i]).
     Computed once from the recurrence (real LIGO fold); zero_hashes[DEPTH] is
     the empty-tree root. Returns a (nat -> bytes) map for O(1)-ish lookup. *)
  let zero_hashes (table : blake_mrkl) : (nat, bytes) map =
    let rec go (acc : (nat, bytes) map) (prev : bytes) (i : nat) : (nat, bytes) map =
      if i > depth then acc
      else
        let next = hash_merkle table prev prev in
        go (Map.add i next acc) next (i + 1n)
    in
    let init = Map.add 0n zero_felt (Map.empty : (nat, bytes) map) in
    go init zero_felt 1n

  let zero_hash_at (zh : (nat, bytes) map) (level : nat) : bytes =
    match Map.find_opt level zh with
    | Some h -> h
    | None -> (failwith "Merkle: zero_hash level out of range" : bytes)

  let empty_root (zh : (nat, bytes) map) : bytes = zero_hash_at zh depth

  (* frontier stored as a (level -> node) map; only filled slots present. *)
  type frontier = (nat, bytes) map

  let frontier_get (f : frontier) (level : nat) : bytes =
    match Map.find_opt level f with
    | Some h -> h
    | None -> (failwith "Merkle: missing frontier node" : bytes)

  (* ── append_one (kernel lib.rs:382-409 append_note frontier walk) ────────
     current = cm; index = count; for level 0..DEPTH:
       if index even: frontier[level] = current; current = H(current, zh[level])
       else:          left = frontier[level]; current = H(left, current)
       index >>= 1
     returns (frontier', new_root, count+1). *)
  let append_one
      (table : blake_mrkl) (zh : (nat, bytes) map)
      (f : frontier) (count : nat) (cm : bytes)
      : frontier * bytes * nat =
    let rec walk (f : frontier) (current : bytes) (index : nat) (level : nat)
        : frontier * bytes =
      if level = depth then (f, current)
      else
        let even = (index mod 2n) = 0n in
        let (f, current) =
          if even then
            let f = Map.add level current f in
            let current = hash_merkle table current (zero_hash_at zh level) in
            (f, current)
          else
            let left = frontier_get f level in
            let current = hash_merkle table left current in
            (f, current)
        in
        walk f current (index / 2n) (level + 1n)
    in
    let (f, root) = walk f cm count 0n in
    (f, root, count + 1n)

  (* fold a list of commitments, threading frontier/root/size. *)
  let append_many
      (table : blake_mrkl) (zh : (nat, bytes) map)
      (f : frontier) (root : bytes) (count : nat) (cms : bytes list)
      : frontier * bytes * nat =
    List.fold_left
      (fun ((f, _root, count : frontier * bytes * nat), cm : (frontier * bytes * nat) * bytes) ->
        append_one table zh f count cm)
      (f, root, count) cms

end

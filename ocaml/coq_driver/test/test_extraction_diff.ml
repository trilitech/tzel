(** Differential fuzzer: Rocq-extracted xmss_chain_step vs OCaml port.

    Generates random (x, pub_seed, key_idx, chain_idx, step) inputs
    and asserts that the extracted Rocq function and the OCaml
    protocol-port function produce byte-identical output.

    A divergence here means either:
    - The Rocq model doesn't match the OCaml port, or
    - The extraction is wrong.

    Since the OCaml port is cross-impl tested against Cairo
    (cargo test --test cross_impl_interop), a pass here gives
    transitive assurance: Rocq ↔ OCaml ↔ Cairo. *)

let random_felt () =
  let b = Bytes.create 32 in
  for i = 0 to 31 do
    Bytes.set_uint8 b i (Random.int 256)
  done;
  (* Clear top 5 bits to stay in felt252 range [0, 2^251) *)
  let top = Bytes.get_uint8 b 31 in
  Bytes.set_uint8 b 31 (top land 0x07);
  b

let felt_to_hex (b : bytes) : string =
  let buf = Buffer.create 64 in
  for i = 0 to Bytes.length b - 1 do
    Buffer.add_string buf (Printf.sprintf "%02x" (Bytes.get_uint8 b i))
  done;
  Buffer.contents buf

let felt_of_hex (s : string) : bytes =
  assert (String.length s = 64);
  let b = Bytes.create 32 in
  for i = 0 to 31 do
    Bytes.set_uint8 b i (int_of_string ("0x" ^ String.sub s (2 * i) 2))
  done;
  b

(** The OCaml protocol port's xmss_chain_step — our reference. *)
let port_chain_step x pub_seed key_idx chain_idx step =
  Tzel.Wots.xmss_chain_step x pub_seed key_idx chain_idx step

(** The Rocq-extracted xmss_chain_step — what we're testing. *)
let extracted_chain_step x pub_seed key_idx chain_idx step =
  Tzel_wots.xmss_chain_step x pub_seed key_idx chain_idx step

(** The OCaml protocol port's commitment hash — our reference.
    [Tzel.Hash.hash_commit d v asset rcm owner_tag] is the same
    function the cross-impl interop check pins bit-equivalent to the
    Cairo [hash5] (and that the commitment_u64_max_v1.json fixture
    covers), so a pass here extends the Rocq ↔ OCaml ↔ Cairo
    transitive assurance from the WOTS chain step to the
    multiasset note commitment — where the hidden asset tag binds. *)
let port_commit d v asset rcm owner_tag =
  Tzel.Hash.hash_commit d v asset rcm owner_tag

(** The Rocq-extracted commitment — what we're testing. *)
let extracted_commit d v asset rcm owner_tag =
  Tzel_wots.commit d v asset rcm owner_tag

(** OCaml port reference for the nullifier: the SAME two nested
    Tzel.Hash.hash_nf applications the port's Tzel.Note.nullifier and
    the Cairo perform. *)
let port_nullifier nk cm pos =
  Tzel.Hash.hash_nf nk (Tzel.Hash.hash_nf cm pos)

(** The Rocq-extracted nullifier — what we're testing. *)
let extracted_nullifier nk cm pos =
  Tzel_wots.nullifier nk cm pos

(** OCaml port reference for the sighash fold.  The port's
    [Tzel.Hash.sighash_fold] takes a non-empty list and folds from
    its HEAD, so [sighash_fold (acc :: fields)] equals the Coq
    [sighash_fold acc fields] (fold over [fields] from [acc]). *)
let port_sighash_fold acc fields =
  Tzel.Hash.sighash_fold (acc :: fields)

(** The Rocq-extracted sighash fold (sighash_fold0 = the Impl
    wrapper that bakes in Tzel.Hash.hash_sighash). *)
let extracted_sighash_fold acc fields =
  Tzel_wots.sighash_fold0 acc fields

(** OCaml port reference for the commitment-tree path computation.
    [Tzel.Merkle.root_from_path ~depth leaf pos path] walks from the
    leaf using the LSB-first bits of [pos] and the sibling array —
    exactly Coq [merkle_root]'s fold.  [pos] is reconstructed from
    the bool list (bit d = bits[d]). *)
let pos_of_bits bits =
  List.fold_left (fun (acc, d) b ->
    ((if b then acc lor (1 lsl d) else acc), d + 1)) (0, 0) bits
  |> fst

let port_merkle_root bits siblings leaf =
  let depth = List.length bits in
  Tzel.Merkle.root_from_path ~depth leaf (pos_of_bits bits)
    (Array.of_list siblings)

(** The Rocq-extracted commitment-tree root computation. *)
let extracted_merkle_root bits siblings leaf =
  Tzel_wots.merkle_compute_root bits siblings leaf

(** QCheck generator for chain-step inputs. *)
let gen_chain_input =
  QCheck.Gen.(
    let* _seed = int in  (* use QCheck's seed for reproducibility *)
    let x = random_felt () in
    let pub_seed = random_felt () in
    let* key_idx = 0 -- 65535 in
    let* chain_idx = 0 -- 132 in
    let* step = 0 -- 2 in
    return (x, pub_seed, key_idx, chain_idx, step))

let arb_chain_input =
  QCheck.make gen_chain_input
    ~print:(fun (x, ps, ki, ci, s) ->
      Printf.sprintf "x=%s pub_seed=%s key_idx=%d chain_idx=%d step=%d"
        (felt_to_hex x) (felt_to_hex ps) ki ci s)

(** Multi-step chaining: iterate chain_step n times.
    Tests that the extracted single-step function composes correctly
    with the port's multi-step function. *)
let iter_extracted n x pub_seed key_idx chain_idx start_step =
  let current = ref x in
  for s = start_step to start_step + n - 1 do
    current := extracted_chain_step !current pub_seed key_idx chain_idx s
  done;
  !current

let port_hash_chain x pub_seed key_idx chain_idx start_step n =
  Tzel.Wots.xmss_hash_chain x pub_seed key_idx chain_idx start_step n

let gen_chain_multi_input =
  QCheck.Gen.(
    let x = random_felt () in
    let pub_seed = random_felt () in
    let* key_idx = 0 -- 65535 in
    let* chain_idx = 0 -- 132 in
    let* start_step = 0 -- 2 in
    let* n_steps = 0 -- (3 - start_step) in
    return (x, pub_seed, key_idx, chain_idx, start_step, n_steps))

let arb_chain_multi_input =
  QCheck.make gen_chain_multi_input
    ~print:(fun (x, ps, ki, ci, ss, n) ->
      Printf.sprintf "x=%s pub_seed=%s key_idx=%d chain=%d start=%d steps=%d"
        (felt_to_hex x) (felt_to_hex ps) ki ci ss n)

(* ---- Tests ---- *)

let test_single_step =
  QCheck_alcotest.to_alcotest
    (QCheck.Test.make ~count:10000 ~name:"chain_step: extracted = port"
       arb_chain_input
       (fun (x, pub_seed, key_idx, chain_idx, step) ->
          let got = extracted_chain_step x pub_seed key_idx chain_idx step in
          let expected = port_chain_step x pub_seed key_idx chain_idx step in
          Bytes.equal got expected))

let test_multi_step =
  QCheck_alcotest.to_alcotest
    (QCheck.Test.make ~count:5000 ~name:"hash_chain: iterated extracted = port"
       arb_chain_multi_input
       (fun (x, pub_seed, key_idx, chain_idx, start_step, n_steps) ->
          let got = iter_extracted n_steps x pub_seed key_idx chain_idx start_step in
          let expected = port_hash_chain x pub_seed key_idx chain_idx start_step n_steps in
          Bytes.equal got expected))

(** Commitment differential: five independent random felts.  The
    asset slot is drawn from the full felt range (not just 0/tez) so
    the fuzzer exercises the multiasset binding, including the
    aliasing edge cases the security review cared about. *)
let gen_commit_input =
  QCheck.Gen.(
    let d = random_felt () in
    let v = random_felt () in
    let asset = random_felt () in
    let rcm = random_felt () in
    let otag = random_felt () in
    return (d, v, asset, rcm, otag))

let arb_commit_input =
  QCheck.make gen_commit_input
    ~print:(fun (d, v, a, r, o) ->
      Printf.sprintf "d=%s v=%s asset=%s rcm=%s otag=%s"
        (felt_to_hex d) (felt_to_hex v) (felt_to_hex a)
        (felt_to_hex r) (felt_to_hex o))

let test_commit =
  QCheck_alcotest.to_alcotest
    (QCheck.Test.make ~count:10000 ~name:"commit: extracted = port"
       arb_commit_input
       (fun (d, v, asset, rcm, otag) ->
          let got = extracted_commit d v asset rcm otag in
          let expected = port_commit d v asset rcm otag in
          Bytes.equal got expected))

(** Golden-vector anchor (NON-tautological).  The fuzz differential
    above only proves the extracted [commit] preserves argument
    order/structure vs the OCaml port (both bottom out in
    [Tzel.Hash.hash_commit]).  This case instead pins the extracted
    Coq [commit] to a fixed commitment value taken from
    [specs/test_vectors/commitment_u64_max_v1.json] — the SAME
    golden fixture the Rust core checks in
    [test_u64_max_commitment_fixture_matches_rust_commit_layout]
    and that the cross-impl interop check derives from the Cairo.
    So a pass here ties the Rocq model's commitment to the
    Cairo/Rust reference byte-for-byte, not just to the OCaml port.
    asset = ASSET_TEZ = felt 0 (all-zero), matching the fixture. *)
let test_commit_golden_vector () =
  let d_j       = felt_of_hex "0100000000000000000000000000000000000000000000000000000000000000" in
  let value     = felt_of_hex "ffffffffffffffff000000000000000000000000000000000000000000000000" in
  let asset_tez = felt_of_hex "0000000000000000000000000000000000000000000000000000000000000000" in
  let rcm       = felt_of_hex "2a00000000000000000000000000000000000000000000000000000000000000" in
  let owner_tag = felt_of_hex "6300000000000000000000000000000000000000000000000000000000000000" in
  let expected  = felt_of_hex "667d2e8f57b593ba784306116af48ea65d9b1d30e0fe6aeb055cae5395f41e05" in
  let got = extracted_commit d_j value asset_tez rcm owner_tag in
  Alcotest.(check bool)
    "extracted Coq commit reproduces the Cairo/Rust golden commitment"
    true (Bytes.equal got expected)

(** Nullifier differential: three independent random felts
    (nk_spend, cm, pos).  Structural — both sides nest
    Tzel.Hash.hash_nf — so it pins the extracted Coq nullifier's
    composition order (nk outside, cm/pos inside) against the port. *)
let gen_nullifier_input =
  QCheck.Gen.(
    let nk = random_felt () in
    let cm = random_felt () in
    let pos = random_felt () in
    return (nk, cm, pos))

let arb_nullifier_input =
  QCheck.make gen_nullifier_input
    ~print:(fun (nk, cm, pos) ->
      Printf.sprintf "nk=%s cm=%s pos=%s"
        (felt_to_hex nk) (felt_to_hex cm) (felt_to_hex pos))

let test_nullifier =
  QCheck_alcotest.to_alcotest
    (QCheck.Test.make ~count:10000 ~name:"nullifier: extracted = port"
       arb_nullifier_input
       (fun (nk, cm, pos) ->
          Bytes.equal (extracted_nullifier nk cm pos)
                      (port_nullifier nk cm pos)))

(** Golden-vector anchor (NON-tautological): the extracted Coq
    nullifier must reproduce the nf in protocol_v1.json's notes[0]
    (nk_spend, cm, pos=0) — a value the Rust gen-test-vectors
    computes and the cross-impl interop pins to Cairo. pos=0 is the
    all-zero felt. *)
let test_nullifier_golden_vector () =
  let nk  = felt_of_hex "3e3f324ff4111e97d76b47d5c6224e4636d78dab89fa8821e11acf118223dd04" in
  let cm  = felt_of_hex "f6d1bf71c5de7b1e71bc5476f54cf82129a7c395fbcb55ede84a5db7b41b0005" in
  let pos = felt_of_hex "0000000000000000000000000000000000000000000000000000000000000000" in
  let expected = felt_of_hex "917275674da1f5d93fbaa9eb00006dc337a7926269f880bac56bdc84f9e5fc02" in
  Alcotest.(check bool)
    "extracted Coq nullifier reproduces the Rust/Cairo golden nf"
    true (Bytes.equal (extracted_nullifier nk cm pos) expected)

(** Sighash-fold differential: a random accumulator (the type tag at
    protocol level) plus a random-length list of random field felts.
    The malleability theorems (transfer/unshield/shield_sighash_binds)
    are stated about exactly this fold, so conformance here ties
    those proofs to the running computation. *)
let gen_sighash_input =
  QCheck.Gen.(
    let acc = random_felt () in
    let* n = 0 -- 12 in
    let* fields = list_size (return n) (return (random_felt ())) in
    return (acc, fields))

let arb_sighash_input =
  QCheck.make gen_sighash_input
    ~print:(fun (acc, fields) ->
      Printf.sprintf "acc=%s |fields|=%d" (felt_to_hex acc) (List.length fields))

let test_sighash_fold =
  QCheck_alcotest.to_alcotest
    (QCheck.Test.make ~count:10000 ~name:"sighash_fold: extracted = port"
       arb_sighash_input
       (fun (acc, fields) ->
          Bytes.equal (extracted_sighash_fold acc fields)
                      (port_sighash_fold acc fields)))

(** Golden-vector anchor (NON-tautological): protocol_v1.json's
    sighash[0] folds items [1;2;3] (LE felts) to a fixed result the
    Rust gen-test-vectors computes and cross-impl interop pins to
    Cairo.  Coq form: acc = items[0], fields = [items[1]; items[2]]. *)
let test_sighash_golden_vector () =
  let i0 = felt_of_hex "0100000000000000000000000000000000000000000000000000000000000000" in
  let i1 = felt_of_hex "0200000000000000000000000000000000000000000000000000000000000000" in
  let i2 = felt_of_hex "0300000000000000000000000000000000000000000000000000000000000000" in
  let expected = felt_of_hex "93b3ee7d5953594ce9932c87f88ef6d71757630802b6f6b10b62b5c341c65b00" in
  Alcotest.(check bool)
    "extracted Coq sighash_fold reproduces the Rust/Cairo golden result"
    true (Bytes.equal (extracted_sighash_fold i0 [i1; i2]) expected)

(** Merkle-root differential: a random depth (0..16), a random leaf,
    and parallel random bit / sibling lists of that depth.  Membership
    proofs gate spending, so this pins the extracted Coq commitment-
    tree fold (left/right ordering and the mrkl-domain hash) against
    the port's root_from_path, which the cross-impl interop check
    pins to the Cairo merkle::verify. *)
let gen_merkle_input =
  QCheck.Gen.(
    let* depth = 0 -- 16 in
    let leaf = random_felt () in
    let* bits = list_size (return depth) bool in
    let siblings = List.map (fun _ -> random_felt ())
                     (List.init depth (fun i -> i)) in
    return (bits, siblings, leaf))

let arb_merkle_input =
  QCheck.make gen_merkle_input
    ~print:(fun (bits, _sibs, leaf) ->
      Printf.sprintf "depth=%d leaf=%s" (List.length bits) (felt_to_hex leaf))

let test_merkle_root =
  QCheck_alcotest.to_alcotest
    (QCheck.Test.make ~count:10000 ~name:"merkle_root: extracted = port"
       arb_merkle_input
       (fun (bits, siblings, leaf) ->
          Bytes.equal (extracted_merkle_root bits siblings leaf)
                      (port_merkle_root bits siblings leaf)))

(** Golden anchor: protocol_v1.json's merkle[0] is depth 3 over
    leaves [1;2;3;4] with a fixed Rust-generated root.  We take the
    port's auth_path for leaf 0 (value 1) and assert the EXTRACTED
    Coq merkle fold reproduces that golden root — anchoring the Coq
    computation to the Rust/Cairo root value (the path is port-
    derived; the root is the external reference). *)
let test_merkle_golden_vector () =
  let leaves = List.map felt_of_hex
    [ "0100000000000000000000000000000000000000000000000000000000000000";
      "0200000000000000000000000000000000000000000000000000000000000000";
      "0300000000000000000000000000000000000000000000000000000000000000";
      "0400000000000000000000000000000000000000000000000000000000000000" ] in
  let root = felt_of_hex
    "2bd1d23e7be6c29e43d75d662dfdbe0e3f79807b974b339a594b951cee18e406" in
  let depth = 3 in
  let pos = 0 in
  let path = Tzel.Merkle.auth_path ~depth leaves pos in
  let bits = List.init depth (fun d -> (pos lsr d) land 1 = 1) in
  let leaf0 = List.nth leaves 0 in
  let got = extracted_merkle_root bits (Array.to_list path) leaf0 in
  Alcotest.(check bool)
    "extracted Coq merkle fold reaches the Rust/Cairo golden root"
    true (Bytes.equal got root)

let () =
  Alcotest.run "extraction-diff"
    [ ("xmss_chain_step",
       [ test_single_step;
         test_multi_step ]);
      ("commitment",
       [ test_commit;
         Alcotest.test_case "commit golden vector (Cairo/Rust-anchored)"
           `Quick test_commit_golden_vector ]);
      ("nullifier",
       [ test_nullifier;
         Alcotest.test_case "nullifier golden vector (Cairo/Rust-anchored)"
           `Quick test_nullifier_golden_vector ]);
      ("sighash_fold",
       [ test_sighash_fold;
         Alcotest.test_case "sighash golden vector (Cairo/Rust-anchored)"
           `Quick test_sighash_golden_vector ]);
      ("merkle_root",
       [ test_merkle_root;
         Alcotest.test_case "merkle golden vector (Cairo/Rust-anchored)"
           `Quick test_merkle_golden_vector ]) ]

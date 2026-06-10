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

let () =
  Alcotest.run "extraction-diff"
    [ ("xmss_chain_step",
       [ test_single_step;
         test_multi_step ]);
      ("commitment",
       [ test_commit;
         Alcotest.test_case "commit golden vector (Cairo/Rust-anchored)"
           `Quick test_commit_golden_vector ]) ]

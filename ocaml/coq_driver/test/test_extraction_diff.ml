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

(** The OCaml protocol port's xmss_chain_step — our reference. *)
let port_chain_step x pub_seed key_idx chain_idx step =
  Tzel.Wots.xmss_chain_step x pub_seed key_idx chain_idx step

(** The Rocq-extracted xmss_chain_step — what we're testing. *)
let extracted_chain_step x pub_seed key_idx chain_idx step =
  Tzel_wots.xmss_chain_step x pub_seed key_idx chain_idx step

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

let () =
  Alcotest.run "extraction-diff"
    [ ("xmss_chain_step",
       [ test_single_step;
         test_multi_step ]) ]

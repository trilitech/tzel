let fixed_felt seed =
  let b = Bytes.init 32 (fun i -> Char.chr ((seed + i) land 0xFF)) in
  Bytes.set_uint8 b 31 (Bytes.get_uint8 b 31 land 0x07);
  b

let fixed_bytes seed =
  Bytes.init 32 (fun i -> Char.chr ((seed + i) land 0xFF))

let payment_address_wire_of_addr (addr : Tzel.Keys.address) =
  let pa = Tzel.Keys.to_payment_address addr in
  let wire : Tzel.Encoding.payment_address_wire = {
    d_j = pa.pa_d_j;
    auth_root = pa.pa_auth_root;
    auth_pub_seed = pa.pa_auth_pub_seed;
    nk_tag = pa.pa_nk_tag;
    ek_v = pa.pa_ek_v;
    ek_d = pa.pa_ek_d;
  } in
  wire

let deterministic_encrypted_note (addr : Tzel.Keys.address) ~v ~rseed ~memo ~detect_seed ~view_seed =
  let (ss_d, ct_d) = Tzel.Mlkem.encaps_derand addr.ek_d (fixed_bytes detect_seed) in
  let tag = Tzel.Detection.compute_tag ss_d in
  let (ss_v, ct_v) = Tzel.Mlkem.encaps_derand addr.ek_v (fixed_bytes view_seed) in
  let (nonce, encrypted_data) = Tzel.Detection.encrypt_memo ~ss_v ~v ~rseed ~memo in
  let enc : Tzel.Encoding.encrypted_note = { ct_d; tag; ct_v; nonce; encrypted_data } in
  let memo_ct_hash = Tzel.Encoding.compute_memo_ct_hash enc in
  (enc, memo_ct_hash)

let json_felt f = `String (Tzel.Felt.to_hex f)

let json_felt_list xs = `List (List.map json_felt xs)

let test_auth_root d_j auth_pub_seed =
  Tzel.Hash.hash2 (Tzel.Hash.felt_tag "interop-auth-root")
    (Tzel.Hash.hash2 d_j auth_pub_seed)

let derive_test_address keys j =
  let d_j = Tzel.Keys.derive_diversifier keys j in
  let ask_j = Tzel.Keys.derive_ask keys j in
  let auth_pub_seed = Tzel.Keys.derive_auth_pub_seed ask_j in
  let nk_spend = Tzel.Keys.derive_nk_spend keys d_j in
  let nk_tag = Tzel.Keys.derive_nk_tag nk_spend in
  let auth_root = test_auth_root d_j auth_pub_seed in
  let (ek_v, dk_v) = Tzel.Mlkem.derive_view_keypair keys.view_root j in
  let (ek_d, dk_d) = Tzel.Mlkem.derive_detect_keypair keys.detect_root j in
  { Tzel.Keys.index = j; d_j; auth_root; auth_pub_seed; nk_tag; nk_spend; ask_j;
    ek_v; dk_v; ek_d; dk_d }

let () =
  let auth_domain = Tzel.Hash.hash_bytes (Bytes.of_string "tzel-auth-domain-local-dev-v1") in
  let fee = 100_000 in
  let producer_fee = 1 in
  let initial_alice_balance = 500_001 in

  let alice_keys = Tzel.Keys.derive (fixed_felt 0x11) in
  let bob_keys = Tzel.Keys.derive (fixed_felt 0x55) in
  let producer_keys = Tzel.Keys.derive (fixed_felt 0x77) in

  let alice_addr0 = derive_test_address alice_keys 0 in
  let alice_addr1 = derive_test_address alice_keys 1 in
  let bob_addr0 = derive_test_address bob_keys 0 in
  let producer_addr0 = derive_test_address producer_keys 0 in

  let shield_rseed = fixed_felt 0x21 in
  let shield_note = Tzel.Note.create alice_addr0 400_000L shield_rseed in
  let (shield_enc, shield_memo_ct_hash) =
    deterministic_encrypted_note alice_addr0
      ~v:400_000L
      ~rseed:shield_rseed
      ~memo:(Bytes.of_string "interop-shield")
      ~detect_seed:0x31
      ~view_seed:0x41
  in
  let shield_producer_rseed = fixed_felt 0x24 in
  let shield_producer_note = Tzel.Note.create producer_addr0 1L shield_producer_rseed in
  let (shield_producer_enc, shield_producer_memo_ct_hash) =
    deterministic_encrypted_note producer_addr0
      ~v:1L
      ~rseed:shield_producer_rseed
      ~memo:(Bytes.of_string "interop-dal-shield")
      ~detect_seed:0x34
      ~view_seed:0x44
  in

  let tree = Tzel.Merkle.create_with_leaves ~depth:48 in
  ignore (Tzel.Merkle.append_with_leaves tree shield_note.cm);
  ignore (Tzel.Merkle.append_with_leaves tree shield_producer_note.cm);
  let root_after_shield = Tzel.Merkle.root_with_leaves tree in
  let shield_nf = Tzel.Note.nullifier alice_addr0.nk_spend shield_note.cm 0 in

  let transfer_rseed_1 = fixed_felt 0x22 in
  let transfer_rseed_2 = fixed_felt 0x23 in
  let transfer_rseed_3 = fixed_felt 0x25 in
  let transfer_note_1 = Tzel.Note.create alice_addr1 99_999L transfer_rseed_1 in
  let transfer_note_2 = Tzel.Note.create bob_addr0 200_000L transfer_rseed_2 in
  let transfer_note_3 = Tzel.Note.create producer_addr0 1L transfer_rseed_3 in
  let (transfer_enc_1, transfer_memo_ct_hash_1) =
    deterministic_encrypted_note alice_addr1
      ~v:99_999L
      ~rseed:transfer_rseed_1
      ~memo:(Bytes.of_string "interop-change")
      ~detect_seed:0x32
      ~view_seed:0x42
  in
  let (transfer_enc_2, transfer_memo_ct_hash_2) =
    deterministic_encrypted_note bob_addr0
      ~v:200_000L
      ~rseed:transfer_rseed_2
      ~memo:(Bytes.of_string "interop-bob")
      ~detect_seed:0x33
      ~view_seed:0x43
  in
  let (transfer_enc_3, transfer_memo_ct_hash_3) =
    deterministic_encrypted_note producer_addr0
      ~v:1L
      ~rseed:transfer_rseed_3
      ~memo:(Bytes.of_string "interop-dal-transfer")
      ~detect_seed:0x35
      ~view_seed:0x45
  in

  ignore (Tzel.Merkle.append_with_leaves tree transfer_note_1.cm);
  ignore (Tzel.Merkle.append_with_leaves tree transfer_note_2.cm);
  ignore (Tzel.Merkle.append_with_leaves tree transfer_note_3.cm);
  let root_after_transfer = Tzel.Merkle.root_with_leaves tree in
  let bob_nf = Tzel.Note.nullifier bob_addr0.nk_spend transfer_note_2.cm 3 in
  let unshield_fee_rseed = fixed_felt 0x26 in
  let unshield_fee_note = Tzel.Note.create producer_addr0 1L unshield_fee_rseed in
  let (unshield_fee_enc, unshield_fee_memo_ct_hash) =
    deterministic_encrypted_note producer_addr0
      ~v:1L
      ~rseed:unshield_fee_rseed
      ~memo:(Bytes.of_string "interop-dal-unshield")
      ~detect_seed:0x36
      ~view_seed:0x46
  in

  let json =
    `Assoc [
      "auth_domain", json_felt auth_domain;
      "initial_alice_balance", `Int initial_alice_balance;
      "shield", `Assoc [
        "sender", `String "alice";
        "v", `Int 400_000;
        "fee", `Int fee;
        "producer_fee", `Int producer_fee;
        "address", Tzel.Encoding.payment_address_to_json (payment_address_wire_of_addr alice_addr0);
        "cm", json_felt shield_note.cm;
        "enc", Tzel.Encoding.encrypted_note_to_json shield_enc;
        "memo_ct_hash", json_felt shield_memo_ct_hash;
        "producer_cm", json_felt shield_producer_note.cm;
        "producer_enc", Tzel.Encoding.encrypted_note_to_json shield_producer_enc;
        "producer_memo_ct_hash", json_felt shield_producer_memo_ct_hash;
      ];
      "transfer", `Assoc [
        "root", json_felt root_after_shield;
        "nullifiers", json_felt_list [shield_nf];
        "fee", `Int fee;
        "cm_1", json_felt transfer_note_1.cm;
        "cm_2", json_felt transfer_note_2.cm;
        "cm_3", json_felt transfer_note_3.cm;
        "enc_1", Tzel.Encoding.encrypted_note_to_json transfer_enc_1;
        "enc_2", Tzel.Encoding.encrypted_note_to_json transfer_enc_2;
        "enc_3", Tzel.Encoding.encrypted_note_to_json transfer_enc_3;
        "memo_ct_hash_1", json_felt transfer_memo_ct_hash_1;
        "memo_ct_hash_2", json_felt transfer_memo_ct_hash_2;
        "memo_ct_hash_3", json_felt transfer_memo_ct_hash_3;
      ];
      "unshield", `Assoc [
        "root", json_felt root_after_transfer;
        "nullifiers", json_felt_list [bob_nf];
        "v_pub", `Int 99_999;
        "fee", `Int fee;
        "recipient", `String "bob";
        "cm_change", json_felt Tzel.Felt.zero;
        "enc_change", `Null;
        "memo_ct_hash_change", json_felt Tzel.Felt.zero;
        "cm_fee", json_felt unshield_fee_note.cm;
        "enc_fee", Tzel.Encoding.encrypted_note_to_json unshield_fee_enc;
        "memo_ct_hash_fee", json_felt unshield_fee_memo_ct_hash;
      ];
      "expected", `Assoc [
        "alice_public_balance", `Int 0;
        "bob_public_balance", `Int 99_999;
        "tree_size", `Int 6;
        "nullifier_count", `Int 2;
      ];
    ]
  in
  print_endline (Yojson.Basic.pretty_to_string json)

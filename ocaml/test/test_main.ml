let hex_of_bytes b =
  let buf = Buffer.create (Bytes.length b * 2) in
  Bytes.iter (fun c -> Buffer.add_string buf (Printf.sprintf "%02x" (Char.code c))) b;
  Buffer.contents buf

(* ══════════════════════════════════════════════════════════════════════
   BLAKE2s
   ══════════════════════════════════════════════════════════════════════ *)

let test_blake2s_empty () =
  let h = Tzel.Blake2s.hash (Bytes.empty) in
  let expected = "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9" in
  Alcotest.(check string) "blake2s empty" expected (hex_of_bytes h)

let test_blake2s_abc () =
  let h = Tzel.Blake2s.hash_string "abc" in
  let expected = "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982" in
  Alcotest.(check string) "blake2s abc" expected (hex_of_bytes h)

let test_blake2s_personal () =
  let h1 = Tzel.Blake2s.hash_string "test" in
  let h2 = Tzel.Blake2s.hash_string ~personal:"mrklSP__" "test" in
  Alcotest.(check bool) "personalization differs" true
    (hex_of_bytes h1 <> hex_of_bytes h2)

let test_blake2s_empty_personal () =
  let h1 = Tzel.Blake2s.hash_string "test" in
  let h2 = Tzel.Blake2s.hash_string ~personal:"" "test" in
  Alcotest.(check string) "empty personal = no personal" (hex_of_bytes h1) (hex_of_bytes h2)

let test_blake2s_long_input () =
  let data = Bytes.make 1000 '\xAB' in
  let h = Tzel.Blake2s.hash data in
  Alcotest.(check int) "output size" 32 (Bytes.length h)

let test_blake2s_deterministic () =
  let h1 = Tzel.Blake2s.hash_string "determinism" in
  let h2 = Tzel.Blake2s.hash_string "determinism" in
  Alcotest.(check string) "deterministic" (hex_of_bytes h1) (hex_of_bytes h2)

let test_blake2s_all_personalizations () =
  let personals = ["mrklSP__"; "nulfSP__"; "cmmtSP__"; "nkspSP__";
                    "nktgSP__"; "ownrSP__"; "wotsSP__";
                    "sighSP__"; "memoSP__"] in
  let hashes = List.map (fun p ->
    hex_of_bytes (Tzel.Blake2s.hash_string ~personal:p "same")) personals in
  (* All must be distinct *)
  let unique = List.sort_uniq String.compare hashes in
  Alcotest.(check int) "all personalizations distinct" (List.length personals) (List.length unique)

(* ══════════════════════════════════════════════════════════════════════
   Felt252
   ══════════════════════════════════════════════════════════════════════ *)

let test_felt_truncation () =
  let h = Tzel.Blake2s.hash_string "test" in
  let f = Tzel.Felt.of_bytes h in
  let last = Bytes.get_uint8 f 31 in
  Alcotest.(check bool) "top 5 bits cleared" true (last land 0xF8 = 0)

let test_felt_zero () =
  let z = Tzel.Felt.zero in
  Alcotest.(check int) "zero length" 32 (Bytes.length z);
  Alcotest.(check bool) "is_zero" true (Tzel.Felt.is_zero z);
  for i = 0 to 31 do
    Alcotest.(check int) (Printf.sprintf "byte %d" i) 0 (Bytes.get_uint8 z i)
  done

let test_felt_of_u64 () =
  let f = Tzel.Felt.of_u64 0x0102030405060708 in
  Alcotest.(check int) "byte 0" 0x08 (Bytes.get_uint8 f 0);
  Alcotest.(check int) "byte 1" 0x07 (Bytes.get_uint8 f 1);
  Alcotest.(check int) "byte 7" 0x01 (Bytes.get_uint8 f 7);
  Alcotest.(check int) "byte 8" 0 (Bytes.get_uint8 f 8);
  Alcotest.(check bool) "not zero" false (Tzel.Felt.is_zero f)

let test_felt_of_u32 () =
  let f = Tzel.Felt.of_u32 0xDEADBEEF in
  Alcotest.(check int) "byte 0" 0xEF (Bytes.get_uint8 f 0);
  Alcotest.(check int) "byte 3" 0xDE (Bytes.get_uint8 f 3)

let test_felt_of_int () =
  let f1 = Tzel.Felt.of_int 42 in
  let f2 = Tzel.Felt.of_u64 42 in
  Alcotest.(check bool) "of_int = of_u64" true (Tzel.Felt.equal f1 f2)

let test_felt_of_bytes_raw () =
  let b = Bytes.make 32 '\xFF' in
  let f = Tzel.Felt.of_bytes_raw b in
  Alcotest.(check int) "byte 31 preserved" 0xFF (Bytes.get_uint8 f 31)

let test_felt_to_bytes () =
  let f = Tzel.Felt.of_u64 42 in
  let b = Tzel.Felt.to_bytes f in
  Alcotest.(check bool) "copy not alias" true (b != f);
  Alcotest.(check bool) "equal" true (Bytes.equal b f)

let test_felt_hex_roundtrip () =
  let f = Tzel.Felt.of_u64 0xCAFEBABE in
  let hex = Tzel.Felt.to_hex f in
  Alcotest.(check int) "hex length" 64 (String.length hex);
  let f2 = Tzel.Felt.of_hex hex in
  Alcotest.(check bool) "hex roundtrip" true (Tzel.Felt.equal f f2)

let test_felt_compare () =
  let a = Tzel.Felt.of_u64 1 in
  let b = Tzel.Felt.of_u64 2 in
  Alcotest.(check bool) "1 < 2" true (Tzel.Felt.compare a b < 0);
  Alcotest.(check bool) "2 > 1" true (Tzel.Felt.compare b a > 0);
  Alcotest.(check bool) "1 = 1" true (Tzel.Felt.compare a a = 0)

let test_felt_equal () =
  let a = Tzel.Felt.of_u64 999 in
  let b = Tzel.Felt.of_u64 999 in
  let c = Tzel.Felt.of_u64 1000 in
  Alcotest.(check bool) "equal" true (Tzel.Felt.equal a b);
  Alcotest.(check bool) "not equal" false (Tzel.Felt.equal a c)

(* ══════════════════════════════════════════════════════════════════════
   Hash (domain-separated)
   ══════════════════════════════════════════════════════════════════════ *)

let test_hash_tag () =
  let h1 = Tzel.Hash.hash_tag "foo" in
  let h2 = Tzel.Hash.hash_tag "bar" in
  Alcotest.(check bool) "different tags" false (Tzel.Felt.equal h1 h2);
  Alcotest.(check bool) "truncated" true (Bytes.get_uint8 h1 31 land 0xF8 = 0)

(* Verify felt_tag matches the spec's Domain Tag Constants table.
   Encoding: interpret UTF8(label) as big-endian integer, store as LE felt.
   This reverses the ASCII byte order in the felt. *)
let test_felt_tag_constants () =
  let check name expected_hex =
    let tag = Tzel.Hash.felt_tag name in
    Alcotest.(check string) name expected_hex (hex_of_bytes tag) in
  check "spend"    "646e657073000000000000000000000000000000000000000000000000000000";
  check "nk"       "6b6e000000000000000000000000000000000000000000000000000000000000";
  check "ask"      "6b73610000000000000000000000000000000000000000000000000000000000";
  check "incoming" "676e696d6f636e69000000000000000000000000000000000000000000000000";
  check "dsk"      "6b73640000000000000000000000000000000000000000000000000000000000";
  check "view"     "7765697600000000000000000000000000000000000000000000000000000000";
  check "detect"   "7463657465640000000000000000000000000000000000000000000000000000";
  check "rcm"      "6d63720000000000000000000000000000000000000000000000000000000000";
  check "mlkem-v"  "762d6d656b6c6d00000000000000000000000000000000000000000000000000";
  check "mlkem-v2" "32762d6d656b6c6d000000000000000000000000000000000000000000000000";
  check "mlkem-d"  "642d6d656b6c6d00000000000000000000000000000000000000000000000000";
  check "mlkem-d2" "32642d6d656b6c6d000000000000000000000000000000000000000000000000";
  check "xmss-sk"  "6b732d73736d7800000000000000000000000000000000000000000000000000";
  check "xmss-ps"  "73702d73736d7800000000000000000000000000000000000000000000000000";
  check "xmss-ch"  "68632d73736d7800000000000000000000000000000000000000000000000000";
  check "xmss-lt"  "746c2d73736d7800000000000000000000000000000000000000000000000000";
  check "xmss-tr"  "72742d73736d7800000000000000000000000000000000000000000000000000"

let test_hash1 () =
  let f = Tzel.Felt.of_u64 42 in
  let h = Tzel.Hash.hash1 f in
  Alcotest.(check bool) "non-zero" true (not (Tzel.Felt.is_zero h));
  Alcotest.(check bool) "truncated" true (Bytes.get_uint8 h 31 land 0xF8 = 0)

let test_hash2 () =
  let a = Tzel.Felt.of_u64 1 in
  let b = Tzel.Felt.of_u64 2 in
  let h = Tzel.Hash.hash2 a b in
  Alcotest.(check bool) "non-zero" true (not (Tzel.Felt.is_zero h));
  (* Order matters *)
  let h2 = Tzel.Hash.hash2 b a in
  Alcotest.(check bool) "non-commutative" false (Tzel.Felt.equal h h2)

let test_hash_personalized_distinct () =
  let data = Bytes.make 32 '\x01' in
  let h1 = Tzel.Hash.hash_bytes data in
  let h2 = Tzel.Hash.hash_merkle data data in  (* uses personalization *)
  Alcotest.(check bool) "personalized differs from unpersonalized" false
    (Tzel.Felt.equal h1 h2)

let test_hash_nk_spend () =
  let nk = Tzel.Felt.of_u64 100 in
  let d1 = Tzel.Felt.of_u64 1 in
  let d2 = Tzel.Felt.of_u64 2 in
  let ns1 = Tzel.Hash.hash_nk_spend nk d1 in
  let ns2 = Tzel.Hash.hash_nk_spend nk d2 in
  Alcotest.(check bool) "different d -> different nk_spend" false (Tzel.Felt.equal ns1 ns2)

let test_hash_nk_tag () =
  let nk_spend = Tzel.Felt.of_u64 100 in
  let tag = Tzel.Hash.hash_nk_tag nk_spend in
  Alcotest.(check bool) "non-zero" true (not (Tzel.Felt.is_zero tag))

let test_hash_owner () =
  let ar = Tzel.Felt.of_u64 1 in
  let ps = Tzel.Felt.of_u64 2 in
  let nt = Tzel.Felt.of_u64 2 in
  let ot = Tzel.Hash.hash_owner ar ps nt in
  Alcotest.(check bool) "non-zero" true (not (Tzel.Felt.is_zero ot))

let test_hash_wots () =
  let data = Tzel.Felt.of_u64 42 in
  let h = Tzel.Hash.hash_wots data in
  Alcotest.(check bool) "non-zero" true (not (Tzel.Felt.is_zero h))

let test_hash_sighash () =
  let a = Tzel.Felt.of_u64 1 in
  let b = Tzel.Felt.of_u64 2 in
  let h = Tzel.Hash.hash_sighash a b in
  Alcotest.(check bool) "non-zero" true (not (Tzel.Felt.is_zero h))

let test_hash_memo () =
  let data = Bytes.make 100 '\xAA' in
  let h = Tzel.Hash.hash_memo data in
  Alcotest.(check bool) "non-zero" true (not (Tzel.Felt.is_zero h))

let test_derive_rcm () =
  let rseed = Tzel.Felt.of_u64 42 in
  let rcm = Tzel.Hash.derive_rcm rseed in
  Alcotest.(check bool) "non-zero" true (not (Tzel.Felt.is_zero rcm));
  (* Deterministic *)
  let rcm2 = Tzel.Hash.derive_rcm rseed in
  Alcotest.(check bool) "deterministic" true (Tzel.Felt.equal rcm rcm2)

let test_sighash_fold_single () =
  let x = Tzel.Felt.of_u64 42 in
  let result = Tzel.Hash.sighash_fold [x] in
  Alcotest.(check bool) "single element returns itself" true (Tzel.Felt.equal x result)

let test_sighash_fold_empty () =
  let raised = ref false in
  (try ignore (Tzel.Hash.sighash_fold []) with Failure _ -> raised := true);
  Alcotest.(check bool) "empty list raises" true !raised

let test_hash_commit () =
  let d = Tzel.Felt.of_u64 1 in
  let v = Tzel.Felt.of_u64 1000 in
  let rcm = Tzel.Felt.of_u64 42 in
  let ot = Tzel.Felt.of_u64 99 in
  let cm = Tzel.Hash.hash_commit d v rcm ot in
  Alcotest.(check bool) "non-zero" true (not (Tzel.Felt.is_zero cm))

let test_hash_commit_uses_only_low_u64_bytes () =
  let d = Tzel.Felt.of_u64 1 in
  let rcm = Tzel.Felt.of_u64 42 in
  let ot = Tzel.Felt.of_u64 99 in
  let canonical_v = Bytes.make 32 '\x00' in
  for i = 0 to 7 do
    Bytes.set_uint8 canonical_v i (0xA0 + i)
  done;
  let noisy_v = Bytes.copy canonical_v in
  for i = 8 to 31 do
    Bytes.set_uint8 noisy_v i 0xFF
  done;
  let cm_canonical = Tzel.Hash.hash_commit d canonical_v rcm ot in
  let cm_noisy = Tzel.Hash.hash_commit d noisy_v rcm ot in
  Alcotest.(check bool) "high bytes ignored" true
    (Bytes.equal cm_canonical cm_noisy);

  let buf = Bytes.make 128 '\x00' in
  Bytes.blit d 0 buf 0 32;
  Bytes.blit canonical_v 0 buf 32 8;
  Bytes.blit rcm 0 buf 64 32;
  Bytes.blit ot 0 buf 96 32;
  let expected = Tzel.Hash.hash_personalized "cmmtSP__" buf in
  Alcotest.(check bool) "matches canonical rust layout" true
    (Bytes.equal cm_canonical expected)

let test_account_id () =
  let id1 = Tzel.Hash.account_id "alice" in
  let id2 = Tzel.Hash.account_id "alice" in
  let id3 = Tzel.Hash.account_id "bob" in
  Alcotest.(check bool) "same" true (Tzel.Felt.equal id1 id2);
  Alcotest.(check bool) "different" false (Tzel.Felt.equal id1 id3)

(* ══════════════════════════════════════════════════════════════════════
   WOTS+ w=4
   ══════════════════════════════════════════════════════════════════════ *)

let sample_wots_pub_seed seed =
  Tzel.Hash.hash2 Tzel.Hash.tag_xmss_ps seed

let test_wots_sign_verify () =
  let seed = Tzel.Felt.of_u64 42 in
  let pub_seed = sample_wots_pub_seed seed in
  let key_idx = 0 in
  let pk = Tzel.Wots.keygen ~seed ~pub_seed ~key_idx in
  let leaf = Tzel.Wots.pk_to_leaf ~pub_seed ~key_idx pk in
  Alcotest.(check int) "pk length" 133 (Array.length pk);
  let sighash = Tzel.Hash.hash_tag "test-sighash" in
  let signature = Tzel.Wots.sign ~seed ~pub_seed ~key_idx sighash in
  Alcotest.(check int) "sig length" 133 (Array.length signature);
  Alcotest.(check bool) "verify" true
    (Tzel.Wots.verify ~pub_seed ~key_idx signature sighash leaf)

let test_wots_sign_verify_high_indices () =
  let seed = Tzel.Felt.of_u64 42 in
  let pub_seed = sample_wots_pub_seed seed in
  let sighash = Tzel.Hash.hash_tag "test-sighash-hi" in
  List.iter (fun key_idx ->
    let pk = Tzel.Wots.keygen ~seed ~pub_seed ~key_idx in
    let leaf = Tzel.Wots.pk_to_leaf ~pub_seed ~key_idx pk in
    let signature = Tzel.Wots.sign ~seed ~pub_seed ~key_idx sighash in
    Alcotest.(check bool) (Printf.sprintf "verify-%d" key_idx) true
      (Tzel.Wots.verify ~pub_seed ~key_idx signature sighash leaf)
  ) [256; 65535]

let test_wots_wrong_message () =
  let seed = Tzel.Felt.of_u64 42 in
  let pub_seed = sample_wots_pub_seed seed in
  let key_idx = 0 in
  let pk = Tzel.Wots.keygen ~seed ~pub_seed ~key_idx in
  let leaf = Tzel.Wots.pk_to_leaf ~pub_seed ~key_idx pk in
  let sighash = Tzel.Hash.hash_tag "test-sighash" in
  let wrong = Tzel.Hash.hash_tag "wrong-sighash" in
  let signature = Tzel.Wots.sign ~seed ~pub_seed ~key_idx sighash in
  Alcotest.(check bool) "reject wrong msg" false
    (Tzel.Wots.verify ~pub_seed ~key_idx signature wrong leaf)

let test_wots_fold_deterministic () =
  let seed = Tzel.Felt.of_u64 100 in
  let pub_seed = sample_wots_pub_seed seed in
  let pk1 = Tzel.Wots.keygen ~seed ~pub_seed ~key_idx:0 in
  let pk2 = Tzel.Wots.keygen ~seed ~pub_seed ~key_idx:0 in
  Alcotest.(check bool) "leaf deterministic" true
    (Tzel.Felt.equal
       (Tzel.Wots.pk_to_leaf ~pub_seed ~key_idx:0 pk1)
       (Tzel.Wots.pk_to_leaf ~pub_seed ~key_idx:0 pk2))

let test_wots_different_seeds () =
  let seed1 = Tzel.Felt.of_u64 1 in
  let seed2 = Tzel.Felt.of_u64 2 in
  let pub_seed1 = sample_wots_pub_seed seed1 in
  let pub_seed2 = sample_wots_pub_seed seed2 in
  let pk1 = Tzel.Wots.keygen ~seed:seed1 ~pub_seed:pub_seed1 ~key_idx:0 in
  let pk2 = Tzel.Wots.keygen ~seed:seed2 ~pub_seed:pub_seed2 ~key_idx:0 in
  Alcotest.(check bool) "different seeds -> different leaves" false
    (Tzel.Felt.equal
       (Tzel.Wots.pk_to_leaf ~pub_seed:pub_seed1 ~key_idx:0 pk1)
       (Tzel.Wots.pk_to_leaf ~pub_seed:pub_seed2 ~key_idx:0 pk2))

let test_wots_wrong_key () =
  let seed1 = Tzel.Felt.of_u64 1 in
  let seed2 = Tzel.Felt.of_u64 2 in
  let pub_seed2 = sample_wots_pub_seed seed2 in
  let pk2 = Tzel.Wots.keygen ~seed:seed2 ~pub_seed:pub_seed2 ~key_idx:0 in
  let leaf2 = Tzel.Wots.pk_to_leaf ~pub_seed:pub_seed2 ~key_idx:0 pk2 in
  let sighash = Tzel.Hash.hash_tag "msg" in
  let pub_seed1 = sample_wots_pub_seed seed1 in
  let sig1 = Tzel.Wots.sign ~seed:seed1 ~pub_seed:pub_seed1 ~key_idx:0 sighash in
  Alcotest.(check bool) "wrong key rejects" false
    (Tzel.Wots.verify ~pub_seed:pub_seed2 ~key_idx:0 sig1 sighash leaf2)

let test_wots_keygen_deterministic () =
  let seed = Tzel.Felt.of_u64 42 in
  let pub_seed = sample_wots_pub_seed seed in
  let pk1 = Tzel.Wots.keygen ~seed ~pub_seed ~key_idx:0 in
  let pk2 = Tzel.Wots.keygen ~seed ~pub_seed ~key_idx:0 in
  let all_eq = ref true in
  for i = 0 to 132 do
    if not (Tzel.Felt.equal pk1.(i) pk2.(i)) then all_eq := false
  done;
  Alcotest.(check bool) "keygen deterministic" true !all_eq

let test_wots_decompose_roundtrip () =
  (* Sign and verify implicitly tests decompose_sighash correctness *)
  let seed = Tzel.Felt.of_u64 77 in
  let pub_seed = sample_wots_pub_seed seed in
  let key_idx = 0 in
  let pk = Tzel.Wots.keygen ~seed ~pub_seed ~key_idx in
  let leaf = Tzel.Wots.pk_to_leaf ~pub_seed ~key_idx pk in
  (* Test with various sighash values *)
  for i = 0 to 9 do
    let sh = Tzel.Hash.hash_tag (Printf.sprintf "sighash-%d" i) in
    let sig_vals = Tzel.Wots.sign ~seed ~pub_seed ~key_idx sh in
    Alcotest.(check bool) (Printf.sprintf "verify-%d" i) true
      (Tzel.Wots.verify ~pub_seed ~key_idx sig_vals sh leaf)
  done

let test_wots_signature_binds_to_auth_leaf () =
  let keys = Tzel.Keys.derive (Tzel.Felt.of_u64 123) in
  let ask_j = Tzel.Keys.derive_ask keys 0 in
  let key_idx = 7 in
  let seed = Tzel.Keys.derive_wots_seed ask_j key_idx in
  let pub_seed = Tzel.Keys.derive_auth_pub_seed ask_j in
  let sighash = Tzel.Hash.hash_tag "bind-wots-auth-leaf" in
  let sig_vals = Tzel.Wots.sign ~seed ~pub_seed ~key_idx sighash in
  let recovered_pk = Tzel.Wots.recover_pk ~pub_seed ~key_idx sig_vals sighash in
  let recovered_leaf = Tzel.Wots.pk_to_leaf ~pub_seed ~key_idx recovered_pk in
  Alcotest.(check bool) "recovered leaf matches expected leaf" true
    (Tzel.Felt.equal recovered_leaf (Tzel.Keys.auth_leaf_hash ask_j key_idx));
  Alcotest.(check bool) "recovered leaf is deterministic" true
    (Tzel.Felt.equal recovered_leaf (Tzel.Keys.auth_leaf_hash ask_j key_idx));
  let wrong_leaf = Tzel.Keys.auth_leaf_hash ask_j (key_idx + 1) in
  Alcotest.(check bool) "wrong leaf rejected" false
    (Tzel.Felt.equal wrong_leaf recovered_leaf)

(* ══════════════════════════════════════════════════════════════════════
   Merkle
   ══════════════════════════════════════════════════════════════════════ *)

let test_merkle_zero_root () =
  let t = Tzel.Merkle.create ~depth:4 in
  let r = Tzel.Merkle.root t in
  Alcotest.(check bool) "non-trivial root" true (not (Tzel.Felt.is_zero r))

let test_merkle_path () =
  let leaves = List.init 4 (fun i -> Tzel.Felt.of_u64 (i + 1)) in
  let depth = 3 in
  let root = Tzel.Merkle.root_of_leaves ~depth leaves in
  for pos = 0 to 3 do
    let path = Tzel.Merkle.auth_path ~depth leaves pos in
    Alcotest.(check bool) (Printf.sprintf "path %d verifies" pos) true
      (Tzel.Merkle.verify_path ~depth (List.nth leaves pos) pos path root)
  done

let test_merkle_single_leaf () =
  let depth = 4 in
  let leaf = Tzel.Hash.hash_tag "leaf0" in
  let root = Tzel.Merkle.root_of_leaves ~depth [leaf] in
  let path = Tzel.Merkle.auth_path ~depth [leaf] 0 in
  Alcotest.(check bool) "single leaf path verifies" true
    (Tzel.Merkle.verify_path ~depth leaf 0 path root)

let test_merkle_root_from_path () =
  let leaves = List.init 8 (fun i -> Tzel.Felt.of_u64 (i + 1)) in
  let depth = 3 in
  let root = Tzel.Merkle.root_of_leaves ~depth leaves in
  let path = Tzel.Merkle.auth_path ~depth leaves 5 in
  let computed = Tzel.Merkle.root_from_path ~depth (List.nth leaves 5) 5 path in
  Alcotest.(check bool) "root_from_path matches" true (Tzel.Felt.equal root computed)

let test_merkle_wrong_leaf () =
  let leaves = List.init 4 (fun i -> Tzel.Felt.of_u64 (i + 1)) in
  let depth = 3 in
  let root = Tzel.Merkle.root_of_leaves ~depth leaves in
  let path = Tzel.Merkle.auth_path ~depth leaves 0 in
  let wrong = Tzel.Felt.of_u64 999 in
  Alcotest.(check bool) "wrong leaf rejects" false
    (Tzel.Merkle.verify_path ~depth wrong 0 path root)

let test_merkle_append_tree () =
  let t = Tzel.Merkle.create ~depth:4 in
  let r0 = Tzel.Merkle.root t in
  let _ = Tzel.Merkle.append t (Tzel.Felt.of_u64 1) in
  let r1 = Tzel.Merkle.root t in
  Alcotest.(check bool) "root changes after append" false (Tzel.Felt.equal r0 r1);
  let _ = Tzel.Merkle.append t (Tzel.Felt.of_u64 2) in
  let r2 = Tzel.Merkle.root t in
  Alcotest.(check bool) "root changes again" false (Tzel.Felt.equal r1 r2)

let test_merkle_tree_full () =
  let t = Tzel.Merkle.create ~depth:2 in
  for i = 0 to 3 do
    ignore (Tzel.Merkle.append t (Tzel.Felt.of_u64 (i + 1)))
  done;
  let raised = ref false in
  (try ignore (Tzel.Merkle.append t (Tzel.Felt.of_u64 5))
   with Failure _ -> raised := true);
  Alcotest.(check bool) "tree full raises" true !raised

let test_merkle_with_leaves_path () =
  let t = Tzel.Merkle.create_with_leaves ~depth:4 in
  let leaves = List.init 5 (fun i -> Tzel.Felt.of_u64 (i + 1)) in
  List.iter (fun l -> ignore (Tzel.Merkle.append_with_leaves t l)) leaves;
  let root = Tzel.Merkle.root_with_leaves t in
  Alcotest.(check int) "size" 5 (Tzel.Merkle.size_with_leaves t);
  for pos = 0 to 4 do
    let path = Tzel.Merkle.path_with_leaves t pos in
    Alcotest.(check bool) (Printf.sprintf "path %d" pos) true
      (Tzel.Merkle.verify_path ~depth:4 (List.nth leaves pos) pos path root)
  done

let test_merkle_path_out_of_range () =
  let t = Tzel.Merkle.create_with_leaves ~depth:4 in
  ignore (Tzel.Merkle.append_with_leaves t (Tzel.Felt.of_u64 1));
  let raised = ref false in
  (try ignore (Tzel.Merkle.path_with_leaves t 5)
   with Failure _ -> raised := true);
  Alcotest.(check bool) "out of range raises" true !raised

let test_merkle_get_leaves () =
  let t = Tzel.Merkle.create_with_leaves ~depth:4 in
  let expected = [Tzel.Felt.of_u64 10; Tzel.Felt.of_u64 20; Tzel.Felt.of_u64 30] in
  List.iter (fun l -> ignore (Tzel.Merkle.append_with_leaves t l)) expected;
  let got = Tzel.Merkle.get_leaves t in
  Alcotest.(check int) "leaf count" 3 (List.length got);
  List.iter2 (fun e g ->
    Alcotest.(check bool) "leaf match" true (Tzel.Felt.equal e g)
  ) expected got

let test_merkle_incremental_matches_materialized () =
  let depth = 4 in
  let leaves = List.init 7 (fun i -> Tzel.Felt.of_u64 (i + 1)) in
  let materialized_root = Tzel.Merkle.root_of_leaves ~depth leaves in
  let t = Tzel.Merkle.create_with_leaves ~depth in
  List.iter (fun l -> ignore (Tzel.Merkle.append_with_leaves t l)) leaves;
  let incremental_root = Tzel.Merkle.root_with_leaves t in
  Alcotest.(check bool) "incremental matches materialized" true
    (Tzel.Felt.equal materialized_root incremental_root)

(* ══════════════════════════════════════════════════════════════════════
   Keys
   ══════════════════════════════════════════════════════════════════════ *)

let test_key_hierarchy () =
  let master_sk = Tzel.Felt.of_u64 12345 in
  let keys = Tzel.Keys.derive master_sk in
  Alcotest.(check bool) "nk non-zero" true (not (Tzel.Felt.is_zero keys.nk));
  Alcotest.(check bool) "ask_base non-zero" true (not (Tzel.Felt.is_zero keys.ask_base));
  Alcotest.(check bool) "dsk non-zero" true (not (Tzel.Felt.is_zero keys.dsk));
  Alcotest.(check bool) "view_root non-zero" true (not (Tzel.Felt.is_zero keys.view_root));
  Alcotest.(check bool) "detect_root non-zero" true (not (Tzel.Felt.is_zero keys.detect_root));
  (* All distinct *)
  let all = [keys.nk; keys.ask_base; keys.dsk; keys.view_root; keys.detect_root] in
  let n = List.length all in
  for i = 0 to n - 2 do
    for j = i + 1 to n - 1 do
      Alcotest.(check bool) (Printf.sprintf "distinct %d %d" i j) false
        (Tzel.Felt.equal (List.nth all i) (List.nth all j))
    done
  done

let test_key_determinism () =
  let master_sk = Tzel.Felt.of_u64 42 in
  let k1 = Tzel.Keys.derive master_sk in
  let k2 = Tzel.Keys.derive master_sk in
  Alcotest.(check bool) "nk" true (Tzel.Felt.equal k1.nk k2.nk);
  Alcotest.(check bool) "ask_base" true (Tzel.Felt.equal k1.ask_base k2.ask_base);
  Alcotest.(check bool) "dsk" true (Tzel.Felt.equal k1.dsk k2.dsk)

let test_key_derive_diversifier () =
  let keys = Tzel.Keys.derive (Tzel.Felt.of_u64 1) in
  let d0 = Tzel.Keys.derive_diversifier keys 0 in
  let d1 = Tzel.Keys.derive_diversifier keys 1 in
  let d2 = Tzel.Keys.derive_diversifier keys 2 in
  Alcotest.(check bool) "d0 != d1" false (Tzel.Felt.equal d0 d1);
  Alcotest.(check bool) "d1 != d2" false (Tzel.Felt.equal d1 d2)

let test_key_derive_ask () =
  let keys = Tzel.Keys.derive (Tzel.Felt.of_u64 1) in
  let a0 = Tzel.Keys.derive_ask keys 0 in
  let a1 = Tzel.Keys.derive_ask keys 1 in
  Alcotest.(check bool) "different j -> different ask" false (Tzel.Felt.equal a0 a1)

let test_key_derive_nk_spend_tag () =
  let keys = Tzel.Keys.derive (Tzel.Felt.of_u64 1) in
  let d0 = Tzel.Keys.derive_diversifier keys 0 in
  let d1 = Tzel.Keys.derive_diversifier keys 1 in
  let ns0 = Tzel.Keys.derive_nk_spend keys d0 in
  let ns1 = Tzel.Keys.derive_nk_spend keys d1 in
  Alcotest.(check bool) "different d -> different nk_spend" false (Tzel.Felt.equal ns0 ns1);
  let nt0 = Tzel.Keys.derive_nk_tag ns0 in
  let nt1 = Tzel.Keys.derive_nk_tag ns1 in
  Alcotest.(check bool) "different nk_spend -> different nk_tag" false (Tzel.Felt.equal nt0 nt1)

let test_key_derive_wots_seed () =
  let keys = Tzel.Keys.derive (Tzel.Felt.of_u64 1) in
  let ask_j = Tzel.Keys.derive_ask keys 0 in
  let s0 = Tzel.Keys.derive_wots_seed ask_j 0 in
  let s1 = Tzel.Keys.derive_wots_seed ask_j 1 in
  Alcotest.(check bool) "different i -> different seed" false (Tzel.Felt.equal s0 s1)

let test_key_auth_seed_helpers_agree () =
  let keys = Tzel.Keys.derive (Tzel.Felt.of_u64 3) in
  let ask0 = Tzel.Keys.derive_ask keys 0 in
  let ask1 = Tzel.Keys.derive_ask keys 1 in
  let auth_seed = Tzel.Keys.derive_auth_key_seed ask0 9 in
  let wots_seed = Tzel.Keys.derive_wots_seed ask0 9 in
  let pub_seed0 = Tzel.Keys.derive_auth_pub_seed ask0 in
  let pub_seed1 = Tzel.Keys.derive_auth_pub_seed ask1 in
  Alcotest.(check bool) "auth seed equals wots seed" true
    (Tzel.Felt.equal auth_seed wots_seed);
  Alcotest.(check bool) "pub seeds differ across addresses" false
    (Tzel.Felt.equal pub_seed0 pub_seed1)

let test_auth_root d_j auth_pub_seed =
  Tzel.Hash.hash2 (Tzel.Hash.felt_tag "test-auth-root")
    (Tzel.Hash.hash2 d_j auth_pub_seed)

let string_contains haystack needle =
  let hay_len = String.length haystack in
  let needle_len = String.length needle in
  let rec loop i =
    if i + needle_len > hay_len then false
    else if String.sub haystack i needle_len = needle then true
    else loop (i + 1)
  in
  needle_len = 0 || loop 0

let expect_failure_contains label needle f =
  try
    let _ = f () in
    Alcotest.failf "%s: expected Failure containing %S" label needle
  with
  | Failure msg ->
    Alcotest.(check bool) label true (string_contains msg needle)

let enable_full_xmss_rebuild_trap () =
  match Sys.getenv_opt "TZEL_ALLOW_FULL_XMSS_REBUILD" with
  | Some _ ->
    Alcotest.fail
      "TZEL_ALLOW_FULL_XMSS_REBUILD must be unset for default unit tests"
  | None -> Unix.putenv "TZEL_TRAP_FULL_XMSS_REBUILDS" "1"

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

let test_key_auth_leaf_small_merkle () =
  let keys = Tzel.Keys.derive (Tzel.Felt.of_u64 1) in
  let ask_j = Tzel.Keys.derive_ask keys 0 in
  let depth = 3 in
  let leaves = List.init (1 lsl depth) (fun i -> Tzel.Keys.auth_leaf_hash ask_j i) in
  let root = Tzel.Merkle.root_of_leaves ~depth leaves in
  let leaf = List.nth leaves 5 in
  let path = Tzel.Merkle.auth_path ~depth leaves 5 in
  Alcotest.(check bool) "root non-zero" true (not (Tzel.Felt.is_zero root));
  Alcotest.(check bool) "auth path verifies" true
    (Tzel.Merkle.verify_path ~depth leaf 5 path root)

let rec reduce_xmss_tree pub_seed level start leaves =
  match leaves with
  | [leaf] -> leaf
  | _ ->
    let rec pair node_idx acc = function
      | [] -> List.rev acc
      | [left] -> List.rev (left :: acc)
      | left :: right :: rest ->
        let node =
          Tzel.Keys.xmss_node_hash pub_seed 0 level
            ((start lsr (level + 1)) + node_idx)
            left right
        in
        pair (node_idx + 1) (node :: acc) rest
    in
    reduce_xmss_tree pub_seed (level + 1) start (pair 0 [] leaves)

let recompute_xmss_root_from_path pub_seed key_idx leaf path =
  let rec go level idx current = function
    | [] -> current
    | sibling :: rest ->
      let node_idx = idx lsr 1 in
      let parent =
        if idx land 1 = 0 then
          Tzel.Keys.xmss_node_hash pub_seed 0 level node_idx current sibling
        else
          Tzel.Keys.xmss_node_hash pub_seed 0 level node_idx sibling current
      in
      go (level + 1) (idx lsr 1) parent rest
  in
  go 0 key_idx leaf path

let test_key_xmss_subtree_root_small_depth () =
  let keys = Tzel.Keys.derive (Tzel.Felt.of_u64 17) in
  let ask_j = Tzel.Keys.derive_ask keys 0 in
  let pub_seed = Tzel.Keys.derive_auth_pub_seed ask_j in
  let depth = 4 in
  let leaves = List.init (1 lsl depth) (fun i -> Tzel.Keys.auth_leaf_hash ask_j i) in
  let manual_root = reduce_xmss_tree pub_seed 0 0 leaves in
  let subtree_root = Tzel.Keys.xmss_subtree_root ask_j pub_seed 0 depth in
  Alcotest.(check bool) "small xmss root matches manual reduction" true
    (Tzel.Felt.equal manual_root subtree_root)

let test_key_xmss_root_and_path_inner_small_depth () =
  let keys = Tzel.Keys.derive (Tzel.Felt.of_u64 19) in
  let ask_j = Tzel.Keys.derive_ask keys 0 in
  let pub_seed = Tzel.Keys.derive_auth_pub_seed ask_j in
  let depth = 4 in
  for idx = 0 to (1 lsl depth) - 1 do
    let (root, path) = Tzel.Keys.xmss_root_and_path_inner ask_j pub_seed 0 depth idx in
    let leaf = Tzel.Keys.auth_leaf_hash ask_j idx in
    let path = Option.get path in
    let recomputed = recompute_xmss_root_from_path pub_seed idx leaf path in
    Alcotest.(check bool) (Printf.sprintf "xmss path %d" idx) true
      (Tzel.Felt.equal root recomputed)
  done

let test_key_xmss_root_and_path_inner_nonzero_start () =
  let keys = Tzel.Keys.derive (Tzel.Felt.of_u64 21) in
  let ask_j = Tzel.Keys.derive_ask keys 0 in
  let pub_seed = Tzel.Keys.derive_auth_pub_seed ask_j in
  let start = 8 in
  let depth = 3 in
  for idx = start to start + (1 lsl depth) - 1 do
    let (root, path) = Tzel.Keys.xmss_root_and_path_inner ask_j pub_seed start depth idx in
    let leaf = Tzel.Keys.auth_leaf_hash ask_j idx in
    let path = Option.get path in
    let recomputed = recompute_xmss_root_from_path pub_seed idx leaf path in
    Alcotest.(check bool) (Printf.sprintf "offset xmss path %d" idx) true
      (Tzel.Felt.equal root recomputed)
  done

let test_key_xmss_subtree_root_nonzero_start () =
  let keys = Tzel.Keys.derive (Tzel.Felt.of_u64 25) in
  let ask_j = Tzel.Keys.derive_ask keys 0 in
  let pub_seed = Tzel.Keys.derive_auth_pub_seed ask_j in
  let start = 8 in
  let depth = 3 in
  let leaves =
    List.init (1 lsl depth) (fun i -> Tzel.Keys.auth_leaf_hash ask_j (start + i))
  in
  let manual_root = reduce_xmss_tree pub_seed 0 start leaves in
  let subtree_root = Tzel.Keys.xmss_subtree_root ask_j pub_seed start depth in
  Alcotest.(check bool) "offset xmss subtree root matches manual reduction" true
    (Tzel.Felt.equal manual_root subtree_root)

let test_key_xmss_node_hash_domain_separation () =
  let keys = Tzel.Keys.derive (Tzel.Felt.of_u64 29) in
  let ask_j = Tzel.Keys.derive_ask keys 0 in
  let pub_seed = Tzel.Keys.derive_auth_pub_seed ask_j in
  let left = Tzel.Keys.auth_leaf_hash ask_j 0 in
  let right = Tzel.Keys.auth_leaf_hash ask_j 1 in
  let base = Tzel.Keys.xmss_node_hash pub_seed 0 0 0 left right in
  let diff_level = Tzel.Keys.xmss_node_hash pub_seed 0 1 0 left right in
  let diff_node = Tzel.Keys.xmss_node_hash pub_seed 0 0 1 left right in
  let diff_key = Tzel.Keys.xmss_node_hash pub_seed 1 0 0 left right in
  Alcotest.(check bool) "level participates" false (Tzel.Felt.equal base diff_level);
  Alcotest.(check bool) "node index participates" false (Tzel.Felt.equal base diff_node);
  Alcotest.(check bool) "key index participates" false (Tzel.Felt.equal base diff_key)

let test_key_wots_pk_matches_auth_leaf_hash () =
  let keys = Tzel.Keys.derive (Tzel.Felt.of_u64 23) in
  let ask_j = Tzel.Keys.derive_ask keys 0 in
  let pub_seed = Tzel.Keys.derive_auth_pub_seed ask_j in
  let key_idx = 7 in
  let pk = Tzel.Keys.wots_pk ask_j key_idx in
  let leaf = Tzel.Wots.pk_to_leaf ~pub_seed ~key_idx pk in
  Alcotest.(check bool) "wots pk leaf matches auth leaf helper" true
    (Tzel.Felt.equal leaf (Tzel.Keys.auth_leaf_hash ask_j key_idx))

let test_owner_tag_binding () =
  let keys = Tzel.Keys.derive (Tzel.Felt.of_u64 99) in
  let addr0 = derive_test_address keys 0 in
  let addr1 = derive_test_address keys 1 in
  let ot0 = Tzel.Keys.owner_tag addr0 in
  let ot1 = Tzel.Keys.owner_tag addr1 in
  Alcotest.(check bool) "different addresses -> different tags" false (Tzel.Felt.equal ot0 ot1)

let test_owner_tag_binds_root_and_pub_seed () =
  let keys = Tzel.Keys.derive (Tzel.Felt.of_u64 101) in
  let addr = derive_test_address keys 0 in
  let base = Tzel.Keys.owner_tag addr in
  let diff_root =
    Tzel.Keys.owner_tag { addr with auth_root = Tzel.Hash.hash_tag "other-root" }
  in
  let diff_seed =
    Tzel.Keys.owner_tag
      { addr with auth_pub_seed = Tzel.Hash.hash_tag "other-auth-pub-seed" }
  in
  Alcotest.(check bool) "auth_root participates" false (Tzel.Felt.equal base diff_root);
  Alcotest.(check bool) "auth_pub_seed participates" false
    (Tzel.Felt.equal base diff_seed)

let test_key_full_depth_wrappers_trap () =
  enable_full_xmss_rebuild_trap ();
  let keys = Tzel.Keys.derive (Tzel.Felt.of_u64 303) in
  let ask_j = Tzel.Keys.derive_ask keys 0 in
  let check op f =
    expect_failure_contains op
      (Printf.sprintf "unexpected full depth-16 XMSS rebuild via %s" op)
      f
  in
  check "build_auth_tree" (fun () -> ignore (Tzel.Keys.build_auth_tree ask_j));
  check "auth_tree_path" (fun () -> ignore (Tzel.Keys.auth_tree_path ask_j 0));
  check "auth_root_and_path" (fun () -> ignore (Tzel.Keys.auth_root_and_path ask_j 0));
  check "derive_address" (fun () -> ignore (Tzel.Keys.derive_address keys 0))

let test_key_to_payment_address () =
  let keys = Tzel.Keys.derive (Tzel.Felt.of_u64 1) in
  let addr = derive_test_address keys 0 in
  let pa = Tzel.Keys.to_payment_address addr in
  Alcotest.(check bool) "d_j" true (Tzel.Felt.equal addr.d_j pa.pa_d_j);
  Alcotest.(check bool) "auth_root" true (Tzel.Felt.equal addr.auth_root pa.pa_auth_root);
  Alcotest.(check bool) "auth_pub_seed" true (Tzel.Felt.equal addr.auth_pub_seed pa.pa_auth_pub_seed);
  Alcotest.(check bool) "nk_tag" true (Tzel.Felt.equal addr.nk_tag pa.pa_nk_tag);
  Alcotest.(check bool) "ek_v" true (Bytes.equal addr.ek_v pa.pa_ek_v);
  Alcotest.(check bool) "ek_d" true (Bytes.equal addr.ek_d pa.pa_ek_d)

let test_key_address_multiple_indices () =
  let keys = Tzel.Keys.derive (Tzel.Felt.of_u64 7) in
  let addr0 = derive_test_address keys 0 in
  let addr1 = derive_test_address keys 1 in
  Alcotest.(check bool) "different d_j" false (Tzel.Felt.equal addr0.d_j addr1.d_j);
  Alcotest.(check bool) "different auth_root" false
    (Tzel.Felt.equal addr0.auth_root addr1.auth_root);
  Alcotest.(check bool) "different nk_tag" false (Tzel.Felt.equal addr0.nk_tag addr1.nk_tag)

(* ══════════════════════════════════════════════════════════════════════
   Note
   ══════════════════════════════════════════════════════════════════════ *)

let test_note_commitment () =
  let keys = Tzel.Keys.derive (Tzel.Felt.of_u64 99) in
  let addr = derive_test_address keys 0 in
  let rseed = Tzel.Felt.of_u64 777 in
  let note = Tzel.Note.create addr 1000L rseed in
  Alcotest.(check bool) "cm non-zero" true (not (Tzel.Felt.is_zero note.cm))

let test_note_determinism () =
  let keys = Tzel.Keys.derive (Tzel.Felt.of_u64 99) in
  let addr = derive_test_address keys 0 in
  let rseed = Tzel.Felt.of_u64 777 in
  let owner_tag1 = Tzel.Keys.owner_tag addr in
  let owner_tag2 = Tzel.Keys.owner_tag addr in
  Alcotest.(check bool) "owner_tag deterministic" true
    (Tzel.Felt.equal owner_tag1 owner_tag2);
  let expected_rcm = Tzel.Hash.derive_rcm rseed in
  let n1 = Tzel.Note.create addr 1000L rseed in
  Alcotest.(check bool) "note stores rcm" true
    (Tzel.Felt.equal expected_rcm n1.rcm);
  Alcotest.(check bool) "note stores owner_tag" true
    (Tzel.Felt.equal owner_tag1 n1.owner_tag);
  let explicit_buf = Bytes.make 128 '\x00' in
  let explicit_v = Tzel.Felt.of_u64 1000 in
  Bytes.blit addr.d_j 0 explicit_buf 0 32;
  Bytes.blit explicit_v 0 explicit_buf 32 8;
  Bytes.blit n1.rcm 0 explicit_buf 64 32;
  Bytes.blit owner_tag1 0 explicit_buf 96 32;
  let explicit_cm = Tzel.Hash.hash_personalized "cmmtSP__" explicit_buf in
  Alcotest.(check bool) "explicit current-layout cm matches note" true
    (Tzel.Felt.equal explicit_cm n1.cm);
  let manual_cm =
    Tzel.Hash.hash_commit addr.d_j (Tzel.Felt.of_u64 1000) n1.rcm owner_tag1
  in
  Alcotest.(check bool) "manual cm matches note" true
    (Tzel.Felt.equal manual_cm n1.cm);
  let n2 = Tzel.Note.create addr 1000L rseed in
  Alcotest.(check bool) "cm deterministic" true (Tzel.Felt.equal n1.cm n2.cm);
  Alcotest.(check bool) "rcm deterministic" true (Tzel.Felt.equal n1.rcm n2.rcm)

let test_note_nullifier () =
  let keys = Tzel.Keys.derive (Tzel.Felt.of_u64 99) in
  let addr = derive_test_address keys 0 in
  let rseed = Tzel.Felt.of_u64 777 in
  let note = Tzel.Note.create addr 1000L rseed in
  let nf0 = Tzel.Note.nullifier addr.nk_spend note.cm 0 in
  let nf1 = Tzel.Note.nullifier addr.nk_spend note.cm 1 in
  Alcotest.(check bool) "nf non-zero" true (not (Tzel.Felt.is_zero nf0));
  Alcotest.(check bool) "different pos -> different nf" false (Tzel.Felt.equal nf0 nf1)

let test_note_create_from_parts () =
  let keys = Tzel.Keys.derive (Tzel.Felt.of_u64 99) in
  let addr = derive_test_address keys 0 in
  let rseed = Tzel.Felt.of_u64 777 in
  let n1 = Tzel.Note.create addr 1000L rseed in
  let n2 = Tzel.Note.create_from_parts
    ~d_j:addr.d_j ~auth_root:addr.auth_root ~auth_pub_seed:addr.auth_pub_seed ~nk_tag:addr.nk_tag
    ~v:1000L ~rseed in
  Alcotest.(check bool) "create matches create_from_parts" true
    (Tzel.Felt.equal n1.cm n2.cm)

let test_note_different_values () =
  let keys = Tzel.Keys.derive (Tzel.Felt.of_u64 99) in
  let addr = derive_test_address keys 0 in
  let rseed = Tzel.Felt.of_u64 777 in
  let n1 = Tzel.Note.create addr 1000L rseed in
  let n2 = Tzel.Note.create addr 2000L rseed in
  Alcotest.(check bool) "different v -> different cm" false (Tzel.Felt.equal n1.cm n2.cm)

let test_note_different_rseed () =
  let keys = Tzel.Keys.derive (Tzel.Felt.of_u64 99) in
  let addr = derive_test_address keys 0 in
  let n1 = Tzel.Note.create addr 1000L (Tzel.Felt.of_u64 1) in
  let n2 = Tzel.Note.create addr 1000L (Tzel.Felt.of_u64 2) in
  Alcotest.(check bool) "different rseed -> different cm" false (Tzel.Felt.equal n1.cm n2.cm)

let test_note_zero_value () =
  let keys = Tzel.Keys.derive (Tzel.Felt.of_u64 99) in
  let addr = derive_test_address keys 0 in
  let note = Tzel.Note.create addr 0L (Tzel.Felt.of_u64 1) in
  Alcotest.(check bool) "zero value note has cm" true (not (Tzel.Felt.is_zero note.cm))

let test_note_nullifier_different_nk_spend () =
  let keys = Tzel.Keys.derive (Tzel.Felt.of_u64 99) in
  let addr = derive_test_address keys 0 in
  let note = Tzel.Note.create addr 1000L (Tzel.Felt.of_u64 1) in
  let nf1 = Tzel.Note.nullifier addr.nk_spend note.cm 0 in
  let fake_nk = Tzel.Felt.of_u64 999 in
  let nf2 = Tzel.Note.nullifier fake_nk note.cm 0 in
  Alcotest.(check bool) "different nk_spend -> different nf" false (Tzel.Felt.equal nf1 nf2)

(* ══════════════════════════════════════════════════════════════════════
   Transaction
   ══════════════════════════════════════════════════════════════════════ *)

let test_sighash_transfer () =
  let pub : Tzel.Transaction.transfer_public = {
    auth_domain = Tzel.Felt.of_u64 1;
    root = Tzel.Hash.hash_tag "root";
    nullifiers = [Tzel.Hash.hash_tag "nf0"];
    cm_1 = Tzel.Hash.hash_tag "cm1";
    cm_2 = Tzel.Hash.hash_tag "cm2";
    memo_ct_hash_1 = Tzel.Hash.hash_tag "mh1";
    memo_ct_hash_2 = Tzel.Hash.hash_tag "mh2";
  } in
  let sh = Tzel.Transaction.transfer_sighash pub in
  Alcotest.(check bool) "non-zero" true (not (Tzel.Felt.is_zero sh))

let test_sighash_unshield () =
  let pub : Tzel.Transaction.unshield_public = {
    auth_domain = Tzel.Felt.of_u64 1;
    root = Tzel.Hash.hash_tag "root";
    nullifiers = [Tzel.Hash.hash_tag "nf0"];
    v_pub = 5000L;
    recipient_id = Tzel.Hash.account_id "bob";
    cm_change = Tzel.Hash.hash_tag "cm_c";
    memo_ct_hash_change = Tzel.Hash.hash_tag "mh_c";
  } in
  let sh = Tzel.Transaction.unshield_sighash pub in
  Alcotest.(check bool) "non-zero" true (not (Tzel.Felt.is_zero sh))

let test_sighash_transfer_unshield_distinct () =
  let common_root = Tzel.Hash.hash_tag "root" in
  let common_nf = [Tzel.Hash.hash_tag "nf0"] in
  let tpub : Tzel.Transaction.transfer_public = {
    auth_domain = Tzel.Felt.of_u64 1;
    root = common_root; nullifiers = common_nf;
    cm_1 = Tzel.Felt.zero; cm_2 = Tzel.Felt.zero;
    memo_ct_hash_1 = Tzel.Felt.zero; memo_ct_hash_2 = Tzel.Felt.zero;
  } in
  let upub : Tzel.Transaction.unshield_public = {
    auth_domain = Tzel.Felt.of_u64 1;
    root = common_root; nullifiers = common_nf;
    v_pub = 0L; recipient_id = Tzel.Felt.zero;
    cm_change = Tzel.Felt.zero; memo_ct_hash_change = Tzel.Felt.zero;
  } in
  let sh_t = Tzel.Transaction.transfer_sighash tpub in
  let sh_u = Tzel.Transaction.unshield_sighash upub in
  Alcotest.(check bool) "transfer != unshield sighash (type tag)" false
    (Tzel.Felt.equal sh_t sh_u)

let test_build_shield () =
  let keys = Tzel.Keys.derive (Tzel.Felt.of_u64 200) in
  let addr = derive_test_address keys 0 in
  let rseed = Tzel.Felt.of_u64 555 in
  let mch = Tzel.Felt.of_u64 0 in
  let (pub, note) = Tzel.Transaction.build_shield
    ~sender_string:"alice" ~recipient:addr ~v:5000L ~rseed ~memo_ct_hash:mch in
  Alcotest.(check bool) "cm matches" true (Tzel.Felt.equal pub.cm_new note.cm);
  Alcotest.(check bool) "sender_id" true
    (Tzel.Felt.equal (Tzel.Hash.account_id "alice") pub.sender_id);
  Alcotest.(check int64) "v_pub" 5000L pub.v_pub

let test_build_output () =
  let keys = Tzel.Keys.derive (Tzel.Felt.of_u64 200) in
  let addr = derive_test_address keys 0 in
  let rseed = Tzel.Felt.of_u64 555 in
  let note = Tzel.Transaction.build_output
    ~d_j:addr.d_j ~auth_root:addr.auth_root ~auth_pub_seed:addr.auth_pub_seed ~nk_tag:addr.nk_tag
    ~v:1000L ~rseed in
  Alcotest.(check bool) "cm non-zero" true (not (Tzel.Felt.is_zero note.cm))

let test_build_transfer_public () =
  let keys = Tzel.Keys.derive (Tzel.Felt.of_u64 200) in
  let addr = derive_test_address keys 0 in
  let rseed = Tzel.Felt.of_u64 555 in
  let out1 = Tzel.Transaction.build_output
    ~d_j:addr.d_j ~auth_root:addr.auth_root ~auth_pub_seed:addr.auth_pub_seed ~nk_tag:addr.nk_tag
    ~v:600L ~rseed in
  let out2 = Tzel.Transaction.build_output
    ~d_j:addr.d_j ~auth_root:addr.auth_root ~auth_pub_seed:addr.auth_pub_seed ~nk_tag:addr.nk_tag
    ~v:400L ~rseed:(Tzel.Felt.of_u64 666) in
  let auth_domain = Tzel.Felt.of_u64 1 in
  let root = Tzel.Hash.hash_tag "root" in
  let nfs = [Tzel.Hash.hash_tag "nf0"] in
  let mh = Tzel.Felt.zero in
  let (pub, sighash) = Tzel.Transaction.build_transfer_public
    ~auth_domain ~root ~nullifiers:nfs ~out1 ~out2
    ~memo_ct_hash_1:mh ~memo_ct_hash_2:mh in
  Alcotest.(check bool) "cm_1 matches" true (Tzel.Felt.equal pub.cm_1 out1.cm);
  Alcotest.(check bool) "cm_2 matches" true (Tzel.Felt.equal pub.cm_2 out2.cm);
  Alcotest.(check bool) "sighash non-zero" true (not (Tzel.Felt.is_zero sighash))

let test_build_unshield_public () =
  let keys = Tzel.Keys.derive (Tzel.Felt.of_u64 200) in
  let addr = derive_test_address keys 0 in
  let change = Tzel.Transaction.build_output
    ~d_j:addr.d_j ~auth_root:addr.auth_root ~auth_pub_seed:addr.auth_pub_seed ~nk_tag:addr.nk_tag
    ~v:200L ~rseed:(Tzel.Felt.of_u64 888) in
  let (pub, sighash) = Tzel.Transaction.build_unshield_public
    ~auth_domain:(Tzel.Felt.of_u64 1)
    ~root:(Tzel.Hash.hash_tag "root")
    ~nullifiers:[Tzel.Hash.hash_tag "nf0"]
    ~v_pub:800L ~recipient_string:"bob"
    ~change_note:(Some change) ~memo_ct_hash_change:Tzel.Felt.zero in
  Alcotest.(check bool) "cm_change matches" true (Tzel.Felt.equal pub.cm_change change.cm);
  Alcotest.(check bool) "sighash non-zero" true (not (Tzel.Felt.is_zero sighash));
  Alcotest.(check bool) "recipient_id" true
    (Tzel.Felt.equal (Tzel.Hash.account_id "bob") pub.recipient_id)

let test_build_unshield_no_change () =
  let (pub, _) = Tzel.Transaction.build_unshield_public
    ~auth_domain:(Tzel.Felt.of_u64 1)
    ~root:(Tzel.Hash.hash_tag "root")
    ~nullifiers:[Tzel.Hash.hash_tag "nf0"]
    ~v_pub:1000L ~recipient_string:"bob"
    ~change_note:None ~memo_ct_hash_change:Tzel.Felt.zero in
  Alcotest.(check bool) "cm_change is zero" true (Tzel.Felt.is_zero pub.cm_change);
  Alcotest.(check bool) "mh_change is zero" true (Tzel.Felt.is_zero pub.memo_ct_hash_change)

let test_sign_verify_inputs () =
  let keys = Tzel.Keys.derive (Tzel.Felt.of_u64 200) in
  let addr = derive_test_address keys 0 in
  let rseed = Tzel.Felt.of_u64 555 in
  let note = Tzel.Note.create addr 1000L rseed in
  let sighash = Tzel.Hash.hash_tag "test-sighash" in
  let input : Tzel.Transaction.spend_input = {
    note; pos = 0; nk_spend = addr.nk_spend;
    auth_root = addr.auth_root; auth_pub_seed = addr.auth_pub_seed; ask_j = addr.ask_j;
    key_idx = 0; commitment_path = [||];
  } in
  let signed = Tzel.Transaction.sign_inputs [input] sighash in
  let (_, sig_vals) = List.hd signed in
  Alcotest.(check bool) "signature verifies" true
    (Tzel.Transaction.verify_input_sig input sig_vals sighash)

let test_sign_wrong_sighash () =
  let keys = Tzel.Keys.derive (Tzel.Felt.of_u64 200) in
  let addr = derive_test_address keys 0 in
  let note = Tzel.Note.create addr 1000L (Tzel.Felt.of_u64 1) in
  let input : Tzel.Transaction.spend_input = {
    note; pos = 0; nk_spend = addr.nk_spend;
    auth_root = addr.auth_root; auth_pub_seed = addr.auth_pub_seed; ask_j = addr.ask_j;
    key_idx = 0; commitment_path = [||];
  } in
  let signed = Tzel.Transaction.sign_inputs [input] (Tzel.Hash.hash_tag "real") in
  let (_, sig_vals) = List.hd signed in
  Alcotest.(check bool) "wrong sighash rejects" false
    (Tzel.Transaction.verify_input_sig input sig_vals (Tzel.Hash.hash_tag "fake"))

(* ══════════════════════════════════════════════════════════════════════
   Detection & Crypto
   ══════════════════════════════════════════════════════════════════════ *)

let test_chacha20_roundtrip () =
  let key = Tzel.Blake2s.hash_string "test-key" in
  let key_obj = Mirage_crypto.Chacha20.of_secret (Bytes.to_string key) in
  let nonce = String.make 12 '\x00' in
  let plaintext = "hello world 1234" in
  let ct = Mirage_crypto.Chacha20.authenticate_encrypt ~key:key_obj ~nonce plaintext in
  let pt = Mirage_crypto.Chacha20.authenticate_decrypt ~key:key_obj ~nonce ct in
  Alcotest.(check (option string)) "chacha20 roundtrip" (Some plaintext) pt

let test_detection_tag () =
  let ss = Tzel.Blake2s.hash_string "shared-secret" in
  let tag = Tzel.Detection.compute_tag ss in
  Alcotest.(check bool) "tag in range" true
    (tag >= 0 && tag < (1 lsl Tzel.Detection.detection_precision))

let test_detection_tag_deterministic () =
  let ss = Tzel.Blake2s.hash_string "shared-secret" in
  let t1 = Tzel.Detection.compute_tag ss in
  let t2 = Tzel.Detection.compute_tag ss in
  Alcotest.(check int) "tag deterministic" t1 t2

let test_memo_encode_decode () =
  let v = 42000L in
  let rseed = Tzel.Felt.of_u64 999 in
  let memo = Tzel.Detection.text_memo "Payment for invoice #42" in
  let pt = Tzel.Detection.encode_plaintext v rseed memo in
  Alcotest.(check int) "plaintext size" Tzel.Detection.plaintext_size (Bytes.length pt);
  let (v', rseed', memo') = Tzel.Detection.decode_plaintext pt in
  Alcotest.(check int64) "value" v v';
  Alcotest.(check bool) "rseed" true (Bytes.equal rseed rseed');
  Alcotest.(check bool) "memo" true (Bytes.equal memo memo')

let test_memo_encode_decode_zero () =
  let v = 0L in
  let rseed = Tzel.Felt.zero in
  let memo = Tzel.Detection.no_memo () in
  let pt = Tzel.Detection.encode_plaintext v rseed memo in
  let (v', rseed', memo') = Tzel.Detection.decode_plaintext pt in
  Alcotest.(check int64) "value zero" 0L v';
  Alcotest.(check bool) "rseed zero" true (Tzel.Felt.is_zero rseed');
  Alcotest.(check int) "memo marker" 0xF6 (Bytes.get_uint8 memo' 0)

let test_memo_encode_max_value () =
  let v = Int64.max_int in
  let rseed = Tzel.Felt.of_u64 1 in
  let memo = Tzel.Detection.no_memo () in
  let pt = Tzel.Detection.encode_plaintext v rseed memo in
  let (v', _, _) = Tzel.Detection.decode_plaintext pt in
  Alcotest.(check int64) "max value roundtrip" v v'

let test_no_memo () =
  let m = Tzel.Detection.no_memo () in
  Alcotest.(check int) "size" 1024 (Bytes.length m);
  Alcotest.(check int) "marker" 0xF6 (Bytes.get_uint8 m 0);
  for i = 1 to 1023 do
    Alcotest.(check int) (Printf.sprintf "zero byte %d" i) 0 (Bytes.get_uint8 m i)
  done

let test_text_memo_padding () =
  let m = Tzel.Detection.text_memo "hi" in
  Alcotest.(check int) "size" 1024 (Bytes.length m);
  Alcotest.(check int) "byte 0" (Char.code 'h') (Bytes.get_uint8 m 0);
  Alcotest.(check int) "byte 1" (Char.code 'i') (Bytes.get_uint8 m 1);
  Alcotest.(check int) "byte 2 zero" 0 (Bytes.get_uint8 m 2)

let test_mlkem_seed_derivation () =
  let view_root = Tzel.Hash.hash_tag "test-view-root" in
  let detect_root = Tzel.Hash.hash_tag "test-detect-root" in
  let vs = Tzel.Mlkem.derive_view_seed view_root 0 in
  let ds = Tzel.Mlkem.derive_detect_seed detect_root 0 in
  Alcotest.(check int) "view seed length" 64 (Bytes.length vs);
  Alcotest.(check int) "detect seed length" 64 (Bytes.length ds);
  let vs2 = Tzel.Mlkem.derive_view_seed view_root 1 in
  Alcotest.(check bool) "different index -> different seed" true
    (not (Bytes.equal vs vs2))

let test_mlkem_keygen_deterministic () =
  let seed = Bytes.make 64 '\x42' in
  let (ek1, dk1) = Tzel.Mlkem.keygen_det seed in
  let (ek2, dk2) = Tzel.Mlkem.keygen_det seed in
  Alcotest.(check int) "ek size" 1184 (Bytes.length ek1);
  Alcotest.(check int) "dk size" 2400 (Bytes.length dk1);
  Alcotest.(check bool) "ek deterministic" true (Bytes.equal ek1 ek2);
  Alcotest.(check bool) "dk deterministic" true (Bytes.equal dk1 dk2);
  let seed2 = Bytes.make 64 '\x43' in
  let (ek3, _) = Tzel.Mlkem.keygen_det seed2 in
  Alcotest.(check bool) "different seed -> different ek" true
    (not (Bytes.equal ek1 ek3))

let test_mlkem_encaps_decaps () =
  let seed = Bytes.make 64 '\x99' in
  let (ek, dk) = Tzel.Mlkem.keygen_det seed in
  let (ss1, ct) = Tzel.Mlkem.encaps ek in
  let ss2 = Tzel.Mlkem.decaps dk ct in
  Alcotest.(check int) "ss size" 32 (Bytes.length ss1);
  Alcotest.(check int) "ct size" 1088 (Bytes.length ct);
  Alcotest.(check bool) "encaps/decaps roundtrip" true (Bytes.equal ss1 ss2)

let test_mlkem_encaps_derand () =
  let seed = Bytes.make 64 '\xAA' in
  let (ek, dk) = Tzel.Mlkem.keygen_det seed in
  let coins = Bytes.make 32 '\xBB' in
  let (ss1, ct1) = Tzel.Mlkem.encaps_derand ek coins in
  let (ss2, ct2) = Tzel.Mlkem.encaps_derand ek coins in
  Alcotest.(check bool) "derand ss deterministic" true (Bytes.equal ss1 ss2);
  Alcotest.(check bool) "derand ct deterministic" true (Bytes.equal ct1 ct2);
  let ss3 = Tzel.Mlkem.decaps dk ct1 in
  Alcotest.(check bool) "derand decaps" true (Bytes.equal ss1 ss3)

let test_mlkem_derive_keypairs () =
  let keys = Tzel.Keys.derive (Tzel.Felt.of_u64 42) in
  let (ek_v, dk_v) = Tzel.Mlkem.derive_view_keypair keys.view_root 0 in
  let (ek_d, dk_d) = Tzel.Mlkem.derive_detect_keypair keys.detect_root 0 in
  Alcotest.(check int) "view ek size" 1184 (Bytes.length ek_v);
  Alcotest.(check int) "detect ek size" 1184 (Bytes.length ek_d);
  let (ss_v, ct_v) = Tzel.Mlkem.encaps ek_v in
  Alcotest.(check bool) "view roundtrip" true
    (Bytes.equal ss_v (Tzel.Mlkem.decaps dk_v ct_v));
  let (ss_d, ct_d) = Tzel.Mlkem.encaps ek_d in
  Alcotest.(check bool) "detect roundtrip" true
    (Bytes.equal ss_d (Tzel.Mlkem.decaps dk_d ct_d))

let test_full_note_encrypt_decrypt () =
  let bob_keys = Tzel.Keys.derive (Tzel.Felt.of_u64 200) in
  let bob_addr = derive_test_address bob_keys 0 in
  let v = 42000L in
  let rseed = Tzel.Felt.of_u64 555 in
  let memo = Tzel.Detection.text_memo "Payment for invoice #42" in
  let enc = Tzel.Detection.encrypt_note
    ~ek_v:bob_addr.ek_v ~ek_d:bob_addr.ek_d ~v ~rseed ~memo in
  match Tzel.Detection.decrypt_note ~dk_v:bob_addr.dk_v enc with
  | None -> Alcotest.fail "decryption failed"
  | Some (v', rseed', memo') ->
    Alcotest.(check int64) "value" v v';
    Alcotest.(check bool) "rseed" true (Bytes.equal rseed rseed');
    Alcotest.(check bool) "memo" true (Bytes.equal memo memo')

let test_detection_check () =
  let bob_keys = Tzel.Keys.derive (Tzel.Felt.of_u64 300) in
  let bob_addr = derive_test_address bob_keys 0 in
  let enc = Tzel.Detection.encrypt_note
    ~ek_v:bob_addr.ek_v ~ek_d:bob_addr.ek_d
    ~v:1000L ~rseed:(Tzel.Felt.of_u64 888)
    ~memo:(Tzel.Detection.no_memo ()) in
  let tag_ok = Tzel.Detection.check_tag
    ~dk_d:bob_addr.dk_d ~ct_d:enc.ct_d ~expected_tag:enc.tag in
  Alcotest.(check bool) "detection tag matches" true tag_ok;
  let mch = Tzel.Encoding.compute_memo_ct_hash enc in
  Alcotest.(check bool) "memo_ct_hash non-zero" true (not (Tzel.Felt.is_zero mch))

let test_encrypt_memo_decrypt_memo () =
  let ss_v = Tzel.Blake2s.hash_string "shared-secret-v" in
  let v = 12345L in
  let rseed = Tzel.Felt.of_u64 42 in
  let memo = Tzel.Detection.text_memo "test memo" in
  let (nonce, ct) = Tzel.Detection.encrypt_memo ~ss_v ~v ~rseed ~memo in
  Alcotest.(check int) "ct size" Tzel.Detection.ciphertext_data_size (Bytes.length ct);
  match Tzel.Detection.decrypt_memo ~ss_v ~nonce ~encrypted_data:ct with
  | None -> Alcotest.fail "decrypt failed"
  | Some (v', rseed', memo') ->
    Alcotest.(check int64) "value" v v';
    Alcotest.(check bool) "rseed" true (Bytes.equal rseed rseed');
    Alcotest.(check bool) "memo" true (Bytes.equal memo memo')

let test_decrypt_wrong_key () =
  let ss1 = Tzel.Blake2s.hash_string "key1" in
  let ss2 = Tzel.Blake2s.hash_string "key2" in
  let (nonce, ct) = Tzel.Detection.encrypt_memo
    ~ss_v:ss1 ~v:100L ~rseed:(Tzel.Felt.of_u64 1)
    ~memo:(Tzel.Detection.no_memo ()) in
  let result = Tzel.Detection.decrypt_memo ~ss_v:ss2 ~nonce ~encrypted_data:ct in
  Alcotest.(check bool) "wrong key -> None" true (result = None)

(* ══════════════════════════════════════════════════════════════════════
   Encoding
   ══════════════════════════════════════════════════════════════════════ *)

let test_encoding_encrypted_note () =
  let enc : Tzel.Encoding.encrypted_note = {
    ct_d = Bytes.make 1088 '\x01';
    tag = 42;
    ct_v = Bytes.make 1088 '\x02';
    nonce = Bytes.make 12 '\x04';
    encrypted_data = Bytes.make 1080 '\x03';
  } in
  let wire = Tzel.Encoding.encode_encrypted_note enc in
  Alcotest.(check int) "wire size" Tzel.Encoding.encrypted_note_size (Bytes.length wire);
  let dec = Tzel.Encoding.decode_encrypted_note wire in
  Alcotest.(check int) "tag" 42 dec.tag;
  Alcotest.(check bool) "ct_d" true (Bytes.equal enc.ct_d dec.ct_d);
  Alcotest.(check bool) "ct_v" true (Bytes.equal enc.ct_v dec.ct_v);
  Alcotest.(check bool) "nonce" true (Bytes.equal enc.nonce dec.nonce);
  Alcotest.(check bool) "encrypted_data" true (Bytes.equal enc.encrypted_data dec.encrypted_data)

let test_encoding_published_note () =
  let cm = Tzel.Hash.hash_tag "test-cm" in
  let enc : Tzel.Encoding.encrypted_note = {
    ct_d = Bytes.make 1088 '\xAA'; tag = 1023;
    ct_v = Bytes.make 1088 '\xBB'; nonce = Bytes.make 12 '\xDD';
    encrypted_data = Bytes.make 1080 '\xCC';
  } in
  let pn = { Tzel.Encoding.pn_cm = cm; pn_enc = enc } in
  let wire = Tzel.Encoding.encode_published_note pn in
  Alcotest.(check int) "size" Tzel.Encoding.published_note_size (Bytes.length wire);
  let dec = Tzel.Encoding.decode_published_note wire in
  Alcotest.(check bool) "cm" true (Tzel.Felt.equal cm dec.pn_cm);
  Alcotest.(check int) "tag" 1023 dec.pn_enc.tag

let test_encoding_note_memo () =
  let cm = Tzel.Hash.hash_tag "test-cm" in
  let enc : Tzel.Encoding.encrypted_note = {
    ct_d = Bytes.make 1088 '\x00'; tag = 7;
    ct_v = Bytes.make 1088 '\x00'; nonce = Bytes.make 12 '\x00';
    encrypted_data = Bytes.make 1080 '\x00';
  } in
  let nm = { Tzel.Encoding.nm_index = 42L; nm_cm = cm; nm_enc = enc } in
  let wire = Tzel.Encoding.encode_note_memo nm in
  Alcotest.(check int) "size" Tzel.Encoding.note_memo_size (Bytes.length wire);
  let dec = Tzel.Encoding.decode_note_memo wire in
  Alcotest.(check int64) "index" 42L dec.nm_index;
  Alcotest.(check bool) "cm" true (Tzel.Felt.equal cm dec.nm_cm)

let test_encoding_u16_le () =
  let buf = Bytes.make 4 '\x00' in
  Tzel.Encoding.put_u16_le buf 0 0x1234;
  Alcotest.(check int) "lo" 0x34 (Bytes.get_uint8 buf 0);
  Alcotest.(check int) "hi" 0x12 (Bytes.get_uint8 buf 1);
  Alcotest.(check int) "roundtrip" 0x1234 (Tzel.Encoding.get_u16_le buf 0)

let test_encoding_u64_le () =
  let buf = Bytes.make 16 '\x00' in
  Tzel.Encoding.put_u64_le buf 0 0x0102030405060708L;
  Alcotest.(check int64) "roundtrip" 0x0102030405060708L
    (Tzel.Encoding.get_u64_le buf 0)

let test_encoding_u16_boundary () =
  let buf = Bytes.make 4 '\x00' in
  Tzel.Encoding.put_u16_le buf 0 0;
  Alcotest.(check int) "zero" 0 (Tzel.Encoding.get_u16_le buf 0);
  Tzel.Encoding.put_u16_le buf 0 0xFFFF;
  Alcotest.(check int) "max u16" 0xFFFF (Tzel.Encoding.get_u16_le buf 0)

let test_encoding_u64_boundary () =
  let buf = Bytes.make 16 '\x00' in
  Tzel.Encoding.put_u64_le buf 0 0L;
  Alcotest.(check int64) "zero" 0L (Tzel.Encoding.get_u64_le buf 0);
  Tzel.Encoding.put_u64_le buf 0 Int64.max_int;
  Alcotest.(check int64) "max" Int64.max_int (Tzel.Encoding.get_u64_le buf 0)

let test_payment_address_wire () =
  let bob_keys = Tzel.Keys.derive (Tzel.Felt.of_u64 400) in
  let bob_addr = derive_test_address bob_keys 0 in
  let pa = Tzel.Keys.to_payment_address bob_addr in
  let wire_addr : Tzel.Encoding.payment_address_wire = {
    d_j = pa.pa_d_j; auth_root = pa.pa_auth_root;
    auth_pub_seed = pa.pa_auth_pub_seed; nk_tag = pa.pa_nk_tag; ek_v = pa.pa_ek_v; ek_d = pa.pa_ek_d;
  } in
  let encoded = Tzel.Encoding.encode_payment_address wire_addr in
  Alcotest.(check int) "size" Tzel.Encoding.payment_address_size (Bytes.length encoded);
  let decoded = Tzel.Encoding.decode_payment_address encoded in
  Alcotest.(check bool) "d_j" true (Tzel.Felt.equal wire_addr.d_j decoded.d_j);
  Alcotest.(check bool) "auth_root" true (Tzel.Felt.equal wire_addr.auth_root decoded.auth_root);
  Alcotest.(check bool) "auth_pub_seed" true (Tzel.Felt.equal wire_addr.auth_pub_seed decoded.auth_pub_seed);
  Alcotest.(check bool) "nk_tag" true (Tzel.Felt.equal wire_addr.nk_tag decoded.nk_tag);
  Alcotest.(check bool) "ek_v" true (Bytes.equal wire_addr.ek_v decoded.ek_v);
  Alcotest.(check bool) "ek_d" true (Bytes.equal wire_addr.ek_d decoded.ek_d)

let test_memo_ct_hash_deterministic () =
  let enc : Tzel.Encoding.encrypted_note = {
    ct_d = Bytes.make 1088 '\x11'; tag = 42;
    ct_v = Bytes.make 1088 '\x22'; nonce = Bytes.make 12 '\x44';
    encrypted_data = Bytes.make 1080 '\x33';
  } in
  let h1 = Tzel.Encoding.compute_memo_ct_hash enc in
  let h2 = Tzel.Encoding.compute_memo_ct_hash enc in
  Alcotest.(check bool) "deterministic" true (Tzel.Felt.equal h1 h2)

let test_encoding_json_encrypted_note () =
  let enc : Tzel.Encoding.encrypted_note = {
    ct_d = Bytes.make 1088 '\x01'; tag = 42;
    ct_v = Bytes.make 1088 '\x02'; nonce = Bytes.make 12 '\x04';
    encrypted_data = Bytes.make 1080 '\x03';
  } in
  let json = Tzel.Encoding.encrypted_note_to_json enc in
  match json with
  | `Assoc fields ->
    Alcotest.(check int) "5 fields" 5 (List.length fields);
    let tag_val = List.assoc "tag" fields in
    Alcotest.(check int) "tag" 42 (match tag_val with `Int n -> n | _ -> -1)
  | _ -> Alcotest.fail "expected Assoc"

let test_encoding_json_published_note () =
  let cm = Tzel.Hash.hash_tag "cm" in
  let enc : Tzel.Encoding.encrypted_note = {
    ct_d = Bytes.make 1088 '\x00'; tag = 0;
    ct_v = Bytes.make 1088 '\x00'; nonce = Bytes.make 12 '\x00';
    encrypted_data = Bytes.make 1080 '\x00';
  } in
  let pn = { Tzel.Encoding.pn_cm = cm; pn_enc = enc } in
  let json = Tzel.Encoding.published_note_to_json pn in
  match json with
  | `Assoc fields ->
    Alcotest.(check int) "2 fields" 2 (List.length fields)
  | _ -> Alcotest.fail "expected Assoc"

let test_encoding_json_payment_address () =
  let addr : Tzel.Encoding.payment_address_wire = {
    d_j = Tzel.Felt.of_u64 1; auth_root = Tzel.Felt.of_u64 2;
    auth_pub_seed = Tzel.Felt.of_u64 3;
    nk_tag = Tzel.Felt.of_u64 3;
    ek_v = Bytes.make 1184 '\x00'; ek_d = Bytes.make 1184 '\x00';
  } in
  let json = Tzel.Encoding.payment_address_to_json addr in
  match json with
  | `Assoc fields ->
    Alcotest.(check int) "6 fields" 6 (List.length fields)
  | _ -> Alcotest.fail "expected Assoc"

let test_encoding_hex_helpers () =
  let f = Tzel.Felt.of_u64 0xCAFE in
  let hex = Tzel.Encoding.hex_of_felt f in
  let f2 = Tzel.Encoding.felt_of_hex_json hex in
  Alcotest.(check bool) "hex felt roundtrip" true (Tzel.Felt.equal f f2);
  let b = Bytes.of_string "\x01\x02\x03" in
  let hex_b = Tzel.Encoding.hex_of_bytes b in
  Alcotest.(check string) "hex bytes" "010203" hex_b;
  let b2 = Tzel.Encoding.bytes_of_hex_json hex_b in
  Alcotest.(check bool) "bytes roundtrip" true (Bytes.equal b b2)

(* ══════════════════════════════════════════════════════════════════════
   Ledger
   ══════════════════════════════════════════════════════════════════════ *)

let test_shield_flow () =
  let auth_domain = Tzel.Hash.hash_tag "test-domain" in
  let ledger = Tzel.Ledger.create ~auth_domain in
  Tzel.Ledger.set_balance ledger "alice" 10000L;
  let bob_keys = Tzel.Keys.derive (Tzel.Felt.of_u64 200) in
  let bob_addr = derive_test_address bob_keys 0 in
  let rseed = Tzel.Felt.of_u64 555 in
  let mch = Tzel.Felt.zero in
  let (pub, note) = Tzel.Transaction.build_shield
    ~sender_string:"alice" ~recipient:bob_addr ~v:5000L ~rseed ~memo_ct_hash:mch in
  let result = Tzel.Ledger.apply_shield ledger ~sender_string:"alice" ~pub ~memo_ct_hash:mch in
  Alcotest.(check bool) "shield ok" true (Result.is_ok result);
  Alcotest.(check int64) "alice balance" 5000L (Tzel.Ledger.get_balance ledger "alice");
  Alcotest.(check int) "tree size" 1 (Tzel.Ledger.tree_size ledger);
  let root = Tzel.Ledger.current_root ledger in
  Alcotest.(check bool) "root valid" true (Tzel.Ledger.is_valid_root ledger root);
  ignore note

let test_shield_insufficient_balance () =
  let auth_domain = Tzel.Hash.hash_tag "test-domain" in
  let ledger = Tzel.Ledger.create ~auth_domain in
  Tzel.Ledger.set_balance ledger "alice" 100L;
  let keys = Tzel.Keys.derive (Tzel.Felt.of_u64 1) in
  let addr = derive_test_address keys 0 in
  let mch = Tzel.Felt.zero in
  let (pub, _) = Tzel.Transaction.build_shield
    ~sender_string:"alice" ~recipient:addr ~v:500L
    ~rseed:(Tzel.Felt.of_u64 1) ~memo_ct_hash:mch in
  let result = Tzel.Ledger.apply_shield ledger ~sender_string:"alice" ~pub ~memo_ct_hash:mch in
  Alcotest.(check bool) "insufficient balance" true (Result.is_error result)

let test_shield_sender_mismatch () =
  let auth_domain = Tzel.Hash.hash_tag "test-domain" in
  let ledger = Tzel.Ledger.create ~auth_domain in
  Tzel.Ledger.set_balance ledger "alice" 10000L;
  let keys = Tzel.Keys.derive (Tzel.Felt.of_u64 1) in
  let addr = derive_test_address keys 0 in
  let mch = Tzel.Felt.zero in
  let (pub, _) = Tzel.Transaction.build_shield
    ~sender_string:"alice" ~recipient:addr ~v:500L
    ~rseed:(Tzel.Felt.of_u64 1) ~memo_ct_hash:mch in
  let result = Tzel.Ledger.apply_shield ledger ~sender_string:"bob" ~pub ~memo_ct_hash:mch in
  Alcotest.(check bool) "sender mismatch" true (Result.is_error result)

let test_shield_memo_mismatch () =
  let auth_domain = Tzel.Hash.hash_tag "test-domain" in
  let ledger = Tzel.Ledger.create ~auth_domain in
  Tzel.Ledger.set_balance ledger "alice" 10000L;
  let keys = Tzel.Keys.derive (Tzel.Felt.of_u64 1) in
  let addr = derive_test_address keys 0 in
  let mch = Tzel.Felt.zero in
  let (pub, _) = Tzel.Transaction.build_shield
    ~sender_string:"alice" ~recipient:addr ~v:500L
    ~rseed:(Tzel.Felt.of_u64 1) ~memo_ct_hash:mch in
  let wrong_mch = Tzel.Felt.of_u64 999 in
  let result = Tzel.Ledger.apply_shield ledger ~sender_string:"alice" ~pub ~memo_ct_hash:wrong_mch in
  Alcotest.(check bool) "memo mismatch" true (Result.is_error result)

let test_ledger_transfer () =
  let auth_domain = Tzel.Hash.hash_tag "test-domain" in
  let ledger = Tzel.Ledger.create ~auth_domain in
  (* Setup: shield two notes *)
  let keys = Tzel.Keys.derive (Tzel.Felt.of_u64 1) in
  let addr = derive_test_address keys 0 in
  Tzel.Ledger.set_balance ledger "alice" 10000L;
  let mch = Tzel.Felt.zero in
  let (pub1, _) = Tzel.Transaction.build_shield
    ~sender_string:"alice" ~recipient:addr ~v:5000L
    ~rseed:(Tzel.Felt.of_u64 1) ~memo_ct_hash:mch in
  ignore (Tzel.Ledger.apply_shield ledger ~sender_string:"alice" ~pub:pub1 ~memo_ct_hash:mch);
  let root = Tzel.Ledger.current_root ledger in
  (* Build transfer *)
  let nf = Tzel.Hash.hash_tag "nf0" in
  let cm1 = Tzel.Hash.hash_tag "cm1" in
  let cm2 = Tzel.Hash.hash_tag "cm2" in
  let tpub : Tzel.Transaction.transfer_public = {
    auth_domain; root; nullifiers = [nf];
    cm_1 = cm1; cm_2 = cm2;
    memo_ct_hash_1 = mch; memo_ct_hash_2 = mch;
  } in
  let result = Tzel.Ledger.apply_transfer ledger tpub
    ~memo_ct_hash_1:mch ~memo_ct_hash_2:mch in
  Alcotest.(check bool) "transfer ok" true (Result.is_ok result);
  Alcotest.(check int) "tree size" 3 (Tzel.Ledger.tree_size ledger)

let test_ledger_transfer_wrong_domain () =
  let auth_domain = Tzel.Hash.hash_tag "domain1" in
  let ledger = Tzel.Ledger.create ~auth_domain in
  let root = Tzel.Ledger.current_root ledger in
  let mch = Tzel.Felt.zero in
  let tpub : Tzel.Transaction.transfer_public = {
    auth_domain = Tzel.Hash.hash_tag "wrong-domain";
    root; nullifiers = []; cm_1 = Tzel.Felt.zero; cm_2 = Tzel.Felt.zero;
    memo_ct_hash_1 = mch; memo_ct_hash_2 = mch;
  } in
  let result = Tzel.Ledger.apply_transfer ledger tpub
    ~memo_ct_hash_1:mch ~memo_ct_hash_2:mch in
  Alcotest.(check bool) "wrong domain" true (Result.is_error result)

let test_ledger_transfer_unknown_root () =
  let auth_domain = Tzel.Hash.hash_tag "domain" in
  let ledger = Tzel.Ledger.create ~auth_domain in
  let fake_root = Tzel.Hash.hash_tag "fake-root" in
  let mch = Tzel.Felt.zero in
  let tpub : Tzel.Transaction.transfer_public = {
    auth_domain; root = fake_root;
    nullifiers = []; cm_1 = Tzel.Felt.zero; cm_2 = Tzel.Felt.zero;
    memo_ct_hash_1 = mch; memo_ct_hash_2 = mch;
  } in
  let result = Tzel.Ledger.apply_transfer ledger tpub
    ~memo_ct_hash_1:mch ~memo_ct_hash_2:mch in
  Alcotest.(check bool) "unknown root" true (Result.is_error result)

let test_ledger_nullifier_double_spend () =
  let auth_domain = Tzel.Hash.hash_tag "domain" in
  let ledger = Tzel.Ledger.create ~auth_domain in
  let root = Tzel.Ledger.current_root ledger in
  let mch = Tzel.Felt.zero in
  let nf = Tzel.Hash.hash_tag "nf" in
  let tpub : Tzel.Transaction.transfer_public = {
    auth_domain; root; nullifiers = [nf];
    cm_1 = Tzel.Hash.hash_tag "cm1"; cm_2 = Tzel.Hash.hash_tag "cm2";
    memo_ct_hash_1 = mch; memo_ct_hash_2 = mch;
  } in
  ignore (Tzel.Ledger.apply_transfer ledger tpub ~memo_ct_hash_1:mch ~memo_ct_hash_2:mch);
  (* Use same nullifier again *)
  let new_root = Tzel.Ledger.current_root ledger in
  let tpub2 : Tzel.Transaction.transfer_public = {
    auth_domain; root = new_root; nullifiers = [nf];
    cm_1 = Tzel.Hash.hash_tag "cm3"; cm_2 = Tzel.Hash.hash_tag "cm4";
    memo_ct_hash_1 = mch; memo_ct_hash_2 = mch;
  } in
  let result = Tzel.Ledger.apply_transfer ledger tpub2
    ~memo_ct_hash_1:mch ~memo_ct_hash_2:mch in
  Alcotest.(check bool) "double spend rejected" true (Result.is_error result)

let test_ledger_duplicate_nullifier_in_tx () =
  let auth_domain = Tzel.Hash.hash_tag "domain" in
  let ledger = Tzel.Ledger.create ~auth_domain in
  let root = Tzel.Ledger.current_root ledger in
  let mch = Tzel.Felt.zero in
  let nf = Tzel.Hash.hash_tag "nf" in
  let tpub : Tzel.Transaction.transfer_public = {
    auth_domain; root; nullifiers = [nf; nf];
    cm_1 = Tzel.Felt.zero; cm_2 = Tzel.Felt.zero;
    memo_ct_hash_1 = mch; memo_ct_hash_2 = mch;
  } in
  let result = Tzel.Ledger.apply_transfer ledger tpub
    ~memo_ct_hash_1:mch ~memo_ct_hash_2:mch in
  Alcotest.(check bool) "duplicate nf in tx rejected" true (Result.is_error result)

let test_ledger_transfer_memo_mismatch () =
  let auth_domain = Tzel.Hash.hash_tag "domain" in
  let ledger = Tzel.Ledger.create ~auth_domain in
  let root = Tzel.Ledger.current_root ledger in
  let mch = Tzel.Felt.zero in
  let tpub : Tzel.Transaction.transfer_public = {
    auth_domain; root; nullifiers = [];
    cm_1 = Tzel.Felt.zero; cm_2 = Tzel.Felt.zero;
    memo_ct_hash_1 = mch; memo_ct_hash_2 = mch;
  } in
  let wrong = Tzel.Felt.of_u64 1 in
  let r1 = Tzel.Ledger.apply_transfer ledger tpub
    ~memo_ct_hash_1:wrong ~memo_ct_hash_2:mch in
  Alcotest.(check bool) "memo1 mismatch" true (Result.is_error r1);
  let r2 = Tzel.Ledger.apply_transfer ledger tpub
    ~memo_ct_hash_1:mch ~memo_ct_hash_2:wrong in
  Alcotest.(check bool) "memo2 mismatch" true (Result.is_error r2)

let test_ledger_unshield () =
  let auth_domain = Tzel.Hash.hash_tag "domain" in
  let ledger = Tzel.Ledger.create ~auth_domain in
  let root = Tzel.Ledger.current_root ledger in
  let mch = Tzel.Felt.zero in
  let nf = Tzel.Hash.hash_tag "nf" in
  let upub : Tzel.Transaction.unshield_public = {
    auth_domain; root; nullifiers = [nf];
    v_pub = 5000L; recipient_id = Tzel.Hash.account_id "bob";
    cm_change = Tzel.Felt.zero; memo_ct_hash_change = Tzel.Felt.zero;
  } in
  let result = Tzel.Ledger.apply_unshield ledger ~recipient_string:"bob" upub
    ~memo_ct_hash_change:mch in
  Alcotest.(check bool) "unshield ok" true (Result.is_ok result);
  Alcotest.(check int64) "bob balance" 5000L (Tzel.Ledger.get_balance ledger "bob")

let test_ledger_unshield_with_change () =
  let auth_domain = Tzel.Hash.hash_tag "domain" in
  let ledger = Tzel.Ledger.create ~auth_domain in
  let root = Tzel.Ledger.current_root ledger in
  let mch = Tzel.Felt.zero in
  let nf = Tzel.Hash.hash_tag "nf" in
  let cm_change = Tzel.Hash.hash_tag "change-cm" in
  let upub : Tzel.Transaction.unshield_public = {
    auth_domain; root; nullifiers = [nf];
    v_pub = 3000L; recipient_id = Tzel.Hash.account_id "bob";
    cm_change; memo_ct_hash_change = mch;
  } in
  let result = Tzel.Ledger.apply_unshield ledger ~recipient_string:"bob" upub
    ~memo_ct_hash_change:mch in
  Alcotest.(check bool) "unshield with change ok" true (Result.is_ok result);
  Alcotest.(check int) "tree has change" 1 (Tzel.Ledger.tree_size ledger);
  Alcotest.(check int64) "bob balance" 3000L (Tzel.Ledger.get_balance ledger "bob")

let test_ledger_unshield_wrong_recipient () =
  let auth_domain = Tzel.Hash.hash_tag "domain" in
  let ledger = Tzel.Ledger.create ~auth_domain in
  let root = Tzel.Ledger.current_root ledger in
  let upub : Tzel.Transaction.unshield_public = {
    auth_domain; root; nullifiers = [];
    v_pub = 1000L; recipient_id = Tzel.Hash.account_id "bob";
    cm_change = Tzel.Felt.zero; memo_ct_hash_change = Tzel.Felt.zero;
  } in
  let result = Tzel.Ledger.apply_unshield ledger ~recipient_string:"alice" upub
    ~memo_ct_hash_change:Tzel.Felt.zero in
  Alcotest.(check bool) "wrong recipient" true (Result.is_error result)

let test_ledger_unshield_wrong_domain () =
  let auth_domain = Tzel.Hash.hash_tag "domain" in
  let ledger = Tzel.Ledger.create ~auth_domain in
  let root = Tzel.Ledger.current_root ledger in
  let upub : Tzel.Transaction.unshield_public = {
    auth_domain = Tzel.Hash.hash_tag "wrong"; root; nullifiers = [];
    v_pub = 1000L; recipient_id = Tzel.Hash.account_id "bob";
    cm_change = Tzel.Felt.zero; memo_ct_hash_change = Tzel.Felt.zero;
  } in
  let result = Tzel.Ledger.apply_unshield ledger ~recipient_string:"bob" upub
    ~memo_ct_hash_change:Tzel.Felt.zero in
  Alcotest.(check bool) "wrong domain" true (Result.is_error result)

let test_ledger_unshield_change_memo_mismatch () =
  let auth_domain = Tzel.Hash.hash_tag "domain" in
  let ledger = Tzel.Ledger.create ~auth_domain in
  let root = Tzel.Ledger.current_root ledger in
  let cm_change = Tzel.Hash.hash_tag "change" in
  let mch = Tzel.Felt.zero in
  let upub : Tzel.Transaction.unshield_public = {
    auth_domain; root; nullifiers = [];
    v_pub = 1000L; recipient_id = Tzel.Hash.account_id "bob";
    cm_change; memo_ct_hash_change = mch;
  } in
  let result = Tzel.Ledger.apply_unshield ledger ~recipient_string:"bob" upub
    ~memo_ct_hash_change:(Tzel.Felt.of_u64 999) in
  Alcotest.(check bool) "change memo mismatch" true (Result.is_error result)

let test_ledger_balance_default () =
  let ledger = Tzel.Ledger.create ~auth_domain:Tzel.Felt.zero in
  Alcotest.(check int64) "default balance" 0L (Tzel.Ledger.get_balance ledger "nobody")

let test_ledger_root_history () =
  let auth_domain = Tzel.Hash.hash_tag "domain" in
  let ledger = Tzel.Ledger.create ~auth_domain in
  let r0 = Tzel.Ledger.current_root ledger in
  Alcotest.(check bool) "initial root valid" true (Tzel.Ledger.is_valid_root ledger r0);
  Tzel.Ledger.append_commitment ledger (Tzel.Felt.of_u64 1);
  let r1 = Tzel.Ledger.current_root ledger in
  Alcotest.(check bool) "new root valid" true (Tzel.Ledger.is_valid_root ledger r1);
  Alcotest.(check bool) "old root still valid" true (Tzel.Ledger.is_valid_root ledger r0);
  Alcotest.(check bool) "fake root invalid" false
    (Tzel.Ledger.is_valid_root ledger (Tzel.Hash.hash_tag "fake"))

let test_ledger_root_history_prunes_oldest () =
  let ledger = Tzel.Ledger.create ~auth_domain:Tzel.Felt.zero in
  let initial_root = Tzel.Ledger.current_root ledger in
  let r1 = Tzel.Felt.of_u64 101 in
  let r2 = Tzel.Felt.of_u64 102 in
  let r3 = Tzel.Felt.of_u64 103 in
  Tzel.Ledger.record_root_with_limit ledger ~max_roots:3 (Tzel.Felt.to_hex r1);
  Tzel.Ledger.record_root_with_limit ledger ~max_roots:3 (Tzel.Felt.to_hex r2);
  Alcotest.(check bool) "initial still valid" true (Tzel.Ledger.is_valid_root ledger initial_root);
  Tzel.Ledger.record_root_with_limit ledger ~max_roots:3 (Tzel.Felt.to_hex r3);
  Alcotest.(check bool) "initial pruned" false (Tzel.Ledger.is_valid_root ledger initial_root);
  Alcotest.(check bool) "r1 valid" true (Tzel.Ledger.is_valid_root ledger r1);
  Alcotest.(check bool) "r2 valid" true (Tzel.Ledger.is_valid_root ledger r2);
  Alcotest.(check bool) "r3 valid" true (Tzel.Ledger.is_valid_root ledger r3)

let test_ledger_check_nullifiers_empty () =
  let ledger = Tzel.Ledger.create ~auth_domain:Tzel.Felt.zero in
  let result = Tzel.Ledger.check_and_insert_nullifiers ledger [] in
  Alcotest.(check bool) "empty list ok" true (Result.is_ok result)

(* ══════════════════════════════════════════════════════════════════════
   Prover boundary
   ══════════════════════════════════════════════════════════════════════ *)

let test_prover_parse_proof_bundle () =
  let json = {|{"proof_bytes":"deadbeef","output_preimage":["0xaabbccdd00000000000000000000000000000000000000000000000000000000","0x1122334400000000000000000000000000000000000000000000000000000000"]}|} in
  let bundle = Tzel.Prover.parse_proof_bundle json in
  Alcotest.(check string) "proof bytes" "deadbeef" bundle.proof_bytes;
  Alcotest.(check int) "preimage len" 2 (List.length bundle.output_preimage)

let test_prover_extract_program_hash () =
  let preimage = [Tzel.Felt.of_u64 1; Tzel.Felt.of_u64 10;
                  Tzel.Felt.of_u64 42; Tzel.Felt.of_u64 100] in
  let ph = Tzel.Prover.extract_program_hash preimage in
  Alcotest.(check bool) "has program hash" true (Option.is_some ph);
  Alcotest.(check bool) "correct ph" true
    (Tzel.Felt.equal (Option.get ph) (Tzel.Felt.of_u64 42))

let test_prover_extract_program_hash_short () =
  let preimage = [Tzel.Felt.of_u64 1] in
  let ph = Tzel.Prover.extract_program_hash preimage in
  Alcotest.(check bool) "too short -> None" true (Option.is_none ph)

let test_prover_extract_public_outputs () =
  let preimage = [Tzel.Felt.of_u64 1; Tzel.Felt.of_u64 3;
                  Tzel.Felt.of_u64 42; Tzel.Felt.of_u64 100;
                  Tzel.Felt.of_u64 200] in
  let outputs = Tzel.Prover.extract_public_outputs preimage in
  Alcotest.(check int) "2 outputs" 2 (List.length outputs);
  Alcotest.(check bool) "first output" true
    (Tzel.Felt.equal (List.nth outputs 0) (Tzel.Felt.of_u64 100))

let test_prover_extract_public_outputs_empty () =
  let outputs = Tzel.Prover.extract_public_outputs [] in
  Alcotest.(check int) "empty -> empty" 0 (List.length outputs)

let test_prover_verify_program_hash () =
  let config : Tzel.Prover.circuit_config = {
    shield_program_hash = Tzel.Felt.of_u64 10;
    transfer_program_hash = Tzel.Felt.of_u64 20;
    unshield_program_hash = Tzel.Felt.of_u64 30;
    auth_domain = Tzel.Felt.of_u64 1;
    prover_binary = ""; verifier_binary = "";
  } in
  let preimage = [Tzel.Felt.of_u64 1; Tzel.Felt.of_u64 1; Tzel.Felt.of_u64 10] in
  let r = Tzel.Prover.verify_program_hash config Tzel.Prover.Shield preimage in
  Alcotest.(check bool) "shield ok" true (Result.is_ok r);
  let preimage_t = [Tzel.Felt.of_u64 1; Tzel.Felt.of_u64 1; Tzel.Felt.of_u64 20] in
  let r2 = Tzel.Prover.verify_program_hash config Tzel.Prover.Transfer preimage_t in
  Alcotest.(check bool) "transfer ok" true (Result.is_ok r2);
  let preimage_u = [Tzel.Felt.of_u64 1; Tzel.Felt.of_u64 1; Tzel.Felt.of_u64 30] in
  let r3 = Tzel.Prover.verify_program_hash config Tzel.Prover.Unshield preimage_u in
  Alcotest.(check bool) "unshield ok" true (Result.is_ok r3)

let test_prover_verify_program_hash_mismatch () =
  let config : Tzel.Prover.circuit_config = {
    shield_program_hash = Tzel.Felt.of_u64 10;
    transfer_program_hash = Tzel.Felt.of_u64 20;
    unshield_program_hash = Tzel.Felt.of_u64 30;
    auth_domain = Tzel.Felt.of_u64 1;
    prover_binary = ""; verifier_binary = "";
  } in
  let preimage = [Tzel.Felt.of_u64 1; Tzel.Felt.of_u64 1; Tzel.Felt.of_u64 99] in
  let r = Tzel.Prover.verify_program_hash config Tzel.Prover.Shield preimage in
  Alcotest.(check bool) "mismatch" true (Result.is_error r)

let test_prover_verify_program_hash_short_error () =
  let config : Tzel.Prover.circuit_config = {
    shield_program_hash = Tzel.Felt.of_u64 10;
    transfer_program_hash = Tzel.Felt.of_u64 20;
    unshield_program_hash = Tzel.Felt.of_u64 30;
    auth_domain = Tzel.Felt.of_u64 1;
    prover_binary = ""; verifier_binary = "";
  } in
  let r = Tzel.Prover.verify_program_hash config Tzel.Prover.Shield [Tzel.Felt.of_u64 1] in
  Alcotest.(check bool) "short preimage rejected" true (Result.is_error r)

let test_prover_verify_auth_domain () =
  let config : Tzel.Prover.circuit_config = {
    shield_program_hash = Tzel.Felt.zero;
    transfer_program_hash = Tzel.Felt.zero;
    unshield_program_hash = Tzel.Felt.zero;
    auth_domain = Tzel.Felt.of_u64 42;
    prover_binary = ""; verifier_binary = "";
  } in
  let outputs = [Tzel.Felt.of_u64 42; Tzel.Felt.of_u64 1] in
  Alcotest.(check bool) "auth domain ok" true
    (Result.is_ok (Tzel.Prover.verify_auth_domain config outputs));
  let bad_outputs = [Tzel.Felt.of_u64 99] in
  Alcotest.(check bool) "auth domain mismatch" true
    (Result.is_error (Tzel.Prover.verify_auth_domain config bad_outputs));
  Alcotest.(check bool) "empty outputs" true
    (Result.is_error (Tzel.Prover.verify_auth_domain config []))

let test_prover_witness_json () =
  let sw : Tzel.Prover.shield_witness = {
    sw_d_j = Tzel.Felt.of_u64 1; sw_v = 1000L;
    sw_rseed = Tzel.Felt.of_u64 2; sw_auth_root = Tzel.Felt.of_u64 3;
    sw_nk_tag = Tzel.Felt.of_u64 4; sw_sender_string = "alice";
    sw_memo_ct_hash = Tzel.Felt.of_u64 5;
  } in
  let json = Tzel.Prover.shield_witness_to_json sw in
  (match json with
   | `Assoc fields ->
     Alcotest.(check int) "7 fields" 7 (List.length fields)
   | _ -> Alcotest.fail "expected Assoc")

let test_prover_spend_witness_json () =
  let spw : Tzel.Prover.spend_witness = {
    spw_d_j = Tzel.Felt.of_u64 1; spw_v = 100L;
    spw_rseed = Tzel.Felt.of_u64 2; spw_nk_spend = Tzel.Felt.of_u64 3;
    spw_auth_root = Tzel.Felt.of_u64 4; spw_pos = 0;
    spw_commitment_path = [|Tzel.Felt.of_u64 5|];
    spw_key_idx = 0; spw_auth_path = [|Tzel.Felt.of_u64 6|];
    spw_wots_sig = [|Tzel.Felt.of_u64 7|];
  } in
  let json = Tzel.Prover.spend_witness_to_json spw in
  (match json with `Assoc f -> Alcotest.(check int) "10 fields" 10 (List.length f) | _ -> Alcotest.fail "")

let test_prover_output_witness_json () =
  let ow : Tzel.Prover.output_witness = {
    ow_d_j = Tzel.Felt.of_u64 1; ow_v = 100L;
    ow_rseed = Tzel.Felt.of_u64 2; ow_auth_root = Tzel.Felt.of_u64 3;
    ow_nk_tag = Tzel.Felt.of_u64 4; ow_memo_ct_hash = Tzel.Felt.of_u64 5;
  } in
  let json = Tzel.Prover.output_witness_to_json ow in
  (match json with `Assoc f -> Alcotest.(check int) "6 fields" 6 (List.length f) | _ -> Alcotest.fail "")

let test_prover_transfer_witness_json () =
  let ow = { Tzel.Prover.ow_d_j = Tzel.Felt.of_u64 1; ow_v = 100L;
    ow_rseed = Tzel.Felt.of_u64 2; ow_auth_root = Tzel.Felt.of_u64 3;
    ow_nk_tag = Tzel.Felt.of_u64 4; ow_memo_ct_hash = Tzel.Felt.of_u64 5 } in
  let tw : Tzel.Prover.transfer_witness = {
    tw_auth_domain = Tzel.Felt.of_u64 1;
    tw_inputs = [];
    tw_outputs = (ow, ow);
  } in
  let json = Tzel.Prover.transfer_witness_to_json tw in
  (match json with `Assoc f -> Alcotest.(check bool) "has type" true (List.mem_assoc "type" f)
   | _ -> Alcotest.fail "")

let test_prover_unshield_witness_json () =
  let uw : Tzel.Prover.unshield_witness = {
    uw_auth_domain = Tzel.Felt.of_u64 1;
    uw_inputs = [];
    uw_v_pub = 5000L;
    uw_recipient_string = "bob";
    uw_change = None;
  } in
  let json = Tzel.Prover.unshield_witness_to_json uw in
  (match json with
   | `Assoc f ->
     Alcotest.(check bool) "change is null" true
       (List.assoc "change" f = `Null)
   | _ -> Alcotest.fail "");
  let ow = { Tzel.Prover.ow_d_j = Tzel.Felt.of_u64 1; ow_v = 100L;
    ow_rseed = Tzel.Felt.of_u64 2; ow_auth_root = Tzel.Felt.of_u64 3;
    ow_nk_tag = Tzel.Felt.of_u64 4; ow_memo_ct_hash = Tzel.Felt.of_u64 5 } in
  let uw2 = { uw with uw_change = Some ow } in
  let json2 = Tzel.Prover.unshield_witness_to_json uw2 in
  (match json2 with
   | `Assoc f ->
     Alcotest.(check bool) "change is assoc" true
       (match List.assoc "change" f with `Assoc _ -> true | _ -> false)
   | _ -> Alcotest.fail "")

let test_prover_felt_json () =
  let f = Tzel.Felt.of_u64 42 in
  let json = Tzel.Prover.felt_to_json f in
  (match json with `String _ -> () | _ -> Alcotest.fail "expected String")

let test_prover_felt_array_json () =
  let arr = [|Tzel.Felt.of_u64 1; Tzel.Felt.of_u64 2|] in
  let json = Tzel.Prover.felt_array_to_json arr in
  (match json with `List l -> Alcotest.(check int) "2 elements" 2 (List.length l)
   | _ -> Alcotest.fail "expected List")

let test_prover_verify_proof_rejects_failed_verifier () =
  let config : Tzel.Prover.circuit_config = {
    shield_program_hash = Tzel.Felt.of_u64 10;
    transfer_program_hash = Tzel.Felt.of_u64 20;
    unshield_program_hash = Tzel.Felt.of_u64 30;
    auth_domain = Tzel.Felt.of_u64 42;
    prover_binary = "/bin/false"; verifier_binary = "/bin/false";
  } in
  let bundle : Tzel.Prover.proof_bundle = {
    proof_bytes = "deadbeef";
    output_preimage = [Tzel.Felt.of_u64 1; Tzel.Felt.of_u64 1; Tzel.Felt.of_u64 10];
  } in
  Alcotest.(check bool) "failing verifier rejected" true
    (Result.is_error (Tzel.Prover.verify_proof config Tzel.Prover.Shield bundle))

let test_prover_verify_proof_shield_returns_public_outputs () =
  let config : Tzel.Prover.circuit_config = {
    shield_program_hash = Tzel.Felt.of_u64 10;
    transfer_program_hash = Tzel.Felt.of_u64 20;
    unshield_program_hash = Tzel.Felt.of_u64 30;
    auth_domain = Tzel.Felt.of_u64 42;
    prover_binary = "/bin/false"; verifier_binary = "/bin/true";
  } in
  let outputs = [Tzel.Felt.of_u64 99; Tzel.Felt.of_u64 100] in
  let bundle : Tzel.Prover.proof_bundle = {
    proof_bytes = "deadbeef";
    output_preimage =
      [Tzel.Felt.of_u64 1; Tzel.Felt.of_u64 2; Tzel.Felt.of_u64 10] @ outputs;
  } in
  match Tzel.Prover.verify_proof config Tzel.Prover.Shield bundle with
  | Ok public_outputs ->
    Alcotest.(check int) "shield output count" 2 (List.length public_outputs);
    Alcotest.(check bool) "shield first output" true
      (Tzel.Felt.equal (List.hd public_outputs) (List.hd outputs))
  | Error e -> Alcotest.failf "shield verify should succeed: %s" e

let test_prover_verify_proof_transfer_checks_auth_domain () =
  let config : Tzel.Prover.circuit_config = {
    shield_program_hash = Tzel.Felt.of_u64 10;
    transfer_program_hash = Tzel.Felt.of_u64 20;
    unshield_program_hash = Tzel.Felt.of_u64 30;
    auth_domain = Tzel.Felt.of_u64 42;
    prover_binary = "/bin/false"; verifier_binary = "/bin/true";
  } in
  let ok_bundle : Tzel.Prover.proof_bundle = {
    proof_bytes = "deadbeef";
    output_preimage =
      [Tzel.Felt.of_u64 1; Tzel.Felt.of_u64 2; Tzel.Felt.of_u64 20;
       Tzel.Felt.of_u64 42; Tzel.Felt.of_u64 7];
  } in
  let bad_bundle : Tzel.Prover.proof_bundle =
    { ok_bundle with
      output_preimage =
        [Tzel.Felt.of_u64 1; Tzel.Felt.of_u64 2; Tzel.Felt.of_u64 20;
         Tzel.Felt.of_u64 99] } in
  Alcotest.(check bool) "transfer auth ok" true
    (Result.is_ok (Tzel.Prover.verify_proof config Tzel.Prover.Transfer ok_bundle));
  Alcotest.(check bool) "transfer auth mismatch rejected" true
    (Result.is_error (Tzel.Prover.verify_proof config Tzel.Prover.Transfer bad_bundle))

let test_prover_prove_returns_error_on_command_failure () =
  let config : Tzel.Prover.circuit_config = {
    shield_program_hash = Tzel.Felt.zero;
    transfer_program_hash = Tzel.Felt.zero;
    unshield_program_hash = Tzel.Felt.zero;
    auth_domain = Tzel.Felt.zero;
    prover_binary = "/bin/false"; verifier_binary = "/bin/false";
  } in
  Alcotest.(check bool) "prover failure propagated" true
    (Result.is_error (Tzel.Prover.prove config ~witness_json:(`Assoc []) ~recursive:false))

(* ══════════════════════════════════════════════════════════════════════
   Multi-transaction integration
   ══════════════════════════════════════════════════════════════════════ *)

let test_multi_shield_transfer_unshield () =
  let auth_domain = Tzel.Hash.hash_tag "multi-test" in
  let ledger = Tzel.Ledger.create ~auth_domain in
  Tzel.Ledger.set_balance ledger "alice" 10000L;
  let keys = Tzel.Keys.derive (Tzel.Felt.of_u64 500) in
  let addr = derive_test_address keys 0 in
  let mch = Tzel.Felt.zero in
  (* Shield 1 *)
  let (pub1, _) = Tzel.Transaction.build_shield
    ~sender_string:"alice" ~recipient:addr ~v:3000L
    ~rseed:(Tzel.Felt.of_u64 1) ~memo_ct_hash:mch in
  ignore (Tzel.Ledger.apply_shield ledger ~sender_string:"alice" ~pub:pub1 ~memo_ct_hash:mch);
  (* Shield 2 *)
  let (pub2, _) = Tzel.Transaction.build_shield
    ~sender_string:"alice" ~recipient:addr ~v:2000L
    ~rseed:(Tzel.Felt.of_u64 2) ~memo_ct_hash:mch in
  ignore (Tzel.Ledger.apply_shield ledger ~sender_string:"alice" ~pub:pub2 ~memo_ct_hash:mch);
  Alcotest.(check int64) "alice after shields" 5000L (Tzel.Ledger.get_balance ledger "alice");
  Alcotest.(check int) "tree after shields" 2 (Tzel.Ledger.tree_size ledger);
  (* Transfer *)
  let root = Tzel.Ledger.current_root ledger in
  let nf1 = Tzel.Hash.hash_tag "nf1" in
  let nf2 = Tzel.Hash.hash_tag "nf2" in
  let cm1 = Tzel.Hash.hash_tag "out1" in
  let cm2 = Tzel.Hash.hash_tag "out2" in
  let tpub : Tzel.Transaction.transfer_public = {
    auth_domain; root; nullifiers = [nf1; nf2];
    cm_1 = cm1; cm_2 = cm2;
    memo_ct_hash_1 = mch; memo_ct_hash_2 = mch;
  } in
  let r = Tzel.Ledger.apply_transfer ledger tpub ~memo_ct_hash_1:mch ~memo_ct_hash_2:mch in
  Alcotest.(check bool) "transfer ok" true (Result.is_ok r);
  Alcotest.(check int) "tree after transfer" 4 (Tzel.Ledger.tree_size ledger);
  (* Unshield *)
  let new_root = Tzel.Ledger.current_root ledger in
  let nf3 = Tzel.Hash.hash_tag "nf3" in
  let upub : Tzel.Transaction.unshield_public = {
    auth_domain; root = new_root; nullifiers = [nf3];
    v_pub = 1500L; recipient_id = Tzel.Hash.account_id "bob";
    cm_change = Tzel.Felt.zero; memo_ct_hash_change = Tzel.Felt.zero;
  } in
  let r2 = Tzel.Ledger.apply_unshield ledger ~recipient_string:"bob" upub
    ~memo_ct_hash_change:mch in
  Alcotest.(check bool) "unshield ok" true (Result.is_ok r2);
  Alcotest.(check int64) "bob balance" 1500L (Tzel.Ledger.get_balance ledger "bob")

(* ══════════════════════════════════════════════════════════════════════
   Test registration
   ══════════════════════════════════════════════════════════════════════ *)

let () =
  Alcotest.run "tzel" [
    "blake2s", [
      Alcotest.test_case "empty" `Quick test_blake2s_empty;
      Alcotest.test_case "abc" `Quick test_blake2s_abc;
      Alcotest.test_case "personalization" `Quick test_blake2s_personal;
      Alcotest.test_case "empty personal" `Quick test_blake2s_empty_personal;
      Alcotest.test_case "long input" `Quick test_blake2s_long_input;
      Alcotest.test_case "deterministic" `Quick test_blake2s_deterministic;
      Alcotest.test_case "all personalizations" `Quick test_blake2s_all_personalizations;
    ];
    "felt", [
      Alcotest.test_case "truncation" `Quick test_felt_truncation;
      Alcotest.test_case "zero" `Quick test_felt_zero;
      Alcotest.test_case "of_u64" `Quick test_felt_of_u64;
      Alcotest.test_case "of_u32" `Quick test_felt_of_u32;
      Alcotest.test_case "of_int" `Quick test_felt_of_int;
      Alcotest.test_case "of_bytes_raw" `Quick test_felt_of_bytes_raw;
      Alcotest.test_case "to_bytes" `Quick test_felt_to_bytes;
      Alcotest.test_case "hex roundtrip" `Quick test_felt_hex_roundtrip;
      Alcotest.test_case "compare" `Quick test_felt_compare;
      Alcotest.test_case "equal" `Quick test_felt_equal;
    ];
    "hash", [
      Alcotest.test_case "hash_tag" `Quick test_hash_tag;
      Alcotest.test_case "felt_tag constants" `Quick test_felt_tag_constants;
      Alcotest.test_case "hash1" `Quick test_hash1;
      Alcotest.test_case "hash2" `Quick test_hash2;
      Alcotest.test_case "personalized distinct" `Quick test_hash_personalized_distinct;
      Alcotest.test_case "nk_spend" `Quick test_hash_nk_spend;
      Alcotest.test_case "nk_tag" `Quick test_hash_nk_tag;
      Alcotest.test_case "owner" `Quick test_hash_owner;
      Alcotest.test_case "wots" `Quick test_hash_wots;
      Alcotest.test_case "sighash" `Quick test_hash_sighash;
      Alcotest.test_case "memo" `Quick test_hash_memo;
      Alcotest.test_case "derive_rcm" `Quick test_derive_rcm;
      Alcotest.test_case "sighash_fold single" `Quick test_sighash_fold_single;
      Alcotest.test_case "sighash_fold empty" `Quick test_sighash_fold_empty;
      Alcotest.test_case "hash_commit" `Quick test_hash_commit;
      Alcotest.test_case "hash_commit canonical u64 layout" `Quick test_hash_commit_uses_only_low_u64_bytes;
      Alcotest.test_case "account_id" `Quick test_account_id;
    ];
    "wots", [
      Alcotest.test_case "sign/verify" `Quick test_wots_sign_verify;
      Alcotest.test_case "sign/verify high indices" `Quick test_wots_sign_verify_high_indices;
      Alcotest.test_case "wrong message" `Quick test_wots_wrong_message;
      Alcotest.test_case "fold determinism" `Quick test_wots_fold_deterministic;
      Alcotest.test_case "different seeds" `Quick test_wots_different_seeds;
      Alcotest.test_case "wrong key" `Quick test_wots_wrong_key;
      Alcotest.test_case "keygen deterministic" `Quick test_wots_keygen_deterministic;
      Alcotest.test_case "decompose roundtrip" `Quick test_wots_decompose_roundtrip;
      Alcotest.test_case "auth leaf binding" `Quick test_wots_signature_binds_to_auth_leaf;
    ];
    "merkle", [
      Alcotest.test_case "zero root" `Quick test_merkle_zero_root;
      Alcotest.test_case "path all positions" `Quick test_merkle_path;
      Alcotest.test_case "single leaf" `Quick test_merkle_single_leaf;
      Alcotest.test_case "root_from_path" `Quick test_merkle_root_from_path;
      Alcotest.test_case "wrong leaf" `Quick test_merkle_wrong_leaf;
      Alcotest.test_case "append tree" `Quick test_merkle_append_tree;
      Alcotest.test_case "tree full" `Quick test_merkle_tree_full;
      Alcotest.test_case "with_leaves path" `Quick test_merkle_with_leaves_path;
      Alcotest.test_case "path out of range" `Quick test_merkle_path_out_of_range;
      Alcotest.test_case "get_leaves" `Quick test_merkle_get_leaves;
      Alcotest.test_case "incremental matches materialized" `Quick test_merkle_incremental_matches_materialized;
    ];
    "keys", [
      Alcotest.test_case "hierarchy" `Quick test_key_hierarchy;
      Alcotest.test_case "determinism" `Quick test_key_determinism;
      Alcotest.test_case "derive_diversifier" `Quick test_key_derive_diversifier;
      Alcotest.test_case "derive_ask" `Quick test_key_derive_ask;
      Alcotest.test_case "derive nk_spend/tag" `Quick test_key_derive_nk_spend_tag;
      Alcotest.test_case "derive_wots_seed" `Quick test_key_derive_wots_seed;
      Alcotest.test_case "auth seed helpers agree" `Quick test_key_auth_seed_helpers_agree;
      Alcotest.test_case "auth leaf small merkle" `Quick test_key_auth_leaf_small_merkle;
      Alcotest.test_case "xmss subtree root small depth" `Quick test_key_xmss_subtree_root_small_depth;
      Alcotest.test_case "xmss root/path inner small depth" `Quick test_key_xmss_root_and_path_inner_small_depth;
      Alcotest.test_case "xmss root/path offset subtree" `Quick test_key_xmss_root_and_path_inner_nonzero_start;
      Alcotest.test_case "xmss subtree root offset subtree" `Quick test_key_xmss_subtree_root_nonzero_start;
      Alcotest.test_case "xmss node hash domain separation" `Quick test_key_xmss_node_hash_domain_separation;
      Alcotest.test_case "wots pk matches auth leaf" `Quick test_key_wots_pk_matches_auth_leaf_hash;
      Alcotest.test_case "owner tag binding" `Quick test_owner_tag_binding;
      Alcotest.test_case "owner tag binds root and pub_seed" `Quick test_owner_tag_binds_root_and_pub_seed;
      Alcotest.test_case "to_payment_address" `Quick test_key_to_payment_address;
      Alcotest.test_case "multiple indices" `Quick test_key_address_multiple_indices;
      Alcotest.test_case "full depth wrappers trap" `Quick test_key_full_depth_wrappers_trap;
    ];
    "note", [
      Alcotest.test_case "commitment" `Quick test_note_commitment;
      Alcotest.test_case "determinism" `Quick test_note_determinism;
      Alcotest.test_case "nullifier" `Quick test_note_nullifier;
      Alcotest.test_case "create_from_parts" `Quick test_note_create_from_parts;
      Alcotest.test_case "different values" `Quick test_note_different_values;
      Alcotest.test_case "different rseed" `Quick test_note_different_rseed;
      Alcotest.test_case "zero value" `Quick test_note_zero_value;
      Alcotest.test_case "different nk_spend" `Quick test_note_nullifier_different_nk_spend;
    ];
    "transaction", [
      Alcotest.test_case "sighash transfer" `Quick test_sighash_transfer;
      Alcotest.test_case "sighash unshield" `Quick test_sighash_unshield;
      Alcotest.test_case "transfer vs unshield" `Quick test_sighash_transfer_unshield_distinct;
      Alcotest.test_case "build shield" `Quick test_build_shield;
      Alcotest.test_case "build output" `Quick test_build_output;
      Alcotest.test_case "build transfer public" `Quick test_build_transfer_public;
      Alcotest.test_case "build unshield public" `Quick test_build_unshield_public;
      Alcotest.test_case "build unshield no change" `Quick test_build_unshield_no_change;
      Alcotest.test_case "sign/verify inputs" `Quick test_sign_verify_inputs;
      Alcotest.test_case "sign wrong sighash" `Quick test_sign_wrong_sighash;
    ];
    "crypto", [
      Alcotest.test_case "chacha20 roundtrip" `Quick test_chacha20_roundtrip;
      Alcotest.test_case "detection tag" `Quick test_detection_tag;
      Alcotest.test_case "detection tag deterministic" `Quick test_detection_tag_deterministic;
      Alcotest.test_case "memo encode/decode" `Quick test_memo_encode_decode;
      Alcotest.test_case "memo zero" `Quick test_memo_encode_decode_zero;
      Alcotest.test_case "memo max value" `Quick test_memo_encode_max_value;
      Alcotest.test_case "no_memo" `Quick test_no_memo;
      Alcotest.test_case "text_memo padding" `Quick test_text_memo_padding;
      Alcotest.test_case "encrypt/decrypt memo" `Quick test_encrypt_memo_decrypt_memo;
      Alcotest.test_case "decrypt wrong key" `Quick test_decrypt_wrong_key;
      Alcotest.test_case "mlkem seed derivation" `Quick test_mlkem_seed_derivation;
      Alcotest.test_case "mlkem keygen det" `Quick test_mlkem_keygen_deterministic;
      Alcotest.test_case "mlkem encaps/decaps" `Quick test_mlkem_encaps_decaps;
      Alcotest.test_case "mlkem encaps derand" `Quick test_mlkem_encaps_derand;
      Alcotest.test_case "mlkem derive keypairs" `Quick test_mlkem_derive_keypairs;
      Alcotest.test_case "full note encrypt/decrypt" `Quick test_full_note_encrypt_decrypt;
      Alcotest.test_case "detection check" `Quick test_detection_check;
    ];
    "encoding", [
      Alcotest.test_case "encrypted note" `Quick test_encoding_encrypted_note;
      Alcotest.test_case "published note" `Quick test_encoding_published_note;
      Alcotest.test_case "note memo" `Quick test_encoding_note_memo;
      Alcotest.test_case "u16_le" `Quick test_encoding_u16_le;
      Alcotest.test_case "u64_le" `Quick test_encoding_u64_le;
      Alcotest.test_case "u16 boundary" `Quick test_encoding_u16_boundary;
      Alcotest.test_case "u64 boundary" `Quick test_encoding_u64_boundary;
      Alcotest.test_case "payment address wire" `Quick test_payment_address_wire;
      Alcotest.test_case "memo_ct_hash det" `Quick test_memo_ct_hash_deterministic;
      Alcotest.test_case "json encrypted note" `Quick test_encoding_json_encrypted_note;
      Alcotest.test_case "json published note" `Quick test_encoding_json_published_note;
      Alcotest.test_case "json payment address" `Quick test_encoding_json_payment_address;
      Alcotest.test_case "hex helpers" `Quick test_encoding_hex_helpers;
    ];
    "ledger", [
      Alcotest.test_case "shield flow" `Quick test_shield_flow;
      Alcotest.test_case "shield insufficient" `Quick test_shield_insufficient_balance;
      Alcotest.test_case "shield sender mismatch" `Quick test_shield_sender_mismatch;
      Alcotest.test_case "shield memo mismatch" `Quick test_shield_memo_mismatch;
      Alcotest.test_case "transfer" `Quick test_ledger_transfer;
      Alcotest.test_case "transfer wrong domain" `Quick test_ledger_transfer_wrong_domain;
      Alcotest.test_case "transfer unknown root" `Quick test_ledger_transfer_unknown_root;
      Alcotest.test_case "nullifier double spend" `Quick test_ledger_nullifier_double_spend;
      Alcotest.test_case "duplicate nf in tx" `Quick test_ledger_duplicate_nullifier_in_tx;
      Alcotest.test_case "transfer memo mismatch" `Quick test_ledger_transfer_memo_mismatch;
      Alcotest.test_case "unshield" `Quick test_ledger_unshield;
      Alcotest.test_case "unshield with change" `Quick test_ledger_unshield_with_change;
      Alcotest.test_case "unshield wrong recipient" `Quick test_ledger_unshield_wrong_recipient;
      Alcotest.test_case "unshield wrong domain" `Quick test_ledger_unshield_wrong_domain;
      Alcotest.test_case "unshield change memo mismatch" `Quick test_ledger_unshield_change_memo_mismatch;
      Alcotest.test_case "balance default" `Quick test_ledger_balance_default;
      Alcotest.test_case "root history" `Quick test_ledger_root_history;
      Alcotest.test_case "root history prunes oldest" `Quick test_ledger_root_history_prunes_oldest;
      Alcotest.test_case "empty nullifiers" `Quick test_ledger_check_nullifiers_empty;
    ];
    "prover", [
      Alcotest.test_case "parse proof bundle" `Quick test_prover_parse_proof_bundle;
      Alcotest.test_case "extract program hash" `Quick test_prover_extract_program_hash;
      Alcotest.test_case "extract ph short" `Quick test_prover_extract_program_hash_short;
      Alcotest.test_case "extract public outputs" `Quick test_prover_extract_public_outputs;
      Alcotest.test_case "extract outputs empty" `Quick test_prover_extract_public_outputs_empty;
      Alcotest.test_case "verify program hash" `Quick test_prover_verify_program_hash;
      Alcotest.test_case "verify ph mismatch" `Quick test_prover_verify_program_hash_mismatch;
      Alcotest.test_case "verify ph short" `Quick test_prover_verify_program_hash_short_error;
      Alcotest.test_case "verify auth domain" `Quick test_prover_verify_auth_domain;
      Alcotest.test_case "felt json" `Quick test_prover_felt_json;
      Alcotest.test_case "felt array json" `Quick test_prover_felt_array_json;
      Alcotest.test_case "shield witness json" `Quick test_prover_witness_json;
      Alcotest.test_case "spend witness json" `Quick test_prover_spend_witness_json;
      Alcotest.test_case "output witness json" `Quick test_prover_output_witness_json;
      Alcotest.test_case "transfer witness json" `Quick test_prover_transfer_witness_json;
      Alcotest.test_case "unshield witness json" `Quick test_prover_unshield_witness_json;
      Alcotest.test_case "verify proof fails verifier" `Quick test_prover_verify_proof_rejects_failed_verifier;
      Alcotest.test_case "verify proof shield outputs" `Quick test_prover_verify_proof_shield_returns_public_outputs;
      Alcotest.test_case "verify proof transfer auth" `Quick test_prover_verify_proof_transfer_checks_auth_domain;
      Alcotest.test_case "prove failure propagated" `Quick test_prover_prove_returns_error_on_command_failure;
    ];
    "integration", [
      Alcotest.test_case "multi shield/transfer/unshield" `Quick test_multi_shield_transfer_unshield;
    ];
  ]

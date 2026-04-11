(* Generate test vectors from the OCaml implementation.
   Run: dune exec test/gen_vectors.exe > ../specs/ocaml_vectors/protocol_v1_ocaml.json

   The Rust side can consume this to verify compatibility in the other direction.

   DESIGN NOTE on determinism:
   Everything here uses fixed inputs with no randomness. For operations that
   are normally randomized (ML-KEM encaps, AEAD), we use deterministic
   variants (encaps_derand, fixed key). This lets both implementations
   produce byte-identical outputs for cross-validation.

   Things we CANNOT cross-check with static vectors:
   - STARK proofs (different runs produce different proofs; verify-only)
   - Randomized ML-KEM encaps (by design; only the derand variant is testable)
   The proofs are checked via verify_proof, not vector comparison.
*)

let hex b =
  let buf = Buffer.create (Bytes.length b * 2) in
  Bytes.iter (fun c -> Buffer.add_string buf (Printf.sprintf "%02x" (Char.code c))) b;
  Buffer.contents buf

let jstr s = `String s
let jhex b = `String (hex b)
let jint n = `Int n

let master_sk = Tzel.Felt.of_u64 12345

(* ── BLAKE2s ── *)

let gen_blake2s () =
  let cases = [
    ("", "");
    ("abc", "");
    ("test", "mrklSP__");
    ("test", "nulfSP__");
    ("test", "cmmtSP__");
    ("test", "nkspSP__");
    ("test", "nktgSP__");
    ("test", "ownrSP__");
    ("test", "wotsSP__");
    ("test", "sighSP__");
    ("test", "memoSP__");
    (* Multi-block input: crosses the 64-byte block boundary *)
    (String.make 200 'x', "");
    (String.make 200 'x', "mrklSP__");
  ] in
  `List (List.map (fun (input, personal) ->
    let input_bytes = Bytes.of_string input in
    let personal_bytes = if personal = "" then Bytes.empty
      else Bytes.of_string personal in
    let output = Tzel.Blake2s.hash ~personal:personal_bytes input_bytes in
    `Assoc [
      "input", jhex input_bytes;
      "personal", jstr personal;
      "output", jhex output;
    ]
  ) cases)

(* ── Key hierarchy ── *)

let gen_key_hierarchy () =
  let keys = Tzel.Keys.derive master_sk in
  `Assoc [
    "master_sk", jhex master_sk;
    "nk", jhex keys.nk;
    "ask_base", jhex keys.ask_base;
    "dsk", jhex keys.dsk;
    "incoming_seed", jhex keys.incoming_seed;
    "view_root", jhex keys.view_root;
    "detect_root", jhex keys.detect_root;
  ]

(* ── Per-address keys (including auth_root and owner_tag) ── *)

let gen_addresses () =
  let keys = Tzel.Keys.derive master_sk in
  `List (List.map (fun j ->
    let addr = Tzel.Keys.derive_address keys j in
    let ot = Tzel.Keys.owner_tag addr in
    `Assoc [
      "j", jint j;
      "d_j", jhex addr.d_j;
      "nk_spend", jhex addr.nk_spend;
      "nk_tag", jhex addr.nk_tag;
      "auth_root", jhex addr.auth_root;
      "auth_pub_seed", jhex addr.auth_pub_seed;
      "owner_tag", jhex ot;
    ]
  ) [0; 1; 2])

(* ── ML-KEM seed derivation ── *)

let gen_mlkem_seeds () =
  let keys = Tzel.Keys.derive master_sk in
  `List (List.concat_map (fun j -> [
    `Assoc [
      "kind", jstr "view";
      "root", jhex keys.view_root;
      "j", jint j;
      "seed", jhex (Tzel.Mlkem.derive_view_seed keys.view_root j);
    ];
    `Assoc [
      "kind", jstr "detect";
      "root", jhex keys.detect_root;
      "j", jint j;
      "seed", jhex (Tzel.Mlkem.derive_detect_seed keys.detect_root j);
    ];
  ]) [0; 1])

(* ── ML-KEM deterministic keygen ──
   keygen_det is FIPS 203 deterministic: given the same 64-byte seed,
   both implementations MUST produce byte-identical encapsulation keys.
   The decapsulation key is reconstructed from the same seed, so we do not
   serialize a second implementation-specific secret-key encoding here. *)

let gen_mlkem_keygen () =
  let keys = Tzel.Keys.derive master_sk in
  `List (List.map (fun j ->
    let view_seed = Tzel.Mlkem.derive_view_seed keys.view_root j in
    let (ek_v, _dk_v) = Tzel.Mlkem.keygen_det view_seed in
    let detect_seed = Tzel.Mlkem.derive_detect_seed keys.detect_root j in
    let (ek_d, _dk_d) = Tzel.Mlkem.keygen_det detect_seed in
    `Assoc [
      "j", jint j;
      "view_seed", jhex view_seed;
      "ek_v", jhex ek_v;
      "detect_seed", jhex detect_seed;
      "ek_d", jhex ek_d;
    ]
  ) [0; 1])

(* ── ML-KEM deterministic encaps ──
   encaps_derand(ek, coins) is deterministic: same ek + same 32-byte coins
   must produce identical (ss, ct). This tests the KEM itself, not just
   seed derivation. *)

let gen_mlkem_encaps_derand () =
  let keys = Tzel.Keys.derive master_sk in
  let view_seed = Tzel.Mlkem.derive_view_seed keys.view_root 0 in
  let (ek, dk) = Tzel.Mlkem.keygen_det view_seed in
  let coins_list = [
    Bytes.make 32 '\x00';
    Bytes.make 32 '\xFF';
    Tzel.Blake2s.hash_string "encaps-coins";
  ] in
  `List (List.mapi (fun i coins ->
    let (ss, ct) = Tzel.Mlkem.encaps_derand ek coins in
    (* Also verify decaps produces the same ss *)
    let ss_dec = Tzel.Mlkem.decaps dk ct in
    assert (Bytes.equal ss ss_dec);
    `Assoc [
      "ek", jhex ek;
      "coins", jhex coins;
      "ss", jhex ss;
      "ct", jhex ct;
      "case", jint i;
    ]
  ) coins_list)

(* ── ChaCha20-Poly1305 ──
   Deterministic given (key, nonce=0, plaintext). We test with known
   key bytes derived from BLAKE2s so both impls can reproduce. *)

let gen_chacha20 () =
  let cases = [
    (* key derived from "key-0", plaintext = v:1000 || rseed:of_u64(42) || memo:zeros *)
    ("key-0", 1000L, Tzel.Felt.of_u64 42, Tzel.Detection.no_memo ());
    (* key derived from "key-1", zero value *)
    ("key-1", 0L, Tzel.Felt.zero, Tzel.Detection.text_memo "hello");
  ] in
  `List (List.mapi (fun i (key_tag, v, rseed, memo) ->
    let ss_v = Tzel.Blake2s.hash_string key_tag in
    let encrypted = Tzel.Detection.encrypt_memo ~ss_v ~v ~rseed ~memo in
    `Assoc [
      "case", jint i;
      "ss_v", jhex ss_v;
      "v", jstr (Int64.to_string v);
      "rseed", jhex rseed;
      "memo", jhex memo;
      "encrypted_data", jhex encrypted;
    ]
  ) cases)

(* ── Detection tag ──
   compute_tag is deterministic: H(ss_d) then extract 2 bytes. *)

let gen_detection_tags () =
  let shared_secrets = List.map Tzel.Blake2s.hash_string
    ["ss-0"; "ss-1"; "ss-2"; "all-zeros"] in
  `List (List.mapi (fun i ss ->
    let tag = Tzel.Detection.compute_tag ss in
    `Assoc [
      "case", jint i;
      "ss_d", jhex ss;
      "tag", jint tag;
    ]
  ) shared_secrets)

(* ── Memo hash (memo_ct_hash) ──
   H_memo(ct_d || tag_le || ct_v || encrypted_data) is deterministic. *)

let gen_memo_ct_hash () =
  let enc : Tzel.Encoding.encrypted_note = {
    ct_d = Bytes.init 1088 (fun i -> Char.chr (i mod 256));
    tag = 42;
    ct_v = Bytes.init 1088 (fun i -> Char.chr ((i + 100) mod 256));
    encrypted_data = Bytes.init 1080 (fun i -> Char.chr ((i + 200) mod 256));
  } in
  let mch = Tzel.Encoding.compute_memo_ct_hash enc in
  `Assoc [
    "ct_d", jhex enc.ct_d;
    "tag", jint enc.tag;
    "ct_v", jhex enc.ct_v;
    "encrypted_data", jhex enc.encrypted_data;
    "memo_ct_hash", jhex mch;
  ]

(* ── Cross-implementation encrypt/decrypt ──
   Use derand encaps so the Rust side can reproduce the exact same
   (ss, ct) pair, then encrypt the memo, and both sides must produce
   identical ciphertext. The Rust side should also decrypt and recover
   the same plaintext. *)

let gen_cross_impl_encrypt () =
  let keys = Tzel.Keys.derive master_sk in
  let view_seed = Tzel.Mlkem.derive_view_seed keys.view_root 0 in
  let detect_seed = Tzel.Mlkem.derive_detect_seed keys.detect_root 0 in
  let (ek_v, _dk_v) = Tzel.Mlkem.keygen_det view_seed in
  let (ek_d, _dk_d) = Tzel.Mlkem.keygen_det detect_seed in
  let coins_v = Tzel.Blake2s.hash_string "view-encaps-coins" in
  let coins_d = Tzel.Blake2s.hash_string "detect-encaps-coins" in
  let (ss_v, ct_v) = Tzel.Mlkem.encaps_derand ek_v coins_v in
  let (ss_d, ct_d) = Tzel.Mlkem.encaps_derand ek_d coins_d in
  let v = 42000L in
  let rseed = Tzel.Felt.of_u64 777 in
  let memo = Tzel.Detection.text_memo "cross-impl test" in
  let encrypted_data = Tzel.Detection.encrypt_memo ~ss_v ~v ~rseed ~memo in
  let tag = Tzel.Detection.compute_tag ss_d in
  let enc : Tzel.Encoding.encrypted_note = { ct_d; tag; ct_v; encrypted_data } in
  let mch = Tzel.Encoding.compute_memo_ct_hash enc in
  `Assoc [
    "master_sk", jhex master_sk;
    "view_seed", jhex view_seed;
    "detect_seed", jhex detect_seed;
    "ek_v", jhex ek_v;
    "ek_d", jhex ek_d;
    "coins_v", jhex coins_v;
    "coins_d", jhex coins_d;
    "ss_v", jhex ss_v;
    "ss_d", jhex ss_d;
    "ct_v", jhex ct_v;
    "ct_d", jhex ct_d;
    "v", jstr (Int64.to_string v);
    "rseed", jhex rseed;
    "memo", jhex memo;
    "encrypted_data", jhex encrypted_data;
    "tag", jint tag;
    "memo_ct_hash", jhex mch;
  ]

(* ── WOTS+ ── *)

let gen_wots () =
  let asks = [Tzel.Felt.of_u64 42; Tzel.Felt.of_u64 100; Tzel.Felt.of_u64 999] in
  `List (List.map (fun ask_j ->
    let key_idx = 0 in
    let seed = Tzel.Keys.derive_auth_key_seed ask_j key_idx in
    let pub_seed = Tzel.Keys.derive_auth_pub_seed ask_j in
    let pk = Tzel.Wots.keygen ~seed ~pub_seed ~key_idx in
    let leaf = Tzel.Wots.pk_to_leaf ~pub_seed ~key_idx pk in
    let sighash = Tzel.Hash.hash_tag "test-sighash" in
    let sig_vals = Tzel.Wots.sign ~seed ~pub_seed ~key_idx sighash in
    `Assoc [
      "ask_j", jhex ask_j;
      "key_idx", jint key_idx;
      "seed", jhex seed;
      "auth_pub_seed", jhex pub_seed;
      "leaf", jhex leaf;
      "sighash", jhex sighash;
      "signature", `List (Array.to_list (Array.map jhex sig_vals));
    ]
  ) asks)

(* ── Merkle ── *)

let gen_merkle () =
  let cases = [
    (3, [1;2;3;4]);
    (4, [10;20;30]);
    (3, [1]);
    (4, [1;2;3;4;5;6;7;8;9;10;11;12;13;14;15;16]);
    (* Empty tree *)
    (3, []);
  ] in
  `List (List.map (fun (depth, vals) ->
    let leaves = List.map Tzel.Felt.of_u64 vals in
    let root = Tzel.Merkle.root_of_leaves ~depth leaves in
    `Assoc [
      "depth", jint depth;
      "leaves", `List (List.map jhex leaves);
      "root", jhex root;
    ]
  ) cases)

(* ── Notes ── *)

let gen_notes () =
  let keys = Tzel.Keys.derive master_sk in
  let addr = Tzel.Keys.derive_address keys 0 in
  let cases = [
    (1000L, Tzel.Felt.of_u64 777, 0);
    (0L, Tzel.Felt.of_u64 1, 5);
    (999999L, Tzel.Felt.of_u64 42, 100);
  ] in
  `List (List.map (fun (v, rseed, pos) ->
    let note = Tzel.Note.create addr v rseed in
    let nf = Tzel.Note.nullifier addr.nk_spend note.cm pos in
    `Assoc [
      "d_j", jhex addr.d_j;
      "v", jstr (Int64.to_string v);
      "rseed", jhex rseed;
      "auth_root", jhex addr.auth_root;
      "auth_pub_seed", jhex addr.auth_pub_seed;
      "nk_tag", jhex addr.nk_tag;
      "rcm", jhex note.rcm;
      "owner_tag", jhex note.owner_tag;
      "cm", jhex note.cm;
      "nk_spend", jhex addr.nk_spend;
      "pos", jint pos;
      "nf", jhex nf;
    ]
  ) cases)

(* ── Sighash ── *)

let gen_sighash () =
  let items_list = [
    [Tzel.Felt.of_u64 1; Tzel.Felt.of_u64 2; Tzel.Felt.of_u64 3];
    (* Simulated transfer sighash: type_tag=0x01, domain, root, nf, cm1, cm2, mh1, mh2 *)
    [Tzel.Felt.of_u64 0x01; Tzel.Hash.hash_tag "domain"; Tzel.Hash.hash_tag "root";
     Tzel.Hash.hash_tag "nf0"; Tzel.Hash.hash_tag "cm1"; Tzel.Hash.hash_tag "cm2";
     Tzel.Felt.zero; Tzel.Felt.zero];
    (* Simulated unshield sighash: type_tag=0x02, domain, root, nf, v_pub, recip, cm_c, mh_c *)
    [Tzel.Felt.of_u64 0x02; Tzel.Hash.hash_tag "domain"; Tzel.Hash.hash_tag "root";
     Tzel.Hash.hash_tag "nf0"; Tzel.Felt.of_u64 5000;
     Tzel.Hash.account_id "bob"; Tzel.Felt.zero; Tzel.Felt.zero];
  ] in
  `List (List.map (fun items ->
    let result = Tzel.Hash.sighash_fold items in
    `Assoc [
      "items", `List (List.map jhex items);
      "result", jhex result;
    ]
  ) items_list)

(* ── Account IDs ── *)

let gen_account_ids () =
  `List (List.map (fun s ->
    `Assoc [
      "string", jstr s;
      "id", jhex (Tzel.Hash.account_id s);
    ]
  ) ["alice"; "bob"; ""; "a]very+long/identifier\x00with\nnulls"])

(* ── Canonical wire encoding ──
   Byte-exact serialization of PaymentAddress and EncryptedNote. *)

let gen_wire_encoding () =
  let keys = Tzel.Keys.derive master_sk in
  let addr = Tzel.Keys.derive_address keys 0 in
  let pa_wire : Tzel.Encoding.payment_address_wire = {
    d_j = addr.d_j; auth_root = addr.auth_root; auth_pub_seed = addr.auth_pub_seed; nk_tag = addr.nk_tag;
    ek_v = addr.ek_v; ek_d = addr.ek_d;
  } in
  let pa_bytes = Tzel.Encoding.encode_payment_address pa_wire in
  let enc : Tzel.Encoding.encrypted_note = {
    ct_d = Bytes.init 1088 (fun i -> Char.chr (i mod 256));
    tag = 42;
    ct_v = Bytes.init 1088 (fun i -> Char.chr ((i + 50) mod 256));
    encrypted_data = Bytes.init 1080 (fun i -> Char.chr ((i + 100) mod 256));
  } in
  let enc_bytes = Tzel.Encoding.encode_encrypted_note enc in
  let cm = Tzel.Hash.hash_tag "wire-test-cm" in
  let pn = { Tzel.Encoding.pn_cm = cm; pn_enc = enc } in
  let pn_bytes = Tzel.Encoding.encode_published_note pn in
  let nm = { Tzel.Encoding.nm_index = 42L; nm_cm = cm; nm_enc = enc } in
  let nm_bytes = Tzel.Encoding.encode_note_memo nm in
  `Assoc [
    "payment_address", jhex pa_bytes;
    "encrypted_note", jhex enc_bytes;
    "published_note", jhex pn_bytes;
    "note_memo", jhex nm_bytes;
  ]

(* ── Entry point ── *)

let () =
  let json = `Assoc [
    "blake2s", gen_blake2s ();
    "key_hierarchy", gen_key_hierarchy ();
    "addresses", gen_addresses ();
    "mlkem_seeds", gen_mlkem_seeds ();
    "mlkem_keygen", gen_mlkem_keygen ();
    "mlkem_encaps_derand", gen_mlkem_encaps_derand ();
    "chacha20", gen_chacha20 ();
    "detection_tags", gen_detection_tags ();
    "memo_ct_hash", gen_memo_ct_hash ();
    "cross_impl_encrypt", gen_cross_impl_encrypt ();
    "wots", gen_wots ();
    "merkle", gen_merkle ();
    "notes", gen_notes ();
    "sighash", gen_sighash ();
    "account_ids", gen_account_ids ();
    "wire_encoding", gen_wire_encoding ();
  ] in
  print_string (Yojson.Basic.pretty_to_string json);
  print_newline ()

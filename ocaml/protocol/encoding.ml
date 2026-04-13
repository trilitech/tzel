(* Canonical binary wire format (TDE-based) and JSON mapping.

   felt252 := bytes[32]

   PaymentAddress := record {
     d_j:       felt252,
     auth_root: felt252,
     auth_pub_seed: felt252,
     nk_tag:    felt252,
     ek_v:      bytes[1184],
     ek_d:      bytes[1184]
   }

   EncryptedNote := record {
     ct_d:           bytes[1088],
     tag:            u16,
     ct_v:           bytes[1088],
     nonce:          bytes[12],
     encrypted_data: bytes[1080]
   }

   PublishedNote := record {
     cm:  felt252,
     enc: EncryptedNote
   }

   NoteMemo := record {
     index: u64le,
     cm:    felt252,
     enc:   EncryptedNote
   }
*)

type encrypted_note = {
  ct_d : bytes;           (* 1088 bytes *)
  tag : int;              (* u16 *)
  ct_v : bytes;           (* 1088 bytes *)
  nonce : bytes;          (* 12 bytes *)
  encrypted_data : bytes; (* 1080 bytes *)
}

type published_note = {
  pn_cm : Felt.t;
  pn_enc : encrypted_note;
}

type note_memo = {
  nm_index : int64;
  nm_cm : Felt.t;
  nm_enc : encrypted_note;
}

type payment_address_wire = {
  d_j : Felt.t;
  auth_root : Felt.t;
  auth_pub_seed : Felt.t;
  nk_tag : Felt.t;
  ek_v : bytes;  (* 1184 bytes *)
  ek_d : bytes;  (* 1184 bytes *)
}

(* Binary serialization *)

let put_u16_le buf ofs v =
  Bytes.set_uint8 buf ofs (v land 0xFF);
  Bytes.set_uint8 buf (ofs + 1) ((v lsr 8) land 0xFF)

let get_u16_le buf ofs =
  Bytes.get_uint8 buf ofs lor (Bytes.get_uint8 buf (ofs + 1) lsl 8)

let put_u64_le buf ofs v =
  for i = 0 to 7 do
    Bytes.set_uint8 buf (ofs + i) ((Int64.to_int (Int64.shift_right_logical v (i * 8))) land 0xFF)
  done

let get_u64_le buf ofs =
  let r = ref 0L in
  for i = 7 downto 0 do
    r := Int64.logor (Int64.shift_left !r 8)
      (Int64.of_int (Bytes.get_uint8 buf (ofs + i)))
  done;
  !r

(* EncryptedNote binary: 1088 + 2 + 1088 + 12 + 1080 = 3270 bytes *)
let encrypted_note_size = 3270

let encode_encrypted_note enc =
  let buf = Bytes.create encrypted_note_size in
  Bytes.blit enc.ct_d 0 buf 0 1088;
  put_u16_le buf 1088 enc.tag;
  Bytes.blit enc.ct_v 0 buf 1090 1088;
  Bytes.blit enc.nonce 0 buf 2178 12;
  Bytes.blit enc.encrypted_data 0 buf 2190 1080;
  buf

let decode_encrypted_note buf =
  assert (Bytes.length buf >= encrypted_note_size);
  let ct_d = Bytes.sub buf 0 1088 in
  let tag = get_u16_le buf 1088 in
  let ct_v = Bytes.sub buf 1090 1088 in
  let nonce = Bytes.sub buf 2178 12 in
  let encrypted_data = Bytes.sub buf 2190 1080 in
  { ct_d; tag; ct_v; nonce; encrypted_data }

(* PublishedNote binary: 32 + 3270 = 3302 bytes *)
let published_note_size = 3302

let encode_published_note pn =
  let buf = Bytes.create published_note_size in
  Bytes.blit pn.pn_cm 0 buf 0 32;
  let enc_bytes = encode_encrypted_note pn.pn_enc in
  Bytes.blit enc_bytes 0 buf 32 encrypted_note_size;
  buf

let decode_published_note buf =
  assert (Bytes.length buf >= published_note_size);
  let pn_cm = Felt.of_bytes_raw (Bytes.sub buf 0 32) in
  let pn_enc = decode_encrypted_note (Bytes.sub buf 32 encrypted_note_size) in
  { pn_cm; pn_enc }

(* NoteMemo binary: 8 + 32 + 3270 = 3310 bytes *)
let note_memo_size = 3310

let encode_note_memo nm =
  let buf = Bytes.create note_memo_size in
  put_u64_le buf 0 nm.nm_index;
  Bytes.blit nm.nm_cm 0 buf 8 32;
  let enc_bytes = encode_encrypted_note nm.nm_enc in
  Bytes.blit enc_bytes 0 buf 40 encrypted_note_size;
  buf

let decode_note_memo buf =
  assert (Bytes.length buf >= note_memo_size);
  let nm_index = get_u64_le buf 0 in
  let nm_cm = Felt.of_bytes_raw (Bytes.sub buf 8 32) in
  let nm_enc = decode_encrypted_note (Bytes.sub buf 40 encrypted_note_size) in
  { nm_index; nm_cm; nm_enc }

(* PaymentAddress binary: 32 + 32 + 32 + 32 + 1184 + 1184 = 2496 bytes *)
let payment_address_size = 2496

let encode_payment_address addr =
  let buf = Bytes.create payment_address_size in
  Bytes.blit addr.d_j 0 buf 0 32;
  Bytes.blit addr.auth_root 0 buf 32 32;
  Bytes.blit addr.auth_pub_seed 0 buf 64 32;
  Bytes.blit addr.nk_tag 0 buf 96 32;
  Bytes.blit addr.ek_v 0 buf 128 1184;
  Bytes.blit addr.ek_d 0 buf 1312 1184;
  buf

let decode_payment_address buf =
  assert (Bytes.length buf >= payment_address_size);
  let d_j = Felt.of_bytes_raw (Bytes.sub buf 0 32) in
  let auth_root = Felt.of_bytes_raw (Bytes.sub buf 32 32) in
  let auth_pub_seed = Felt.of_bytes_raw (Bytes.sub buf 64 32) in
  let nk_tag = Felt.of_bytes_raw (Bytes.sub buf 96 32) in
  let ek_v = Bytes.sub buf 128 1184 in
  let ek_d = Bytes.sub buf 1312 1184 in
  { d_j; auth_root; auth_pub_seed; nk_tag; ek_v; ek_d }

(* Memo hash: H_memo(ct_d || tag_le || ct_v || encrypted_data) *)
let compute_memo_ct_hash enc =
  let buf = encode_encrypted_note enc in
  Hash.hash_memo buf

(* JSON mapping (reference convenience format) *)

let hex_of_felt f = Felt.to_hex f

let felt_of_hex_json s = Felt.of_hex s

let hex_of_bytes b = Hex.show (Hex.of_bytes b)

let bytes_of_hex_json s = Hex.to_bytes (`Hex s)

let encrypted_note_to_json enc =
  `Assoc [
    "ct_d", `String (hex_of_bytes enc.ct_d);
    "tag", `Int enc.tag;
    "ct_v", `String (hex_of_bytes enc.ct_v);
    "nonce", `String (hex_of_bytes enc.nonce);
    "encrypted_data", `String (hex_of_bytes enc.encrypted_data);
  ]

let published_note_to_json pn =
  `Assoc [
    "cm", `String (hex_of_felt pn.pn_cm);
    "enc", encrypted_note_to_json pn.pn_enc;
  ]

let payment_address_to_json addr =
  `Assoc [
    "d_j", `String (hex_of_felt addr.d_j);
    "auth_root", `String (hex_of_felt addr.auth_root);
    "auth_pub_seed", `String (hex_of_felt addr.auth_pub_seed);
    "nk_tag", `String (hex_of_felt addr.nk_tag);
    "ek_v", `String (hex_of_bytes addr.ek_v);
    "ek_d", `String (hex_of_bytes addr.ek_d);
  ]

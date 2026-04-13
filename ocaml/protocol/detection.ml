(* Fuzzy Message Detection and memo encryption.

   Detection (FMD):
     (ss_d, ct_d) = ML-KEM.Encaps(ek_d_j)
     tag_u16      = LE16(H(ss_d)[0], H(ss_d)[1]) & ((1 << k) - 1)
     tag          = LE16(tag_u16)

   Memo encryption:
     (ss_v, ct_v) = ML-KEM.Encaps(ek_v_j)
     nonce        = H_mnon(H(ss_v) || plaintext)[0..12)
     encrypted_data = ChaCha20-Poly1305(key=H(ss_v), nonce, plaintext=(v:8 || rseed:32 || memo:1024))
*)

let detection_precision = 10  (* k = 10 *)
let memo_size = 1024
let plaintext_size = 8 + 32 + memo_size  (* v:8 + rseed:32 + memo:1024 = 1064 *)
let aead_tag_size = 16
let ciphertext_data_size = plaintext_size + aead_tag_size  (* 1080 *)

(* Compute detection tag from shared secret *)
let compute_tag (ss_d : bytes) =
  let h = Blake2s.hash ss_d in
  let b0 = Bytes.get_uint8 h 0 in
  let b1 = Bytes.get_uint8 h 1 in
  let raw = b0 lor (b1 lsl 8) in
  raw land ((1 lsl detection_precision) - 1)

let equal_u16_ct a b =
  let x = a lxor b in
  let diff = ref 0 in
  diff := !diff lor (x land 0xFF);
  diff := !diff lor ((x lsr 8) land 0xFF);
  !diff = 0

(* Check a detection tag (server-side with dk_d) *)
let check_tag ~dk_d ~ct_d ~expected_tag =
  let ss_d = Mlkem.decaps dk_d ct_d in
  let computed = compute_tag ss_d in
  equal_u16_ct computed expected_tag

(* Encode plaintext for memo encryption: v:8 || rseed:32 || memo:1024 *)
let encode_plaintext (v : int64) (rseed : Felt.t) (memo : bytes) =
  let pt = Bytes.make plaintext_size '\x00' in
  (* v as 8-byte little-endian *)
  for i = 0 to 7 do
    Bytes.set_uint8 pt i
      ((Int64.to_int (Int64.shift_right_logical v (i * 8))) land 0xFF)
  done;
  (* rseed: 32 bytes *)
  Bytes.blit rseed 0 pt 8 32;
  (* memo: up to 1024 bytes, zero-padded *)
  let len = min (Bytes.length memo) memo_size in
  Bytes.blit memo 0 pt 40 len;
  pt

(* Decode plaintext *)
let decode_plaintext pt =
  assert (Bytes.length pt >= plaintext_size);
  let v = ref 0L in
  for i = 7 downto 0 do
    v := Int64.logor (Int64.shift_left !v 8)
      (Int64.of_int (Bytes.get_uint8 pt i))
  done;
  let rseed = Bytes.sub pt 8 32 in
  let memo = Bytes.sub pt 40 memo_size in
  (!v, rseed, memo)

let derive_note_aead_nonce ~(aead_key : bytes) ~(plaintext : bytes) =
  let input = Bytes.create (Bytes.length aead_key + Bytes.length plaintext) in
  Bytes.blit aead_key 0 input 0 (Bytes.length aead_key);
  Bytes.blit plaintext 0 input (Bytes.length aead_key) (Bytes.length plaintext);
  Bytes.sub (Hash.hash_personalized "mnonSP__" input) 0 12

(* Encrypt memo data using ChaCha20-Poly1305 *)
let encrypt_memo ~(ss_v : bytes) ~(v : int64) ~(rseed : Felt.t) ~(memo : bytes) =
  let key_bytes = Hash.hash_bytes ss_v in
  let key = Mirage_crypto.Chacha20.of_secret (Bytes.to_string key_bytes) in
  let plaintext = encode_plaintext v rseed memo in
  let nonce = derive_note_aead_nonce ~aead_key:key_bytes ~plaintext in
  let ct = Mirage_crypto.Chacha20.authenticate_encrypt ~key ~nonce:(Bytes.to_string nonce)
    (Bytes.to_string plaintext) in
  (nonce, Bytes.of_string ct)

(* Decrypt memo data *)
let decrypt_memo ~(ss_v : bytes) ~(nonce : bytes) ~(encrypted_data : bytes) =
  let key_bytes = Hash.hash_bytes ss_v in
  let key = Mirage_crypto.Chacha20.of_secret (Bytes.to_string key_bytes) in
  match Mirage_crypto.Chacha20.authenticate_decrypt ~key ~nonce:(Bytes.to_string nonce)
    (Bytes.to_string encrypted_data) with
  | Some pt -> Some (decode_plaintext (Bytes.of_string pt))
  | None -> None

(* Create a "no memo" marker (0xF6 followed by zeros) per ZIP 302 *)
let no_memo () =
  let m = Bytes.make memo_size '\x00' in
  Bytes.set_uint8 m 0 0xF6;
  m

(* Create a UTF-8 text memo, zero-padded *)
let text_memo s =
  let m = Bytes.make memo_size '\x00' in
  let len = min (String.length s) memo_size in
  Bytes.blit_string s 0 m 0 len;
  m

(* Full note encryption: create detection ciphertext, tag, and encrypted memo.
   Requires ML-KEM encapsulation (currently stubbed). *)
let encrypt_note ~(ek_v : Mlkem.encapsulation_key) ~(ek_d : Mlkem.encapsulation_key)
    ~(v : int64) ~(rseed : Felt.t) ~(memo : bytes) =
  let (ss_d, ct_d) = Mlkem.encaps ek_d in
  let tag = compute_tag ss_d in
  let (ss_v, ct_v) = Mlkem.encaps ek_v in
  let (nonce, encrypted_data) = encrypt_memo ~ss_v ~v ~rseed ~memo in
  let enc : Encoding.encrypted_note = { ct_d; tag; ct_v; nonce; encrypted_data } in
  enc

(* Decrypt a note (recipient with dk_v) *)
let decrypt_note ~(dk_v : Mlkem.decapsulation_key) (enc : Encoding.encrypted_note) =
  let ss_v = Mlkem.decaps dk_v enc.ct_v in
  decrypt_memo ~ss_v ~nonce:enc.nonce ~encrypted_data:enc.encrypted_data

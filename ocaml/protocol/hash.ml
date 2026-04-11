(* Domain-separated hash functions for the TzEL protocol.
   All use BLAKE2s-256, truncated to 251 bits (felt252).

   Domain tags are FIXED felt252 constants with ASCII bytes packed into
   the low bytes — NOT hashed strings. See spec § Domain Tag Constants. *)

let personal_of_string s =
  let b = Bytes.make 8 '\x00' in
  let len = min (String.length s) 8 in
  Bytes.blit_string s 0 b 0 len;
  b

(* Encode a label string as a felt252 domain tag constant.
   Per spec: interpret UTF8(label) as a big-endian unsigned integer,
   then encode as 32-byte little-endian felt252.
   This means the ASCII bytes appear reversed in the felt.
   E.g. felt_tag("spend") = [0x64,0x6e,0x65,0x70,0x73, 0x00...0x00]
        (that's "d","n","e","p","s" — "spend" reversed) *)
let felt_tag s =
  let len = String.length s in
  assert (len <= 31);  (* must fit in felt252 *)
  let b = Bytes.make 32 '\x00' in
  for i = 0 to len - 1 do
    Bytes.set b (len - 1 - i) (String.get s i)
  done;
  b

(* ── Fixed domain tag constants ── *)

let tag_spend    = felt_tag "spend"
let tag_nk       = felt_tag "nk"
let tag_ask      = felt_tag "ask"
let tag_auth_key = felt_tag "auth-key"
let tag_incoming = felt_tag "incoming"
let tag_dsk      = felt_tag "dsk"
let tag_view     = felt_tag "view"
let tag_detect   = felt_tag "detect"
let tag_rcm      = felt_tag "rcm"
let tag_mlkem_v  = felt_tag "mlkem-v"
let tag_mlkem_v2 = felt_tag "mlkem-v2"
let tag_mlkem_d  = felt_tag "mlkem-d"
let tag_mlkem_d2 = felt_tag "mlkem-d2"
let tag_xmss_sk  = felt_tag "xmss-sk"
let tag_xmss_ps  = felt_tag "xmss-ps"

(* ── Core hash primitives ── *)

(* Unpersonalized BLAKE2s, truncated to 251 bits *)
let hash_bytes data = Felt.of_bytes (Blake2s.hash data)

(* H(a): single felt input, unpersonalized *)
let hash1 a = hash_bytes a

(* H(a, b): two felt inputs concatenated, unpersonalized *)
let hash2 a b =
  let buf = Bytes.create 64 in
  Bytes.blit a 0 buf 0 32;
  Bytes.blit b 0 buf 32 32;
  hash_bytes buf

let hash3 a b c =
  let buf = Bytes.create 96 in
  Bytes.blit a 0 buf 0 32;
  Bytes.blit b 0 buf 32 32;
  Bytes.blit c 0 buf 64 32;
  hash_bytes buf

let hash4 a b c d =
  let buf = Bytes.create 128 in
  Bytes.blit a 0 buf 0 32;
  Bytes.blit b 0 buf 32 32;
  Bytes.blit c 0 buf 64 32;
  Bytes.blit d 0 buf 96 32;
  hash_bytes buf

(* Personalized BLAKE2s of data, truncated to 251 bits *)
let hash_personalized personal data =
  Felt.of_bytes (Blake2s.hash ~personal:(personal_of_string personal) data)

(* ── Domain-separated hash functions ── *)

(* H_merkle(a, b): Merkle tree node hash *)
let hash_merkle a b =
  let buf = Bytes.create 64 in
  Bytes.blit a 0 buf 0 32;
  Bytes.blit b 0 buf 32 32;
  hash_personalized "mrklSP__" buf

(* H_nf: Nullifier hash *)
let hash_nf a b =
  let buf = Bytes.create 64 in
  Bytes.blit a 0 buf 0 32;
  Bytes.blit b 0 buf 32 32;
  hash_personalized "nulfSP__" buf

(* H_commit(d, v, rcm, owner_tag): Note commitment *)
let hash_commit d v_felt rcm owner_tag =
  let buf = Bytes.create 128 in
  Bytes.blit d 0 buf 0 32;
  Bytes.blit v_felt 0 buf 32 32;
  Bytes.blit rcm 0 buf 64 32;
  Bytes.blit owner_tag 0 buf 96 32;
  hash_personalized "cmmtSP__" buf

(* H_nksp(nk, d_j): Per-address nullifier spend key *)
let hash_nk_spend nk d_j =
  let buf = Bytes.create 64 in
  Bytes.blit nk 0 buf 0 32;
  Bytes.blit d_j 0 buf 32 32;
  hash_personalized "nkspSP__" buf

(* H_nktg(nk_spend): Per-address nullifier tag *)
let hash_nk_tag nk_spend =
  hash_personalized "nktgSP__" nk_spend

(* H_owner(auth_root, auth_pub_seed, nk_tag): Owner tag *)
let hash_owner auth_root auth_pub_seed nk_tag =
  let buf = Bytes.create 96 in
  Bytes.blit auth_root 0 buf 0 32;
  Bytes.blit auth_pub_seed 0 buf 32 32;
  Bytes.blit nk_tag 0 buf 64 32;
  hash_personalized "ownrSP__" buf

(* H_wots(data): WOTS+ chain hash *)
let hash_wots data =
  hash_personalized "wotsSP__" data

(* Sighash fold: H_sighash(a, b) *)
let hash_sighash a b =
  let buf = Bytes.create 64 in
  Bytes.blit a 0 buf 0 32;
  Bytes.blit b 0 buf 32 32;
  hash_personalized "sighSP__" buf

(* Memo hash: H_memo(data) *)
let hash_memo data =
  hash_personalized "memoSP__" data

(* rcm = H(H(TAG_RCM), rseed)
   Note: H(TAG_RCM) is hash1 of the raw ASCII-packed felt, not a hash of "rcm". *)
let derive_rcm rseed =
  hash2 (hash1 tag_rcm) rseed

(* Hash a raw UTF-8 string: H(UTF8(s)). Used for account_id and as a test
   utility to create arbitrary felts. NOT for domain tag derivation —
   use the tag_* constants for that. *)
let hash_tag s = hash_bytes (Bytes.of_string s)

(* Account ID: H(UTF8(account_string)), unpersonalized *)
let account_id s = hash_bytes (Bytes.of_string s)

(* Fold a list of felts with sighash personalization: fold(items) *)
let sighash_fold items =
  match items with
  | [] -> failwith "sighash_fold: empty list"
  | [x] -> x
  | first :: rest ->
    List.fold_left hash_sighash first rest

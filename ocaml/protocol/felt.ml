(* Felt252: 32-byte little-endian values with top 5 bits cleared.
   All protocol hash outputs are truncated to [0, 2^251). *)

type t = bytes

let zero = Bytes.make 32 '\x00'

let of_bytes b =
  assert (Bytes.length b = 32);
  let r = Bytes.copy b in
  let last = Bytes.get_uint8 r 31 in
  Bytes.set_uint8 r 31 (last land 0x07);
  r

let of_bytes_raw b =
  assert (Bytes.length b = 32);
  Bytes.copy b

let to_bytes t = Bytes.copy t

let of_int64 v =
  let b = Bytes.make 32 '\x00' in
  Bytes.set_int64_le b 0 v;
  b

let of_u64 v =
  let b = Bytes.make 32 '\x00' in
  Bytes.set_uint8 b 0 (v land 0xFF);
  Bytes.set_uint8 b 1 ((v lsr 8) land 0xFF);
  Bytes.set_uint8 b 2 ((v lsr 16) land 0xFF);
  Bytes.set_uint8 b 3 ((v lsr 24) land 0xFF);
  Bytes.set_uint8 b 4 ((v lsr 32) land 0xFF);
  Bytes.set_uint8 b 5 ((v lsr 40) land 0xFF);
  Bytes.set_uint8 b 6 ((v lsr 48) land 0xFF);
  Bytes.set_uint8 b 7 ((v lsr 56) land 0xFF);
  b

let of_u32 v = of_u64 v

let of_int = of_u64

let equal a b = Bytes.equal a b

let to_hex t = Hex.show (Hex.of_bytes t)

let of_hex s =
  let b = Hex.to_bytes (`Hex s) in
  assert (Bytes.length b = 32);
  b

let compare a b = Bytes.compare a b

let is_zero t = Bytes.equal t zero

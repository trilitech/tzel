
type felt = bytes

(** val sighash_fold : (felt -> felt -> felt) -> felt -> felt list -> felt **)

let rec sighash_fold h_sighash acc = function
| [] -> acc
| x::rest -> sighash_fold h_sighash (h_sighash acc x) rest

(** val hash3 : felt -> felt -> felt -> felt **)

let hash3 = Tzel.Hash.hash3

(** val hash5 : felt -> felt -> felt -> felt -> felt -> felt **)

let hash5 = Tzel.Hash.hash_commit

(** val commit : felt -> felt -> felt -> felt -> felt -> felt **)

let commit =
  hash5

(** val hash_nf : felt -> felt -> felt **)

let hash_nf = Tzel.Hash.hash_nf

(** val nullifier : felt -> felt -> felt -> felt **)

let nullifier nk_spend cm pos =
  hash_nf nk_spend (hash_nf cm pos)

(** val hash_sighash : felt -> felt -> felt **)

let hash_sighash = Tzel.Hash.hash_sighash

(** val sighash_fold0 : felt -> felt list -> felt **)

let sighash_fold0 acc fields =
  sighash_fold hash_sighash acc fields

(** val pack_adrs_chain : int -> int -> int -> felt **)

let pack_adrs_chain = (fun key_idx chain_idx step ->
      Tzel.Wots.pack_adrs Tzel.Wots.tag_xmss_chain key_idx chain_idx step 0)

(** val xmss_chain_step : felt -> felt -> int -> int -> int -> felt **)

let xmss_chain_step x pub_seed key_idx chain_idx step =
  hash3 pub_seed (pack_adrs_chain key_idx chain_idx step) x

(** val merkle_step :
    (felt -> felt -> felt) -> bool -> felt -> felt -> felt **)

let merkle_step h bit current sibling =
  if bit then h sibling current else h current sibling

(** val merkle_root :
    (felt -> felt -> felt) -> bool list -> felt list -> felt -> felt **)

let rec merkle_root h bits siblings leaf =
  match bits with
  | [] -> leaf
  | b::bs ->
    (match siblings with
     | [] -> leaf
     | s::ss -> merkle_root h bs ss (merkle_step h b leaf s))

(** val hash2_merkle : felt -> felt -> felt **)

let hash2_merkle = Tzel.Hash.hash_merkle

(** val merkle_compute_root : bool list -> felt list -> felt -> felt **)

let merkle_compute_root bits siblings leaf =
  merkle_root hash2_merkle bits siblings leaf

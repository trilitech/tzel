
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

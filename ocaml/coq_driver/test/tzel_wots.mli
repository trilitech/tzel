
val length : 'a1 list -> int

type felt = bytes

module Nat :
 sig
  val add : int -> int -> int

  val mul : int -> int -> int

  val leb : int -> int -> bool

  val ltb : int -> int -> bool

  val pow : int -> int -> int
 end

val firstn : int -> 'a1 list -> 'a1 list

val skipn : int -> 'a1 list -> 'a1 list

val sighash_fold : (felt -> felt -> felt) -> felt -> felt list -> felt

val hash3 : felt -> felt -> felt -> felt

val hash5 : felt -> felt -> felt -> felt -> felt -> felt

val commit : felt -> felt -> felt -> felt -> felt -> felt

val hash_nf : felt -> felt -> felt

val nullifier : felt -> felt -> felt -> felt

val hash_sighash : felt -> felt -> felt

val sighash_fold0 : felt -> felt list -> felt

val pack_adrs_chain : int -> int -> int -> felt

val xmss_chain_step : felt -> felt -> int -> int -> int -> felt

val merkle_step : (felt -> felt -> felt) -> bool -> felt -> felt -> felt

val merkle_root :
  (felt -> felt -> felt) -> bool list -> felt list -> felt -> felt

val hash2_merkle : felt -> felt -> felt

val merkle_compute_root : bool list -> felt list -> felt -> felt

val zero_hash : ('a1 -> 'a1 -> 'a1) -> 'a1 -> int -> 'a1

val build_level : ('a1 -> 'a1 -> 'a1) -> 'a1 list -> 'a1 list

val fold_levels : ('a1 -> 'a1 -> 'a1) -> int -> 'a1 list -> 'a1 list

val root_of : ('a1 -> 'a1 -> 'a1) -> 'a1 -> int -> 'a1 list -> 'a1

val mroot : ('a1 -> 'a1 -> 'a1) -> 'a1 -> int -> 'a1 list -> 'a1

val tdfront : ('a1 -> 'a1 -> 'a1) -> 'a1 -> int -> 'a1 list -> 'a1 -> 'a1

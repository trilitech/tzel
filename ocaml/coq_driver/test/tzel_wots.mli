
type felt = bytes

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

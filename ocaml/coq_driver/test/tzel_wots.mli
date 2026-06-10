
type felt = bytes

val hash3 : felt -> felt -> felt -> felt

val hash5 : felt -> felt -> felt -> felt -> felt -> felt

val commit : felt -> felt -> felt -> felt -> felt -> felt

val hash_nf : felt -> felt -> felt

val nullifier : felt -> felt -> felt -> felt

val pack_adrs_chain : int -> int -> int -> felt

val xmss_chain_step : felt -> felt -> int -> int -> int -> felt

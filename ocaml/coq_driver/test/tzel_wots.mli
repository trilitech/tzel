
type felt = bytes

val hash3 : felt -> felt -> felt -> felt

val pack_adrs_chain : int -> int -> int -> felt

val xmss_chain_step : felt -> felt -> int -> int -> int -> felt


type felt = bytes

(** val hash3 : felt -> felt -> felt -> felt **)

let hash3 = Tzel.Hash.hash3

(** val pack_adrs_chain : int -> int -> int -> felt **)

let pack_adrs_chain = (fun key_idx chain_idx step ->
      Tzel.Wots.pack_adrs Tzel.Wots.tag_xmss_chain key_idx chain_idx step 0)

(** val xmss_chain_step : felt -> felt -> int -> int -> int -> felt **)

let xmss_chain_step x pub_seed key_idx chain_idx step =
  hash3 pub_seed (pack_adrs_chain key_idx chain_idx step) x

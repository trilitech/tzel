(* XMSS-style WOTS+ with w=4 and BLAKE2s.
   133 chains: 128 message digits + 5 checksum digits.
   Public keys are compressed with an L-tree instead of a left fold. *)

let w = 4
let n_msg = 128
let n_csum = 5
let n_chains = 133
let chain_max = w - 1

let tag_xmss_chain = 0x0068632d73736d78L
let tag_xmss_ltree = 0x00746c2d73736d78L

let pack_adrs tag key_idx a b c =
  let out = Bytes.make 32 '\x00' in
  for i = 0 to 7 do
    let byte =
      Int64.(to_int (logand (shift_right_logical tag (8 * i)) 0xffL))
    in
    Bytes.set_uint8 out i byte
  done;
  Bytes.set_uint8 out 8 (key_idx land 0xFF);
  Bytes.set_uint8 out 9 ((key_idx lsr 8) land 0xFF);
  Bytes.set_uint8 out 10 ((key_idx lsr 16) land 0xFF);
  Bytes.set_uint8 out 11 ((key_idx lsr 24) land 0xFF);
  Bytes.set_uint8 out 12 (a land 0xFF);
  Bytes.set_uint8 out 13 ((a lsr 8) land 0xFF);
  Bytes.set_uint8 out 14 ((a lsr 16) land 0xFF);
  Bytes.set_uint8 out 15 ((a lsr 24) land 0xFF);
  Bytes.set_uint8 out 16 (b land 0xFF);
  Bytes.set_uint8 out 17 ((b lsr 8) land 0xFF);
  Bytes.set_uint8 out 18 ((b lsr 16) land 0xFF);
  Bytes.set_uint8 out 19 ((b lsr 24) land 0xFF);
  Bytes.set_uint8 out 20 (c land 0xFF);
  Bytes.set_uint8 out 21 ((c lsr 8) land 0xFF);
  Bytes.set_uint8 out 22 ((c lsr 16) land 0xFF);
  Bytes.set_uint8 out 23 ((c lsr 24) land 0xFF);
  Felt.of_bytes_raw out

let xmss_chain_step x pub_seed key_idx chain_idx step =
  let adrs = pack_adrs tag_xmss_chain key_idx chain_idx step 0 in
  Hash.hash3 pub_seed adrs x

let xmss_hash_chain x pub_seed key_idx chain_idx start steps =
  let r = ref x in
  for step = start to (start + steps - 1) do
    r := xmss_chain_step !r pub_seed key_idx chain_idx step
  done;
  !r

let decompose_sighash (h : bytes) =
  let msg_digits = Array.make n_msg 0 in
  for i = 0 to n_msg - 1 do
    let byte_idx = i / 4 in
    let bit_ofs = (i mod 4) * 2 in
    let byte_val = Bytes.get_uint8 h byte_idx in
    msg_digits.(i) <- (byte_val lsr bit_ofs) land 3
  done;
  let csum = Array.fold_left (fun acc d -> acc + (chain_max - d)) 0 msg_digits in
  let csum_digits = Array.make n_csum 0 in
  let c = ref csum in
  for i = 0 to n_csum - 1 do
    csum_digits.(i) <- !c mod w;
    c := !c / w
  done;
  let all = Array.make n_chains 0 in
  Array.blit msg_digits 0 all 0 n_msg;
  Array.blit csum_digits 0 all n_msg n_csum;
  all

let derive_sk seed i =
  Hash.hash2 seed (Felt.of_int i)

let keygen ~seed ~pub_seed ~key_idx =
  Array.init n_chains (fun i ->
    let sk_i = derive_sk seed i in
    xmss_hash_chain sk_i pub_seed key_idx i 0 chain_max)

let pk_to_leaf ~pub_seed ~key_idx pk =
  assert (Array.length pk = n_chains);
  let level = ref 0 in
  let current = ref (Array.copy pk) in
  while Array.length !current > 1 do
    let next_len = (Array.length !current + 1) / 2 in
    let next = Array.make next_len Felt.zero in
    let node_idx = ref 0 in
    for i = 0 to next_len - 1 do
      let left = (!current).(2 * i) in
      if 2 * i + 1 >= Array.length !current then
        next.(i) <- left
      else begin
        let right = (!current).(2 * i + 1) in
        let adrs = pack_adrs tag_xmss_ltree key_idx !level !node_idx 0 in
        next.(i) <- Hash.hash4 pub_seed adrs left right;
        incr node_idx
      end
    done;
    current := next;
    incr level
  done;
  (!current).(0)

let sign ~seed ~pub_seed ~key_idx sighash =
  let digits = decompose_sighash sighash in
  Array.init n_chains (fun i ->
    let sk_i = derive_sk seed i in
    xmss_hash_chain sk_i pub_seed key_idx i 0 digits.(i))

let recover_pk ~pub_seed ~key_idx sig_vals sighash =
  let digits = decompose_sighash sighash in
  Array.init n_chains (fun i ->
    let remaining = chain_max - digits.(i) in
    xmss_hash_chain sig_vals.(i) pub_seed key_idx i digits.(i) remaining)

let verify ~pub_seed ~key_idx sig_vals sighash leaf =
  let pk = recover_pk ~pub_seed ~key_idx sig_vals sighash in
  Felt.equal (pk_to_leaf ~pub_seed ~key_idx pk) leaf

(* out_hash.test.mligo — validates the LIGO OutHash chain against the
   Rust-pinned golden vectors. Run with:  ligo run test out_hash.test.mligo

   Each blake2s call's (preimage -> digest) is fixed in `blake_table` from the
   reference oracle, so every NON-blake stage (felt encode, pack_256_le_to_felt
   mod reduction, 9-bit limb split, LE-u32 lane framing, reduce_to_m31) is
   exercised as real LIGO and asserted equal to the golden output lanes. *)

#include "out_hash.mligo"
module O = OutHash

(* ── blake2s seam fixtures (preimage -> blake2s-256 digest, 32 LE bytes) ──
   Computed off-chain by the Rust reference / hashlib.blake2s. In production
   these are replaced by the Layer-1 BLAKE2S instruction. *)
let blake_table : O.blake_table =
  Map.literal [
    (* SHIELD leaf — STAGE 1a inner felt-encode blake *)
    ( 0x0000000001000000000000000b0000001dfab1831024cecad39a93b8fad1562a52bbe62a6bf4a82cbfeb39dadfd5ecf3000000000800000000000000400d030000000000a086010000000000010000007092da85d8b8262d1c667bccaeb7bd034314904cf15f62048af62cddca31a91019aa5b834766c10d2d33aef61562729dbc2c6902912c14e142824e6127b88ca14f6e4c80aee0d7f44eb9c9a12e98fe2bc7ecabbb4074edb685f79572ec13a28e0000000005c000000000000005c10000
    , 0x969bd033201e998bf805dbe1a1842f2755bbce6657ac9ab483975493635e8790 );
    (* SHIELD leaf — STAGE 1c outer pack/blake_qm31 *)
    ( 0x840100004d000000f400000006000000e2010000c80000002e000000f101000005010000ed0000007800000094000000f8000000390100005401000076010000ce000000b30100001501000055010000490100008d00000059000000a90000009301000031010000d701000010000000
    , 0x1090513ad60a4d4d1f322514169effc05f349e4e2dbc1402f9d55df8ed00a916 );
    (* STAGE 2 mv-mode wrap OutHash *)
    ( 0x0b38551b4456ef029086970a2f0ee7415a7e052ab5c5f526344ad2439942fc5166cace2f9e89d918205cdb6ebfeace0393ab5d068bd3a970abc9f26c04f20e6d
    , 0x5e7b411ad58d42932dd6e69ea5917c1a55a2f8a30ca40b5f8c550ba650148cf3 );
    (* STAGE 2 mv fold (compute_mv_output_values) *)
    ( 0x0ee5384feaa9bb046f85e512b275704112447631d00af82bc6a94c2f89b8cb2299934961cdc8031e8d38187c25bc0117530c9578835f53311c8e8d21a86bba560ee5384feaa9bb046f85e512b275704112447631d00af82bc6a94c2f89b8cb22b579c953b6426c20da912a3832587c080af1f35bcceebe35b10660730804ff22
    , 0x66cace2f9d89d998205cdb6ebfeace0392ab5d868ad3a9f0abc9f26c04f20e6d );
    (* LEAF-MODE golden vector (snark.rs compute_*_golden_vector) — inner *)
    ( 0x00000000010000000000000004000000aab1d087573f1bfa47c8d4a0f73fd212bc5fb50f241ef8b14e6ccf5208c5e77400000000630000000000000064000000
    , 0x5134842acbb89952a585a44da1d000817eb798204d9de65de6f3ea1c5736e63d );
    (* LEAF-MODE golden vector — outer (stage 1 blake_qm31) *)
    ( 0x4a0000001a000000a1000000650100008c010000cd0000004a0100004a01000085000000d200000053000000140000000d00000008000000fa0100006e010000980000009000000053010000d3000000de0100007a010000cd010000d50100001c0100002b0100008d010000bc000000
    , 0x39744f5ec530b4dbb8f94aff551c715fd17bce6a601e300c24592fb0a39658d5 );
    (* LEAF-MODE golden vector — wrap OutHash (root || out8 || U_VALUE) *)
    ( 0xae20985c63c835435d346b78c87f8d61d8afe270ba30ab3e906f21456dc5e43339744f5ec630b45bb9f94a7f551c715fd17bce6a601e300c25592f30a496585500000000000000000100000000000000
    , 0x0b0a1e4f0693fc89fb1708022f665915200d581b2ca340a859fc07269f31397b )
  ]

let b2s = O.blake2s blake_table

(* ── golden inputs ──────────────────────────────────────────────────── *)

(* SHIELD leaf output_preimage, each felt as 32-byte BE bytes
   (verifier/testdata/leaf_junction.json, "shield"). *)
let shield_felts : bytes list = [
  0x0000000000000000000000000000000000000000000000000000000000000001 ;
  0x000000000000000000000000000000000000000000000000000000000000000b ;
  0x03b1fa1dcace2410b8939ad32a56d1fa2ae6bb522ca8f46bda39ebbff3ecd5df ;
  0x0000000000000000000000000000000000000000000000000000000000000008 ;
  0x0000000000000000000000000000000000000000000000000000000000030d40 ;
  0x00000000000000000000000000000000000000000000000000000000000186a0 ;
  0x0000000000000000000000000000000000000000000000000000000000000001 ;
  0x05da92702d26b8d8cc7b661c03bdb7ae4c90144304625ff1dd2cf68a10a931ca ;
  0x035baa190dc16647f6ae332d9d72621502692cbce1142c91614e8242a18cb827 ;
  0x004c6e4ff4d7e0aea1c9b94e2bfe982ebbabecc7b6ed74407295f7858ea213ec ;
  0x000000000000000000000000000000000000000000000000000000000000c005 ;
  0x000000000000000000000000000000000000000000000000000000000000c105
]

(* ── helpers ────────────────────────────────────────────────────────── *)
let assert_lanes (label : string) (got : nat list) (want : nat list) : unit =
  let _ = Test.println (label ^ ": " ^ (if got = want then "PASS" else "FAIL")) in
  if got <> want then
    let _ = Test.println ("  got:  " ^ Test.to_string got) in
    let _ = Test.println ("  want: " ^ Test.to_string want) in
    failwith ("golden vector mismatch: " ^ label)
  else ()

(* ── tests ──────────────────────────────────────────────────────────── *)

(* STAGE 1 end-to-end: leaf_junction shield output_preimage -> 8 leaf lanes. *)
let test_stage1_leaf_junction_shield =
  let got = O.compute_output_hash_values blake_table shield_felts in
  let want : nat list =
    [978423824n;1296894678n;337981983n;1090493975n;
     1318990943n;34913325n;2019415546n;380174573n] in
  assert_lanes "STAGE1 leaf_junction(shield)" got want

(* STAGE 1b isolated: felt -> 28 limbs (against the oracle dump). *)
let test_stage1b_limbs =
  (* inner felt = digest_le_to_felt(inner_digest) — see oracle. *)
  let felt =
    O.digest_le_to_felt 0x969bd033201e998bf805dbe1a1842f2755bbce6657ac9ab483975493635e8790 in
  let got = O.felt_to_28_limbs felt in
  let want : nat list =
    [388n;77n;244n;6n;482n;200n;46n;497n;261n;237n;120n;148n;248n;313n;
     340n;374n;206n;435n;277n;341n;329n;141n;89n;169n;403n;305n;471n;16n] in
  assert_lanes "STAGE1b felt->28 limbs" got want

(* STAGE 2 mv-mode wrap OutHash (snark.rs mv_out_hash_matches_wrap_fixture). *)
let test_stage2_mv_out_hash =
  let root = 0x0b38551b4456ef029086970a2f0ee7415a7e052ab5c5f526344ad2439942fc51 in
  let lanes : nat list =
    [802081382n;416909726n;1859869728n;63892159n;
     106802067n;1890177931n;1827850667n;1829696004n] in
  let got = O.compute_expected_out_hash_mv blake_table root lanes in
  let want : nat list =
    [440499038n;323128790n;518444590n;444371365n;
     603497046n;1594598412n;638277005n;1938560081n] in
  assert_lanes "STAGE2 mv wrap OutHash" got want

(* STAGE 2 mv fold (snark.rs mv_output_values_golden_vector). *)
let test_stage2_mv_fold =
  let lroot : nat list =
    [1329128718n;79407594n;317031791n;1097889202n;
     829834258n;737675984n;793553350n;583776393n] in
  let lov : nat list =
    [1632211865n;503564493n;2081962125n;385989669n;
     2023033939n;827547523n;562925084n;1455057832n] in
  let rov : nat list =
    [1405712821n;543965878n;942313946n;142366770n;
     1542713610n;901705420n;1935673009n;587138056n] in
  let got = O.compute_mv_output_values blake_table lroot lov lroot rov in
  let want : nat list =
    [802081382n;416909726n;1859869728n;63892159n;
     106802067n;1890177931n;1827850667n;1829696004n] in
  assert_lanes "STAGE2 mv fold" got want

(* FULL leaf-mode chain: felt preimage -> STAGE 1 leaf output -> STAGE 2 wrap
   OutHash with U_VALUE. End-to-end against snark.rs
   compute_expected_out_hash_golden_vector. *)
let test_leaf_mode_full =
  let felts : bytes list = [
    0x0000000000000000000000000000000000000000000000000000000000000001 ;
    0x0000000000000000000000000000000000000000000000000000000000000004 ;
    0x07d0b1aafa1b3f57a0d4c84712d23ff70fb55fbcb1f81e2452cf6c4e74e7c508 ;
    0x0000000000000000000000000000000000000000000000000000000000000063 ;
    0x0000000000000000000000000000000000000000000000000000000000000064
  ] in
  (* STAGE 1 *)
  let leaf = O.compute_output_hash_values blake_table felts in
  let want_leaf : nat list =
    [1582265401n;1538535622n;2135620025n;1601248341n;
     1791917009n;204480096n;808409381n;1431869092n] in
  let () = assert_lanes "LEAF-MODE stage1 output_hash" leaf want_leaf in
  (* STAGE 2 leaf mode (appends U_VALUE) *)
  let root = 0xae20985c63c835435d346b78c87f8d61d8afe270ba30ab3e906f21456dc5e433 in
  let got = O.compute_expected_out_hash blake_table root leaf in
  let want : nat list =
    [1327368715n;167547655n;34084859n;358180399n;
     458755360n;675324717n;638057561n;2067345823n] in
  assert_lanes "LEAF-MODE wrap OutHash" got want

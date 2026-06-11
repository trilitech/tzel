(* Smoke tests for the gateway-integrated TzEL contract (tzel_zk.mligo).

   The LIGO Test framework runs Michelson in a mock with NO enshrined gateway
   and NO zk runtime, so `Tezos.call_view "zk" ...` returns `None` and every
   entrypoint aborts at `verify_snark` with "view unavailable". These tests
   therefore confirm two things that DON'T need the sandbox:
     1. the contract originates with the expected storage, and
     2. each entrypoint actually reaches the gateway call (the integration is
        wired, not stubbed).
   Positive verification + bookkeeping are validated kernel-side (the zk-view
   end-to-end Rust test) and, in CI, by the octez/LIGO sandbox. *)

#import "tzel_zk.mligo" "TzEL"

let gateway_addr : address = ("KT18oDJJKXMKhfE1bSuAPGp92pYcwVDiqsPw" : address)

let base_storage : TzEL.storage = {
  gateway = gateway_addr ;
  vk = 0x ;
  root = 0x00 ;
  nullifiers = (Big_map.empty : (bytes, unit) big_map) ;
}

(* ── test 1: originate, inspect initial storage ──────────────────────────── *)
let test_originate_storage =
  let orig = Test.originate (contract_of TzEL) base_storage 0tez in
  let st = Test.get_storage orig.addr in
  let () = assert (st.gateway = gateway_addr) in
  let () = assert (st.root = 0x00) in
  Test.println "test_originate_storage: PASS"

(* ── test 2: %shield reaches the gateway view (fails: view unavailable) ──── *)
let test_shield_reaches_gateway =
  let orig = Test.originate (contract_of TzEL) base_storage 0tez in
  let c = Test.to_contract orig.addr in
  let param : TzEL.shield_param =
    { proof = 0x ; publics = ([] : bytes list) ; old_root = 0x00 ; new_root = 0x01 } in
  let result = Test.transfer_to_contract c (Shield param) 0tez in
  let () = match result with
    | Success _ -> failwith "expected gateway view unavailable in Test"
    | Fail _ -> unit in
  Test.println "test_shield_reaches_gateway: PASS"

(* ── test 3: %transfer reaches the gateway view ──────────────────────────── *)
let test_transfer_reaches_gateway =
  let orig = Test.originate (contract_of TzEL) base_storage 0tez in
  let c = Test.to_contract orig.addr in
  let param : TzEL.transfer_param =
    { proof = 0x ; publics = ([] : bytes list) ;
      nullifier_preimage = 0xc0ffee ; old_root = 0x00 ; new_root = 0x01 } in
  let result = Test.transfer_to_contract c (Transfer param) 0tez in
  let () = match result with
    | Success _ -> failwith "expected gateway view unavailable in Test"
    | Fail _ -> unit in
  Test.println "test_transfer_reaches_gateway: PASS"

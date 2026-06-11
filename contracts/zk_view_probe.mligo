(* Minimal probe to validate the synchronous `zk` gateway view in an octez
   sandbox (tezt). Generic on purpose: the parameter carries the (path, body)
   for the zk view, so the SAME contract probes "blake2s" today and
   "verify_snark" when the test is extended. Storage holds the bytes the view
   returned (empty if it returned None).

   Compiles to michelson_test_scripts/mini_scenarios/zk_view_probe.tz. *)

type param = string * bytes      (* (endpoint path, request body) *)
type storage = bytes             (* last view result *)

[@entry]
let probe ((path, body) : param) (_ : storage) : operation list * storage =
  let gateway : address = ("KT18oDJJKXMKhfE1bSuAPGp92pYcwVDiqsPw" : address) in
  let result =
    match (Tezos.call_view "zk" (path, body) gateway : bytes option) with
    | Some b -> b
    | None -> (0x : bytes) in
  ([] : operation list), result

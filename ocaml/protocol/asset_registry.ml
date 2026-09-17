(* L2 asset registry: maps L1 ticketer (KT1) contracts to L2 asset_ids.

   Direct port of the Rust `tzel-core` registry (core/src/lib.rs):
   - asset_id = ASSET_TEZ (Felt.zero) for the tez bridge,
   - asset_id = derive_asset_id(ticketer) = H("tzel:asset:" || ticketer)
     for each FA2 bridge.
   The L1 -> L2 binding is structural (a hash of the ticketer address),
   so two FA2 tokens served by different ticketers cannot collide on
   asset_id. Lookups are first-match; the only dedup is skipping any FA2
   ticketer equal to the tez ticketer. *)

let asset_tez : Felt.t = Felt.zero

(* derive_asset_id(ticketer) = H("tzel:asset:" || ticketer).
   Must be byte-identical to core::derive_asset_id. *)
let derive_asset_id (ticketer : string) : Felt.t =
  Hash.hash_bytes (Bytes.of_string ("tzel:asset:" ^ ticketer))

type entry = {
  asset_id : Felt.t;
  ticketer : string;
}

let tez_entry (ticketer : string) : entry =
  { asset_id = asset_tez; ticketer }

let fa2_entry (ticketer : string) : entry =
  { asset_id = derive_asset_id ticketer; ticketer }

(* Entry 0 is the tez bridge; subsequent entries are FA2 bridges.
   Defense-in-depth: skip any FA2 ticketer string equal to the tez
   ticketer (mirrors compose_asset_registry_with's dedup). *)
let compose_with ~(tez_ticketer : string) (fa2_ticketers : string list) : entry list =
  tez_entry tez_ticketer
  :: List.filter_map
       (fun fa2 ->
         if String.equal fa2 tez_ticketer then None else Some (fa2_entry fa2))
       fa2_ticketers

(* Tez-only registry (no FA2 bridges). The OCaml reference takes its FA2
   bridge list explicitly via [compose_with]; the Rust kernel reads a
   compile-time / env list. *)
let compose ~(tez_ticketer : string) : entry list = compose_with ~tez_ticketer []

(* First-match lookups (mirror the Rust `find`). *)
let ticketer_for_asset (registry : entry list) (asset_id : Felt.t) : string option =
  match List.find_opt (fun e -> Felt.equal e.asset_id asset_id) registry with
  | Some e -> Some e.ticketer
  | None -> None

let asset_for_ticketer (registry : entry list) (ticketer : string) : Felt.t option =
  match List.find_opt (fun e -> String.equal e.ticketer ticketer) registry with
  | Some e -> Some e.asset_id
  | None -> None

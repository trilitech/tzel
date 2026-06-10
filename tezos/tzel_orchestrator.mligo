(* tzel_orchestrator.mligo

   TzEL orchestrator — Shape A.

   A Michelson contract on the Tezos X Michelson interface that exposes
   shield / transfer / unshield entrypoints. Each entrypoint takes the
   wire-encoded body of a `KernelInboxMessage` variant (see
   `core/src/kernel_wire.rs` — `WireKernelShieldReq`, `WireKernelTransferReq`,
   `WireKernelUnshieldReq`), wraps it with the matching one-byte tag and the
   two-byte little-endian wire version, and forwards the resulting
   `KernelInboxMessage` bytes to the TzEL smart rollup.

   ---

   Wire format mirrored (source of truth: `core/src/kernel_wire.rs`):

     KernelInboxEnvelope :=
         version       : WireU16Le        ([u8;2] little-endian, see lines 14, 339-342)
         message       : WireKernelInboxMessage (u8 tag + body, lines 322-336)

   The `tezos_data_encoding` derive macro generates a u8 discriminant tag
   driven by `#[encoding(tags = "u8")]` (kernel_wire.rs:262-275 / 322-336).
   The relevant tags are:

       ConfigureVerifier = 0x00
       ConfigureBridge   = 0x01
       Shield            = 0x02
       Transfer          = 0x03
       Unshield          = 0x04
       StageChunk        = 0x07
       SubmitOps         = 0x08

   (Tag 0x06, the v17 DalPointer, is retired and must not be reused.)

   This orchestrator only exposes the three user-driven variants (Shield,
   Transfer, Unshield). Verifier/bridge configuration stays on the off-chain
   admin path; the staged v18 submission variants (StageChunk/SubmitOps)
   are produced by the operator pipeline and are not exposed here.

   `KERNEL_WIRE_VERSION` is pinned to 18 (kernel_wire.rs:14). If the kernel
   bumps it, redeploy this contract — the literal at `kernel_wire_envelope`
   below must match.

   ---

   Calling pattern.

   Smart contracts on Tezos can only emit internal `TRANSFER_TOKENS`
   operations. The TzEL kernel currently parses external rollup messages
   (`ExternalMessageFrame::Targetted` — see
   `tezos/rollup-kernel/src/lib.rs:684-696`) and internal bridge deposits
   (FA2 tickets, `tez_bridge_ticketer.tz`). External messages cannot be
   emitted from a Michelson contract.

   This contract therefore relies on the rollup learning a new internal
   inbox shape — a `Transfer<MichelsonBytes>` sent directly to the rollup
   address (see "Kernel-side delta required" in TZEL_ORCHESTRATOR_README.md).
   The kernel extension is small: in `parse_rollup_message_against`
   (`rollup-kernel/src/lib.rs:673-697`), accept
   `TezosInternalInboxMessage::Transfer<MichelsonBytes>` and feed the
   payload bytes into `decode_kernel_inbox_message` exactly as the external
   path does.

   Until that delta lands, this contract still compiles, originates and
   accepts calls — the rollup will simply log "ignored" inbox entries. A
   secondary deployment mode that does not require a kernel change is the
   `%emit_only` flag in storage (`forward_mode = Emit_only`), which records
   the payload in an event for a relayer to pick up. Both modes are
   exercised in TZEL_ORCHESTRATOR_README.md. *)

(* ------------------------------------------------------------------ *)
(* Wire constants — must stay in sync with core/src/kernel_wire.rs    *)
(* ------------------------------------------------------------------ *)

(* KERNEL_WIRE_VERSION = 18 as u16 little-endian. *)
[@inline]
let kernel_wire_version_le : bytes = 0x1200

(* Variant tag bytes for WireKernelInboxMessage (kernel_wire.rs:322-336). *)
[@inline] let tag_shield   : bytes = 0x02
[@inline] let tag_transfer : bytes = 0x03
[@inline] let tag_unshield : bytes = 0x04

(* Build the framed envelope: version_le (2B) ++ tag (1B) ++ body. *)
[@inline]
let envelope (tag : bytes) (body : bytes) : bytes =
  Bytes.concats [kernel_wire_version_le; tag; body]

(* ------------------------------------------------------------------ *)
(* Storage                                                            *)
(* ------------------------------------------------------------------ *)

type forward_mode =
  | Forward_to_rollup of address  (* dispatch via TRANSFER_TOKENS to rollup *)
  | Emit_only                      (* dispatch via an event, off-chain relay *)

type storage = {
  admin        : address ;
  rollup       : address ;     (* The TzEL smart rollup address (sr1...). *)
  forward_mode : forward_mode ;
  paused       : bool ;
  nonce        : nat ;         (* monotonically increasing per call *)
}

(* ------------------------------------------------------------------ *)
(* Errors                                                             *)
(* ------------------------------------------------------------------ *)

[@inline] let err_paused           = "TZEL_ORCH_PAUSED"
[@inline] let err_not_admin        = "TZEL_ORCH_NOT_ADMIN"
[@inline] let err_rollup_not_found = "TZEL_ORCH_ROLLUP_NOT_FOUND"
[@inline] let err_zero_amount      = "TZEL_ORCH_UNEXPECTED_AMOUNT"
[@inline] let err_empty_calldata   = "TZEL_ORCH_EMPTY_CALLDATA"

(* ------------------------------------------------------------------ *)
(* Dispatch                                                           *)
(* ------------------------------------------------------------------ *)

(* The rollup parameter type for an internal-transfer-as-payload route is
   simply `bytes`. This matches the kernel-side extension described in
   TZEL_ORCHESTRATOR_README.md. *)
let dispatch_to_rollup (rollup : address) (payload : bytes) : operation =
  match (Tezos.get_contract_opt rollup : bytes contract option) with
  | None -> failwith err_rollup_not_found
  | Some c -> Tezos.Next.Operation.transaction payload 0mutez c

(* Emit-only dispatch: record the payload as an event with a stable tag
   so off-chain relayers can subscribe and forward it as an external
   rollup message. *)
let dispatch_via_event (payload : bytes) (nonce : nat) : operation =
  Tezos.Next.Operation.emit "%tzel_inbox" (nonce, payload)

let dispatch (s : storage) (payload : bytes) : operation =
  let () =
    if Bytes.length payload = 0n then failwith err_empty_calldata
  in
  match s.forward_mode with
  | Forward_to_rollup r -> dispatch_to_rollup r payload
  | Emit_only           -> dispatch_via_event payload s.nonce

(* Guard rails common to every user-facing entrypoint. *)
let check_active (s : storage) : unit =
  let () =
    if s.paused then failwith err_paused
  in
  (* No tez is consumed by Shield/Transfer/Unshield bodies — the deposit
     pool is funded out-of-band via the bridge ticketer. Reject incoming
     amount to avoid silent loss on this contract. *)
  if Tezos.get_amount () > 0mutez then failwith err_zero_amount

(* ------------------------------------------------------------------ *)
(* Entrypoints                                                        *)
(* ------------------------------------------------------------------ *)

(* `shield_body` is the wire-encoded `WireKernelShieldReq` (kernel_wire.rs:
   222-233 + `encode_kernel_inbox_message`, lines 367-391). The caller MUST
   supply the body only; this contract prepends version + tag. *)
[@entry]
let shield (shield_body : bytes) (s : storage) : operation list * storage =
  let () = check_active s in
  let payload = envelope tag_shield shield_body in
  let op = dispatch s payload in
  [op], { s with nonce = s.nonce + 1n }

(* `transfer_body` is the wire-encoded `WireKernelTransferReq`
   (kernel_wire.rs:243-247 — itself a `dynamic` byte container of the
   nested encoding produced by `kernel_transfer_req_to_wire`,
   lines 950-963). *)
[@entry]
let transfer (transfer_body : bytes) (s : storage) : operation list * storage =
  let () = check_active s in
  let payload = envelope tag_transfer transfer_body in
  let op = dispatch s payload in
  [op], { s with nonce = s.nonce + 1n }

(* `unshield_body` is the wire-encoded `WireKernelUnshieldReq`
   (kernel_wire.rs:256-260 — same dynamic-bytes shape as the transfer
   variant, see `kernel_unshield_req_to_wire` lines 1030-1051). *)
[@entry]
let unshield (unshield_body : bytes) (s : storage) : operation list * storage =
  let () = check_active s in
  let payload = envelope tag_unshield unshield_body in
  let op = dispatch s payload in
  [op], { s with nonce = s.nonce + 1n }

(* ------------------------------------------------------------------ *)
(* Admin                                                              *)
(* ------------------------------------------------------------------ *)

let assert_admin (s : storage) : unit =
  if Tezos.get_sender () <> s.admin then failwith err_not_admin

[@entry]
let set_paused (paused : bool) (s : storage) : operation list * storage =
  let () = assert_admin s in
  [], { s with paused = paused }

[@entry]
let set_admin (new_admin : address) (s : storage) : operation list * storage =
  let () = assert_admin s in
  [], { s with admin = new_admin }

[@entry]
let set_forward_mode (mode : forward_mode) (s : storage) : operation list * storage =
  let () = assert_admin s in
  [], { s with forward_mode = mode }

[@entry]
let set_rollup (new_rollup : address) (s : storage) : operation list * storage =
  let () = assert_admin s in
  [], { s with rollup = new_rollup }

(* ------------------------------------------------------------------ *)
(* Views                                                              *)
(* ------------------------------------------------------------------ *)

[@view]
let get_storage () (s : storage) : storage = s

[@view]
let get_nonce () (s : storage) : nat = s.nonce

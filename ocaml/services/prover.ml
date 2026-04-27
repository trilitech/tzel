(* Prover boundary: OCaml interface to the Rust tzel-prove / tzel-verify
   CLI binaries wrapping StarkWare's proving-utils v1.2.2 stack.

   The OCaml side:
   1. Builds the transaction witness (private inputs)
   2. Serializes it as JSON for the Cairo program runner
   3. Calls tzel-prove which runs the bootloader + Stwo prover
   4. Parses the proof bundle (compressed proof + output_preimage)
   5. Verifies the bootloader-authenticated program hash and public outputs

   The Rust side is an opaque boundary — it runs the Cairo circuit through
   the StarkWare bootloader and produces a two-level recursive STARK proof. *)

(* Expected program hashes for each circuit type.
   These must match the compiled Cairo executables used by the prover.
   Set via configuration; the values below are placeholders. *)
type circuit_config = {
  shield_program_hash : Felt.t;
  transfer_program_hash : Felt.t;
  unshield_program_hash : Felt.t;
  auth_domain : Felt.t;
  prover_binary : string;    (* path to tzel-prove *)
  verifier_binary : string;  (* path to tzel-verify *)
}

type circuit_type =
  | Shield
  | Transfer
  | Unshield

(* Proof bundle returned by the prover *)
type proof_bundle = {
  proof_bytes : string;
  output_preimage : Felt.t list;
}

(* Per-note witness inside a shield (recipient or producer). *)
type shield_note_witness = {
  snw_d_j : Felt.t;
  snw_rseed : Felt.t;
  snw_auth_root : Felt.t;
  snw_auth_pub_seed : Felt.t;
  snw_nk_tag : Felt.t;
}

(* Witness for the shield circuit. The shield is pool-keyed: the
   `pubkey_hash` public output is recomputed inside the circuit from
   the recipient's `(auth_domain, auth_root, auth_pub_seed, blind)`
   tuple, and the entire request payload is signed with an in-circuit
   WOTS+ signature under the recipient's auth tree. The witness exposes
   everything needed to rebuild both the recipient and producer
   commitments. *)
type shield_witness = {
  sw_auth_domain : Felt.t;
  sw_v : int64;
  sw_fee : int64;
  sw_producer_fee : int64;
  sw_recipient : shield_note_witness;
  sw_producer : shield_note_witness;
  sw_memo_ct_hash : Felt.t;
  sw_producer_memo_ct_hash : Felt.t;
}

(* Per-input witness for transfer/unshield *)
type spend_witness = {
  spw_d_j : Felt.t;
  spw_v : int64;
  spw_rseed : Felt.t;
  spw_nk_spend : Felt.t;
  spw_auth_root : Felt.t;
  spw_pos : int;
  spw_commitment_path : Felt.t array;
  spw_key_idx : int;
  spw_auth_path : Felt.t array;
  spw_wots_sig : Felt.t array;
}

(* Output witness for transfer/unshield *)
type output_witness = {
  ow_d_j : Felt.t;
  ow_v : int64;
  ow_rseed : Felt.t;
  ow_auth_root : Felt.t;
  ow_nk_tag : Felt.t;
  ow_memo_ct_hash : Felt.t;
}

(* Transfer witness *)
type transfer_witness = {
  tw_auth_domain : Felt.t;
  tw_inputs : spend_witness list;
  tw_outputs : output_witness * output_witness;
}

(* Unshield witness *)
type unshield_witness = {
  uw_auth_domain : Felt.t;
  uw_inputs : spend_witness list;
  uw_v_pub : int64;
  uw_recipient_string : string;
  uw_change : output_witness option;
}

(* JSON serialization for witness exchange *)

let felt_to_json f = `String (Felt.to_hex f)
let felt_array_to_json arr =
  `List (Array.to_list (Array.map felt_to_json arr))

let shield_note_witness_to_json (n : shield_note_witness) =
  `Assoc [
    "d_j", felt_to_json n.snw_d_j;
    "rseed", felt_to_json n.snw_rseed;
    "auth_root", felt_to_json n.snw_auth_root;
    "auth_pub_seed", felt_to_json n.snw_auth_pub_seed;
    "nk_tag", felt_to_json n.snw_nk_tag;
  ]

let shield_witness_to_json w =
  `Assoc [
    "type", `String "shield";
    "auth_domain", felt_to_json w.sw_auth_domain;
    "v", `String (Int64.to_string w.sw_v);
    "fee", `String (Int64.to_string w.sw_fee);
    "producer_fee", `String (Int64.to_string w.sw_producer_fee);
    "recipient", shield_note_witness_to_json w.sw_recipient;
    "producer", shield_note_witness_to_json w.sw_producer;
    "memo_ct_hash", felt_to_json w.sw_memo_ct_hash;
    "producer_memo_ct_hash", felt_to_json w.sw_producer_memo_ct_hash;
  ]

let spend_witness_to_json w =
  `Assoc [
    "d_j", felt_to_json w.spw_d_j;
    "v", `String (Int64.to_string w.spw_v);
    "rseed", felt_to_json w.spw_rseed;
    "nk_spend", felt_to_json w.spw_nk_spend;
    "auth_root", felt_to_json w.spw_auth_root;
    "pos", `Int w.spw_pos;
    "commitment_path", felt_array_to_json w.spw_commitment_path;
    "key_idx", `Int w.spw_key_idx;
    "auth_path", felt_array_to_json w.spw_auth_path;
    "wots_sig", felt_array_to_json w.spw_wots_sig;
  ]

let output_witness_to_json w =
  `Assoc [
    "d_j", felt_to_json w.ow_d_j;
    "v", `String (Int64.to_string w.ow_v);
    "rseed", felt_to_json w.ow_rseed;
    "auth_root", felt_to_json w.ow_auth_root;
    "nk_tag", felt_to_json w.ow_nk_tag;
    "memo_ct_hash", felt_to_json w.ow_memo_ct_hash;
  ]

let transfer_witness_to_json w =
  let (out1, out2) = w.tw_outputs in
  `Assoc [
    "type", `String "transfer";
    "auth_domain", felt_to_json w.tw_auth_domain;
    "inputs", `List (List.map spend_witness_to_json w.tw_inputs);
    "outputs", `List [output_witness_to_json out1; output_witness_to_json out2];
  ]

let unshield_witness_to_json w =
  `Assoc [
    "type", `String "unshield";
    "auth_domain", felt_to_json w.uw_auth_domain;
    "inputs", `List (List.map spend_witness_to_json w.uw_inputs);
    "v_pub", `String (Int64.to_string w.uw_v_pub);
    "recipient_string", `String w.uw_recipient_string;
    "change", (match w.uw_change with
      | Some c -> output_witness_to_json c
      | None -> `Null);
  ]

(* Parse proof bundle from prover JSON output *)
let parse_proof_bundle json_str =
  let json = Yojson.Basic.from_string json_str in
  let open Yojson.Basic.Util in
  let proof_bytes = json |> member "proof_bytes" |> to_string in
  let preimage_list = json |> member "output_preimage" |> to_list in
  let output_preimage = List.map (fun j ->
    let s = to_string j in
    let s = if String.length s > 2 && String.sub s 0 2 = "0x"
      then String.sub s 2 (String.length s - 2) else s in
    Felt.of_hex s
  ) preimage_list in
  { proof_bytes; output_preimage }

(* ── Bootloader output verification ──
   The bootloader output_preimage contains:
   - The task program hash (identifies which circuit was proved)
   - The public outputs of the circuit

   Per spec ("Executable binding"): the verifier MUST authenticate which
   circuit executable was actually proved by checking the bootloader-reported
   task program hash against the deployment's expected hashes. *)

(* Extract program hash from output_preimage.
   In the StarkWare bootloader, the output format is:
   [n_tasks=1, task_output_size, program_hash, ...public_outputs...]
   The program hash is at index 2 (0-indexed). *)
let extract_program_hash (preimage : Felt.t list) =
  match preimage with
  | _ :: _ :: ph :: _ -> Some ph
  | _ -> None

(* Extract public outputs from output_preimage (everything after program hash) *)
let extract_public_outputs (preimage : Felt.t list) =
  match preimage with
  | _ :: _ :: _ :: rest -> rest
  | _ -> []

(* Verify executable binding: check that the proved program hash matches
   the expected circuit type *)
let verify_program_hash config circuit_type preimage =
  let expected = match circuit_type with
    | Shield -> config.shield_program_hash
    | Transfer -> config.transfer_program_hash
    | Unshield -> config.unshield_program_hash
  in
  match extract_program_hash preimage with
  | None -> Error "output_preimage too short to contain program hash"
  | Some ph ->
    if Felt.equal ph expected then Ok ()
    else Error (Printf.sprintf
      "program hash mismatch: expected %s, got %s"
      (Felt.to_hex expected) (Felt.to_hex ph))

(* Verify auth_domain in public outputs for spending transactions *)
let verify_auth_domain config (public_outputs : Felt.t list) =
  match public_outputs with
  | auth_domain :: _ ->
    if Felt.equal auth_domain config.auth_domain then Ok ()
    else Error "auth_domain mismatch in public outputs"
  | [] -> Error "empty public outputs"

(* Full proof verification pipeline:
   1. Call tzel-verify to verify the STARK proof
   2. Check program hash (executable binding)
   3. Check auth_domain (for spending txs)
   4. Return the verified public outputs *)
let verify_proof config circuit_type bundle =
  (* Step 1: STARK verification via Rust binary *)
  let tmp = Filename.temp_file "tzel-proof-" ".json" in
  let json = `Assoc [
    "proof_bytes", `String bundle.proof_bytes;
    "output_preimage", `List (List.map (fun f ->
      `String ("0x" ^ Felt.to_hex f)) bundle.output_preimage);
  ] in
  let oc = open_out tmp in
  output_string oc (Yojson.Basic.to_string json);
  close_out oc;
  let cmd = Printf.sprintf "%s --proof %s --recursive 2>&1"
    config.verifier_binary tmp in
  let exit_code = Sys.command cmd in
  Sys.remove tmp;
  if exit_code <> 0 then
    Error "STARK proof verification failed"
  else
    (* Step 2: Executable binding *)
    match verify_program_hash config circuit_type bundle.output_preimage with
    | Error e -> Error e
    | Ok () ->
      let public_outputs = extract_public_outputs bundle.output_preimage in
      (* Step 3: Auth domain check for spending transactions *)
      (match circuit_type with
       | Shield -> Ok public_outputs
       | Transfer | Unshield ->
         match verify_auth_domain config public_outputs with
         | Error e -> Error e
         | Ok () -> Ok public_outputs)

(* Invoke the prover *)
let prove config ~witness_json ~recursive =
  let tmp_witness = Filename.temp_file "tzel-witness-" ".json" in
  let tmp_proof = Filename.temp_file "tzel-proof-" ".json" in
  let oc = open_out tmp_witness in
  output_string oc (Yojson.Basic.to_string witness_json);
  close_out oc;
  let recursive_flag = if recursive then "--recursive" else "" in
  let cmd = Printf.sprintf "%s --pie %s --output %s %s 2>&1"
    config.prover_binary tmp_witness tmp_proof recursive_flag in
  let exit_code = Sys.command cmd in
  Sys.remove tmp_witness;
  if exit_code <> 0 then begin
    (try Sys.remove tmp_proof with _ -> ());
    Error "prover failed"
  end else begin
    let ic = open_in tmp_proof in
    let json_str = really_input_string ic (in_channel_length ic) in
    close_in ic;
    Sys.remove tmp_proof;
    Ok (parse_proof_bundle json_str)
  end

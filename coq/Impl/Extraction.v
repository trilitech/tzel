(** * Impl.Extraction

    Coq → OCaml extraction directives.

    Realizes the abstract [Felt] type and the opaque [Hash3] /
    [pack_adrs_chain] parameters with the bit-equivalent OCaml
    protocol-port functions:

    - [Felt] → OCaml [bytes] (32-byte little-endian, matching
      [ocaml/protocol/felt.ml]).
    - [Hash3] → [Tzel.Hash.hash3] (BLAKE2s of the 96-byte
      concatenation [a || b || c], truncated to 251 bits).
    - [pack_adrs_chain] → wrapper around [Tzel.Wots.pack_adrs]
      that bakes in the [TAG_XMSS_CHAIN] domain tag and the
      trailing zero, exposing exactly the three indices the
      chain step varies over.

    The OCaml port is bit-equivalent to the Cairo
    [xmss_common::xmss_chain_step] under the existing cross-impl
    interop check, so the extracted [xmss_chain_step] driver
    matches the Cairo on the same inputs by construction. The
    forthcoming Cairo-side [run_chain_step] runner plus a
    QCheck2 differential harness will exercise that equivalence
    on randomized witnesses.

    Note: extraction writes [tzel_wots.ml] / [tzel_wots.mli] to
    [Impl/] (relative to where [rocq make] runs, which is [coq/]).
    [coq/Extracted/build.sh] then copies them into
    [ocaml/coq_driver/] alongside [main.ml] before invoking
    [dune build] — the executable links against the [tzel] library
    so the [Tzel.*] references in the realizations resolve.
*)

From Stdlib Require Extraction.
From Common Require Import Felt.
From Impl Require Import Hashes.
From Impl Require Import Wots.

Extraction Language OCaml.

(** Force the extraction output directory so the [.ml]/[.mli] files
    land alongside [Impl/Extraction.v] regardless of where [rocq
    make] is invoked from. Without this, Rocq 9 defaults to the
    current working directory and emits a [extraction-default-
    directory] warning. *)
Set Extraction Output Directory "Impl".

(** Realize [Felt] as OCaml [bytes] (32-byte buffer), matching
    [ocaml/protocol/felt.ml] in the OCaml port. *)
Extract Constant Felt => "bytes".

(** Realize [Hash3] as [Tzel.Hash.hash3] (BLAKE2s of [a || b || c],
    truncated to 251 bits). The Cairo [hash3_generic] is bit-
    equivalent to this under the cross-impl interop check; domain
    separation comes from the ADRS-encoded second argument, not a
    separate IV. *)
Extract Constant Hash3 => "Tzel.Hash.hash3".

(** Realize [pack_adrs_chain] as [Tzel.Wots.pack_adrs] specialized
    to the chain-step ADRS encoding: tag = [TAG_XMSS_CHAIN], plus
    the trailing-zero slot. The three free indices are the only
    ones the chain step actually varies over. *)
Extract Constant pack_adrs_chain =>
  "(fun key_idx chain_idx step ->
      Tzel.Wots.pack_adrs Tzel.Wots.tag_xmss_chain key_idx chain_idx step 0)".

(** Map Coq [nat] to OCaml [int] so indices don't go through
    Peano-encoded linked lists — readable extracted code, fast
    arithmetic. Standard idiom. *)
Extract Inductive nat => "int" [ "0" "Stdlib.succ" ]
  "(fun fO fS n -> if n=0 then fO () else fS (n-1))".

Extraction "tzel_wots.ml" xmss_chain_step.

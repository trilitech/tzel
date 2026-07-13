(** * Impl.Wots — extractable WOTS+ chain step (Cairo refinement)

    Mirror of the WOTS+ portion of [cairo/src/xmss_common.cairo]:

      pub fn xmss_chain_step(
        x: felt252, pub_seed: felt252,
        key_idx: u32, chain_idx: u32, step: u32,
      ) -> felt252 {
        let adrs = pack_adrs(TAG_XMSS_CHAIN, key_idx, chain_idx, step, 0);
        hash::hash3_generic(pub_seed, adrs, x)
      }

    Position in the architecture: this module is the *implementation*
    layer — the executable, extractable refinement of the abstract
    chain step in [Spec.Wots]. The Cairo source informs the structure
    here (we are allowed to look at the Cairo); the [Spec] layer is
    derived from the protocol-level documents only.

    The refinement theorem [refines_spec] below states:

      forall x p k c s,
        xmss_chain_step x p k c s
          = Spec.Wots.step Hash3 pack_adrs_chain x p k c s

    which by [Definition] expansion holds reflexively. The theorem
    is what closes the [Spec] ↔ [Impl] connection so that any
    [Spec.Wots]-level soundness lemma transfers automatically to
    the extracted code.
*)

From Common Require Import Felt.
From Impl Require Import Hashes.
From Spec Require Wots.

(** ADRS encoding of the chain-step address: [pack_adrs(TAG_XMSS_CHAIN,
    key_idx, chain_idx, step, 0)] in Cairo. Opaque here; the
    extraction maps it to [Tzel.Wots.pack_adrs] in the OCaml protocol
    port (which is bit-equivalent to the Cairo [pack_adrs] under the
    cross-impl interop check). *)
Parameter pack_adrs_chain : nat -> nat -> nat -> Felt.

(** One step of WOTS+ chain hashing. Mirrors [xmss_chain_step] in
    [cairo/src/xmss_common.cairo]:

      hash3_generic(pub_seed, pack_adrs(TAG, key_idx, chain_idx, step, 0), x)
*)
Definition xmss_chain_step
  (x pub_seed : Felt) (key_idx chain_idx step : nat) : Felt :=
  Hash3 pub_seed (pack_adrs_chain key_idx chain_idx step) x.

(** Refinement: the executable [xmss_chain_step] equals
    [Spec.Wots.step] under the realized [Hash3] and
    [pack_adrs_chain]. Trivial by [Definition] expansion — both
    sides reduce to the same hash invocation. The point of stating
    it is that any future [Spec.Wots]-level lemma about [step]
    transfers to [xmss_chain_step] by rewriting through this
    equation. *)
Theorem refines_spec :
  forall x pub_seed key_idx chain_idx step_no,
    xmss_chain_step x pub_seed key_idx chain_idx step_no =
    Spec.Wots.step Hash3 pack_adrs_chain
                   x pub_seed key_idx chain_idx step_no.
Proof. reflexivity. Qed.

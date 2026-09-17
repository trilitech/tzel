(** * Impl.Common

    Implementation-side shared declarations. The [Felt] type itself
    lives in [Common.Felt] so the [Spec] and [Impl] layers can
    reference the same type when stating refinement theorems. This
    module is a placeholder for any [Impl]-only shared declarations
    that may appear later (e.g., concrete bit-width constants).
    Empty for now. *)

From Common Require Import Felt.

(** * Impl.Hashes

    Implementation-side hash declarations, mirroring
    [cairo/src/blake_hash.cairo].

    [Hash3] is the generic 3-input hash ([blake_hash::hash3_generic]
    in Cairo) used by [xmss_chain_step] to mix [pub_seed], the
    ADRS-encoded chain index, and the running chain element.

    [Hash4] is the generic 4-input hash ([blake_hash::hash4_generic]
    in Cairo) used by the L-tree and auth-tree node computation to
    mix [pub_seed], the ADRS, and two child nodes.

    Domain separation comes from the ADRS encoding, not separate IVs.

    The [Spec] layer's hash parameters are abstract Section variables;
    the [Impl] layer here declares the concrete parameters that
    extraction realizes bit-equivalently to the Cairo.
*)

From Common Require Import Felt.

Parameter Hash3 : Felt -> Felt -> Felt -> Felt.
Parameter Hash4 : Felt -> Felt -> Felt -> Felt -> Felt.

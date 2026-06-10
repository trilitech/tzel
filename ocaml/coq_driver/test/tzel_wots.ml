
(** val length : 'a1 list -> int **)

let rec length = function
| [] -> 0
| _::l' -> Stdlib.succ (length l')

type felt = bytes

module Nat =
 struct
  (** val add : int -> int -> int **)

  let rec add n m =
    (fun fO fS n -> if n=0 then fO () else fS (n-1))
      (fun _ -> m)
      (fun p -> Stdlib.succ (add p m))
      n

  (** val mul : int -> int -> int **)

  let rec mul n m =
    (fun fO fS n -> if n=0 then fO () else fS (n-1))
      (fun _ -> 0)
      (fun p -> add m (mul p m))
      n

  (** val leb : int -> int -> bool **)

  let rec leb n m =
    (fun fO fS n -> if n=0 then fO () else fS (n-1))
      (fun _ -> true)
      (fun n' ->
      (fun fO fS n -> if n=0 then fO () else fS (n-1))
        (fun _ -> false)
        (fun m' -> leb n' m')
        m)
      n

  (** val ltb : int -> int -> bool **)

  let ltb n m =
    leb (Stdlib.succ n) m

  (** val pow : int -> int -> int **)

  let rec pow n m =
    (fun fO fS n -> if n=0 then fO () else fS (n-1))
      (fun _ -> Stdlib.succ 0)
      (fun m0 -> mul n (pow n m0))
      m
 end

(** val firstn : int -> 'a1 list -> 'a1 list **)

let rec firstn n l =
  (fun fO fS n -> if n=0 then fO () else fS (n-1))
    (fun _ -> [])
    (fun n0 -> match l with
               | [] -> []
               | a::l0 -> a::(firstn n0 l0))
    n

(** val skipn : int -> 'a1 list -> 'a1 list **)

let rec skipn n l =
  (fun fO fS n -> if n=0 then fO () else fS (n-1))
    (fun _ -> l)
    (fun n0 -> match l with
               | [] -> []
               | _::l0 -> skipn n0 l0)
    n

(** val sighash_fold : (felt -> felt -> felt) -> felt -> felt list -> felt **)

let rec sighash_fold h_sighash acc = function
| [] -> acc
| x::rest -> sighash_fold h_sighash (h_sighash acc x) rest

(** val hash3 : felt -> felt -> felt -> felt **)

let hash3 = Tzel.Hash.hash3

(** val hash5 : felt -> felt -> felt -> felt -> felt -> felt **)

let hash5 = Tzel.Hash.hash_commit

(** val commit : felt -> felt -> felt -> felt -> felt -> felt **)

let commit =
  hash5

(** val hash_nf : felt -> felt -> felt **)

let hash_nf = Tzel.Hash.hash_nf

(** val nullifier : felt -> felt -> felt -> felt **)

let nullifier nk_spend cm pos =
  hash_nf nk_spend (hash_nf cm pos)

(** val hash_sighash : felt -> felt -> felt **)

let hash_sighash = Tzel.Hash.hash_sighash

(** val sighash_fold0 : felt -> felt list -> felt **)

let sighash_fold0 acc fields =
  sighash_fold hash_sighash acc fields

(** val pack_adrs_chain : int -> int -> int -> felt **)

let pack_adrs_chain = (fun key_idx chain_idx step ->
      Tzel.Wots.pack_adrs Tzel.Wots.tag_xmss_chain key_idx chain_idx step 0)

(** val xmss_chain_step : felt -> felt -> int -> int -> int -> felt **)

let xmss_chain_step x pub_seed key_idx chain_idx step =
  hash3 pub_seed (pack_adrs_chain key_idx chain_idx step) x

(** val merkle_step :
    (felt -> felt -> felt) -> bool -> felt -> felt -> felt **)

let merkle_step h bit current sibling =
  if bit then h sibling current else h current sibling

(** val merkle_root :
    (felt -> felt -> felt) -> bool list -> felt list -> felt -> felt **)

let rec merkle_root h bits siblings leaf =
  match bits with
  | [] -> leaf
  | b::bs ->
    (match siblings with
     | [] -> leaf
     | s::ss -> merkle_root h bs ss (merkle_step h b leaf s))

(** val hash2_merkle : felt -> felt -> felt **)

let hash2_merkle = Tzel.Hash.hash_merkle

(** val merkle_compute_root : bool list -> felt list -> felt -> felt **)

let merkle_compute_root bits siblings leaf =
  merkle_root hash2_merkle bits siblings leaf

(** val zero_hash : ('a1 -> 'a1 -> 'a1) -> 'a1 -> int -> 'a1 **)

let rec zero_hash h z0 h0 =
  (fun fO fS n -> if n=0 then fO () else fS (n-1))
    (fun _ -> z0)
    (fun h' -> h (zero_hash h z0 h') (zero_hash h z0 h'))
    h0

(** val build_level : ('a1 -> 'a1 -> 'a1) -> 'a1 list -> 'a1 list **)

let rec build_level h = function
| [] -> []
| a::l0 -> (match l0 with
            | [] -> []
            | b::r -> (h a b)::(build_level h r))

(** val fold_levels : ('a1 -> 'a1 -> 'a1) -> int -> 'a1 list -> 'a1 list **)

let rec fold_levels h h0 l =
  (fun fO fS n -> if n=0 then fO () else fS (n-1))
    (fun _ -> l)
    (fun h' -> fold_levels h h' (build_level h l))
    h0

(** val root_of : ('a1 -> 'a1 -> 'a1) -> 'a1 -> int -> 'a1 list -> 'a1 **)

let root_of h z0 h0 l =
  match fold_levels h h0 l with
  | [] -> z0
  | x::_ -> x

(** val mroot : ('a1 -> 'a1 -> 'a1) -> 'a1 -> int -> 'a1 list -> 'a1 **)

let rec mroot h z0 d leaves =
  (fun fO fS n -> if n=0 then fO () else fS (n-1))
    (fun _ -> match leaves with
              | [] -> z0
              | x::_ -> x)
    (fun d' ->
    h
      (mroot h z0 d'
        (firstn (Nat.pow (Stdlib.succ (Stdlib.succ 0)) d') leaves))
      (mroot h z0 d'
        (skipn (Nat.pow (Stdlib.succ (Stdlib.succ 0)) d') leaves)))
    d

(** val tdfront :
    ('a1 -> 'a1 -> 'a1) -> 'a1 -> int -> 'a1 list -> 'a1 -> 'a1 **)

let rec tdfront h z0 d pre cm =
  (fun fO fS n -> if n=0 then fO () else fS (n-1))
    (fun _ -> cm)
    (fun d' ->
    if Nat.ltb (length pre) (Nat.pow (Stdlib.succ (Stdlib.succ 0)) d')
    then h (tdfront h z0 d' pre cm) (zero_hash h z0 d')
    else h
           (mroot h z0 d'
             (firstn (Nat.pow (Stdlib.succ (Stdlib.succ 0)) d') pre))
           (tdfront h z0 d'
             (skipn (Nat.pow (Stdlib.succ (Stdlib.succ 0)) d') pre) cm))
    d

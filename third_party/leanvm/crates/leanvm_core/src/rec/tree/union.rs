//! The union of claim sets in rows: a node reads its children's sets, declares a set of their claims, and proves
//! every declared claim is one of theirs.
//!
//! Each side is a pool of items, each item one compression of a set's written form ([`super::multiset`]):
//!
//! - The children's pool holds one run per child, in order, each starting at a chunk's first item; a run is its
//!   child's items, then padding to its last chunk's end. The declared pool holds one run, the node's set.
//! - Each item's kind (header, members, end, padding) and whether its second member is one are hinted bits, which
//!   give its counter word. A set's counters say what each item is, so the chain of a run equals its set's digest
//!   only if its bits are those of the set's own written form, and the run is read as that set.
//! - Every run's end item holds the digest of its run, and the run's place says whose: a one-hot over the children,
//!   moved on at each chunk that begins a run. So once the begin bits place the runs, a pool's contents are fixed by
//!   the digests.
//! - Each child claim has a selection bit, attached to its place in the pool. A challenge point `(X, A)` is drawn
//!   from a transcript of the children's digests, the node's, and the begin and selection words, so the runs'
//!   places and the selections are fixed before it, and the rows check
//!
//!   ```text
//!   prod over child slots (1 + s · valid · (X + 1 + fp(c)))  ==  prod over declared slots (1 + valid · (X + 1 + fp(d)))
//!   fp(t) = sum over k < 16 of eq(A, k) · t[k],   t = (1, label[0..6], member[0..4], 0, ...)
//!   ```
//!
//!   which holds at a random point only if the selected child claims and the declared claims are one multiset.
//!   A claim's tuple carries its label, so a member can only back a declared claim of its own label.
//!
//! A run's label fingerprint is reset at its start, so a set read at any place in a pool is read the same way.

use super::multiset::{Capacity, Claim, ClaimSet, Item, code};
use crate::rec::circuit::{Builder, Dw, Ew, Kw, PARAM_IV};
use crate::rec::transcript::{ProofSource, Transcript};
use crate::rv::Hash;
use fiat_shamir::SessionId;
use primitives::field::F192;
use std::collections::HashMap;

/// Items in a chunk: a run starts only at a chunk's first item.
pub(crate) const CHUNK: usize = 32;

/// The tag of the union's transcript's session, beside the tree's.
const SESSION_TAG: &[u8] = b"leanvm-claim-union-3";

/// A pool's size, in chunks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PoolShape {
    /// Its chunks.
    pub(crate) chunks: usize,
}

/// What a node's union reads and declares: its children's pool, shared by its `arity` runs, and its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct UnionShape {
    /// The children.
    pub(crate) arity: usize,
    /// The children's pool.
    pub(crate) children: PoolShape,
    /// The declared pool.
    pub(crate) declared: PoolShape,
    /// Whether a child may be absent, its run then the empty set's.
    pub(crate) optional: bool,
}

/// What an item is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ItemKind {
    /// A group's header.
    Header,
    /// A block of members, the second one a member if `pair`.
    Members {
        /// Whether the second member is one.
        pair: bool,
    },
    /// A set's end.
    End,
    /// Padding after a run's end.
    Pad,
}

/// One item as a prover fills it.
#[derive(Clone, Copy, Debug)]
struct FillItem {
    block: [u64; 8],
    kind: ItemKind,
    /// Whether each member slot is selected.
    select: [bool; 2],
}

/// A pool's values, as its prover fills it.
#[derive(Clone, Debug)]
pub(crate) struct PoolFill {
    items: Vec<FillItem>,
    /// Whether each chunk begins a run, the first chunk's unread.
    begins: Vec<bool>,
}

/// A union's values, as its prover fills it.
#[derive(Clone, Debug)]
pub(crate) struct UnionFill {
    children: PoolFill,
    declared: PoolFill,
    /// The declared set's digest.
    digest: [u64; 4],
    /// Whether each child is absent.
    absent: Vec<bool>,
}

/// Why a union cannot be filled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FillError {
    /// The children's sets do not fit the children's pool.
    Children,
    /// The declared set does not fit the declared pool.
    Declared,
    /// A declared claim no child holds, past those already taken.
    NotCovered(Claim),
}

/// The wires of one item the products read.
struct ItemWires {
    /// The block's words.
    m: [Kw; 8],
    /// One for a block of members.
    is_members: Ew,
    /// One for a block of two members.
    is_pair: Ew,
    /// Zero for a header.
    not_header: Ew,
    /// Whether the item starts a run: a constant at the pool's first item, a begin bit at a chunk's first.
    start: Start,
    /// The member slots' selection bits, on the children's side.
    select: Option<[Kw; 2]>,
}

/// Whether an item starts a run.
#[derive(Clone, Copy)]
enum Start {
    /// It never does.
    No,
    /// It always does: the pool's first item.
    Yes,
    /// If this bit is set: a chunk's first item.
    If(Kw),
}

/// The challenge point.
struct Point {
    /// `X + 1`.
    x1: Ew,
    /// `eq(A, k)` for each tuple slot `k`.
    weights: [Ew; 16],
}

impl ItemKind {
    /// The kind of an item of a set's written form.
    const fn of(item: &Item) -> Self {
        if item.code & code::END != 0 {
            Self::End
        } else if item.code & code::MEMBER != 0 {
            Self::Members {
                pair: item.code & code::PAIR != 0,
            }
        } else {
            Self::Header
        }
    }

    /// Its hinted bits: `b0`, `b1` (header 00, members 10, end 01, padding 11), then whether its second member is one.
    const fn bits(self) -> [bool; 3] {
        match self {
            Self::Header => [false, false, false],
            Self::Members { pair } => [true, false, pair],
            Self::End => [false, true, false],
            Self::Pad => [true, true, false],
        }
    }
}

impl PoolShape {
    /// A pool of runs together of at most `items` items: each run's last chunk wastes less than a chunk.
    pub(crate) const fn new(items: usize, runs: usize) -> Self {
        Self {
            chunks: items.div_ceil(CHUNK) + runs,
        }
    }

    /// Its items.
    pub(crate) const fn items(self) -> usize {
        self.chunks * CHUNK
    }
}

impl UnionShape {
    /// The union of `arity` children whose sets together are within `capacity`, declaring a set within it.
    pub(crate) const fn new(capacity: Capacity, arity: usize) -> Self {
        Self {
            arity,
            // Each child's set has its own end item; the capacity's count has one.
            children: PoolShape::new(capacity.items() + arity - 1, arity),
            declared: PoolShape::new(capacity.items(), 1),
            optional: false,
        }
    }

    /// The same union of at most `arity` children, the rest absent.
    ///
    /// An absent child's run is the empty set's one item, within the chunk its run already has.
    pub(crate) const fn optional(capacity: Capacity, arity: usize) -> Self {
        Self {
            optional: true,
            ..Self::new(capacity, arity)
        }
    }
}

impl PoolFill {
    /// A pool holding these sets, one run each, in order.
    fn new(shape: PoolShape, sets: &[&ClaimSet]) -> Option<Self> {
        let mut items = Vec::with_capacity(shape.items());
        let mut begins = vec![false; shape.chunks];
        let pad = FillItem {
            block: [0; 8],
            kind: ItemKind::Pad,
            select: [false; 2],
        };
        for (r, set) in sets.iter().enumerate() {
            if r > 0 {
                items.resize(items.len().next_multiple_of(CHUNK), pad);
                *begins.get_mut(items.len() / CHUNK)? = true;
            }
            items.extend(set.items().iter().map(|item| FillItem {
                block: item.block,
                kind: ItemKind::of(item),
                select: [false; 2],
            }));
        }
        if items.len() > shape.items() {
            return None;
        }
        items.resize(shape.items(), pad);
        Some(Self { items, begins })
    }

    /// Every member slot's claim, by item and slot, as the rows read them.
    fn slots(&self) -> Vec<(usize, usize, Claim)> {
        let mut slots = Vec::new();
        let mut label: Option<[u64; 6]> = None;
        for (i, item) in self.items.iter().enumerate() {
            if i % CHUNK == 0 && (i == 0 || self.begins[i / CHUNK]) {
                label = None;
            }
            let m = item.block;
            match item.kind {
                ItemKind::Header => label = Some([m[0], m[1], m[2], m[3], m[4], m[5]]),
                ItemKind::Members { pair } => {
                    if let Some(label) = label {
                        for slot in 0..1 + usize::from(pair) {
                            let member = std::array::from_fn(|j| m[4 * slot + j]);
                            slots.push((i, slot, Claim { label, member }));
                        }
                    }
                }
                ItemKind::End | ItemKind::Pad => {}
            }
        }
        slots
    }
}

impl UnionFill {
    /// The union's values: the children's sets, and the declared set, each of whose claims some child slot backs.
    ///
    /// With fewer sets than the shape's arity, the rest of its children are absent, which an optional shape allows.
    pub(crate) fn new(shape: &UnionShape, children: &[&ClaimSet], declared: &ClaimSet) -> Result<Self, FillError> {
        Self::fill(shape, children, declared, true)
    }

    /// The union's values with each declared claim some child slot backs selected, the others left unbacked: what
    /// a prover forging coverage would hand the rows.
    #[cfg(test)]
    pub(crate) fn unbacked(shape: &UnionShape, children: &[&ClaimSet], declared: &ClaimSet) -> Self {
        Self::fill(shape, children, declared, false).expect("the sets fit")
    }

    /// The union's values, refusing a claim no child slot backs if `strict`, else leaving it unbacked.
    fn fill(shape: &UnionShape, children: &[&ClaimSet], declared: &ClaimSet, strict: bool) -> Result<Self, FillError> {
        assert!(
            children.len() == shape.arity || (shape.optional && children.len() <= shape.arity),
            "one set a child, but for an optional shape's absent ones"
        );
        let empty = ClaimSet::new();
        let absent: Vec<bool> = (0..shape.arity).map(|r| r >= children.len()).collect();
        let runs: Vec<&ClaimSet> = (0..shape.arity)
            .map(|r| children.get(r).copied().unwrap_or(&empty))
            .collect();
        let mut child = PoolFill::new(shape.children, &runs).ok_or(FillError::Children)?;
        let declared_pool = PoolFill::new(shape.declared, &[declared]).ok_or(FillError::Declared)?;
        let mut free: HashMap<Claim, Vec<(usize, usize)>> = HashMap::new();
        for (i, slot, claim) in child.slots().into_iter().rev() {
            free.entry(claim).or_default().push((i, slot));
        }
        for claim in declared.claims() {
            match free.get_mut(&claim).and_then(Vec::pop) {
                Some((i, slot)) => child.items[i].select[slot] = true,
                None if strict => return Err(FillError::NotCovered(claim)),
                None => {}
            }
        }
        Ok(Self {
            children: child,
            declared: declared_pool,
            digest: declared.digest(),
            absent,
        })
    }

    /// The same values with child `index` read as absent, its run left as it was: what a prover dropping a present
    /// child's set while keeping its claims would hand the rows.
    #[cfg(test)]
    pub(crate) fn absent_at(mut self, index: usize) -> Self {
        self.absent[index] = true;
        self
    }
}

/// The session of a union's transcript, under the tree's.
pub(crate) fn session(tree: &SessionId) -> SessionId {
    SessionId::new(&[SESSION_TAG, &tree.0].concat())
}

/// A pool's wires before any challenge: its items, and the hinted bits the transcript must hold, packed in words.
struct PoolWires {
    /// The items.
    items: Vec<ItemWires>,
    /// The begin bits, which place the runs.
    begins: Vec<Kw>,
    /// The selection bits, when selecting.
    selections: Vec<Kw>,
}

/// A pool's rows before any challenge: each item's compression, its kind and the run it belongs to.
///
/// The begin bits place each run, and the selection bits attach to places, so both go into the transcript: the
/// rest of the pool is fixed by the digests once the runs are placed.
fn pool_rows(b: &mut Builder, shape: PoolShape, digests: &[Dw], fill: Option<&PoolFill>, selecting: bool) -> PoolWires {
    let runs = digests.len();
    assert!(runs >= 1 && runs <= shape.chunks, "a run a chunk at most");
    let (zero, one) = (b.zero(), b.one());
    let k_zero = b.k_const(0);
    let [iv_lo, iv_hi] = [
        F192::new(PARAM_IV[0], PARAM_IV[1], 0),
        F192::new(PARAM_IV[2], PARAM_IV[3], 0),
    ]
    .map(|v| b.e_const(v));
    let [c_member, c_end, c_pair] = [code::MEMBER, code::END, code::PAIR].map(|c| b.e_const(F192::new(c, 0, 0)));
    let c_final = b.e_const(F192::new(0, Hash::FINAL, 0));
    let halves: Vec<[Ew; 2]> = digests.iter().map(|&d| b.d_to_halves(d)).collect();

    // The run the current chunk belongs to, one-hot over the runs.
    let mut current: Vec<Ew> = (0..runs).map(|r| if r == 0 { one } else { zero }).collect();
    let mut bits: Vec<Kw> = Vec::new();
    let mut begins: Vec<Kw> = Vec::new();
    let mut selections: Vec<Kw> = Vec::new();
    let mut items = Vec::with_capacity(shape.items());
    let mut previous: Option<(Ew, [Ew; 2], Dw)> = None;
    for j in 0..shape.chunks {
        let begin = (j > 0 && runs > 1).then(|| {
            let bit = b.free_k(u64::from(fill.is_some_and(|f| f.begins[j])));
            begins.push(bit);
            bit
        });
        if let Some(bit) = begin {
            current = (0..runs)
                .map(|r| {
                    let moved = if r == 0 { zero } else { current[r - 1] };
                    let diff = b.add(moved, current[r]);
                    b.mul_k_add(diff, bit, current[r])
                })
                .collect();
        }
        // The digest the run's end item must have.
        let expected: [Ew; 2] = if runs == 1 {
            halves[0]
        } else {
            std::array::from_fn(|h| (0..runs).fold(zero, |acc, r| b.mul_add(current[r], halves[r][h], acc)))
        };
        for k in 0..CHUNK {
            let i = j * CHUNK + k;
            let item = fill.map(|f| f.items[i]);
            let [b0, b1, pair] = item
                .map_or([false; 3], |it| it.kind.bits())
                .map(|x| b.free_k(u64::from(x)));
            bits.extend([b0, b1, pair]);
            let e0 = b.mul_k_add(one, b0, zero);
            let e1 = b.mul_k_add(one, b1, zero);
            let is_pad = b.mul_k_add(e0, b1, zero);
            let is_members = b.add(e0, is_pad);
            let is_end = b.add(e1, is_pad);
            let either = b.add(e0, e1);
            let not_header = b.add(either, is_pad);
            // The second member only in a block of members.
            let e_pair = b.mul_k_add(one, pair, zero);
            let is_pair = b.mul_k_add(is_members, pair, zero);
            b.eq_e(e_pair, is_pair);

            let start = match (i, k, begin) {
                (0, ..) => Start::Yes,
                (_, 0, Some(bit)) => Start::If(bit),
                _ => Start::No,
            };
            // Padding follows a run's end or padding, and only within the run; a run starts after its last.
            let start_e = match (start, previous) {
                (Start::Yes, _) => {
                    b.eq_e(is_pad, zero);
                    one
                }
                (Start::If(bit), Some((ended, ..))) => {
                    let e_bit = b.mul_k_add(one, bit, zero);
                    let after_end = b.mul(ended, e_bit);
                    b.eq_e(after_end, e_bit);
                    let pad = b.add(ended, e_bit);
                    b.eq_e(is_pad, pad);
                    e_bit
                }
                (_, Some((ended, ..))) => {
                    b.eq_e(is_pad, ended);
                    zero
                }
                (_, None) => unreachable!("only the first item has none before it"),
            };

            // The counter word: its kind's bits, and the finalization word of an end.
            let t = b.mul_k_add(c_member, b0, start_e);
            let t = b.mul_k_add(c_end, b1, t);
            let t = b.mul_k_add(c_pair, pair, t);
            let t = b.mul_add(c_final, is_end, t);
            let [t, f, _] = b.e_to_k(t);
            let tf = b.k_to_d([t, f, k_zero, k_zero]);

            // The chaining value: the parameter IV at a run's start, the previous output within it.
            let h = match (start, previous) {
                (Start::Yes, _) => b.d_const(PARAM_IV),
                (Start::If(bit), Some((_, [lo, hi], _))) => {
                    let d_lo = b.add(lo, iv_lo);
                    let d_hi = b.add(hi, iv_hi);
                    let lo = b.mul_k_add(d_lo, bit, lo);
                    let hi = b.mul_k_add(d_hi, bit, hi);
                    b.halves_to_d(lo, hi)
                }
                (_, Some((.., out))) => out,
                (_, None) => unreachable!("only the first item has none before it"),
            };
            let m: [Kw; 8] = std::array::from_fn(|w| b.free_k(item.map_or(0, |it| it.block[w])));
            let out = b.block(h, m, tf);
            let out_halves = b.d_to_halves(out);

            // A run's end holds its run's digest.
            for (&o, &e) in out_halves.iter().zip(&expected) {
                let diff = b.add(o, e);
                let held = b.mul(is_end, diff);
                b.eq_e(held, zero);
            }

            let select = selecting.then(|| {
                let s = item.map_or([false; 2], |it| it.select).map(|x| b.free_k(u64::from(x)));
                selections.extend(s);
                s
            });
            items.push(ItemWires {
                m,
                is_members,
                is_pair,
                not_header,
                start,
                select,
            });
            previous = Some((e1, out_halves, out));
        }
    }
    // The pool ends after an end or padding, in its last run.
    let (ended, ..) = previous.expect("a pool has items");
    b.eq_e(ended, one);
    for (r, &c) in current.iter().enumerate() {
        b.eq_e_const(c, F192::new(u64::from(r + 1 == runs), 0, 0));
    }
    // The hinted bits are bits; the begin and selection bits' words are kept for the transcript.
    for chunk in bits.chunks(64) {
        b.pack(chunk);
    }
    let mut words = |bits: &[Kw]| bits.chunks(64).map(|chunk| b.pack(chunk)).collect();
    PoolWires {
        items,
        begins: words(&begins),
        selections: words(&selections),
    }
}

/// The product over a pool's claims of `1 + s · valid · (X + 1 + fp)`, `s` a slot's selection bit or one.
fn product(b: &mut Builder, items: &[ItemWires], point: &Point) -> Ew {
    let (zero, one) = (b.zero(), b.one());
    let w = &point.weights;
    let mut label = zero;
    let mut product = one;
    for item in items {
        label = match item.start {
            Start::Yes => zero,
            Start::If(bit) => b.mul_k_add(label, bit, label),
            Start::No => label,
        };
        // The fingerprint's label part, were the item a header: the tag, then the label's words.
        let header = (0..6).fold(w[0], |acc, j| b.mul_k_add(w[1 + j], item.m[j], acc));
        let diff = b.add(header, label);
        label = b.mul_add(item.not_header, diff, header);
        for (slot, valid) in [item.is_members, item.is_pair].into_iter().enumerate() {
            let fp = (0..4).fold(label, |acc, j| b.mul_k_add(w[7 + j], item.m[4 * slot + j], acc));
            let term = b.add(point.x1, fp);
            let factor = match item.select {
                Some(select) => {
                    let held = b.mul(valid, term);
                    b.mul_k_add(held, select[slot], one)
                }
                None => b.mul_add(valid, term, one),
            };
            product = b.mul(product, factor);
        }
    }
    product
}

/// `eq(A, k)` for each `k < 16`, bit `j` of `k` choosing `A_j` over `1 + A_j`.
fn eq_weights(b: &mut Builder, a: [Ew; 4]) -> [Ew; 16] {
    let one = b.one();
    let mut table = vec![one];
    for &aj in &a {
        let not = b.add(aj, one);
        let low: Vec<Ew> = table.iter().map(|&x| b.mul(x, not)).collect();
        let high: Vec<Ew> = table.iter().map(|&x| b.mul(x, aj)).collect();
        table = [low, high].concat();
    }
    table.try_into().expect("sixteen weights")
}

/// The union's rows: the children's sets read from their digests, the declared set's digest, and the product check
/// that every declared claim is a selected child claim.
///
/// Where the shape lets a child be absent, a hinted bit per child says whether it is; an absent child's run is the
/// empty set, whatever its digest, so a node of fewer children than its arity verifies a repeat in each absent place
/// and reads nothing of it.
///
/// Returns the declared set's digest.
pub(crate) fn union_rows(
    b: &mut Builder,
    shape: &UnionShape,
    session: &SessionId,
    children: &[Dw],
    fill: Option<&UnionFill>,
) -> Dw {
    assert_eq!(children.len(), shape.arity, "one digest a child");
    // Where a child may be absent, its bit, packed into words the challenge binds, picks the digest read.
    let (read, absent): (Vec<Dw>, Vec<Kw>) = if shape.optional {
        let empty = ClaimSet::new().digest();
        let [e_lo, e_hi] = [F192::new(empty[0], empty[1], 0), F192::new(empty[2], empty[3], 0)].map(|v| b.e_const(v));
        let bits: Vec<Kw> = (0..shape.arity)
            .map(|r| b.free_k(u64::from(fill.is_some_and(|f| f.absent[r]))))
            .collect();
        // The bits are bits, and their words are bound.
        let words = bits.chunks(64).map(|chunk| b.pack(chunk)).collect();
        let read = (children.iter().zip(&bits))
            .map(|(&d, &absent)| {
                let [lo, hi] = b.d_to_halves(d);
                let d_lo = b.add(lo, e_lo);
                let d_hi = b.add(hi, e_hi);
                let lo = b.mul_k_add(d_lo, absent, lo);
                let hi = b.mul_k_add(d_hi, absent, hi);
                b.halves_to_d(lo, hi)
            })
            .collect();
        (read, words)
    } else {
        (children.to_vec(), Vec::new())
    };
    let digest = b.free_d(fill.map_or([0; 4], |f| f.digest));
    let pool = b.scope("children's pool", |b| {
        pool_rows(b, shape.children, &read, fill.map(|f| &f.children), true)
    });
    let declared = b.scope("declared pool", |b| {
        pool_rows(b, shape.declared, &[digest], fill.map(|f| &f.declared), false)
    });
    let point = challenge(b, session, &read, digest, &absent, &[&pool, &declared]);
    b.scope("coverage", |b| {
        let selected = product(b, &pool.items, &point);
        let declared = product(b, &declared.items, &point);
        b.eq_e(selected, declared);
    });
    digest
}

/// The challenge point, drawn from a transcript of everything that decides which claims the products read: the sets
/// the children's pool reads (an absent child's the empty set's), the node's, the absent bits' words, and the pools'
/// begin and selection words.
fn challenge(
    b: &mut Builder,
    session: &SessionId,
    read: &[Dw],
    digest: Dw,
    absent: &[Kw],
    pools: &[&PoolWires],
) -> Point {
    let mut instance = Vec::new();
    for &d in read.iter().chain([&digest]) {
        instance.extend(b.d_to_k(d));
    }
    instance.extend(absent);
    for pool in pools {
        instance.extend(&pool.begins);
        instance.extend(&pool.selections);
    }
    let mut t = Transcript::new(b, &self::session(session), &instance, ProofSource::Shape);
    let x = t.verifier_message(b);
    let a = std::array::from_fn(|_| t.verifier_message(b));
    let one = b.one();
    Point {
        x1: b.add(x, one),
        weights: eq_weights(b, a),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rec::circuit::Unsatisfied;
    use crate::rec::tree::multiset::ClaimGroup;

    fn member(i: u64) -> [u64; 4] {
        [i, 3 * i + 1, i << 7, 0xabcd ^ i]
    }

    fn group(tag: u64, word: u64, members: &[u64]) -> ClaimGroup {
        ClaimGroup {
            label: [tag, word, 1, 2, 3, 4],
            members: members.iter().map(|&i| member(i)).collect(),
        }
    }

    /// Two overlapping children, written out of canonical order.
    fn children() -> [ClaimSet; 2] {
        [
            ClaimSet {
                groups: vec![group(1, 5, &[1, 2, 3]), group(1, 2, &[1])],
            },
            ClaimSet {
                groups: vec![group(1, 5, &[3, 4]), group(1, 7, &[2]), group(2, 0, &[9])],
            },
        ]
    }

    const CAPACITY: Capacity = Capacity { claims: 24, groups: 6 };

    fn union_of(sets: &[ClaimSet]) -> ClaimSet {
        ClaimSet::from_claims(sets.iter().flat_map(ClaimSet::claims))
    }

    /// The union's rows over these children and fill, and the checks that failed; the declared digest must be
    /// that of `expected`.
    fn run(sets: &[ClaimSet], fill: &UnionFill, expected: Option<&ClaimSet>) -> Vec<Unsatisfied> {
        run_shape(&UnionShape::new(CAPACITY, sets.len()), sets, fill, expected)
    }

    /// The same, of a given shape, each child's digest its set's.
    fn run_shape(
        shape: &UnionShape,
        sets: &[ClaimSet],
        fill: &UnionFill,
        expected: Option<&ClaimSet>,
    ) -> Vec<Unsatisfied> {
        let mut b = Builder::new();
        let digests: Vec<Dw> = sets.iter().map(|s| b.free_d(s.digest())).collect();
        let d = union_rows(&mut b, shape, &SessionId([7; 32]), &digests, Some(fill));
        if let Some(e) = expected {
            assert_eq!(b.d(d), e.digest());
        }
        b.finish().failures
    }

    fn fill(sets: &[ClaimSet], declared: &ClaimSet) -> UnionFill {
        let refs: Vec<&ClaimSet> = sets.iter().collect();
        UnionFill::new(&UnionShape::new(CAPACITY, sets.len()), &refs, declared).expect("covered")
    }

    #[test]
    fn the_union_of_overlapping_children_holds() {
        let sets = children();
        let union = union_of(&sets);
        assert_eq!(union.n_claims(), 7, "the shared claim is one");
        assert_eq!(run(&sets, &fill(&sets, &union), Some(&union)), vec![]);
    }

    #[test]
    fn a_node_may_declare_less_or_nothing() {
        let sets = children();
        let one_group = ClaimSet {
            groups: vec![group(1, 5, &[1, 4])],
        };
        for declared in [one_group, ClaimSet::new()] {
            assert_eq!(run(&sets, &fill(&sets, &declared), Some(&declared)), vec![]);
        }
    }

    #[test]
    fn repeated_and_empty_children_hold() {
        let [a, _] = children();
        let sets = [a.clone(), ClaimSet::new(), a.clone()];
        assert_eq!(run(&sets, &fill(&sets, &a), Some(&a)), vec![]);
    }

    #[test]
    fn absent_children_read_nothing() {
        let [a, b] = children();
        let shape = UnionShape::optional(CAPACITY, 3);
        // Two children present, the third a repeat of the first, absent: its set is not read.
        let sets = [a.clone(), b.clone(), a.clone()];
        let union = union_of(&[a.clone(), b.clone()]);
        let honest = UnionFill::new(&shape, &[&a, &b], &union).expect("covered");
        assert_eq!(run_shape(&shape, &sets, &honest, Some(&union)), vec![]);
        // A present child's run read as absent: its run is not the empty set's.
        let dropped = UnionFill::new(&shape, &[&a, &b], &union).expect("covered").absent_at(1);
        assert!(!run_shape(&shape, &sets, &dropped, Some(&union)).is_empty());
        // A claim only an absent child holds backs nothing.
        assert!(matches!(
            UnionFill::new(&shape, &[&a], &union),
            Err(FillError::NotCovered(_))
        ));
        let forged = UnionFill::unbacked(&shape, &[&a], &union);
        let failures = run_shape(&shape, &sets, &forged, Some(&union));
        assert!(
            failures.iter().any(|f| f.scope().iter().any(|s| s == "coverage")),
            "{failures:?}"
        );
    }

    #[test]
    fn a_shape_is_the_same_circuit() {
        let sets = children();
        let shape = UnionShape::new(CAPACITY, 2);
        let build = |fill: Option<&UnionFill>| {
            let mut b = Builder::new();
            let digests: Vec<Dw> = sets.iter().map(|s| b.free_d(s.digest())).collect();
            union_rows(&mut b, &shape, &SessionId([7; 32]), &digests, fill);
            b.finish().circuit
        };
        assert_eq!(build(None), build(Some(&fill(&sets, &union_of(&sets)))));
    }

    #[test]
    fn an_uncovered_claim_is_refused() {
        let sets = children();
        let mut declared = union_of(&sets);
        declared.groups[0].members.push(member(99));
        let refs: Vec<&ClaimSet> = sets.iter().collect();
        let shape = UnionShape::new(CAPACITY, 2);
        assert!(matches!(
            UnionFill::new(&shape, &refs, &declared),
            Err(FillError::NotCovered(c)) if c.member == member(99)
        ));
        // Handed to the rows anyway, the product refuses it.
        let forged = UnionFill::unbacked(&shape, &refs, &declared);
        assert!(!run(&sets, &forged, Some(&declared)).is_empty());
        // A member at another label is another claim.
        let moved = ClaimSet {
            groups: vec![group(1, 2, &[2])],
        };
        assert!(matches!(
            UnionFill::new(&shape, &refs, &moved),
            Err(FillError::NotCovered(_))
        ));
        // Children past the pool.
        let big = ClaimSet {
            groups: vec![group(1, 1, &(0..100).collect::<Vec<_>>())],
        };
        assert_eq!(
            UnionFill::new(&shape, &[&big, &big], &ClaimSet::new()).err(),
            Some(FillError::Children)
        );
    }

    /// The honest fill of the union, then forged.
    fn forged(forge: impl FnOnce(&mut UnionFill)) -> Vec<Unsatisfied> {
        let sets = children();
        let mut f = fill(&sets, &union_of(&sets));
        forge(&mut f);
        run(&sets, &f, None)
    }

    /// The declared pool of `set`, with its digest.
    fn declare(f: &mut UnionFill, set: &ClaimSet) {
        f.declared = PoolFill::new(UnionShape::new(CAPACITY, 2).declared, &[set]).expect("fits");
        f.digest = set.digest();
    }

    /// A change to an honest fill, by name.
    type Forge = (&'static str, Box<dyn FnOnce(&mut UnionFill)>);

    #[test]
    fn forged_coverage_is_refused() {
        let cases: Vec<Forge> = vec![
            (
                "a declared member changed",
                Box::new(|f| {
                    let i = (f.declared.items.iter()).position(|it| matches!(it.kind, ItemKind::Members { .. }));
                    f.declared.items[i.expect("a block of members")].block[0] ^= 1;
                }),
            ),
            (
                "a declared member changed, the digest with it",
                Box::new(|f| {
                    let mut set = union_of(&children());
                    set.groups[0].members[0][0] ^= 1;
                    declare(f, &set);
                }),
            ),
            (
                "a declared claim at another label",
                Box::new(|f| {
                    let mut set = union_of(&children());
                    let m = set.groups[0].members.pop().expect("a member");
                    set.groups[1].members.push(m);
                    set.groups[1].members.sort_unstable();
                    declare(f, &set);
                }),
            ),
            (
                "a claim declared twice, selected once",
                Box::new(|f| {
                    let mut set = union_of(&children());
                    let m = set.groups[0].members[0];
                    set.groups[0].members.push(m);
                    declare(f, &set);
                }),
            ),
            (
                "a selected slot unselected",
                Box::new(|f| {
                    let it = (f.children.items.iter_mut())
                        .find(|it| it.select[0])
                        .expect("a selection");
                    it.select[0] = false;
                }),
            ),
            (
                "a padding slot backing a declared claim",
                Box::new(|f| {
                    // The half block of member 3 at (1, 5) pads with zeros: declare a zero member, select the padding.
                    let mut set = union_of(&children());
                    let at = (set.groups.iter()).position(|g| g.label == group(1, 5, &[]).label);
                    set.groups[at.expect("the group")].members.insert(0, [0; 4]);
                    declare(f, &set);
                    let it = (f.children.items.iter_mut())
                        .find(|it| it.kind == ItemKind::Members { pair: false })
                        .expect("a half block");
                    it.select[1] = true;
                }),
            ),
            (
                "a child's pair bit dropped",
                Box::new(|f| {
                    let it = (f.children.items.iter_mut())
                        .find(|it| it.kind == ItemKind::Members { pair: true })
                        .expect("a full block");
                    it.kind = ItemKind::Members { pair: false };
                    it.select[1] = false;
                }),
            ),
            (
                "a header read as members",
                Box::new(|f| {
                    f.children.items[0].kind = ItemKind::Members { pair: true };
                }),
            ),
            (
                "a run's end read as padding",
                Box::new(|f| {
                    let it = (f.children.items.iter_mut())
                        .find(|it| it.kind == ItemKind::End)
                        .expect("an end");
                    it.kind = ItemKind::Pad;
                }),
            ),
            (
                "a run begun a chunk late",
                Box::new(|f| {
                    f.children.begins[1] = false;
                    f.children.begins[2] = true;
                }),
            ),
            (
                "a child's member changed",
                Box::new(|f| {
                    let it = (f.children.items.iter_mut())
                        .find(|it| matches!(it.kind, ItemKind::Members { .. }))
                        .expect("members");
                    it.block[1] ^= 4;
                }),
            ),
        ];
        for (name, forge) in cases {
            assert!(!forged(forge).is_empty(), "{name} holds");
        }
    }

    #[test]
    fn a_run_placed_elsewhere_draws_another_challenge() {
        // A run may start at any chunk after the one before it ends, and a selection bit attaches to a place in the
        // pool. Were the runs' places chosen after the challenge, one set of selection words would select another
        // multiset at each placement, and the prover would pick among them having seen `(X, A)`. Every tier's node
        // reads its children through one of these shapes.
        let sets = children();
        let refs: Vec<&ClaimSet> = sets.iter().collect();
        for shape in [UnionShape::new(CAPACITY, 2), UnionShape::optional(CAPACITY, 2)] {
            let honest = UnionFill::new(&shape, &refs, &union_of(&sets)).expect("covered");

            // The second run a chunk later, the chunk before it padding: every row holds.
            let pad = FillItem {
                block: [0; 8],
                kind: ItemKind::Pad,
                select: [false; 2],
            };
            let mut moved = honest.clone();
            let n = moved.children.items.len();
            let tail: Vec<FillItem> = moved.children.items.drain(CHUNK..).collect();
            moved.children.items.extend(std::iter::repeat_n(pad, CHUNK));
            moved.children.items.extend(tail);
            moved.children.items.truncate(n);
            moved.children.begins[1] = false;
            moved.children.begins[2] = true;
            assert_eq!(run_shape(&shape, &sets, &moved, None), vec![]);

            // The honest places, with the moved fill's selection bits at their places: only coverage fails.
            let mut placed = honest;
            for (a, b) in placed.children.items.iter_mut().zip(&moved.children.items) {
                a.select = b.select;
            }
            let failures = run_shape(&shape, &sets, &placed, None);
            assert!(!failures.is_empty());
            assert!(
                failures.iter().all(|u| u.scope().iter().any(|s| s == "coverage")),
                "{failures:?}"
            );

            // Mutation: the two placements under one challenge.
            //
            //     same sets read, same selection words → same instance were the begin bits not in it
            //     → the prover picks the placement after the challenge
            //     the begin words are in the transcript → each placement draws its own point
            let drawn = |f: &UnionFill| {
                let mut b = Builder::new();
                // Every child is present: the sets read are the children's.
                let read: Vec<Dw> = sets.iter().map(|s| b.free_d(s.digest())).collect();
                let digest = b.free_d(f.digest);
                let pool = pool_rows(&mut b, shape.children, &read, Some(&f.children), true);
                let declared = pool_rows(&mut b, shape.declared, &[digest], Some(&f.declared), false);
                let point = challenge(&mut b, &SessionId([7; 32]), &read, digest, &[], &[&pool, &declared]);
                let words = |ws: &[Kw]| ws.iter().map(|&w| b.k(w)).collect::<Vec<u64>>();
                (words(&pool.selections), words(&pool.begins), b.e(point.x1))
            };
            let (moved, placed) = (drawn(&moved), drawn(&placed));
            assert_eq!(moved.0, placed.0, "one set of selection words");
            assert_ne!(moved.1, placed.1, "two placements");
            assert_ne!(moved.2, placed.2, "two challenges");
        }
    }
}

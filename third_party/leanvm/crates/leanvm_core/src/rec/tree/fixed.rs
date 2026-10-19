//! The nodes' fixed polynomial `W_node`: each circuit's fixed columns stacked, in the order of their kind's index.
//!
//! The circuits share their heights, so their stacks have one layout, and the kind's bits, more variables, select the circuit.

use crate::rec::fixed::{FixedColumn, FixedColumns};
use crate::rec::table::PerRecTable;
use primitives::field::F64;

/// Where each fixed column sits in one circuit's stack: the circuit's fixed polynomial over `kappa_fix` variables.
///
/// Columns are stacked largest first, each at an offset that is a multiple of its length.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FixedLayout {
    /// Each column's variables.
    taus: Vec<usize>,
    /// Each column's offset in the stack.
    offsets: Vec<usize>,
    /// The stack's variables, `kappa_fix`.
    kappa: usize,
}

impl FixedLayout {
    /// The stack of a circuit's fixed columns at the given table heights.
    pub(crate) fn new(taus: &PerRecTable<usize>) -> Self {
        let taus: Vec<usize> = (0..FixedColumn::COUNT)
            .map(|c| taus[FixedColumn::at(c).table()])
            .collect();
        let kappas: Vec<Option<usize>> = taus.iter().copied().map(Some).collect();
        let (offsets, placed) = crate::witness::stack_offsets(&kappas);
        Self {
            taus,
            offsets,
            kappa: crate::log2_ceil_usize(placed.max(1)),
        }
    }

    /// The stack's variables.
    pub(crate) const fn kappa(&self) -> usize {
        self.kappa
    }

    /// A column's variables.
    pub(crate) fn tau(&self, column: FixedColumn) -> usize {
        self.taus[column.index()]
    }

    /// A column's offset in the stack, as the bits of its block's index: `offset >> tau`, over `kappa_fix - tau` bits.
    pub(crate) fn block(&self, column: FixedColumn) -> usize {
        self.offsets[column.index()] >> self.tau(column)
    }

    /// The stack of a circuit's fixed columns, zero between them.
    fn stack(&self, columns: &FixedColumns) -> Vec<F64> {
        let mut out = vec![F64::ZERO; 1 << self.kappa];
        for (c, &offset) in self.offsets.iter().enumerate() {
            let column = columns.get(FixedColumn::at(c));
            out[offset..offset + column.len()].copy_from_slice(column);
        }
        out
    }

    /// The fixed polynomial of the circuits' columns, in order, zero for the indices past the last.
    pub(crate) fn polynomial(&self, columns: &[&FixedColumns]) -> Vec<F64> {
        let mut out: Vec<F64> = columns.iter().flat_map(|c| self.stack(c)).collect();
        out.resize(out.len().next_power_of_two(), F64::ZERO);
        out
    }
}

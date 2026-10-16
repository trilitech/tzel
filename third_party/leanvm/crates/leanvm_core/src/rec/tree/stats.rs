//! What a tree's circuits cost.

use super::design::{LARGE, Level, SMALL};
use super::{Kind, Tree, TreeProof};
use crate::rec::table::Table;

/// What one of a tree's circuits costs.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct CircuitStats {
    /// Each table of the recursion machine, in the machine's order.
    pub tables: Vec<TableStats>,
    /// The words a proof of the circuit commits.
    pub committed: usize,
}

/// One table of a circuit: its rows, and the height they are padded to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct TableStats {
    /// The table's name.
    pub name: &'static str,
    /// The rows the circuit puts in the table.
    pub rows: usize,
    /// The base-two logarithm of the table's height.
    ///
    /// The height is a power of two, at least the rows.
    pub height_log: usize,
}

impl Tree<'_> {
    /// What the circuit of one kind of node costs: of a claim-set tree's nodes, the one of the largest arity.
    #[must_use]
    pub fn stats(&self, kind: Kind) -> CircuitStats {
        self.circuit_stats(match kind {
            Kind::First => 0,
            Kind::Node => self.design.places.len() - 1,
        })
    }

    /// What the node circuit of this arity costs, if the tree has one: of a tree of two tiers, the large tier's.
    #[must_use]
    pub fn node_stats(&self, arity: usize) -> Option<CircuitStats> {
        let tier = self.design.tiers.len() - 1;
        (self.design.place(tier, Level::Node(arity))).map(|p| self.circuit_stats(p))
    }

    /// What the small tier's node circuit of this arity costs, if the tree has one.
    #[must_use]
    pub fn small_node_stats(&self, arity: usize) -> Option<CircuitStats> {
        let small = self.design.tiers.len() > 1;
        (small.then(|| self.design.place(SMALL, Level::Node(arity))).flatten()).map(|p| self.circuit_stats(p))
    }

    /// What the wrap of the large tier's proofs costs, if the tree has two tiers.
    #[must_use]
    pub fn wrap_stats(&self) -> Option<CircuitStats> {
        (self.design.place(SMALL, Level::Wrap)).map(|p| self.circuit_stats(p))
    }

    /// What the circuit that made a proof costs, if the proof is of one of the tree's circuits.
    #[must_use]
    pub fn proof_stats(&self, proof: &TreeProof) -> Option<CircuitStats> {
        self.known(proof).ok().map(|p| self.circuit_stats(p))
    }

    /// Whether a proof is of a claim-set tree's large tier.
    #[must_use]
    pub fn is_large(&self, proof: &TreeProof) -> bool {
        (self.known(proof)).is_ok_and(|p| self.design.places[p].tier == LARGE)
    }

    /// What the circuit at this position costs.
    fn circuit_stats(&self, position: usize) -> CircuitStats {
        // The circuit's rows per table, and the padded heights it is proven at.
        let circuit = self.circuit(position);
        let (rows, heights) = (circuit.row_counts(), circuit.heights());

        // One entry per table of the recursion machine, in its order.
        let tables = (Table::ALL.iter())
            .map(|&table| TableStats {
                name: table.name(),
                rows: rows[table],
                height_log: heights[table],
            })
            .collect();

        // Invariant: building the tree refused any circuit that fits no commitment.
        let committed = circuit.committed_words().expect("a tree's circuits fit one commitment");
        CircuitStats { tables, committed }
    }
}

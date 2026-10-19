//! The verifier's core of one RISC-V proof, in rows: every check that depends on the proof.

use super::{Rows, infallible};
use crate::cpu::{Announcement, CpuError, DeferredClaims, Layout, Program, ProofKind};
use crate::pcs::Rate;
use crate::rec::circuit::{Builder, Dw, Ew, Kw};
use crate::rec::transcript::{ProofSource, Transcript};
use crate::tables::{Clock, PerTable};
use fiat_shamir::arith::Verifier;
use zk::{Recorder, Value};

/// What fixes the rows of a RISC-V proof's verifier: the program, each table's height, the commitment's rate, and whether the proof is zero knowledge.
///
/// Two proofs of one shape are verified by one circuit.
pub struct ProofShape<'p> {
    program: &'p Program,
    taus: PerTable<usize>,
    rate: Rate,
    kind: ProofKind,
    layout: Layout,
}

/// What the core leaves as wires.
pub struct CoreRows {
    /// The claims on the program's fixed polynomials and on each circuit's matrices, which the core does not settle.
    pub claims: DeferredClaims<Ew>,
    /// A digest the transcript draws once the proof is read, which binds every message the proof sent.
    pub state: Dw,
}

impl<'p> ProofShape<'p> {
    /// The shape of a proof of a program, from its tables' base-two logarithms of rows and its rate.
    ///
    /// # Errors
    ///
    /// Refuses what the native verifier refuses of an announcement: a height out of range, or a witness the commitment does not take.
    pub fn new(program: &'p Program, taus: PerTable<usize>, rate: Rate, kind: ProofKind) -> Result<Self, CpuError> {
        let layout = Layout::announced(program.rv(), taus, kind)?;
        Ok(Self {
            program,
            taus,
            rate,
            kind,
            layout,
        })
    }

    /// The kind of the proofs.
    pub(crate) const fn kind(&self) -> ProofKind {
        self.kind
    }

    /// The program.
    pub const fn program(&self) -> &'p Program {
        self.program
    }

    /// Each table's base-two logarithm of rows.
    pub const fn taus(&self) -> &PerTable<usize> {
        &self.taus
    }

    /// The commitment's rate.
    pub const fn rate(&self) -> Rate {
        self.rate
    }

    /// The verifier's core of a proof of this shape returning `output`, read from `source`, as rows of `b`.
    ///
    /// The rows check everything the native core checks, and leave its deferred claims as wires.
    pub fn verify_core(&self, b: &mut Builder, output: [Kw; 4], source: ProofSource<'_>) -> CoreRows {
        if self.kind == ProofKind::ZeroKnowledge {
            return self.verify_core_zk(b, output, source);
        }
        let mut t = Transcript::new(b, &self.program.session(), &output, source);
        let mut r = Rows::new(b, &mut t);

        let clock = r.scope("announcement", |r| self.read_announcement(r));
        let output = output.map(|o| r.b.k_to_e1(o));
        let claims = infallible(self.layout.verify_core(&mut r, clock, &output, self.rate));
        CoreRows {
            claims,
            state: t.digest(b),
        }
    }

    /// The verifier's core of a zero-knowledge proof, as rows: the native recorder's own code over the rows' arithmetic.
    ///
    /// The recorder makes the same record from wires as from values, so the outer proof is checked in rows as natively.
    ///
    /// It leaves the batched claims of the plain shape, which the tree carries as a plain leaf's.
    fn verify_core_zk(&self, b: &mut Builder, output: [Kw; 4], source: ProofSource<'_>) -> CoreRows {
        let mut t = Transcript::new(b, &self.program.zk_session(), &output, source);
        let (claims, fits) = {
            let mut r = Rows::new(b, &mut t);
            r.scope("announcement", |r| self.read_shape(r));
            let output = output.map(|o| Value::Public(r.b.k_to_e1(o)));
            let mut rec = Recorder::new(r);
            let core = infallible(self.layout.record_core(&mut rec, self.rate, &output));
            let claims = infallible(core.claims.into_plain(&mut rec));
            // A record too large for the key commitment has no outer proof: the rows then refuse every proof.
            let fits = zk::outer::verify(rec, &core.keys).map(|mut r| infallible(r.check_eof()));
            (claims, fits.is_ok())
        };
        if !fits {
            b.fail("the record outgrows the key commitment");
        }
        CoreRows {
            claims,
            state: t.digest(b),
        }
    }

    /// The announced shape: every height and the rate the shape's.
    fn read_shape(&self, r: &mut Rows<'_, '_>) {
        for size in Announcement::sizes(&self.taus, self.rate) {
            let x = infallible(r.prover_message());
            r.b.eq_e_const(x, size);
        }
    }

    /// The announced sizes: the shape, then the final clock, a live clock at slot zero.
    ///
    /// Returns the clock, which closes the run's last state on the bus.
    fn read_announcement(&self, r: &mut Rows<'_, '_>) -> Ew {
        self.read_shape(r);
        let clock = infallible(r.prover_message());
        let [word, high, top] = r.b.e_to_k(clock);
        r.b.eq_k_const(high, 0);
        r.b.eq_k_const(top, 0);
        // Bit 40 set, every bit above it clear, and the slot bits below the cycle clear.
        let slot_bits = Clock::CYCLE.trailing_zeros() as usize;
        for (i, bit) in r.b.split(word).into_iter().enumerate() {
            if i == Clock::LIVE_BIT as usize {
                r.b.eq_k_const(bit, 1);
            } else if i > Clock::LIVE_BIT as usize || i < slot_bits {
                r.b.eq_k_const(bit, 0);
            }
        }
        clock
    }
}

# Apps

This directory contains the thin user-facing shells:

- `wallet/` for `sp-client`
- `ledger/` for `sp-ledger`
- `prover/` for `reprove`
- `demo/` for the standalone demo binary

The shells are intentionally kept outside the implementation directories so
they stay separate from any particular language. Today they call the shared
Rust service crate directly; if a real alternate backend is added later, the
app surface can be factored around that concrete need rather than a placeholder
adapter layer.

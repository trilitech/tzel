//! Acceptance tests for the Groth16 wrap verifier on the **mv-target**
//! artifacts (2026-06-10 cloud Setup+Prove cycle on the TzEL multiverifier
//! root proof — the production chip shape).
//!
//! Fixtures (`verifier/testdata/`):
//! * `proof.bin` / `vk.bin` — the real mv-target gnark artifacts (388 B /
//!   9680 B; gnark's own `groth16.Verify` PASSED on them, see
//!   gs://tezosx-snark-artifacts/2026-06-10-mv-target-setup/). The wrapped
//!   statement is a real TzEL multiverifier root proof aggregating
//!   2 shield + 2 transfer leaves. `vk.bin` is byte-identical to the
//!   embedded `src/wrap_vk.bin`.
//! * `wrap_public_witness.txt` — the 136 public inputs (128 TreeRoots
//!   bytes + 8 OutHash M31 lanes) dumped via gnark
//!   `frontend.NewWitness(..., PublicOnly())` from the mv fixture
//!   (stwo-gnark-tzel `TestDumpPublicWitness` helper).
//!
//! NOTE: the full `verify_snark` happy path (Groth16 PASS **and** OutHash
//! binding PASS) is not exercised here: it needs the mv root's
//! `output_preimage`, whose derivation chain is pinned by golden vectors in
//! `src/snark.rs` tests instead. The negative direction (valid Groth16,
//! wrong preimage -> reject at the binding step) IS exercised below.

use tzel_verifier::groth16::{
    parse_gnark_vk, verify_groth16_wrap, verify_groth16_wrap_with_vk, VerifyError, N_PUBLIC_INPUTS,
    WRAP_VK_BYTES,
};
use tzel_verifier::snark::verify_snark;

const PROOF_BIN: &[u8] = include_bytes!("../testdata/proof.bin");
const VK_BIN: &[u8] = include_bytes!("../testdata/vk.bin");
const PUBLIC_WITNESS_TXT: &str = include_str!("../testdata/wrap_public_witness.txt");

/// Parse the dumped public witness (`<index> <decimal>` lines) into the
/// wrap circuit's (tree_roots, out_hash_lanes) public inputs.
fn fixture_publics() -> ([[u8; 32]; 4], [u32; 8]) {
    let vals: Vec<u64> = PUBLIC_WITNESS_TXT
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            l.split_whitespace()
                .nth(1)
                .expect("`<idx> <dec>` line")
                .parse()
                .expect("decimal")
        })
        .collect();
    assert_eq!(vals.len(), N_PUBLIC_INPUTS);

    let mut tree_roots = [[0u8; 32]; 4];
    for t in 0..4 {
        for b in 0..32 {
            let v = vals[t * 32 + b];
            assert!(v < 256, "TreeRoots entry must be a byte");
            tree_roots[t][b] = v as u8;
        }
    }
    let mut out_hash_lanes = [0u32; 8];
    for (i, lane) in out_hash_lanes.iter_mut().enumerate() {
        let v = vals[128 + i];
        assert!(v < (1 << 31), "OutHash lane must be M31");
        *lane = v as u32;
    }
    (tree_roots, out_hash_lanes)
}

/// Build the `verify_snark` wire envelope:
/// `tree_roots (4×32) ‖ out_hash lanes (8×u32 LE) ‖ gnark proof bytes`.
fn fixture_envelope(proof_tail: &[u8]) -> Vec<u8> {
    let (tree_roots, out_hash_lanes) = fixture_publics();
    let mut bytes = Vec::with_capacity(160 + proof_tail.len());
    for root in &tree_roots {
        bytes.extend_from_slice(root);
    }
    for lane in &out_hash_lanes {
        bytes.extend_from_slice(&lane.to_le_bytes());
    }
    bytes.extend_from_slice(proof_tail);
    bytes
}

#[test]
fn embedded_vk_matches_testdata_vk() {
    // The embedded VK (mv-target, 2026-06-10 Setup) must be byte-identical
    // to the testdata VK.
    assert_eq!(WRAP_VK_BYTES, VK_BIN);
    parse_gnark_vk(WRAP_VK_BYTES).expect("embedded VK parses");
}

#[test]
fn accepts_real_mv_proof() {
    let (tree_roots, out_hash_lanes) = fixture_publics();
    verify_groth16_wrap(PROOF_BIN, &tree_roots, &out_hash_lanes)
        .expect("real mv-target proof must verify against the embedded VK");
}

#[test]
fn accepts_real_mv_proof_with_explicit_vk() {
    let (tree_roots, out_hash_lanes) = fixture_publics();
    verify_groth16_wrap_with_vk(PROOF_BIN, &tree_roots, &out_hash_lanes, VK_BIN)
        .expect("real mv-target proof must verify");
}

#[test]
fn rejects_bit_flipped_proof() {
    let (tree_roots, out_hash_lanes) = fixture_publics();
    let mut proof = PROOF_BIN.to_vec();
    // Flip a low bit of Ar.Y (offset 63 = last byte of Y_BE): the point
    // either falls off the curve (InvalidPoint) or breaks the pairing.
    proof[63] ^= 0x01;
    match verify_groth16_wrap(&proof, &tree_roots, &out_hash_lanes) {
        Err(_) => {}
        Ok(()) => panic!("bit-flipped proof must not verify"),
    }
}

#[test]
fn rejects_tampered_commitment() {
    let (tree_roots, out_hash_lanes) = fixture_publics();
    let mut proof = PROOF_BIN.to_vec();
    // Commitment starts after Ar(64) + Bs(128) + Krs(64) + u32 len(4) = 260.
    proof[260 + 63] ^= 0x01;
    match verify_groth16_wrap(&proof, &tree_roots, &out_hash_lanes) {
        Err(_) => {}
        Ok(()) => panic!("tampered commitment must not verify"),
    }
}

#[test]
fn rejects_tampered_pok() {
    let (tree_roots, out_hash_lanes) = fixture_publics();
    let mut proof = PROOF_BIN.to_vec();
    // PoK is the last 64 bytes (offset 324).
    proof[324 + 63] ^= 0x01;
    match verify_groth16_wrap(&proof, &tree_roots, &out_hash_lanes) {
        Err(VerifyError::PokCheckFailed) | Err(VerifyError::InvalidPoint { .. }) => {}
        other => panic!("tampered PoK must fail the PoK check, got {other:?}"),
    }
}

#[test]
fn rejects_wrong_tree_root_byte() {
    let (mut tree_roots, out_hash_lanes) = fixture_publics();
    tree_roots[0][0] ^= 0x01;
    match verify_groth16_wrap(PROOF_BIN, &tree_roots, &out_hash_lanes) {
        Err(VerifyError::ProofRejected) => {}
        other => panic!("wrong tree root must reject the pairing, got {other:?}"),
    }
}

#[test]
fn rejects_wrong_out_hash_lane() {
    let (tree_roots, mut out_hash_lanes) = fixture_publics();
    out_hash_lanes[7] ^= 0x01;
    match verify_groth16_wrap(PROOF_BIN, &tree_roots, &out_hash_lanes) {
        Err(VerifyError::ProofRejected) => {}
        other => panic!("wrong OutHash lane must reject the pairing, got {other:?}"),
    }
}

#[test]
fn rejects_truncated_proof_tail() {
    let (tree_roots, out_hash_lanes) = fixture_publics();
    match verify_groth16_wrap(&PROOF_BIN[..PROOF_BIN.len() - 1], &tree_roots, &out_hash_lanes) {
        Err(VerifyError::Truncated { .. }) => {}
        other => panic!("truncated proof must fail to parse, got {other:?}"),
    }
}

/// `verify_snark` full path against the real proof: step (a) (Groth16 on the
/// envelope publics) PASSES, then step (c) (OutHash binding) must REJECT a
/// preimage that does not re-derive the proof's OutHash — there is no
/// consistent `output_preimage` for the leaf fixture, so any preimage must
/// be rejected at the binding step, never accepted.
#[test]
fn verify_snark_rejects_mismatched_output_preimage() {
    let envelope = fixture_envelope(PROOF_BIN);
    // Shape-valid single-task preimage: [n_tasks=1, size=4, hash, out, out].
    let f = |v: u64| {
        let mut raw = [0u8; 32];
        raw[..8].copy_from_slice(&v.to_le_bytes());
        raw
    };
    let preimage = vec![f(1), f(4), f(0xdead), f(99), f(100)];
    let err = verify_snark(&envelope, &preimage).unwrap_err();
    assert!(
        err.contains("does not match proof OutHash"),
        "must fail at the OutHash binding step (Groth16 already passed), got: {err}"
    );
}

/// `verify_snark` step (a) failure: tampering the gnark proof inside the
/// envelope is rejected before the binding step.
#[test]
fn verify_snark_rejects_tampered_envelope_proof() {
    let mut tampered = PROOF_BIN.to_vec();
    tampered[63] ^= 0x01;
    let envelope = fixture_envelope(&tampered);
    let f = |v: u64| {
        let mut raw = [0u8; 32];
        raw[..8].copy_from_slice(&v.to_le_bytes());
        raw
    };
    let preimage = vec![f(1), f(4), f(0xdead), f(99), f(100)];
    let err = verify_snark(&envelope, &preimage).unwrap_err();
    assert!(
        err.contains("groth16 wrap verification failed"),
        "must fail at the Groth16 step, got: {err}"
    );
}

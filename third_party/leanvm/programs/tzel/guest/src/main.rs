//! TzEL Multiasset Guest Entrypoint on leanVM.
//!
//! Reads an `OpTag` (`1..=3`) from the advice tape, verifies the corresponding
//! TzEL Multiasset transaction (`Shield`, `Transfer N->4`, or `Unshield`), and commits
//! the full bootloader-framed public output preimage (`[1, 3 + k, program_hash, k, ...public_outputs]`).
#![no_std]
#![no_main]

use leanvm_guest::{commit, read, read_slice};
use tzel_guest::{
    OpTag, PROGRAM_HASH_SHIELD, PROGRAM_HASH_TRANSFER, PROGRAM_HASH_UNSHIELD,
    exact::{InputNoteWitness, ShieldTx, TransferHeader, UnshieldHeader},
    u64_to_felt,
};

leanvm_guest::advice_words!(1 << 13);

#[unsafe(no_mangle)]
extern "C" fn main() {
    let op = OpTag::from_u64(*read::<u64>()).expect("valid TzEL OpTag");
    match op {
        OpTag::ExactShield => {
            let tx = read::<ShieldTx>();
            let outputs = tx.verify().expect("valid TzEL Shield proof");
            commit(&u64_to_felt(1));
            commit(&u64_to_felt(13));
            commit(&PROGRAM_HASH_SHIELD);
            commit(&u64_to_felt(10));
            commit(&outputs);
        }
        OpTag::ExactTransfer => {
            let header = read::<TransferHeader>();
            let inputs = read_slice::<InputNoteWitness>(header.n_inputs as usize);
            header.verify(inputs).expect("valid TzEL Transfer proof");
            let k = (11 + inputs.len()) as u64;
            commit(&u64_to_felt(1));
            commit(&u64_to_felt(3 + k));
            commit(&PROGRAM_HASH_TRANSFER);
            commit(&u64_to_felt(k));
            commit(&header.auth_domain);
            commit(&header.root);
            for inp in inputs {
                commit(&inp.nf);
            }
            commit(&u64_to_felt(header.fee));
            for out in &header.outputs {
                commit(&out.cm);
            }
            for out in &header.outputs {
                commit(&out.memo_ct_hash);
            }
        }
        OpTag::ExactUnshield => {
            let header = read::<UnshieldHeader>();
            let inputs = read_slice::<InputNoteWitness>(header.n_inputs as usize);
            let (cm_c1, cm_c2, cm_fee) =
                header.verify(inputs).expect("valid TzEL Unshield proof");
            let k = (12 + inputs.len()) as u64;
            commit(&u64_to_felt(1));
            commit(&u64_to_felt(3 + k));
            commit(&PROGRAM_HASH_UNSHIELD);
            commit(&u64_to_felt(k));
            commit(&header.auth_domain);
            commit(&header.root);
            for inp in inputs {
                commit(&inp.nf);
            }
            commit(&u64_to_felt(header.v_pub));
            commit(&header.asset_pub);
            commit(&u64_to_felt(header.fee));
            commit(&header.recipient);
            commit(&cm_c1);
            commit(&header.change_1.memo_ct_hash);
            commit(&cm_c2);
            commit(&header.change_2.memo_ct_hash);
            commit(&cm_fee);
            commit(&header.fee_note.memo_ct_hash);
        }
    }
}

#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
base_cairo="$repo_root/cairo"
tmp_root="$(mktemp -d /tmp/starkprivacy-cairo-statement-mutants.XXXXXX)"
trap 'rm -rf "$tmp_root"' EXIT

run_mutant() {
  local name="$1"
  local rel_file="$2"
  local needle="$3"
  local replacement="$4"
  local filter="$5"
  local mutant_dir="$tmp_root/$name"
  local source_file="$mutant_dir/$rel_file"
  local log_file="$tmp_root/$name.log"

  cp -R "$base_cairo" "$mutant_dir"
  perl -0pi -e "s/\Q$needle\E/$replacement/" "$source_file"

  if (cd "$mutant_dir" && scarb test -- --filter "$filter" >"$log_file" 2>&1); then
    echo "mutant survived: $name" >&2
    cat "$log_file" >&2
    exit 1
  fi

  echo "mutant killed: $name"
}

run_mutant \
  "shield_skip_commitment_check" \
  "src/shield.cairo" \
  "assert(hash::commit(d_j, v_pub, rcm, otag) == cm_new, 'shield: bad commitment');" \
  "assert(1 == 1, 'shield: bad commitment');" \
  "test_shield_rejects_mutated_commitment"

run_mutant \
  "transfer_skip_nf_check" \
  "src/transfer.cairo" \
  "assert(nf == *nf_list.at(i), 'transfer: bad nf');" \
  "assert(1 == 1, 'transfer: bad nf');" \
  "test_transfer_rejects_private_nullifier_preimage_mutation"

run_mutant \
  "transfer_skip_cm1_check" \
  "src/transfer.cairo" \
  "assert(hash::commit(d_j_1, v_1, rcm_1, otag_1) == cm_1, 'transfer: bad cm_1');" \
  "assert(1 == 1, 'transfer: bad cm_1');" \
  "test_transfer_rejects_private_output_commitment_preimage_mutation"

run_mutant \
  "transfer_skip_balance_check" \
  "src/transfer.cairo" \
  "assert(sum_in == sum_out, 'transfer: balance mismatch');" \
  "assert(1 == 1, 'transfer: balance mismatch');" \
  "test_transfer_rejects_balance_mismatch_even_with_consistent_output_commitment"

run_mutant \
  "transfer_skip_dup_nf_check" \
  "src/transfer.cairo" \
  "assert(*nf_list.at(a) != *nf_list.at(b), 'transfer: dup nf');" \
  "assert(1 == 1, 'transfer: dup nf');" \
  "test_transfer_rejects_duplicate_nullifiers_after_all_other_checks"

run_mutant \
  "transfer_break_second_input_auth_slice" \
  "src/transfer.cairo" \
  "let auth_sib_start = i * merkle::AUTH_DEPTH;" \
  "let auth_sib_start = 0;" \
  "test_transfer_accepts_valid_two_input_statement"

run_mutant \
  "unshield_skip_nf_check" \
  "src/unshield.cairo" \
  "assert(nf == *nf_list.at(i), 'unshield: bad nf');" \
  "assert(1 == 1, 'unshield: bad nf');" \
  "test_unshield_rejects_private_nullifier_preimage_mutation"

run_mutant \
  "unshield_skip_balance_check" \
  "src/unshield.cairo" \
  "assert(sum_in == sum_out, 'unshield: balance mismatch');" \
  "assert(1 == 1, 'unshield: balance mismatch');" \
  "test_unshield_rejects_balance_mismatch_even_with_consistent_change_commitment"

run_mutant \
  "unshield_skip_no_change_value_check" \
  "src/unshield.cairo" \
  "assert(v_change == 0, 'unshield: no change but v!=0');" \
  "assert(1 == 1, 'unshield: no change but v!=0');" \
  "test_change_commitment_or_zero_rejects_nonzero_value_without_change"

echo "all statement-level cairo mutants were killed"

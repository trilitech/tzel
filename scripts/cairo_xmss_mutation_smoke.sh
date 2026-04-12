#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
base_cairo="$repo_root/cairo"
tmp_root="$(mktemp -d /tmp/starkprivacy-cairo-xmss-mutants.XXXXXX)"
trap 'rm -rf "$tmp_root"' EXIT

run_mutant() {
  local name="$1"
  local needle="$2"
  local replacement="$3"
  local mutant_dir="$tmp_root/$name"
  local source_file="$mutant_dir/src/xmss_common.cairo"
  local log_file="$tmp_root/$name.log"

  cp -R "$base_cairo" "$mutant_dir"
  perl -0pi -e "s/\Q$needle\E/$replacement/" "$source_file"

  if (cd "$mutant_dir" && scarb test >"$log_file" 2>&1); then
    echo "mutant survived: $name" >&2
    cat "$log_file" >&2
    exit 1
  fi

  echo "mutant killed: $name"
}

run_mutant \
  "skip_chain_hash" \
  "let mut step = digit;" \
  "let mut step = digit + 1;"

run_mutant \
  "ignore_pub_seed" \
  "hash::hash3_generic(pub_seed, adrs, x)" \
  "hash::hash3_generic(0, adrs, x)"

run_mutant \
  "wrong_ltree_tag" \
  "TAG_XMSS_LTREE," \
  "TAG_XMSS_TREE,"

run_mutant \
  "ignore_auth_sibling" \
  "let sibling = *siblings.at(level);" \
  "let sibling = 0;"

run_mutant \
  "skip_key_idx_range_check" \
  "assert(idx == 0, 'xmss key idx out of range');" \
  "assert(1 == 1, 'xmss key idx out of range');"

run_mutant \
  "skip_auth_root_check" \
  "assert(current == auth_root, 'xmss auth root mismatch');" \
  "assert(1 == 1, 'xmss auth root mismatch');"

echo "all xmss verifier mutants were killed"

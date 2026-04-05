#!/bin/bash
set -e

# Usage: ./bench.sh [--depth 16|32|48]
DEPTH=48
while [[ $# -gt 0 ]]; do
    case $1 in
        --depth) DEPTH="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

case $DEPTH in
    16|32|48) ;;
    *) echo "ERROR: unsupported depth $DEPTH (use 16, 32, or 48)"; exit 1 ;;
esac

DEPTH_FEATURE="depth${DEPTH}"
STWO_FEATURES="blake,$DEPTH_FEATURE"
STONE_FEATURES="$DEPTH_FEATURE"

echo "=== StarkPrivacy Proof Benchmark (depth=$DEPTH) ==="
echo ""

command -v scarb >/dev/null 2>&1 || { echo "ERROR: scarb not found"; exit 1; }

STEPS=("step_shield" "step_unshield" "step_join" "step_split")
LABELS=("Shield" "Unshield" "Join (2→2)" "Split (2→2)")

# ─── Stwo (uses Blake2s for Merkle tree) ──────────────────────────────
echo ""
echo "--- Stwo (Blake2s Merkle) ---"
scarb build --no-default-features --features "$STWO_FEATURES" 2>&1 | tail -1

declare -a STWO_PROVES STWO_SIZES STWO_VERIFIES

for i in "${!STEPS[@]}"; do
    step=${STEPS[$i]}
    label=${LABELS[$i]}

    START=$(date +%s%N)
    scarb prove --execute --executable-name "$step" --no-default-features --features "$STWO_FEATURES" 2>&1
    STWO_PROVES[$i]=$(( ($(date +%s%N) - START) / 1000000 ))

    LATEST=$(ls -td target/execute/starkprivacy/execution*/proof/proof.json 2>/dev/null | head -1)
    STWO_SIZES[$i]=$(stat --printf="%s" "$LATEST" 2>/dev/null || stat -f%z "$LATEST" 2>/dev/null)

    EXEC_DIR=$(dirname $(dirname "$LATEST"))
    EXEC_ID=$(basename "$EXEC_DIR" | sed 's/execution//')
    START=$(date +%s%N)
    scarb verify --execution-id "$EXEC_ID" 2>&1
    STWO_VERIFIES[$i]=$(( ($(date +%s%N) - START) / 1000000 ))

    echo ""
done

# ─── Stone (uses Poseidon for Merkle tree) ────────────────────────────
echo "--- Stone (Poseidon Merkle) ---"
scarb build --no-default-features --features "$STONE_FEATURES" 2>&1 | tail -1

STONE_OK=1
if ! command -v cairo-execute >/dev/null 2>&1; then
    echo "Installing cairo-execute (may take a few minutes)..."
    cargo install cairo-execute --version "=2.16.1" 2>&1 | tail -3
    command -v cairo-execute >/dev/null 2>&1 || { echo "cairo-execute build failed — skipping Stone"; STONE_OK=0; }
fi
if ! command -v cpu_air_prover >/dev/null 2>&1; then
    echo "cpu_air_prover not found — skipping Stone"
    echo "Install from: https://github.com/dipdup-io/stone-packaging/releases"
    STONE_OK=0
fi

declare -a STONE_PROVES STONE_SIZES STONE_VERIFIES

if [ "$STONE_OK" = "1" ]; then
    for i in "${!STEPS[@]}"; do
        step=${STEPS[$i]}
        label=${LABELS[$i]}
        SDIR="target/stone/$step"
        mkdir -p "$SDIR"

        EXECUTABLE="target/dev/${step}.executable.json"

        echo "[$label] trace..."
        cairo-execute \
            "$EXECUTABLE" \
            --prebuilt \
            --standalone \
            --layout recursive_with_poseidon \
            --trace-file "$SDIR/trace.bin" \
            --memory-file "$SDIR/memory.bin" \
            --air-public-input "$SDIR/air_public_input.json" \
            --air-private-input "$SDIR/air_private_input.json" \
            2>&1

        # Auto-generate FRI params matching the trace size
        python3 -c "
import json, math
pub = json.load(open('$SDIR/air_public_input.json'))
n_steps = pub['n_steps']
# recursive_with_poseidon layout: 16 trace columns → degree = n_steps * 16
log_degree = int(math.log2(n_steps * 16))
# Build FRI steps: start with 0, then chunks of 4, remainder
remaining = log_degree
fri_steps = [0]
remaining -= 0
while remaining > 10:
    fri_steps.append(4)
    remaining -= 4
if remaining > 0:
    fri_steps.append(remaining)
    remaining = 0
last_layer = 1 << remaining if remaining > 0 else 1
params = {
    'field': 'PrimeField0',
    'stark': {
        'fri': {
            'fri_step_list': fri_steps,
            'last_layer_degree_bound': last_layer,
            'n_queries': 18,
            'proof_of_work_bits': 24
        },
        'log_n_cosets': 4
    },
    'use_extension_field': False
}
json.dump(params, open('$SDIR/params.json', 'w'), indent=2)
print(f'  degree=2^{log_degree}, fri_steps={fri_steps}, last_layer={last_layer}')
" 2>&1

        echo "[$label] prove..."
        START=$(date +%s%N)
        cpu_air_prover \
            --out_file="$SDIR/proof.json" \
            --public_input_file="$SDIR/air_public_input.json" \
            --private_input_file="$SDIR/air_private_input.json" \
            --prover_config_file=cpu_air_prover_config.json \
            --parameter_file="$SDIR/params.json" \
            --generate_annotations 2>&1
        STONE_PROVES[$i]=$(( ($(date +%s%N) - START) / 1000000 ))
        STONE_SIZES[$i]=$(stat --printf="%s" "$SDIR/proof.json" 2>/dev/null || stat -f%z "$SDIR/proof.json" 2>/dev/null)

        echo "[$label] verify..."
        START=$(date +%s%N)
        cpu_air_verifier --in_file="$SDIR/proof.json" 2>&1
        STONE_VERIFIES[$i]=$(( ($(date +%s%N) - START) / 1000000 ))

        echo ""
    done
fi

# ─── Summary ───────────────────────────────────────────────────────────
fmt_size() {
    local bytes=$1
    if [ "$bytes" -ge 1048576 ]; then
        echo "$(echo "scale=1; $bytes/1048576" | bc)MB"
    elif [ "$bytes" -ge 1024 ]; then
        echo "$(echo "scale=0; $bytes/1024" | bc)KB"
    else
        echo "${bytes}B"
    fi
}

echo ""
echo "=== Results ==="
echo ""
echo "Stwo (Circle STARK, Blake2s, depth=$DEPTH):"
printf "  %-16s %10s %10s %10s\n" "Operation" "Prove" "Size" "Verify"
for i in "${!STEPS[@]}"; do
    printf "  %-16s %8sms %10s %8sms\n" \
        "${LABELS[$i]}" "${STWO_PROVES[$i]}" "$(fmt_size ${STWO_SIZES[$i]})" "${STWO_VERIFIES[$i]}"
done

if [ "$STONE_OK" = "1" ]; then
    echo ""
    echo "Stone (FRI STARK, Poseidon, depth=$DEPTH):"
    printf "  %-16s %10s %10s %10s\n" "Operation" "Prove" "Size" "Verify"
    for i in "${!STEPS[@]}"; do
        printf "  %-16s %8sms %10s %8sms\n" \
            "${LABELS[$i]}" "${STONE_PROVES[$i]}" "$(fmt_size ${STONE_SIZES[$i]})" "${STONE_VERIFIES[$i]}"
    done
fi

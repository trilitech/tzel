#!/bin/bash
set -e

# Usage: ./bench.sh [--depth 16|32|48] [--single]
DEPTH=48
RECURSIVE=1
while [[ $# -gt 0 ]]; do
    case $1 in
        --depth) DEPTH="$2"; shift 2 ;;
        --single) RECURSIVE=0; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

case $DEPTH in
    16|32|48) ;;
    *) echo "ERROR: unsupported depth $DEPTH (use 16, 32, or 48)"; exit 1 ;;
esac

echo "=== StarkPrivacy Proof Benchmark (depth=$DEPTH) ==="
echo ""

# Build Cairo executables
echo "Building Cairo executables..."
scarb build --no-default-features --features "depth${DEPTH}" 2>&1 | tail -1

# Build reprover if needed
if [ ! -f reprover/target/release/reprove ]; then
    echo "Building reprover (first time, may take a few minutes)..."
    (cd reprover && cargo build --release 2>&1 | tail -1)
fi

STEPS=("step_shield" "step_unshield" "step_join" "step_split")
LABELS=("Shield" "Unshield" "Join (2→2)" "Split (2→2)")

if [ "$RECURSIVE" = "1" ]; then
    echo ""
    echo "--- Recursive mode (Stwo + circuit reprover) ---"
    echo ""

    declare -a CAIRO_PROVES CIRCUIT_PROVES TOTAL_PROVES VERIFY_TIMES PROOF_SIZES PEAK_MEMS

    for i in "${!STEPS[@]}"; do
        step=${STEPS[$i]}
        label=${LABELS[$i]}
        echo "[$label]"

        OUTPUT=$(./reprover/target/release/reprove "target/dev/${step}.executable.json" --recursive 2>&1)
        CAIRO_PROVES[$i]=$(echo "$OUTPUT" | grep "^cairo_prove_ms=" | cut -d= -f2)
        CIRCUIT_PROVES[$i]=$(echo "$OUTPUT" | grep "^circuit_prove_ms=" | cut -d= -f2)
        TOTAL_PROVES[$i]=$(echo "$OUTPUT" | grep "^prove_ms=" | cut -d= -f2)
        VERIFY_TIMES[$i]=$(echo "$OUTPUT" | grep "^verify_ms=" | cut -d= -f2)
        PROOF_SIZES[$i]=$(echo "$OUTPUT" | grep "^proof_bytes=" | cut -d= -f2)
        PEAK_MEMS[$i]=$(echo "$OUTPUT" | grep "^peak_rss_kb=" | cut -d= -f2)
    done

    echo ""
    echo "=== Results (depth=$DEPTH, recursive) ==="
    echo ""
    printf "  %-14s %10s %12s %10s %8s %10s %10s\n" \
        "Operation" "Cairo" "Circuit" "Total" "Verify" "Proof" "Peak RSS"
    for i in "${!STEPS[@]}"; do
        sz=${PROOF_SIZES[$i]}
        sz_kb=$(echo "scale=1; $sz/1024" | bc)
        mem=${PEAK_MEMS[$i]}
        mem_gb=$(echo "scale=1; $mem/1048576" | bc)
        printf "  %-14s %8sms %10sms %8sms %6sms %8sKB %8sGB\n" \
            "${LABELS[$i]}" "${CAIRO_PROVES[$i]}" "${CIRCUIT_PROVES[$i]}" \
            "${TOTAL_PROVES[$i]}" "${VERIFY_TIMES[$i]}" "$sz_kb" "$mem_gb"
    done
else
    echo ""
    echo "--- Single-level mode (Stwo only) ---"
    echo ""

    declare -a PROVES VERIFY_TIMES PROOF_SIZES PEAK_MEMS

    for i in "${!STEPS[@]}"; do
        step=${STEPS[$i]}
        label=${LABELS[$i]}
        echo "[$label]"

        OUTPUT=$(./reprover/target/release/reprove "target/dev/${step}.executable.json" 2>&1)
        PROVES[$i]=$(echo "$OUTPUT" | grep "^prove_ms=" | cut -d= -f2)
        PROOF_SIZES[$i]=$(echo "$OUTPUT" | grep "^proof_zstd_bytes=" | cut -d= -f2)
        PEAK_MEMS[$i]=$(echo "$OUTPUT" | grep "^peak_rss_kb=" | cut -d= -f2)
    done

    echo ""
    echo "=== Results (depth=$DEPTH, single-level) ==="
    echo ""
    printf "  %-14s %10s %10s %10s\n" "Operation" "Prove" "Proof" "Peak RSS"
    for i in "${!STEPS[@]}"; do
        sz=${PROOF_SIZES[$i]}
        sz_kb=$(echo "scale=1; $sz/1024" | bc)
        mem=${PEAK_MEMS[$i]}
        mem_gb=$(echo "scale=1; $mem/1048576" | bc)
        printf "  %-14s %8sms %8sKB %8sGB\n" \
            "${LABELS[$i]}" "${PROVES[$i]}" "$sz_kb" "$mem_gb"
    done
fi

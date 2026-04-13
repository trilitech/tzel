#!/bin/bash
set -e

# Usage: ./apps/prover/bench.sh [--depth 16|32|48] [--debug-single-level]
DEPTH=48
RECURSIVE=1
while [[ $# -gt 0 ]]; do
    case $1 in
        --depth) DEPTH="$2"; shift 2 ;;
        --debug-single-level) RECURSIVE=0; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

case $DEPTH in
    16|32|48) ;;
    *) echo "ERROR: unsupported depth $DEPTH (use 16, 32, or 48)"; exit 1 ;;
esac

echo "=== TzEL Proof Benchmark (depth=$DEPTH) ==="
echo ""

# Run from repo root
cd "$(dirname "$0")/../.."

# Build Cairo executables
echo "Building Cairo executables..."
(
  cd cairo
  scarb build --no-default-features --features "depth${DEPTH}" 2>&1 | tail -1
)

# Build reprover if needed
if [ ! -f apps/prover/target/release/reprove ]; then
    echo "Building reprover (first time, may take a few minutes)..."
    (
      cd apps/prover
      cargo build --release 2>&1 | tail -1
    )
fi

echo "Building bench witness generator..."
(
  cargo build -p tzel-services --bin gen_proof_bench_args 2>&1 | tail -1
)

GEN_ARGS_BIN="target/debug/gen_proof_bench_args"

CASES=(
  "Shield|run_shield.executable.json|shield|"
  "Unshield (N=1)|run_unshield.executable.json|unshield|1"
  "Unshield (N=7)|run_unshield.executable.json|unshield|7"
  "Join (N=2)|run_transfer.executable.json|transfer|2"
  "Split (N=1)|run_transfer.executable.json|transfer|1"
  "Consolidate (N=7)|run_transfer.executable.json|transfer|7"
)

# Format bytes as KB (integer)
fmt_kb() { echo "$(( $1 / 1024 ))"; }
# Format KB as GB with one decimal
fmt_gb() { echo "$(( $1 / 1048576 )).$(( ($1 % 1048576) * 10 / 1048576 ))"; }

if [ "$RECURSIVE" = "1" ]; then
    echo ""
    echo "--- Recursive mode (Stwo + circuit reprover, zero-knowledge) ---"
    echo ""

    declare -a CAIRO_PROVES CIRCUIT_PROVES TOTAL_PROVES VERIFY_TIMES PROOF_SIZES PEAK_MEMS

    for i in "${!CASES[@]}"; do
        IFS="|" read -r label executable kind n_inputs <<<"${CASES[$i]}"
        echo "[$label]"

        args_file=$(mktemp)
        if [ -n "$n_inputs" ]; then
            "$GEN_ARGS_BIN" "$kind" "$n_inputs" > "$args_file"
        else
            "$GEN_ARGS_BIN" "$kind" > "$args_file"
        fi

        OUTPUT=$(./apps/prover/target/release/reprove "cairo/target/dev/${executable}" --arguments-file "$args_file" 2>&1)
        CAIRO_PROVES[$i]=$(echo "$OUTPUT" | grep "^cairo_prove_ms=" | cut -d= -f2)
        CIRCUIT_PROVES[$i]=$(echo "$OUTPUT" | grep "^circuit_prove_ms=" | cut -d= -f2)
        TOTAL_PROVES[$i]=$(echo "$OUTPUT" | grep "^prove_ms=" | cut -d= -f2)
        VERIFY_TIMES[$i]=$(echo "$OUTPUT" | grep "^verify_ms=" | cut -d= -f2)
        PROOF_SIZES[$i]=$(echo "$OUTPUT" | grep "^proof_bytes=" | cut -d= -f2)
        PEAK_MEMS[$i]=$(echo "$OUTPUT" | grep "^peak_rss_kb=" | cut -d= -f2)
        rm -f "$args_file"
    done

    echo ""
    echo "=== Results (depth=$DEPTH, recursive) ==="
    echo ""
    printf "  %-14s %10s %12s %10s %8s %10s %10s\n" \
        "Operation" "Cairo" "Circuit" "Total" "Verify" "Proof" "Peak RSS"
    for i in "${!CASES[@]}"; do
        printf "  %-14s %8sms %10sms %8sms %6sms %7sKB %7sGB\n" \
            "$(echo "${CASES[$i]}" | cut -d'|' -f1)" "${CAIRO_PROVES[$i]}" "${CIRCUIT_PROVES[$i]}" \
            "${TOTAL_PROVES[$i]}" "${VERIFY_TIMES[$i]}" \
            "$(fmt_kb ${PROOF_SIZES[$i]})" "$(fmt_gb ${PEAK_MEMS[$i]})"
    done
else
    echo ""
    echo "--- Single-level mode (NOT zero-knowledge, debug only) ---"
    echo ""

    declare -a PROVES PROOF_SIZES PEAK_MEMS

    for i in "${!CASES[@]}"; do
        IFS="|" read -r label executable kind n_inputs <<<"${CASES[$i]}"
        echo "[$label]"

        args_file=$(mktemp)
        if [ -n "$n_inputs" ]; then
            "$GEN_ARGS_BIN" "$kind" "$n_inputs" > "$args_file"
        else
            "$GEN_ARGS_BIN" "$kind" > "$args_file"
        fi

        OUTPUT=$(./apps/prover/target/release/reprove "cairo/target/dev/${executable}" --arguments-file "$args_file" --debug-single-level 2>&1)
        PROVES[$i]=$(echo "$OUTPUT" | grep "^prove_ms=" | cut -d= -f2)
        PROOF_SIZES[$i]=$(echo "$OUTPUT" | grep "^proof_zstd_bytes=" | cut -d= -f2)
        PEAK_MEMS[$i]=$(echo "$OUTPUT" | grep "^peak_rss_kb=" | cut -d= -f2)
        rm -f "$args_file"
    done

    echo ""
    echo "=== Results (depth=$DEPTH, single-level, NOT zero-knowledge) ==="
    echo ""
    printf "  %-14s %10s %10s %10s\n" "Operation" "Prove" "Proof" "Peak RSS"
    for i in "${!CASES[@]}"; do
        printf "  %-14s %8sms %7sKB %7sGB\n" \
            "$(echo "${CASES[$i]}" | cut -d'|' -f1)" "${PROVES[$i]}" \
            "$(fmt_kb ${PROOF_SIZES[$i]})" "$(fmt_gb ${PEAK_MEMS[$i]})"
    done
fi

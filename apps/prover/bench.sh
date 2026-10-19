#!/bin/bash
set -e

# Usage: ./apps/prover/bench.sh [--depth 48] [--debug-single-level]
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
    48) ;;
    *) echo "ERROR: unsupported depth $DEPTH (leanVM tzel guest uses depth 48)"; exit 1 ;;
esac

echo "=== TzEL leanVM Proof Benchmark (depth=$DEPTH) ==="
echo ""

# Run from repo root
cd "$(dirname "$0")/../.."

# Build reprover if needed
if [ ! -f target/release/reprove ]; then
    echo "Building reprover..."
    cargo build --release -p tzel-prover-app --bin reprove 2>&1 | tail -1
fi

echo "Building bench witness generator..."
cargo build --release -p tzel-services --bin gen-proof-bench-args 2>&1 | tail -1

REPROVE_BIN="target/release/reprove"
GEN_ARGS_BIN="target/release/gen-proof-bench-args"

CASES=(
  "Shield|tzel_run_shield.executable.json|shield|"
  "Unshield (N=1)|tzel_run_unshield.executable.json|unshield|1"
  "Unshield (N=5)|tzel_run_unshield.executable.json|unshield|5"
  "Join (N=2)|tzel_run_transfer.executable.json|transfer|2"
  "Split (N=1)|tzel_run_transfer.executable.json|transfer|1"
  "Consolidate (N=5)|tzel_run_transfer.executable.json|transfer|5"
)

# Format bytes as KB (integer)
fmt_kb() { echo "$(( $1 / 1024 ))"; }
# Format KB as GB with one decimal
fmt_gb() { echo "$(( $1 / 1048576 )).$(( ($1 % 1048576) * 10 / 1048576 ))"; }

if [ "$RECURSIVE" = "1" ]; then
    echo ""
    echo "--- ZK STARK mode (leanVM zero-knowledge) ---"
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

        OUTPUT=$("$REPROVE_BIN" "$executable" --arguments-file "$args_file" 2>&1)
        CAIRO_PROVES[$i]=$(echo "$OUTPUT" | grep "^cairo_prove_ms=" | cut -d= -f2)
        CIRCUIT_PROVES[$i]=$(echo "$OUTPUT" | grep "^circuit_prove_ms=" | cut -d= -f2)
        TOTAL_PROVES[$i]=$(echo "$OUTPUT" | grep "^prove_ms=" | cut -d= -f2)
        VERIFY_TIMES[$i]=$(echo "$OUTPUT" | grep "^verify_ms=" | cut -d= -f2)
        PROOF_SIZES[$i]=$(echo "$OUTPUT" | grep "^proof_bytes=" | cut -d= -f2)
        PEAK_MEMS[$i]=$(echo "$OUTPUT" | grep "^peak_rss_kb=" | cut -d= -f2)
        rm -f "$args_file"
    done

    echo ""
    echo "=== Results (depth=$DEPTH, ZK STARK) ==="
    echo ""
    printf "  %-18s %10s %12s %10s %8s %10s %10s\n" \
        "Operation" "Cairo" "Circuit" "Total" "Verify" "Proof" "Peak RSS"
    for i in "${!CASES[@]}"; do
        printf "  %-18s %8sms %10sms %8sms %6sms %7sKB %7sGB\n" \
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

        OUTPUT=$("$REPROVE_BIN" "$executable" --arguments-file "$args_file" --debug-single-level 2>&1)
        PROVES[$i]=$(echo "$OUTPUT" | grep "^prove_ms=" | cut -d= -f2)
        PROOF_SIZES[$i]=$(echo "$OUTPUT" | grep "^proof_zstd_bytes=" | cut -d= -f2)
        PEAK_MEMS[$i]=$(echo "$OUTPUT" | grep "^peak_rss_kb=" | cut -d= -f2)
        rm -f "$args_file"
    done

    echo ""
    echo "=== Results (depth=$DEPTH, single-level, NOT zero-knowledge) ==="
    echo ""
    printf "  %-18s %10s %10s %10s\n" "Operation" "Prove" "Proof" "Peak RSS"
    for i in "${!CASES[@]}"; do
        printf "  %-18s %8sms %7sKB %7sGB\n" \
            "$(echo "${CASES[$i]}" | cut -d'|' -f1)" "${PROVES[$i]}" \
            "$(fmt_kb ${PROOF_SIZES[$i]})" "$(fmt_gb ${PEAK_MEMS[$i]})"
    done
fi

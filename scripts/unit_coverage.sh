#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$ROOT/target"
WORKDIR="$(mktemp -d "$ROOT/target/tzel-unit-coverage.XXXXXX")"
CACHE_DIR="$ROOT/target/unit-coverage-cache"
mkdir -p "$CACHE_DIR"
KEEP_WORKDIR="${KEEP_UNIT_COVERAGE_WORKDIR:-0}"
SUMMARY_TXT="$CACHE_DIR/latest-summary.txt"

cleanup() {
  rm -f "$ROOT"/default_*.profraw
  if [[ "$KEEP_WORKDIR" != "1" ]]; then
    rm -rf "$WORKDIR"
  else
    printf 'kept coverage workdir: %s\n' "$WORKDIR" >&2
  fi
}
trap cleanup EXIT

rm -f "$ROOT"/default_*.profraw

llvm_bin_for_toolchain() {
  local toolchain="$1"
  local sysroot
  if [[ -n "$toolchain" ]]; then
    sysroot="$(rustup run "${toolchain#+}" rustc --print sysroot)"
  else
    sysroot="$(rustc --print sysroot)"
  fi
  printf '%s/lib/rustlib/x86_64-unknown-linux-gnu/bin' "$sysroot"
}

export TZEL_TRAP_FULL_XMSS_REBUILDS=1

# Unit coverage only: run default unit-test binaries directly and keep ignored
# slow tests out of the default coverage/CI path.
COMPONENTS=(
  "core|cargo test -p tzel-core --lib --no-run --message-format=json|$ROOT/core/src||measure"
  "verifier|cargo +nightly-2025-07-14 test -p tzel-verifier --lib --no-run --message-format=json|$ROOT/verifier/src|+nightly-2025-07-14|measure"
  "services|cargo test --lib -p tzel-services --no-run --message-format=json|$ROOT/services/tzel/src||measure"
  "wallet|cargo test -p tzel-wallet-app --bin sp-client --no-run --message-format=json|$ROOT/apps/wallet/src||measure"
  "ledger|cargo test -p tzel-ledger-app --bin sp-ledger --no-run --message-format=json|$ROOT/apps/ledger/src||measure"
  "demo|cargo test -p tzel-demo --no-run --message-format=json|$ROOT/apps/demo/src||measure"
  "rollup-kernel|cargo +nightly-2025-07-14 test -p tzel-rollup-kernel --lib --no-run --message-format=json|$ROOT/tezos/rollup-kernel/src|+nightly-2025-07-14|measure"
  "reprover||$ROOT/services/reprover/src|+nightly-2025-07-14|no-unit-tests"
  "prover-app||$ROOT/apps/prover/src|+nightly-2025-07-14|no-unit-tests"
)

RUST_SUMMARY_JSON="$WORKDIR/rust-summary.jsonl"
: >"$RUST_SUMMARY_JSON"

run_rust_component() {
  local name="$1"
  local cargo_cmd="$2"
  local src_root="$3"
  local toolchain="$4"
  local mode="$5"
  local target_key="stable"
  if [[ -n "$toolchain" ]]; then
    target_key="${toolchain#+}"
  fi
  local target_dir="$CACHE_DIR/rust-target-$target_key"
  local cargo_json="$target_dir/cargo.jsonl"
  local profraw_pattern="$target_dir/run-%p-%m.profraw"
  local profdata="$target_dir/unit.profdata"
  local export_json="$target_dir/export.json"
  local llvm_bin
  local llvm_profdata
  local llvm_cov

  mkdir -p "$target_dir"
  rm -f "$target_dir"/run-*.profraw "$cargo_json" "$profdata" "$export_json"

  llvm_bin="$(llvm_bin_for_toolchain "$toolchain")"
  llvm_profdata="$llvm_bin/llvm-profdata"
  llvm_cov="$llvm_bin/llvm-cov"

  if [[ "$mode" == "no-unit-tests" ]]; then
    python3 - "$name" "$src_root" >>"$RUST_SUMMARY_JSON" <<'PY'
import json, sys
print(json.dumps({
    "component": sys.argv[1],
    "source_root": sys.argv[2],
    "covered": 0,
    "count": 0,
    "pct": 0.0,
    "files": [],
    "note": "no unit tests",
}))
PY
    return
  fi

  (
    cd "$ROOT"
    LLVM_PROFILE_FILE="$target_dir/build-%p.profraw" \
    CARGO_TARGET_DIR="$target_dir" \
    CARGO_INCREMENTAL=0 \
    RUSTFLAGS="-Cinstrument-coverage" \
    bash -lc "$cargo_cmd" >"$cargo_json"
  )

  mapfile -t test_bins < <(
    python3 - "$cargo_json" <<'PY'
import json
import sys

seen = set()
for line in open(sys.argv[1], "r", encoding="utf-8"):
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        continue
    if obj.get("reason") != "compiler-artifact":
        continue
    exe = obj.get("executable")
    if not exe or exe in seen:
        continue
    profile = obj.get("profile") or {}
    if profile.get("test"):
        seen.add(exe)
        print(exe)
PY
  )

  if [[ "${#test_bins[@]}" -eq 0 ]]; then
    python3 - "$name" "$src_root" >>"$RUST_SUMMARY_JSON" <<'PY'
import json, sys
print(json.dumps({
    "component": sys.argv[1],
    "source_root": sys.argv[2],
    "covered": 0,
    "count": 0,
    "files": []
}))
PY
    return
  fi

  for bin in "${test_bins[@]}"; do
    LLVM_PROFILE_FILE="$profraw_pattern" "$bin" --quiet >/dev/null
  done

  "$llvm_profdata" merge -sparse "$target_dir"/run-*.profraw -o "$profdata"
  "$llvm_cov" export --summary-only --instr-profile="$profdata" "${test_bins[@]}" >"$export_json"

  python3 - "$name" "$src_root" "$ROOT" "$export_json" >>"$RUST_SUMMARY_JSON" <<'PY'
import json
import os
import sys

component = sys.argv[1]
source_root = os.path.realpath(sys.argv[2])
repo_root = os.path.realpath(sys.argv[3])
export_path = sys.argv[4]
doc = json.load(open(export_path, "r", encoding="utf-8"))

files = {}
for bundle in doc.get("data", []):
    for item in bundle.get("files", []):
        path = os.path.realpath(item["filename"])
        if not path.startswith(source_root + os.sep):
            continue
        summary = item["summary"]["lines"]
        entry = files.setdefault(path, {"covered": 0, "count": 0})
        entry["covered"] += int(summary["covered"])
        entry["count"] += int(summary["count"])

rows = []
covered = 0
count = 0
for path, stats in sorted(files.items()):
    file_count = stats["count"]
    file_covered = stats["covered"]
    pct = 100.0 if file_count == 0 else (100.0 * file_covered / file_count)
    rel = os.path.relpath(path, repo_root)
    rows.append({
        "path": rel,
        "covered": file_covered,
        "count": file_count,
        "pct": round(pct, 2),
    })
    covered += file_covered
    count += file_count

print(json.dumps({
    "component": component,
    "source_root": source_root,
    "covered": covered,
    "count": count,
    "pct": round(100.0 if count == 0 else (100.0 * covered / count), 2),
    "files": rows,
}))
PY
}

for entry in "${COMPONENTS[@]}"; do
  IFS='|' read -r name cargo_cmd src_root toolchain mode <<<"$entry"
  run_rust_component "$name" "$cargo_cmd" "$src_root" "$toolchain" "$mode"
done

OCAML_COVERAGE_DIR="$WORKDIR/ocaml-coverage"
OCAML_REPO_DIR="$WORKDIR/ocaml-repo"
OCAML_SRC_DIR="$OCAML_REPO_DIR/ocaml"
mkdir -p "$OCAML_COVERAGE_DIR" "$OCAML_REPO_DIR/specs"
cp -a "$ROOT/ocaml" "$OCAML_SRC_DIR"
cp -a "$ROOT/specs/test_vectors" "$OCAML_REPO_DIR/specs/test_vectors"
rm -rf "$OCAML_SRC_DIR/_build"
python3 - "$OCAML_SRC_DIR/dune" "$OCAML_SRC_DIR/test/dune" "$ROOT/ocaml/vendor/mlkem-native/test/build" <<'PY'
from pathlib import Path
import sys

root_dune = Path(sys.argv[1])
test_dune = Path(sys.argv[2])
mlkem_lib_dir = sys.argv[3]

root_old = """(library
 (name tzel)
 (foreign_stubs (language c) (names blake2s_stubs mlkem_stubs))
 (c_library_flags
  -Lvendor/mlkem-native/test/build
  -lmlkem768)
 (libraries mirage-crypto hex cstruct yojson))
"""
root_new = """(library
 (name tzel)
 (foreign_stubs (language c) (names blake2s_stubs mlkem_stubs))
 (c_library_flags
  -L{mlkem_lib_dir}
  -lmlkem768)
 (libraries mirage-crypto hex cstruct yojson)
 (preprocess (pps bisect_ppx)))
""".format(mlkem_lib_dir=mlkem_lib_dir)

test_old = """(test
 (name test_main)
 (modules test_main)
 (libraries tzel alcotest hex mirage-crypto yojson))
"""
test_new = """(test
 (name test_main)
 (modules test_main)
 (libraries tzel alcotest hex mirage-crypto yojson)
 (preprocess (pps bisect_ppx)))
"""

root_text = root_dune.read_text()
test_text = test_dune.read_text()
if root_old not in root_text:
    raise SystemExit("unexpected ocaml/dune shape for bisect patch")
if test_old not in test_text:
    raise SystemExit("unexpected ocaml/test/dune shape for bisect patch")
root_dune.write_text(root_text.replace(root_old, root_new, 1))
test_dune.write_text(test_text.replace(test_old, test_new, 1))
PY
(
  cd "$OCAML_SRC_DIR"
  rm -f ocaml-unit-*.coverage "$OCAML_COVERAGE_DIR"/*.coverage
  dune build test/test_main.exe >/dev/null
  BISECT_ENABLE=YES BISECT_FILE="ocaml-unit-%p.coverage" \
    ./_build/default/test/test_main.exe >/dev/null
  shopt -s nullglob
  coverage_files=(ocaml-unit-*.coverage)
  if [[ "${#coverage_files[@]}" -eq 0 ]]; then
    echo "expected bisect coverage files, found none" >&2
    exit 1
  fi
  mv "${coverage_files[@]}" "$OCAML_COVERAGE_DIR"/
  bisect-ppx-report summary --per-file \
    "$OCAML_COVERAGE_DIR"/*.coverage >"$OCAML_COVERAGE_DIR/summary.txt"
)

python3 - "$RUST_SUMMARY_JSON" "$OCAML_COVERAGE_DIR/summary.txt" "$OCAML_SRC_DIR" <<'PY' | tee "$SUMMARY_TXT"
import json
import re
import sys

rust_rows = [json.loads(line) for line in open(sys.argv[1], "r", encoding="utf-8") if line.strip()]
ocaml_src_dir = sys.argv[3].rstrip("/") + "/"

print("Rust Unit Coverage")
for row in rust_rows:
    count = row["count"]
    covered = row["covered"]
    pct = row.get("pct", 0.0) if count == 0 else (100.0 * covered / count)
    note = row.get("note")
    suffix = f" [{note}]" if note else ""
    print(f"- {row['component']}: {pct:.2f}% ({covered}/{count}){suffix}")

print("\nRust Lowest-Coverage Files")
file_rows = []
for row in rust_rows:
    for file_row in row["files"]:
        file_rows.append((file_row["pct"], row["component"], file_row["path"], file_row["covered"], file_row["count"]))
for pct, component, path, covered, count in sorted(file_rows)[:20]:
    print(f"- [{component}] {path}: {pct:.2f}% ({covered}/{count})")

summary_lines = open(sys.argv[2], "r", encoding="utf-8").read().splitlines()
print("\nOCaml Unit Coverage")
file_re = re.compile(r"^\s*([0-9.]+)\s*%\s+(\d+)/(\d+)\s+(.+)$")
for line in summary_lines:
    line = line.strip()
    if not line:
        continue
    match = file_re.match(line)
    if not match:
        continue
    pct, covered, count, path = match.groups()
    path = path.replace(ocaml_src_dir, "ocaml/")
    label = "total" if path == "Project coverage" else path
    print(f"- {label}: {pct}% ({covered}/{count})")
PY

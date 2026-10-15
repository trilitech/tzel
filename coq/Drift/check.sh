#!/usr/bin/env bash
#
# coq/Drift/check.sh — fail if any circuit source file's SHA-256 differs
# from the SHA pinned in coq/MANIFEST.toml. CI runs this on every
# coq/** or third_party/leanvm/programs/tzel/guest/src/** change.
#
# Drift means: the circuit source has moved out of sync with its Coq
# mirror. Resolving drift requires (a) re-reading the affected Coq
# mirror and updating it if the circuit change had semantic impact, and
# (b) bumping the SHA in MANIFEST.toml in the same commit.

set -euo pipefail

manifest="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)/../MANIFEST.toml"
repo_root="$(git rev-parse --show-toplevel)"

python3 - "$manifest" "$repo_root" <<'PY'
import hashlib
import sys
import tomllib

manifest_path, repo_root = sys.argv[1:3]
with open(manifest_path, "rb") as f:
    data = tomllib.load(f)

mirrors = data.get("mirror", [])
failures = []
for entry in mirrors:
    rel_path = entry.get("source") or entry["cairo"]
    source_path = f"{repo_root}/{rel_path}"
    expected = entry["sha256"]
    with open(source_path, "rb") as f:
        actual = hashlib.sha256(f.read()).hexdigest()
    if actual != expected:
        failures.append((rel_path, expected, actual, entry["coq"]))

if failures:
    print("DRIFT DETECTED — circuit source has changed since the manifest was last")
    print("updated; the Coq model may no longer reflect the circuit it claims to")
    print("model.")
    print()
    for src, expected, actual, coq_files in failures:
        print(f"  {src}")
        print(f"    manifest SHA-256: {expected}")
        print(f"    current SHA-256:  {actual}")
        print(f"    coq mirror(s):    {', '.join(coq_files)}")
    print()
    print("Action: re-read each affected Coq mirror against the new circuit source,")
    print("update the mirror if the change had semantic impact, and bump the SHA")
    print("in coq/MANIFEST.toml in the same commit.")
    sys.exit(1)

print(f"OK: all {len(mirrors)} circuit↔Coq mirrors match.")
PY


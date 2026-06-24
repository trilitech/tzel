#!/usr/bin/env python3
"""Generate the Michelson storage + shield-arg fixtures for the mv full-contract
tezt (test_zk_tzel_mv_shield in cross_runtime.ml), from verifier/testdata +
the pinned circuit-root lane constants (verifier/src/snark.rs).
Run from the tzel repo root: python3 contracts/tezt-fixtures/gen_mv_fixtures.py"""
import json, os
TD = "verifier/testdata"
def feltbe(h): return "%064x" % int(h, 16)
proof = open(f"{TD}/proof.bin", "rb").read().hex()
vk = open(f"{TD}/vk.bin", "rb").read().hex()
vals = [int(l.split()[1]) for l in open(f"{TD}/wrap_public_witness.txt") if l.strip()]
tree_roots = "".join("%064x" % v for v in vals[:4])   # item-D: 4 TreeRoots as 32-byte BE Fr scalars
circuit_root = "%064x" % vals[0]                       # item-D: TreeRoots[0] = mv root circuit identity
d = json.load(open(f"{TD}/leaf_junction.json"))
leaf = {lf["label"]: lf["output_preimage_hex"] for lf in d["leaves"]}
shield, transfer = leaf["shield"], leaf["transfer"]
program_hash, auth_domain = feltbe(shield[2]), feltbe(shield[3])
# snark.rs LEAF / LEAF_TO_MV / MV_TO_MV _CIRCUIT_ROOT_LANES
LEAF = [260776853,1309242768,1145090100,1598670544,369006849,883527537,842476743,1550035524]
LEAF_TO_MV = [1329128718,79407594,317031791,1097889202,829834258,737675984,793553350,583776393]
MV_TO_MV = [458569739,49239620,177702544,1105661487,705003098,653641141,1137855028,1375486617]
lanes = lambda L: "{ " + " ; ".join(map(str, L)) + " }"
feltlist = lambda fs: "{ " + " ; ".join("0x" + feltbe(f) for f in fs) + " }"
GATEWAY = "KT18oDJJKXMKhfE1bSuAPGp92pYcwVDiqsPw"
storage = (f'(Pair "{GATEWAY}" 0x{vk} 0x{circuit_root} 0x{program_hash} 0x{auth_domain} '
           f'{lanes(LEAF)} {{ {lanes(LEAF_TO_MV)} ; {lanes(MV_TO_MV)} }} {{}})')
leaves = f'{{ {feltlist(shield)} ; {feltlist(shield)} ; {feltlist(transfer)} ; {feltlist(transfer)} }}'
# value-custody nats (bound to the proof): shield v_note=[5], fee=[6], producer_fee=[7].
# NOTE: these come straight from the proof's value felts. For the deposit check to
# pass (amount == v_note+fee+producer_fee), the PROOF must be generated with
# economically-sane values — the current structural-test fixture has a hash-sized
# producer_fee, so a sane-value re-prove is needed before the value E2E can pass.
v_note, fee, producer_fee = int(shield[5], 16), int(shield[6], 16), int(shield[7], 16)
arg = (f'(Pair 0x{proof} 0x{tree_roots} {leaves} {feltlist(shield)} {{}} '
       f'{v_note} {fee} {producer_fee})')
here = os.path.dirname(__file__)
open(os.path.join(here, "tzel_mv_storage.tz"), "w").write(storage)
open(os.path.join(here, "tzel_mv_shield_arg.tz"), "w").write(arg)
print("generated tzel_mv_storage.tz + tzel_mv_shield_arg.tz")

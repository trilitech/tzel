import subprocess
import textwrap
import unittest
from pathlib import Path


class OctezRollupSandboxDalSmokeTest(unittest.TestCase):
    def test_extract_fixture_fields_includes_shield_total_debit_and_tree_size(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        script = repo_root / "scripts" / "octez_rollup_sandbox_dal_smoke.sh"
        metadata = textwrap.dedent(
            """\
            {
              "auth_domain": "aa",
              "shield_program_hash": "bb",
              "transfer_program_hash": "cc",
              "unshield_program_hash": "dd",
              "shield_deposit_id": "deposit:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
              "shield_amount": 400000,
              "shield_total_debit": 500001,
              "shield_tree_size_after": 2
            }
            """
        )

        proc = subprocess.run(
            [
                "bash",
                "-lc",
                textwrap.dedent(
                    f"""\
                    set -Eeuo pipefail
                    source "{script}"
                    extract_fixture_fields '{metadata}'
                    """
                ),
            ],
            cwd=repo_root,
            text=True,
            capture_output=True,
            check=True,
        )

        self.assertEqual(
            proc.stdout.splitlines(),
            [
                "aa",
                "bb",
                "cc",
                "dd",
                "deposit:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "400000",
                "500001",
                "2",
            ],
        )

    def test_await_fixture_shield_postconditions_uses_expected_tree_size(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        script = repo_root / "scripts" / "octez_rollup_sandbox_dal_smoke.sh"

        proc = subprocess.run(
            [
                "bash",
                "-lc",
                textwrap.dedent(
                    f"""\
                    set -Eeuo pipefail
                    source "{script}"
                    await_rollup_u64() {{
                      printf '%s|%s|%s\\n' "$1" "$2" "$3"
                    }}
                    await_fixture_shield_postconditions "/balances/by-key/alice" "2"
                    """
                ),
            ],
            cwd=repo_root,
            text=True,
            capture_output=True,
            check=True,
        )

        self.assertEqual(
            proc.stdout.splitlines(),
            [
                "/balances/by-key/alice|0|public balance drain after shield",
                "/tzel/v1/state/tree/size|2|shielded note insertion",
            ],
        )


if __name__ == "__main__":
    unittest.main()

import json
import tempfile
import unittest
from pathlib import Path

from scripts.build_alpha_sandbox_params import build_params


class BuildAlphaSandboxParamsTest(unittest.TestCase):
    def test_rewrites_only_the_trailing_dal_attestation_lag_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            constants_path = tmpdir / "constants.json"
            accounts_path = tmpdir / "accounts.json"
            out_path = tmpdir / "out.json"

            constants_path.write_text(
                json.dumps(
                    {
                        "chain_id": "NetX",
                        "initial_timestamp": "1970-01-01T00:00:00Z",
                        "dal_parametric": {
                            "attestation_lag": 2,
                            "attestation_lags": [1, 2, 3, 4, 9],
                        },
                    }
                ),
                encoding="utf-8",
            )
            accounts_path.write_text(
                json.dumps(
                    [
                        {"amount": "1000"},
                        {"amount": "2000"},
                    ]
                ),
                encoding="utf-8",
            )

            build_params(
                constants_path=constants_path,
                accounts_path=accounts_path,
                out_path=out_path,
                operator_pk="edpk-operator",
                attestation_lag=5,
                bootstrap_pks=["edpk-bootstrap-1", "edpk-bootstrap-2"],
            )

            data = json.loads(out_path.read_text(encoding="utf-8"))
            self.assertEqual(data["dal_parametric"]["attestation_lag"], 5)
            self.assertEqual(data["dal_parametric"]["attestation_lags"], [1, 2, 3, 4, 5])
            self.assertEqual(
                data["bootstrap_accounts"],
                [
                    ["edpk-bootstrap-1", "1000"],
                    ["edpk-bootstrap-2", "2000"],
                    ["edpk-operator", "3800000000000"],
                ],
            )
            self.assertEqual(data["minimal_block_delay"], "1")
            self.assertEqual(data["delay_increment_per_round"], "1")
            self.assertNotIn("chain_id", data)
            self.assertNotIn("initial_timestamp", data)

    def test_does_not_invent_attestation_lags_when_constants_do_not_have_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            constants_path = tmpdir / "constants.json"
            accounts_path = tmpdir / "accounts.json"
            out_path = tmpdir / "out.json"

            constants_path.write_text(
                json.dumps(
                    {
                        "dal_parametric": {
                            "attestation_lag": 2,
                        },
                    }
                ),
                encoding="utf-8",
            )
            accounts_path.write_text(
                json.dumps(
                    [
                        {"amount": "1000"},
                    ]
                ),
                encoding="utf-8",
            )

            build_params(
                constants_path=constants_path,
                accounts_path=accounts_path,
                out_path=out_path,
                operator_pk="edpk-operator",
                attestation_lag=5,
                bootstrap_pks=["edpk-bootstrap-1"],
            )

            data = json.loads(out_path.read_text(encoding="utf-8"))
            self.assertEqual(data["dal_parametric"]["attestation_lag"], 5)
            self.assertNotIn("attestation_lags", data["dal_parametric"])


if __name__ == "__main__":
    unittest.main()

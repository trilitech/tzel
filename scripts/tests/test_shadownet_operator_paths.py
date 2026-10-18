import unittest
from pathlib import Path


class ShadownetOperatorPathTest(unittest.TestCase):
    def test_operator_unit_uses_installer_default_config_admin_env(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        unit_path = repo_root / "ops" / "shadownet" / "systemd" / "tzel-operator.service"
        unit = unit_path.read_text(encoding="utf-8")

        self.assertIn(
            "EnvironmentFile=-/usr/local/etc/tzel/rollup-config-admin-build.env",
            unit,
        )

    def test_operator_preflight_checks_installer_default_config_admin_env(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        script_path = repo_root / "scripts" / "shadownet_operator_preflight.sh"
        script = script_path.read_text(encoding="utf-8")

        self.assertIn(
            'CONFIG_ADMIN_BUILD_ENV_FILE="/usr/local/etc/tzel/rollup-config-admin-build.env"',
            script,
        )

    def test_pqnet_operator_unit_and_env_cover_slot_range_and_network_url(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        unit = (
            repo_root / "ops" / "pqnet" / "systemd" / "tzel-operator.service"
        ).read_text(encoding="utf-8")
        env_example = (repo_root / "ops" / "pqnet" / "pqnet.env.example").read_text(
            encoding="utf-8"
        )
        init_script = (
            repo_root / "scripts" / "init_shadownet_operator_box.sh"
        ).read_text(encoding="utf-8")

        self.assertIn(
            "EnvironmentFile=-/usr/local/etc/tzel/rollup-config-admin-build.env",
            unit,
        )
        self.assertIn("--dal-slot-range=${TZEL_OPERATOR_DAL_SLOT_RANGE}", unit)
        self.assertIn("TZEL_OPERATOR_DAL_SLOT_RANGE=1..4", env_example)
        self.assertIn(
            "TZEL_OCTEZ_NETWORK=https://pqnet-10-16.pqpark.dal.nomadic-labs.com/network.json",
            env_example,
        )
        self.assertIn('OCTEZ_NETWORK="${TZEL_OCTEZ_NETWORK:-shadownet}"', init_script)


if __name__ == "__main__":
    unittest.main()

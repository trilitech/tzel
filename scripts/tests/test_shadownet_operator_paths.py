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


if __name__ == "__main__":
    unittest.main()

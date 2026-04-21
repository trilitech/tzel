import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


class SubmitRollupConfigTest(unittest.TestCase):
    def test_tutorial_documents_operator_submission_status_route(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        tutorial = repo_root / "docs" / "shadownet_tutorial.md"
        text = tutorial.read_text(encoding="utf-8")

        self.assertIn("$OPERATOR_URL/v1/rollup/submissions/<id>", text)
        self.assertNotIn("$OPERATOR_URL/v1/submissions/<id>", text)

    def test_posts_to_rollup_submission_route(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        script = repo_root / "scripts" / "submit_rollup_config.sh"

        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            log_path = tmpdir / "curl.log"
            octez_path = tmpdir / "octez_kernel_message"
            curl_path = tmpdir / "curl"

            octez_path.write_text(
                "#!/usr/bin/env bash\n"
                "if [[ \"$1\" == \"raw-configure-bridge\" ]]; then\n"
                "  echo deadbeef\n"
                "  exit 0\n"
                "fi\n"
                "exit 2\n",
                encoding="utf-8",
            )
            curl_path.write_text(
                "#!/usr/bin/env bash\n"
                f"printf '%s\\n' \"$@\" > \"{log_path}\"\n"
                "echo '{\"submission\":{\"id\":\"sub-test\"}}'\n",
                encoding="utf-8",
            )

            for path in (octez_path, curl_path):
                path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

            env = os.environ.copy()
            env["PATH"] = f"{tmpdir}:{env['PATH']}"

            subprocess.run(
                [
                    str(script),
                    "--operator-url",
                    "http://operator.example",
                    "--rollup-address",
                    "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP",
                    "configure-bridge",
                    "KT1BuEZtb68c1Q4yjtckcNjGELqWt56Xyesc",
                ],
                cwd=repo_root,
                env=env,
                check=True,
            )

            curl_args = log_path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(
                curl_args[-1],
                "http://operator.example/v1/rollup/submissions",
            )

    def test_fails_when_operator_reports_failed_submission(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        script = repo_root / "scripts" / "submit_rollup_config.sh"

        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            octez_path = tmpdir / "octez_kernel_message"
            curl_path = tmpdir / "curl"

            octez_path.write_text(
                "#!/usr/bin/env bash\n"
                "if [[ \"$1\" == \"raw-configure-bridge\" ]]; then\n"
                "  echo deadbeef\n"
                "  exit 0\n"
                "fi\n"
                "exit 2\n",
                encoding="utf-8",
            )
            curl_path.write_text(
                "#!/usr/bin/env bash\n"
                "echo '{\"submission\":{\"id\":\"sub-test\",\"status\":\"failed\",\"detail\":\"boom\"}}'\n",
                encoding="utf-8",
            )

            for path in (octez_path, curl_path):
                path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

            env = os.environ.copy()
            env["PATH"] = f"{tmpdir}:{env['PATH']}"

            with self.assertRaises(subprocess.CalledProcessError):
                subprocess.run(
                    [
                        str(script),
                        "--operator-url",
                        "http://operator.example",
                        "--rollup-address",
                        "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP",
                        "configure-bridge",
                        "KT1BuEZtb68c1Q4yjtckcNjGELqWt56Xyesc",
                    ],
                    cwd=repo_root,
                    env=env,
                    check=True,
                )

    def test_default_octez_kernel_message_resolves_next_to_script(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        script = repo_root / "scripts" / "submit_rollup_config.sh"

        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            install_dir = tmpdir / "install-bin"
            tools_dir = tmpdir / "path-tools"
            install_dir.mkdir()
            tools_dir.mkdir()

            installed_script = install_dir / "submit_rollup_config"
            octez_path = install_dir / "octez_kernel_message"
            curl_path = tools_dir / "curl"
            log_path = tmpdir / "curl.log"

            installed_script.write_text(script.read_text(encoding="utf-8"), encoding="utf-8")
            octez_path.write_text(
                "#!/usr/bin/env bash\n"
                "if [[ \"$1\" == \"raw-configure-bridge\" ]]; then\n"
                "  echo deadbeef\n"
                "  exit 0\n"
                "fi\n"
                "exit 2\n",
                encoding="utf-8",
            )
            curl_path.write_text(
                "#!/usr/bin/env bash\n"
                f"printf '%s\\n' \"$@\" > \"{log_path}\"\n"
                "echo '{\"submission\":{\"id\":\"sub-test\"}}'\n",
                encoding="utf-8",
            )

            for path in (installed_script, octez_path, curl_path):
                path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

            env = os.environ.copy()
            env["PATH"] = f"{tools_dir}:/usr/bin:/bin"

            subprocess.run(
                [
                    "bash",
                    str(installed_script),
                    "--operator-url",
                    "http://operator.example",
                    "--rollup-address",
                    "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP",
                    "configure-bridge",
                    "KT1BuEZtb68c1Q4yjtckcNjGELqWt56Xyesc",
                ],
                cwd=repo_root,
                env=env,
                check=True,
            )

            curl_args = log_path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(
                curl_args[-1],
                "http://operator.example/v1/rollup/submissions",
            )


if __name__ == "__main__":
    unittest.main()

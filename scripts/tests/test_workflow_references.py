import re
import subprocess
import unittest
from pathlib import Path


class WorkflowReferencesTest(unittest.TestCase):
    def test_script_unittest_modules_exist_and_are_tracked(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        workflow = repo_root / ".github" / "workflows" / "unit-tests.yml"
        text = workflow.read_text(encoding="utf-8")
        modules = sorted(set(re.findall(r"\bscripts\.tests\.[A-Za-z0-9_]+", text)))

        missing = []
        untracked = []
        for module in modules:
            rel_path = Path(*module.split(".")).with_suffix(".py")
            path = repo_root / rel_path
            if not path.exists():
                missing.append(str(rel_path))
                continue
            proc = subprocess.run(
                ["git", "ls-files", "--error-unmatch", str(rel_path)],
                cwd=repo_root,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if proc.returncode != 0:
                untracked.append(str(rel_path))

        self.assertEqual([], missing)
        self.assertEqual([], untracked)


if __name__ == "__main__":
    unittest.main()

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from guard import command_findings


SCRIPT = Path(__file__).resolve().parents[1] / "guard.py"
FAKE = "synthetic-approval-test-fixture"


class CommandTests(unittest.TestCase):
    def test_detects_secret_positions_and_provider_tokens(self):
        cases = {
            f'Bash(PGPASSWORD="{FAKE}" psql)': "credential-assignment",
            f'curl -H "Authorization: Bearer {FAKE}" https://example.invalid': "authorization-header",
            f'curl -H "Authorization: Basic {FAKE}" https://example.invalid': "authorization-header",
            f'curl -H "X-API-Key: {FAKE}" https://example.invalid': "authorization-header",
            f"psql 'postgresql://user:{FAKE}@example.invalid/db'": "url-password",
            f"db-client --password '{FAKE}'": "credential-argument",
            f"db-client --client-secret={FAKE}": "credential-argument",
            f"sshpass -p '{FAKE}' ssh example.invalid": "credential-argument",
            f"mysql -p{FAKE}": "credential-argument",
            "echo gh" + "p_" + "0" * 36: "provider-token",
        }
        for command, rule in cases.items():
            with self.subTest(rule=rule):
                self.assertIn(rule, command_findings(command))

    def test_allows_references_and_benign_commands(self):
        for command in (
            'Bash(PGPASSWORD="$PGPASSWORD" psql)',
            'curl -H "Authorization: Bearer ${TOKEN}" https://example.invalid',
            'Bash(curl -H "Authorization: Bearer ${TOKEN}")',
            'db-client --password "${DB_PASSWORD}"',
            "ssh -p 2222 example.invalid",
            "mysql -p",
            "git status --short",
            "npm test *",
        ):
            with self.subTest(command=command):
                self.assertEqual(command_findings(command), set())

    def hook(self, command):
        return subprocess.run(
            [sys.executable, SCRIPT, "claude-hook"],
            input=json.dumps({"tool_name": "Bash", "tool_input": {"command": command}}),
            capture_output=True, text=True, check=True,
        )

    def test_hook_denies_without_echoing_input(self):
        result = self.hook(f"PGPASSWORD={FAKE} psql")
        response = json.loads(result.stdout)["hookSpecificOutput"]
        self.assertEqual(response["permissionDecision"], "deny")
        self.assertNotIn(FAKE, result.stdout + result.stderr)
        self.assertEqual(self.hook('PGPASSWORD="$PGPASSWORD" psql').stdout, "")

    def test_hook_denies_oversize_input(self):
        result = self.hook("x" * (32 * 1024 + 1))
        self.assertEqual(json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")


class GitTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.repo = Path(tmp.name)
        self.git("init", "--quiet")
        self.git("config", "user.name", "Synthetic Test")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "core.hooksPath", str(self.repo / "test-hooks"))
        self.git("commit", "--quiet", "--allow-empty", "-m", "Base")

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.repo, text=True).strip()

    def run_guard(self, *args):
        result = subprocess.run(
            [sys.executable, SCRIPT, *args], cwd=self.repo, capture_output=True, text=True,
        )
        self.assertNotIn(FAKE, result.stdout + result.stderr)
        return result

    def stage(self, path, content):
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        self.git("add", "-f", "--", path)

    def test_force_added_local_settings_are_blocked_with_safe_output(self):
        path = f"{FAKE}\tproject/.claude/settings.local.json"
        self.stage(path, "{}")
        result = self.run_guard("staged")
        self.assertEqual(result.returncode, 1)
        self.assertIn("local-settings-in-git", result.stdout)
        self.assertIn("path-id=", result.stdout)

    def test_index_is_checked_even_after_working_tree_cleanup(self):
        path = ".claude/settings.json"
        self.stage(path, json.dumps({"permissions": {"allow": [f"Bash(PGPASSWORD={FAKE} psql)"]}}))
        (self.repo / path).write_text("{}")
        result = self.run_guard("staged")
        self.assertEqual(result.returncode, 1)
        self.assertIn("credential-assignment", result.stdout)
        self.git("add", "--", path)
        self.assertEqual(self.run_guard("staged").returncode, 0)

    def test_range_catches_an_intermediate_leak_cleaned_at_the_tip(self):
        base = self.git("rev-parse", "HEAD")
        self.stage(".claude/settings.json", json.dumps({"env": {"DB_PASSWORD": FAKE}}))
        self.git("commit", "--quiet", "-m", "Synthetic exposure")
        exposed = self.git("rev-parse", "HEAD")
        self.stage(".claude/settings.json", "{}")
        self.git("commit", "--quiet", "-m", "Clean tip")
        self.assertEqual(self.run_guard("tree").returncode, 0)
        result = self.run_guard("range", base, "HEAD")
        self.assertEqual(result.returncode, 1)
        self.assertIn(exposed, result.stdout)
        self.assertIn("credential-setting", result.stdout)

    def test_valid_shared_configuration_and_removal_are_allowed(self):
        path = ".claude/settings.json"
        self.stage(path, json.dumps({"permissions": {"allow": ["Bash(npm test *)"]}}))
        self.assertEqual(self.run_guard("staged").returncode, 0)
        self.git("commit", "--quiet", "-m", "Shared config")
        self.git("rm", "--quiet", "--", path)
        self.assertEqual(self.run_guard("staged").returncode, 0)

    def test_pre_commit_hook_refuses_commit(self):
        hook = self.repo / "test-hooks/pre-commit"
        hook.parent.mkdir()
        hook.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{SCRIPT}" staged\n')
        hook.chmod(0o755)
        self.stage(".claude/settings.local.json", "{}")
        result = subprocess.run(
            ["git", "commit", "--quiet", "-m", "Should be blocked"],
            cwd=self.repo, capture_output=True, text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("local-settings-in-git", result.stdout + result.stderr)
        self.assertEqual(self.git("log", "-1", "--format=%s"), "Base")

    def test_duplicate_keys_and_invalid_refs_do_not_pass(self):
        self.stage(".claude/settings.json", '{"env": {}, "env": {}}')
        self.assertEqual(self.run_guard("staged").returncode, 1)
        self.assertEqual(self.run_guard("tree", "unknown-ref").returncode, 2)

    def test_symlink_target_is_never_opened_or_printed(self):
        path = self.repo / ".claude" / "settings.json"
        path.parent.mkdir()
        path.symlink_to("/tmp/" + FAKE)
        self.git("add", "--", ".claude/settings.json")
        result = self.run_guard("staged")
        self.assertEqual(result.returncode, 1)
        self.assertIn("settings-not-regular-file", result.stdout)


if __name__ == "__main__":
    unittest.main()

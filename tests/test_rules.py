"""Rules added after the reviews, checked without a sandbox: what may come back under a
.git directory, instruction files, settings, the command-length limit, and what the
runner does when it fails itself."""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fake_agent import PLUGIN, run_hook  # noqa: E402

RUNNER = PLUGIN / "bin" / "sbx.py"
spec = importlib.util.spec_from_file_location("sbx_rules", RUNNER)
sbx = importlib.util.module_from_spec(spec)
sys.modules["sbx_rules"] = sbx
spec.loader.exec_module(sbx)

MARKER = "sbx: the sandbox layer failed; nothing was run on this machine instead"


class WhatComesBackUnderGit(unittest.TestCase):
    """Only plain repository data returns. Everything git can execute, follow or replay stays."""

    FILES_BACK = [
        ".git/HEAD", ".git/index", ".git/ORIG_HEAD", ".git/packed-refs", ".git/COMMIT_EDITMSG",
        ".git/refs/heads/main", ".git/refs/tags/v1", ".git/objects/ab/cdef0123",
        ".git/objects/pack/pack-1.pack", ".git/logs/HEAD", ".git/logs/refs/heads/main",
        ".git/info/exclude", ".git/modules/lib/HEAD", ".git/modules/libs/deep/refs/heads/x",
        ".git/worktrees/w/index", "sub/.git/index", "a/b/.git/refs/heads/y",
    ]
    DIRS_BACK = [".git", ".git/refs", ".git/objects", ".git/logs", ".git/info", ".git/refs/heads",
                 ".git/modules", ".git/modules/lib", "sub/.git"]
    FILES_KEPT_OUT = [
        ".git", ".git/config", ".git/config.worktree", ".git/commondir", ".git/gitdir",
        ".git/hooks/pre-commit", ".git/info/attributes", ".git/objects/info/alternates",
        ".git/objects/info/http-alternates", ".git/rebase-merge/git-rebase-todo", ".git/rebase-apply/next",
        ".git/sequencer/todo", ".git/refs", ".git/modules/lib", ".git/modules/lib/config",
        ".git/modules/lib/hooks/post-checkout", ".git/modules/x/refs/hooks/pre-commit",
        ".git/modules/lib/objects/info/alternates", ".git/worktrees/w/gitdir", ".git/worktrees/w/commondir",
        ".GIT/Config", ".git/HOOKS/pre-commit", ".Git/Hooks/x", "sub/.git/config", "sub/.GIT/hooks/x",
        ".g‌it/config", ".git/hooks‍/pre-commit",
    ]
    DIRS_KEPT_OUT = [".git/hooks", ".git/rebase-merge", ".git/sequencer", ".git/modules/lib/hooks"]

    def test_plain_repository_data_returns(self):
        for path in self.FILES_BACK:
            self.assertFalse(sbx.Rules.pull_denied(path, False), path)
        for path in self.DIRS_BACK:
            self.assertFalse(sbx.Rules.pull_denied(path, True), path)

    def test_hooks_config_redirects_and_rebase_state_stay_out(self):
        for path in self.FILES_KEPT_OUT:
            self.assertTrue(sbx.Rules.pull_denied(path, False), path)
        for path in self.DIRS_KEPT_OUT:
            self.assertTrue(sbx.Rules.pull_denied(path, True), path)

    def test_instruction_files_never_return_at_any_depth(self):
        for path in ("AGENTS.md", "docs/Claude.md", "pkg/.cursorrules", "GEMINI.md", "a/b/agents.MD"):
            self.assertTrue(sbx.Rules.pull_denied(path, False), path)
        for path in ("AGENTS.md.bak", "agents.txt", "README.md", "docs/claude-notes.md"):
            self.assertFalse(sbx.Rules.pull_denied(path, False), path)


class Settings(unittest.TestCase):
    def setUp(self):
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="sbx-rules-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.config = os.path.join(self.tmp, "conf", "config.json")
        os.makedirs(os.path.dirname(self.config))
        self.saved = os.environ.get("SBX_CONFIG")
        os.environ["SBX_CONFIG"] = self.config
        self.addCleanup(lambda: os.environ.pop("SBX_CONFIG", None) if self.saved is None
                        else os.environ.__setitem__("SBX_CONFIG", self.saved))
        os.environ.pop("SBX_BACKEND", None)

    def write(self, settings):
        Path(self.config).write_text(json.dumps(settings))

    def test_secret_looking_names_include_snowflake_keys_and_dbt_profiles(self):
        rules = sbx.Rules({"exclude": [], "secrets": [], "allow": []})
        for name in ("rsa_key.p8", "profiles.yml", "PROFILES.YML", "connections.toml", ".Env", "Server.PEM",
                     ".kube", "kubeconfig", "terraform.tfstate", ".mcp.json", ".claude", ".git-credentials"):
            self.assertTrue(rules.skip(name), name)
        for name in (".env.example", "profiles.yml.example", "app.py", "keys.md", ".git"):
            self.assertFalse(rules.skip(name), name)

    def test_allow_lets_a_named_file_through(self):
        self.write({"allow": ["profiles.yml"]})
        rules = sbx.Rules(sbx.load_config())
        self.assertFalse(rules.skip("profiles.yml"))
        self.assertTrue(rules.skip("connections.toml"))

    def test_bad_settings_are_reported_not_guessed(self):
        for settings in ({"max_file_mb": "big"}, {"max_file_mb": 0}, {"max_file_mb": True},
                         {"allow": "profiles.yml"}, {"exclude": [1]}, {"openshell": "gw"}):
            self.write(settings)
            with self.assertRaises(sbx.SbxError, msg=settings):
                sbx.load_config()
        Path(self.config).write_text("{not json")
        with self.assertRaises(sbx.SbxError):
            sbx.load_config()

    def test_a_relative_policy_path_is_read_next_to_the_settings_file_not_in_the_project(self):
        self.write({"openshell": {"policy": "policy.yaml"}})
        self.assertEqual(sbx.load_config()["openshell"]["policy"],
                         os.path.join(os.path.dirname(self.config), "policy.yaml"))
        self.write({"openshell": {"policy": "/etc/sbx/policy.yaml"}})
        self.assertEqual(sbx.load_config()["openshell"]["policy"], "/etc/sbx/policy.yaml")

    def test_unknown_keys_are_ignored(self):
        self.write({"backend": "openshell", "colour": "blue"})
        self.assertEqual(sbx.load_config()["backend"], "openshell")


class LengthLimitAndRunnerFailures(unittest.TestCase):
    def setUp(self):
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="sbx-fail-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.project = os.path.join(self.tmp, "proj")
        os.makedirs(self.project)

    def test_hook_blocks_a_command_too_long_to_pass_as_one_argument(self):
        done = run_hook({"command": "x" * 100_001}, self.project)
        self.assertEqual(done.returncode, 2)
        self.assertIn(b"longer than 100000 bytes", done.stderr)
        self.assertIn(b"script file", done.stderr)
        self.assertEqual(run_hook({"command": "x" * 100_000}, self.project).returncode, 0)

    def test_runner_refuses_the_same_command_with_exit_125(self):
        done = subprocess.run([sys.executable, "-I", str(RUNNER), "run", "--root", self.project, "--", "x" * 100_001],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(done.returncode, 125)
        self.assertIn("longer than 100000 bytes", done.stderr.decode())
        self.assertIn(MARKER, done.stderr.decode())

    def test_a_fault_inside_the_runner_is_exit_125_with_the_marker_line_not_a_traceback(self):
        fake_bin = os.path.join(self.tmp, "bin")
        os.makedirs(fake_bin)
        fake = os.path.join(fake_bin, "openshell")
        Path(fake).write_text("#!/bin/sh\nexit 0\n")
        os.chmod(fake, 0o755)
        blocker = os.path.join(self.tmp, "not-a-directory")
        Path(blocker).write_text("")
        env = dict(os.environ, PATH=fake_bin + os.pathsep + os.environ["PATH"], SBX_BACKEND="openshell",
                   SBX_STATE_DIR=os.path.join(blocker, "state"), SBX_CONFIG=os.path.join(self.tmp, "none.json"))
        done = subprocess.run([sys.executable, "-I", str(RUNNER), "run", "--root", self.project, "--", "true"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        text = done.stderr.decode()
        self.assertEqual(done.returncode, 125, text)
        self.assertIn("internal error", text)
        self.assertIn(MARKER, text)
        self.assertNotIn("Traceback", text)

    def test_a_time_limit_under_one_second_is_rounded_up_not_dropped(self):
        import math
        self.assertEqual(math.ceil(400 / 1000), 1)
        source = RUNNER.read_text()
        self.assertIn("math.ceil(args.timeout_ms / 1000)", source)


class LocalOnlyEntries(unittest.TestCase):
    def test_a_pipe_or_socket_here_is_never_replaced_by_the_sandbox(self):
        import io, tarfile
        tmp = os.path.realpath(tempfile.mkdtemp(prefix="sbx-fifo-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        root = os.path.join(tmp, "project")
        os.makedirs(root)
        os.mkfifo(os.path.join(root, "agent.sock"))
        os.mkfifo(os.path.join(root, "queue"))
        archive = os.path.join(tmp, "pull.tar")
        with tarfile.open(archive, "w") as tar:
            info = tarfile.TarInfo("agent.sock"); info.size = 1
            tar.addfile(info, io.BytesIO(b"x"))
            info = tarfile.TarInfo("queue"); info.type = tarfile.DIRTYPE
            tar.addfile(info)
            info = tarfile.TarInfo("fine.txt"); info.size = 2
            tar.addfile(info, io.BytesIO(b"ok"))
        rules = sbx.Rules({"exclude": [], "secrets": [], "allow": []})
        written, removed, refused = sbx.apply_pull_tar(root, archive, rules, set(), {})
        self.assertEqual(written, ["fine.txt"])
        self.assertEqual(len(refused), 2, refused)
        import stat as stat_module
        for name in ("agent.sock", "queue"):
            self.assertTrue(stat_module.S_ISFIFO(os.lstat(os.path.join(root, name)).st_mode), name)


if __name__ == "__main__":
    unittest.main()

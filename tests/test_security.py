"""Regression tests from the security review. Each one failed before its fix. No sandbox needed."""
import gzip
import io
import json
import os
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fake_agent import run_hook  # noqa: E402
from test_local import CFG, make_tar, sbx  # noqa: E402


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="sbx-sec-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root = os.path.join(self.tmp, "project")
        os.makedirs(self.root)
        self.rules = sbx.Rules(CFG)
        self.archive = os.path.join(self.tmp, "pull.tar")

    def write(self, rel, text="x"):
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        Path(path).write_text(text)
        return path

    def exists(self, rel):
        return os.path.lexists(os.path.join(self.root, rel))

    def pull(self, members, known=None, conflicts=(), **kwargs):
        make_tar(self.archive, members)
        return sbx.apply_pull_tar(self.root, self.archive, self.rules, set(conflicts), known or {}, **kwargs)


class WayBack(Base):
    def test_protected_paths_cannot_be_reached_through_a_link(self):
        self.write(".git/HEAD")
        self.write(".venv/bin/python", "real")
        os.makedirs(os.path.join(self.root, ".claude"))
        self.pull([("a", "sym", ".git/hooks"), ("a/pre-commit", "file", "#!/bin/sh"),
                   ("g", "sym", ".git"), ("g/config", "file", "[core]\nfsmonitor = evil"),
                   ("c", "sym", ".claude"), ("c/settings.json", "file", "{}"),
                   ("v", "sym", ".venv/bin"), ("v/python", "file", "evil")])
        for rel in (".git/hooks/pre-commit", ".git/config", ".claude/settings.json"):
            self.assertFalse(self.exists(rel), rel)
        self.assertEqual(Path(self.root, ".venv/bin/python").read_text(), "real")
        os.symlink(".git/hooks", os.path.join(self.root, "already-here"))  # pulled by an earlier command
        _, _, refused = self.pull([("already-here/post-checkout", "file", "#!/bin/sh")])
        self.assertEqual(refused, ["already-here/post-checkout"])
        self.assertFalse(self.exists(".git/hooks/post-checkout"))

    def test_names_are_compared_the_way_a_case_insensitive_disk_does(self):
        self.write(".git/HEAD")
        self.write(".env", "TOKEN=real")
        written, _, refused = self.pull([
            (".GIT/hooks/pre-commit", "file", "x"), (".Git/config", "file", "x"), (".CLAUDE/settings.json", "file", "{}"),
            (".Cortex/settings.json", "file", "{}"), (".MCP.JSON", "file", "{}"), (".Envrc", "file", "x"),
            (".ENV", "file", "TOKEN=attacker"), ("NODE_MODULES/.bin/eslint", "file", "x"),
            (".g‌it/config", "file", "x")])
        self.assertEqual((written, len(refused)), ([], 9))
        self.assertEqual(Path(self.root, ".env").read_text(), "TOKEN=real")

    def test_git_metadata_cannot_be_swapped_or_redirected(self):
        self.write(".git/HEAD", "ref: refs/heads/main")
        for kind, payload in (("file", "gitdir: .g\n"), ("sym", ".g")):
            _, _, refused = self.pull([(".g/config", "file", "[core]\nfsmonitor = evil"), (".git", kind, payload)])
            self.assertEqual(refused, [".git"])
            self.assertTrue(os.path.isdir(os.path.join(self.root, ".git")) and not os.path.islink(os.path.join(self.root, ".git")))
            self.assertTrue(self.exists(".git/HEAD"))
        denied = [".git/commondir", ".git/config.worktree", "sub/.git/config", "sub/.git/hooks/pre-commit",
                  ".git/modules/lib/config", ".git/modules/lib/hooks/post-checkout", ".git/worktrees/w/commondir"]
        allowed = [".git/refs/heads/main", ".git/modules/lib/HEAD", "sub/.git/HEAD"]
        written, _, refused = self.pull([(name, "file", "x") for name in denied + allowed] + [("new/.git", "dir", None)])
        self.assertEqual(sorted(refused), sorted(denied))
        self.assertEqual(sorted(written), sorted(allowed + ["new/.git"]))

    def test_a_directory_cannot_become_a_repository_that_git_takes_commands_from(self):
        config = "[core]\n\tbare = false\n\tworktree = ..\n\tfsmonitor = evil\n"
        _, _, refused = self.pull([("tools/HEAD", "file", "ref: refs/heads/main\n"), ("tools/objects", "dir", None),
                                   ("tools/refs", "dir", None), ("tools/config", "file", config),
                                   ("tools/hooks/post-checkout", "file", "#!/bin/sh"), ("./up/Head", "file", "x"),
                                   ("up/CONFIG", "file", config)])
        self.assertEqual(sorted(refused), ["tools/config", "tools/hooks/post-checkout", "up/CONFIG"])
        self.pull([("two/config", "file", config), ("two/objects", "dir", None), ("two/refs", "dir", None)])
        _, _, refused = self.pull([("two/HEAD", "file", "ref: refs/heads/main\n")])  # the other order, in two pulls
        self.assertEqual(refused, ["two/HEAD"])
        self.write(".git/config", "[core]\n")  # a real repository still gets its HEAD
        written, _, _ = self.pull([(".git/HEAD", "file", "ref: refs/heads/dev\n"), ("docs/config", "file", "plain")])
        self.assertEqual(sorted(written), [".git/HEAD", "docs/config"])

    def test_a_file_replacing_a_directory_keeps_what_was_never_mirrored(self):
        self.write("conf/.env", "TOKEN=real")
        self.write("conf/app.yml")
        self.write("conf/node_modules/x.js")
        known = {"conf": ["d"], "conf/app.yml": ["f"]}
        written, _, refused = self.pull([("conf", "file", "now a file")], known=known)
        self.assertEqual(written, [])
        self.assertEqual(len(refused), 1)
        self.assertEqual(Path(self.root, "conf/.env").read_text(), "TOKEN=real")
        self.assertTrue(self.exists("conf/node_modules/x.js"))
        self.write("gone/a.txt")  # fully mirrored and unchanged: the replacement goes through
        written, _, _ = self.pull([("gone", "file", "now a file")], known={"gone": ["d"], "gone/a.txt": ["f"]})
        self.assertEqual(written, ["gone"])
        self.assertTrue(os.path.isfile(os.path.join(self.root, "gone")))

    def test_pull_is_bounded_and_survives_hostile_members(self):
        _, _, refused = self.pull([("big.bin", "file", "x" * 2048), ("ok.txt", "file", "x")], max_bytes=1024)
        self.assertEqual(refused, ["big.bin (too large)"])
        with tarfile.open(self.archive, "w") as tar:
            for name, mtime in (("first.txt", 0), ("when.txt", 10 ** 30), ("last.txt", 0)):
                info = tarfile.TarInfo(name)
                info.size, info.mtime = 1, mtime
                tar.addfile(info, io.BytesIO(b"x"))
        written, _, refused = sbx.apply_pull_tar(self.root, self.archive, self.rules, set(), {})
        self.assertEqual((written, len(refused)), (["first.txt", "last.txt"], 1))
        self.assertEqual([name for name in os.listdir(self.root) if name.startswith(".sbx-")], [])
        with gzip.open(self.archive, "wb") as packed:  # a compressed archive could unpack to any size
            with tarfile.open(fileobj=packed, mode="w") as tar:
                info = tarfile.TarInfo("bomb.bin")
                info.size = 1
                tar.addfile(info, io.BytesIO(b"x"))
        with self.assertRaises(tarfile.TarError):
            sbx.apply_pull_tar(self.root, self.archive, self.rules, set(), {})
        self.assertFalse(self.exists("bomb.bin"))


class WayOut(Base):
    def test_agent_configuration_and_credential_files_are_not_mirrored(self):
        for rel in (".mcp.json", ".claude/settings.local.json", ".cortex/settings.json", ".cursor/mcp.json", ".envrc",
                    ".git-credentials", ".dockercfg", ".docker/config.json", ".kube/config", "kubeconfig",
                    "terraform.tfstate", "prod.tfvars", ".snowsql/config", "connections.toml", "client.p12",
                    "server.key", "id_ecdsa", ".Env", "certs/Server.PEM", ".vault-token", "gcp-service-account.json",
                    "src/app.py"):
            self.write(rel)
        self.assertEqual(set(sbx.scan(self.root, self.rules)), {"src", "src/app.py", "certs"})

    def test_git_config_is_pushed_without_credentials(self):
        self.write(".git/config", '[remote "origin"]\n\turl = https://x-access-token:SECRET1@github.com/o/r.git\n'
                                  '[http "https://github.com/"]\n\textraheader = AUTHORIZATION: basic SECRET2\n'
                                  '[remote "ssh"]\n\turl = ssh://git@github.com/o/r.git\n')
        self.write("sub/.git/config", "[remote \"o\"]\n\turl = https://SECRET3@example.com/r.git\n")
        packed, _ = sbx.build_push_tar(self.root, [".git", ".git/config", "sub", "sub/.git", "sub/.git/config"], [],
                                       self.archive, 10 ** 9)
        self.assertIn(".git/config", packed)
        with tarfile.open(self.archive) as tar:
            top = tar.extractfile(".git/config").read().decode()
            sub = tar.extractfile("sub/.git/config").read().decode()
        self.assertNotIn("SECRET", top + sub)
        self.assertIn("url = https://github.com/o/r.git", top)
        self.assertIn("url = ssh://git@github.com/o/r.git", top)

    def test_the_home_directory_is_not_a_project(self):
        cfg = {"backend": "openshell", "exclude": [], "secrets": [], "openshell": {}, "islo": {}}
        env = {"HOME": self.root, "SBX_STATE_DIR": os.path.join(self.tmp, "state")}
        with mock.patch.dict(os.environ, env):
            for root in (self.root, self.tmp, "/"):
                with self.assertRaisesRegex(sbx.SbxError, "home directory"):
                    sbx.Sandbox(root, cfg)
            inner = os.path.join(self.root, "code", "repo")
            os.makedirs(inner)
            try:
                sbx.Sandbox(inner, cfg)
            except sbx.SbxError as exc:  # no backend installed on this machine: a different refusal
                self.assertNotIn("home directory", str(exc))


class Hook(Base):
    def rewritten(self, command, env=None, raw=None):
        done = run_hook(raw if raw is not None else {"command": command}, self.root, env=env)
        self.assertEqual(done.returncode, 0, done.stderr)
        return json.loads(done.stdout)["hookSpecificOutput"]["updatedInput"]["command"]

    def test_modules_in_the_project_cannot_shadow_the_standard_library(self):
        canary = os.path.join(self.tmp, "host-canary")
        for module in ("json", "shlex", "tarfile", "re"):
            self.write(f"{module}.py", f"open({canary!r}, 'w').close()\nraise SystemExit(0)\n")
        env = dict(os.environ, PYTHONPATH=".", SBX_BACKEND="no-such-backend", SBX_STATE_DIR=os.path.join(self.tmp, "state"),
                   SBX_CONFIG=os.path.join(self.tmp, "none.json"))
        line = self.rewritten("echo hi", env=env)
        done = subprocess.run(["/bin/sh", "-c", line], cwd=self.root, env=env, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(done.returncode, 125, done.stderr)  # the real runner ran and refused the backend
        self.assertFalse(os.path.exists(canary))

    def test_a_word_that_starts_with_an_equals_sign_reaches_the_runner_unchanged(self):
        for command in ("=ls", "==x", "="):
            tail = self.rewritten(command).rsplit(" -- ", 1)[1]
            self.assertEqual(shlex.split(tail), [command])
            for shell in ("zsh", "bash", "sh"):
                if shutil.which(shell):
                    done = subprocess.run([shell, "-c", "printf %s " + tail], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    self.assertEqual((done.returncode, done.stdout.decode()), (0, command), shell)

    def test_an_answer_that_is_not_strict_json_is_never_printed(self):
        done = run_hook({"command": "echo hi", "timeout": float("nan")}, self.root)
        self.assertEqual((done.returncode, done.stdout), (2, b""))


if __name__ == "__main__":
    unittest.main()

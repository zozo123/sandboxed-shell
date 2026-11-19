"""Regression tests for the second review round, all without a sandbox."""
import argparse
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_local  # noqa: E402

sbx = test_local.sbx
make_tar = test_local.make_tar


def digest(rules):
    return rules.digest() if hasattr(rules, "digest") else None


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="sbx-delta-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root = os.path.join(self.tmp, "project")
        os.makedirs(self.root)
        self.rules = sbx.Rules({"exclude": [], "secrets": [], "allow": []})
        self.config = os.path.join(self.tmp, "config.json")
        saved = {key: os.environ.get(key) for key in ("SBX_STATE_DIR", "SBX_NAME", "SBX_CONFIG", "SBX_BACKEND")}
        self.addCleanup(lambda: [os.environ.pop(key, None) if value is None else os.environ.__setitem__(key, value)
                                 for key, value in saved.items()])
        os.environ.update(SBX_STATE_DIR=os.path.join(self.tmp, "state"), SBX_NAME="sbx-delta", SBX_CONFIG=self.config)
        os.environ.pop("SBX_BACKEND", None)

    def patch(self, owner, name, value):
        saved = getattr(owner, name)
        setattr(owner, name, value)
        self.addCleanup(setattr, owner, name, saved)

    def write(self, rel, text="x"):
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        Path(path).write_text(text)
        return path

    def pull(self, members, deleted=(), known=None, max_bytes=0):
        archive = os.path.join(self.tmp, "pull.tar")
        make_tar(archive, members, deleted)
        return sbx.apply_pull_tar(self.root, archive, self.rules, set(), known or {}, max_bytes)


class GitRules(Base):
    def test_every_git_in_a_path_is_checked_not_only_the_first(self):
        for path in (".git/refs/x/.git/config", ".git/refs/x/.git/hooks/pre-commit", ".git/refs/x/.git",
                     "sub/.git/objects/zz/.git/hooks/x", ".git/logs/x/.git/config", ".git/refs/x/.git/commondir"):
            self.assertTrue(sbx.Rules.pull_denied(path, False), path)
        self.assertFalse(sbx.Rules.pull_denied(".git/refs/heads/main", False))

    def test_a_link_below_git_is_refused(self):
        os.makedirs(os.path.join(self.root, ".git", "objects", "info"))
        written, _, refused = self.pull([(".git/objects/info", "sym", "../../stuff"), ("stuff", "dir", None),
                                         ("stuff/alternates", "file", "/elsewhere/objects\n")])
        self.assertIn(".git/objects/info", refused)
        self.assertFalse(os.path.exists(os.path.join(self.root, ".git/objects/info/alternates")))

    def test_reftable_returns_and_claude_local_md_does_not(self):
        self.assertFalse(sbx.Rules.pull_denied(".git/reftable/tables.list", False))
        self.assertFalse(sbx.Rules.pull_denied(".git/reftable", True))
        for path in ("CLAUDE.local.md", "pkg/claude.LOCAL.md"):
            self.assertTrue(sbx.Rules.pull_denied(path, False), path)

    def test_a_finished_rebase_may_remove_its_state_here_but_nothing_else_protected(self):
        for rel in (".git/rebase-merge/git-rebase-todo", ".git/hooks/pre-commit", ".git/config"):
            self.write(rel)
        known = {rel: ["f"] for rel in (".git/rebase-merge/git-rebase-todo", ".git/rebase-merge",
                                        ".git/hooks/pre-commit", ".git/config")}
        _, removed, _ = self.pull([], deleted=list(known), known=known)
        self.assertEqual(sorted(removed), [".git/rebase-merge", ".git/rebase-merge/git-rebase-todo"])
        self.assertTrue(sbx.Rules.pull_denied(".git/rebase-merge/git-rebase-todo", False))
        for rel in (".git/modules/rebase-merge/config", ".git/hooks/rebase-merge/x", "AGENTS.md"):
            self.assertTrue(sbx.Rules.delete_denied(rel), rel)

    def test_a_pack_that_did_not_arrive_does_not_cost_the_old_objects(self):
        old = [".git/objects/ab/cdef", ".git/objects/pack/pack-old.pack", ".git/refs/heads/main"]
        for rel in old + ["notes.txt"]:
            self.write(rel)
        known = {rel: ["f"] for rel in old + ["notes.txt"]}
        written, removed, refused = self.pull(
            [(".git/objects/pack/pack-new.pack", "file", "P" * 4096), (".git/packed-refs", "file", "refs\n")],
            deleted=old + ["notes.txt"], known=known, max_bytes=1024)
        self.assertEqual(removed, ["notes.txt"])
        for rel in old:
            self.assertTrue(os.path.exists(os.path.join(self.root, rel)), rel)
        self.assertIn(".git/objects/pack/pack-new.pack (too large)", refused)


class FakeBackend(sbx.Backend):
    name, cli = "openshell", "true"
    pull_tar = None

    def phase(self, sandbox):
        return "ready", "id1"

    def put(self, sandbox, local, remote):
        pass

    def get(self, sandbox, remote, local):
        shutil.copy(self.pull_tar, local)


class Unmirrored(Base):
    def setUp(self):
        super().setUp()
        self.backend = FakeBackend({})
        self.changes = ["0", "0", "1", "0"]
        self.patch(sbx, "pick_backend", lambda cfg: self.backend)
        self.patch(sbx.Sandbox, "_answer", lambda box, op, *args: list(self.changes) if op == "changes" else ["ok"])

    def box(self, limit):
        Path(self.config).write_text(json.dumps({"max_file_mb": limit}))
        box = sbx.Sandbox(self.root)
        box.state.update(meta="/m", remote_root="/r")
        return box

    def test_a_file_that_shrank_is_mirrored_and_the_sandbox_may_change_it_again(self):
        data = Path(self.root, "data.bin")
        data.write_bytes(os.urandom(2 * 1024 * 1024))
        self.assertEqual(self.box(1).sync()["pushed"], 0)
        data.write_text("small now\n")
        box = self.box(1)
        self.assertEqual(box.sync()["pushed"], 1)
        self.assertEqual(box.state["unmirrored"], {})
        self.backend.pull_tar = os.path.join(self.tmp, "from-sandbox.tar")
        make_tar(self.backend.pull_tar, [("data.bin", "file", "edited in the sandbox\n")])
        self.changes = ["1", "0", "2", "0"]
        report = self.box(1).sync()
        self.assertEqual((report["pulled"], report["refused"]), (1, []))
        self.assertEqual(data.read_text(), "edited in the sandbox\n")

    def test_a_raised_limit_offers_the_file_again(self):
        Path(self.root, "model.bin").write_bytes(os.urandom(2 * 1024 * 1024))
        self.assertEqual(self.box(1).sync()["pushed"], 0)
        self.assertFalse(self.box(1).local_dirty())
        self.assertTrue(self.box(200).local_dirty())
        box = self.box(200)
        self.assertEqual(box.sync()["pushed"], 1)
        self.assertEqual(box.state["unmirrored"], {})


class RecoveryAndSettings(Base):
    def test_unknown_identity_at_start_is_not_proof_that_the_command_did_not_run(self):
        calls = {"run": 0, "sync": 0}

        class Islo(sbx.Backend):
            name, cli, trust_seconds = "islo", "true", 120

            def phase(self, sandbox):
                if threading.current_thread() is not threading.main_thread():
                    raise sbx.SbxError("Islo is not reachable")
                return "ready", "id2"

        def sync(box):
            calls["sync"] += 1
            if calls["sync"] == 1:
                raise sbx.SbxError("sandbox helper 'changes' failed (exit 127)")
            return {}

        def run(box, command, session, rel, timeout_s, nonce):
            calls["run"] += 1
            return 0
        self.patch(sbx, "pick_backend", lambda cfg: Islo({}))
        self.patch(sbx.Sandbox, "_bootstrap", lambda box, ident: box.state.update(
            sandbox_id=ident, helper=sbx.HELPER_VERSION, rules=digest(box.rules), meta="/m", remote_root="/r",
            local={}, ack=""))
        self.patch(sbx.Sandbox, "local_dirty", lambda box: False)
        self.patch(sbx.Sandbox, "sync", sync)
        self.patch(sbx.Sandbox, "run", run)
        self.patch(sbx.Sandbox, "started", lambda box, nonce: False)
        state = os.path.join(self.tmp, "state", "sbx-delta")
        os.makedirs(state)
        Path(state, "state.json").write_text(json.dumps({
            "backend": "islo", "root": self.root, "ready": True, "last_ok": time.time(), "sandbox_id": "id1",
            "helper": sbx.HELPER_VERSION, "rules": digest(self.rules), "local": {}, "ack": "",
            "meta": "/m", "remote_root": "/r"}))
        with self.assertRaises(sbx.SbxError) as caught:
            sbx.cmd_run(argparse.Namespace(command="echo once >> ledger", root=self.root, session="s", timeout_ms=0))
        self.assertIn("result is unknown", str(caught.exception))
        self.assertEqual(calls["run"], 1)

    def test_changed_lists_reach_the_helper_in_a_sandbox_that_exists_already(self):
        installed = []
        self.patch(sbx, "pick_backend", lambda cfg: FakeBackend({}))
        self.patch(sbx.Sandbox, "_bootstrap", lambda box, ident: (installed.append(list(box.rules.kept)), box.state.update(
            sandbox_id=ident, helper=sbx.HELPER_VERSION, rules=digest(box.rules), meta="/m", remote_root="/r")))
        Path(self.config).write_text("{}")
        sbx.Sandbox(self.root).ensure()
        sbx.Sandbox(self.root).ensure()
        self.assertEqual(len(installed), 1)
        Path(self.config).write_text(json.dumps({"allow": [".env"]}))
        sbx.Sandbox(self.root).ensure()
        self.assertEqual(len(installed), 2)
        self.assertIn(".env", installed[-1])

    def test_size_limits_that_are_not_a_usable_number_are_refused(self):
        for text in ('{"max_file_mb": NaN}', '{"max_file_mb": Infinity}', '{"max_file_mb": 1e-9}'):
            Path(self.config).write_text(text)
            with self.assertRaises(sbx.SbxError, msg=text):
                sbx.load_config()
        Path(self.config).write_text('{"max_file_mb": 0.5}')
        self.assertEqual(sbx.load_config()["max_file_mb"], 0.5)

    def test_an_inline_command_fits_into_one_openshell_argument(self):
        self.assertLessEqual(len(sbx.b64("x" * sbx.INLINE_COMMAND_BYTES)), 32_768)


if __name__ == "__main__":
    unittest.main()

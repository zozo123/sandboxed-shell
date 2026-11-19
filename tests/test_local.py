"""What is mirrored and what is refused, without a sandbox: the scan rules, the push
archive, and every way a hostile sandbox could try to write outside the project."""
import importlib.util
import io
import os
import shutil
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

RUNNER = Path(__file__).resolve().parent.parent / "plugins" / "sandboxed-shell" / "bin" / "sbx.py"
spec = importlib.util.spec_from_file_location("sbx", RUNNER)
sbx = importlib.util.module_from_spec(spec)
sys.modules["sbx"] = sbx
spec.loader.exec_module(sbx)

CFG = {"exclude": [], "secrets": []}


def make_tar(path, members, deleted=()):
    """members: list of (name, kind, payload) with kind in file, dir, sym, hard, fifo."""
    with tarfile.open(path, "w") as tar:
        listing = b"".join(name.encode() + b"\0" for name in deleted)
        info = tarfile.TarInfo(f"{sbx.META}/deleted")
        info.size = len(listing)
        tar.addfile(info, io.BytesIO(listing))
        for name, kind, payload in members:
            info = tarfile.TarInfo(name)
            if kind == "file":
                data = payload.encode()
                info.size, info.mode = len(data), 0o755
                tar.addfile(info, io.BytesIO(data))
                continue
            info.type = {"dir": tarfile.DIRTYPE, "sym": tarfile.SYMTYPE,
                         "hard": tarfile.LNKTYPE, "fifo": tarfile.FIFOTYPE}[kind]
            info.linkname = payload or ""
            tar.addfile(info)


class Mirroring(unittest.TestCase):
    def setUp(self):
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="sbx-local-"))
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

    def pull(self, members, deleted=(), conflicts=(), known=None):
        make_tar(self.archive, members, deleted)
        return sbx.apply_pull_tar(self.root, self.archive, self.rules, set(conflicts), known or {})

    # -- what leaves this machine
    def test_scan_skips_secrets_caches_and_agent_config(self):
        for rel in ("src/app.py", ".env", ".env.local", ".env.example", "certs/server.pem", "id_rsa",
                    "node_modules/x/index.js", ".venv/bin/python", "pkg/__pycache__/a.pyc",
                    ".snowflake/connections.toml", ".aws/credentials", "deep/dir/.npmrc", ".git/HEAD"):
            self.write(rel)
        found = set(sbx.scan(self.root, self.rules))
        self.assertEqual(found, {"src", "src/app.py", ".env.example", "certs", "deep", "deep/dir",
                                 "pkg", ".git", ".git/HEAD"})

    def test_scan_does_not_follow_symlinks_out_of_the_project(self):
        outside = os.path.join(self.tmp, "outside")
        os.makedirs(outside)
        Path(outside, "secret.txt").write_text("s")
        os.symlink(outside, os.path.join(self.root, "link"))
        found = sbx.scan(self.root, self.rules)
        self.assertEqual(found["link"], ["l", outside])
        self.assertNotIn("link/secret.txt", found)

    def test_push_archive_carries_changes_and_deletions(self):
        self.write("a.txt", "A")
        self.write("dir/b.txt", "B")
        os.symlink("a.txt", os.path.join(self.root, "ln"))
        target = os.path.join(self.tmp, "push.tar")
        packed, skipped = sbx.build_push_tar(self.root, ["dir/b.txt", "a.txt", "dir", "ln", "gone.txt"],
                                             ["old.txt", "old dir/x"], target, 10 ** 9)
        self.assertEqual(sorted(packed), ["a.txt", "dir", "dir/b.txt", "ln"])
        self.assertEqual(skipped, [])
        with tarfile.open(target) as tar:
            names = tar.getnames()
            self.assertEqual(names[0], f"{sbx.META}/deleted")
            self.assertLess(names.index("dir"), names.index("dir/b.txt"))
            self.assertEqual(tar.extractfile(names[0]).read(), b"old.txt\0old dir/x\0")
            self.assertEqual(tar.getmember("ln").linkname, "a.txt")
            self.assertEqual(tar.getmember("a.txt").uid, 0)

    def test_push_archive_leaves_out_oversized_files(self):
        self.write("big.bin", "x" * 5000)
        packed, skipped = sbx.build_push_tar(self.root, ["big.bin"], [], os.path.join(self.tmp, "p.tar"), 1000)
        self.assertEqual((packed, skipped), ([], ["big.bin"]))

    # -- regressions
    def test_push_archive_lists_what_it_carries(self):
        self.write("a.txt", "A")
        self.write("-dash", "D")
        target = os.path.join(self.tmp, "push.tar")
        sbx.build_push_tar(self.root, ["a.txt", "-dash", "gone.txt"], [], target, 10 ** 9)
        with tarfile.open(target) as tar:
            self.assertEqual(tar.extractfile(f"{sbx.META}/pushed").read(), b"./-dash\0./a.txt\0")

    def test_pull_keeps_apart_names_this_disk_cannot_tell_apart(self):
        self.write("Probe")
        if not os.path.exists(os.path.join(self.root, "probe")):
            self.skipTest("this file system is case-sensitive")
        os.unlink(os.path.join(self.root, "Probe"))
        written, _, refused = self.pull([
            ("cc", "dir", None), ("cc/Case.txt", "file", "A"), ("cc/case.txt", "file", "b"),
            ("Dir", "dir", None), ("Dir/x", "file", "x"), ("dir", "dir", None), ("dir/y", "file", "y")])
        self.assertEqual(sorted(written), ["Dir", "Dir/x", "cc", "cc/Case.txt"])
        self.assertEqual(len(refused), 3)
        self.assertEqual(Path(self.root, "cc/Case.txt").read_text(), "A")
        self.assertEqual(os.listdir(os.path.join(self.root, "cc")), ["Case.txt"])
        self.assertEqual(os.listdir(os.path.join(self.root, "Dir")), ["x"])

    def test_failed_pull_leaves_no_temporary_file(self):
        from unittest import mock
        os.makedirs(os.path.join(self.root, "d"))
        with mock.patch("os.replace", side_effect=OSError(92, "Illegal byte sequence")):
            written, _, refused = self.pull([("d/f.txt", "file", "x")])
        self.assertEqual((written, len(refused)), ([], 1))
        self.assertEqual(os.listdir(os.path.join(self.root, "d")), [])

    def test_pull_never_removes_a_directory_holding_files_only_this_machine_has(self):
        self.write("conf/app.yaml", "a")
        self.write("conf/.env", "TOKEN=x")
        self.write("plain/a.txt", "a")
        known = {"conf": ["d"], "conf/app.yaml": ["f"], "plain": ["d"], "plain/a.txt": ["f"]}
        written, _, refused = self.pull([("conf", "file", "flat"), ("plain", "file", "flat")], known=known)
        self.assertEqual(written, ["plain"])
        self.assertEqual(len(refused), 1)
        self.assertEqual(Path(self.root, "conf/.env").read_text(), "TOKEN=x")
        self.assertTrue(os.path.isfile(os.path.join(self.root, "plain")))

    # -- what is allowed back onto this machine
    def test_pull_writes_files_dirs_and_inner_symlinks(self):
        written, removed, refused = self.pull([
            ("out/build.log", "file", "done"), ("empty", "dir", None), ("out/latest", "sym", "build.log")])
        self.assertEqual(sorted(written), ["empty", "out/build.log", "out/latest"])
        self.assertEqual((removed, refused), ([], []))
        self.assertEqual(Path(self.root, "out/build.log").read_text(), "done")
        self.assertEqual(os.readlink(os.path.join(self.root, "out/latest")), "build.log")
        self.assertTrue(os.access(os.path.join(self.root, "out/build.log"), os.X_OK))

    def test_pull_refuses_every_path_that_leaves_the_project(self):
        outside = os.path.join(self.tmp, "outside")
        os.makedirs(outside)
        os.symlink(outside, os.path.join(self.root, "users-own-link"))
        written, _, refused = self.pull([
            ("../escape.txt", "file", "x"),
            ("/abs/escape.txt", "file", "x"),
            ("a/../../escape.txt", "file", "x"),
            ("abs-link", "sym", "/etc"),
            ("up-link", "sym", "../../outside"),
            ("sub/sneaky", "sym", "../../outside"),
            ("users-own-link/planted.txt", "file", "x"),
            ("hard", "hard", "/etc/passwd"),
            ("pipe", "fifo", None),
            ("fine.txt", "file", "ok"),
        ])
        self.assertEqual(written, ["fine.txt"])
        self.assertEqual(len(refused), 9)
        self.assertEqual(os.listdir(outside), [])
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "escape.txt")))
        for name in ("abs-link", "up-link", "sub/sneaky", "hard", "pipe"):
            self.assertFalse(os.path.lexists(os.path.join(self.root, name)), name)

    def test_pull_cannot_write_through_a_symlink_from_the_same_archive(self):
        outside = os.path.join(self.tmp, "outside")
        os.makedirs(outside)
        self.pull([("d", "sym", "../outside"), ("d/planted", "file", "x"), ("e", "sym", "d"), ("e/planted", "file", "x")])
        self.assertEqual(os.listdir(outside), [])

    def test_pull_never_writes_paths_that_make_the_host_run_code(self):
        written, _, refused = self.pull([
            (".git/hooks/pre-commit", "file", "#!/bin/sh\nrm -rf ~"),
            (".git/config", "file", "[core]\nfsmonitor = evil"),
            (".claude/settings.json", "file", "{}"),
            (".cortex/settings.json", "file", "{}"),
            (".cortex", "dir", None),
            (".mcp.json", "file", "{}"),
            (".envrc", "file", "evil"),
            (".env", "file", "TOKEN=1"),
            ("node_modules/pkg/postinstall.js", "file", "x"),
            (".git/HEAD", "file", "ref: refs/heads/main"),
        ])
        self.assertEqual(written, [".git/HEAD"])
        self.assertEqual(len(refused), 9)
        for name in (".git/hooks", ".git/config", ".claude", ".cortex", ".mcp.json", ".envrc", ".env", "node_modules"):
            self.assertFalse(os.path.lexists(os.path.join(self.root, name)), name)

    def test_local_edits_win_over_sandbox_changes(self):
        self.write("both.txt", "local")
        written, _, refused = self.pull([("both.txt", "file", "remote"), ("only.txt", "file", "remote")],
                                        conflicts={"both.txt"})
        self.assertEqual((written, refused), (["only.txt"], ["both.txt"]))
        self.assertEqual(Path(self.root, "both.txt").read_text(), "local")

    def test_deletions_only_touch_files_this_machine_mirrored(self):
        self.write("synced.txt")
        self.write("mine.txt")
        self.write("dir/synced.txt")
        self.write("dir/node_modules/keep.js")
        self.write("edited.txt")
        known = {"synced.txt": 1, "dir": 1, "dir/synced.txt": 1, "edited.txt": 1}
        _, removed, _ = self.pull([], deleted=["synced.txt", "mine.txt", "dir", "dir/synced.txt", "edited.txt",
                                               "../outside.txt", ".git/config"],
                                  conflicts={"edited.txt"}, known=known)
        self.assertEqual(sorted(removed), ["dir/synced.txt", "synced.txt"])
        self.assertTrue(os.path.exists(os.path.join(self.root, "mine.txt")))
        self.assertTrue(os.path.exists(os.path.join(self.root, "edited.txt")))
        self.assertTrue(os.path.exists(os.path.join(self.root, "dir/node_modules/keep.js")))

    # -- configuration
    def test_openshell_is_the_only_backend(self):
        real = shutil.which
        try:
            shutil.which = lambda name: f"/bin/{name}"
            self.assertEqual(sbx.pick_backend({"backend": "auto"}).name, "openshell")
            self.assertEqual(sbx.pick_backend({"backend": "openshell"}).name, "openshell")
            for other in ("cloud", "host", "local"):
                with self.assertRaises(sbx.SbxError):
                    sbx.pick_backend({"backend": other})
            shutil.which = lambda name: None  # OpenShell not installed: fail, never fall back
            with self.assertRaises(sbx.SbxError):
                sbx.pick_backend({"backend": "auto"})
        finally:
            shutil.which = real

    def test_helper_script_is_valid_bash(self):
        if not shutil.which("bash"):
            self.skipTest("bash not installed")
        import subprocess
        done = subprocess.run(["bash", "-n"], input=sbx.HELPER.encode(), stderr=subprocess.PIPE)
        self.assertEqual(done.returncode, 0, done.stderr.decode())
        self.assertNotIn("$meta_name", sbx.HELPER)


if __name__ == "__main__":
    unittest.main()

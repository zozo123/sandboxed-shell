"""The hook contract and the one property everything rests on: no part of the agent's
command is interpreted by the host shell."""
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fake_agent import PLUGIN, run_hook, run_tool  # noqa: E402

CANARY = "{canary}"
# Each payload would create the canary file if any layer on the host interpreted it.
PAYLOADS = [
    "echo hello",
    "echo 'single quoted'",
    'echo "double $HOME quoted"',
    "echo $(touch {canary})",
    "echo `touch {canary}`",
    "cat < <(sh < <(echo 'touch {canary}'))",  # the shape used in CVE-2026-6442
    "true; touch {canary}",
    "true && touch {canary} || touch {canary}",
    "true\ntouch {canary}",
    "true\r\ntouch {canary}",
    "echo '; touch {canary}; '",
    "echo ' ; touch {canary} #",
    "echo \\'; touch {canary}",
    "x='a'\\''b'; touch {canary}",
    "echo ${IFS}x; touch${IFS}{canary}",
    "echo $'\\x27; touch {canary}; \\x27'",
    "!!; touch {canary}",
    "echo ~ * {a,b}; touch {canary}",
    "touch {canary} # héllo wörld ✓ 日本語",
    "printf '%s\\n' \"it's\" 'say \"hi\"' `echo back`; touch {canary}",
    "\ttouch {canary}\t",
    "",
    " ",
    "--help",
    "-rf /",
    "'",
    '"',
    "\\",
    "$",
    "''",
    "'\\''",
    "a" * 90_000 + "; touch {canary}",
]
SHELLS = [shell for shell in ("sh", "bash", "zsh", "dash", "ksh") if shutil.which(shell)]

FAKE_RUNNER = """import json, os, sys
with open(os.environ["SBX_TEST_ARGV"], "w") as handle:
    json.dump(sys.argv[1:], handle)
"""


class HookContract(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sbx-hook-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def hook(self, tool_input, tool_name="bash", env=None):
        return run_hook(tool_input, self.tmp, tool_name=tool_name, env=env)

    def test_other_tools_pass_untouched(self):
        for tool in ("read", "edit", "write", "sql_execute", "mcp__x__y"):
            entry_env = dict(os.environ)
            done = subprocess.run(
                [sys.executable, str(PLUGIN / "hooks" / "route_bash.py")],
                input=json.dumps({"tool_name": tool, "tool_input": {"command": "x"}}).encode(),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=entry_env)
            self.assertEqual(done.returncode, 0, tool)
            self.assertEqual(done.stdout, b"", tool)

    def test_shell_call_is_rewritten_and_other_fields_survive(self):
        for tool in ("bash", "Bash"):
            done = subprocess.run(
                [sys.executable, str(PLUGIN / "hooks" / "route_bash.py")],
                input=json.dumps({
                    "session_id": "abc/../123", "cwd": self.tmp, "tool_name": tool,
                    "tool_input": {"command": "ls -la", "description": "list", "timeout": 5000,
                                   "run_in_background": True},
                }).encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(done.returncode, 0, done.stderr)
            answer = json.loads(done.stdout)["hookSpecificOutput"]
            self.assertEqual(answer["hookEventName"], "PreToolUse")
            self.assertNotIn("permissionDecision", answer)  # the normal permission prompt still applies
            updated = answer["updatedInput"]
            self.assertEqual(updated["description"], "list")
            self.assertIs(updated["run_in_background"], True)
            argv = shlex.split(updated["command"])
            self.assertEqual(argv[-1], "ls -la")
            self.assertEqual(argv[1:3], ["-I", str(PLUGIN / "bin" / "sbx.py")])
            self.assertEqual(argv[argv.index("--session") + 1], "abc..123")
            self.assertEqual(argv[argv.index("--timeout-ms") + 1], "5000")
            self.assertEqual(argv[argv.index("--root") + 1], self.tmp)

    def test_coco_timeout_ms_reaches_the_runner(self):
        # CoCo 1.2.46 sends the limit as tool_input.timeout_ms (seen in a live session, 2026-11-19).
        for tool_input, expected in (({"command": "sleep 20", "timeout_ms": 5000}, "5000"),
                                     ({"command": "sleep 20", "timeout_ms": None, "timeout": 7000}, "7000"),
                                     ({"command": "sleep 20", "timeout_ms": True}, None)):
            done = subprocess.run(
                [sys.executable, str(PLUGIN / "hooks" / "route_bash.py")],
                input=json.dumps({"cwd": self.tmp, "tool_name": "Bash", "tool_input": tool_input}).encode(),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(done.returncode, 0, done.stderr)
            updated = json.loads(done.stdout)["hookSpecificOutput"]["updatedInput"]
            argv = shlex.split(updated["command"])
            if expected is None:
                self.assertNotIn("--timeout-ms", argv)
            else:
                self.assertEqual(argv[argv.index("--timeout-ms") + 1], expected)
            self.assertEqual(updated.get("timeout_ms"), tool_input.get("timeout_ms"))  # CoCo still enforces its own limit
            self.assertEqual(argv[-1], "sleep 20")

    def test_bad_input_blocks_with_exit_2(self):
        cases = [b"not json", b"{}"[:1], json.dumps({"tool_name": "bash"}).encode(),
                 json.dumps({"tool_name": "bash", "tool_input": {"command": 5}}).encode(),
                 json.dumps({"tool_name": "bash", "tool_input": {"command": "a\u0000b"}}).encode(),
                 json.dumps({"tool_name": "bash", "tool_input": "ls"}).encode()]
        for raw in cases:
            done = subprocess.run([sys.executable, str(PLUGIN / "hooks" / "route_bash.py")],
                                  input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(done.returncode, 2, raw)
            self.assertIn(b"did not run on this machine", done.stderr)

    def test_missing_interpreter_blocks_instead_of_falling_back(self):
        empty = os.path.join(self.tmp, "empty-bin")
        os.mkdir(empty)
        done = self.hook({"command": "touch x"}, env={"PATH": empty})
        self.assertEqual(done.returncode, 2)

    def test_user_can_opt_into_auto_approval(self):
        config = os.path.join(self.tmp, "config.json")
        Path(config).write_text(json.dumps({"permission": "allow"}))
        done = self.hook({"command": "ls"}, env=dict(os.environ, SBX_CONFIG=config))
        answer = json.loads(done.stdout)["hookSpecificOutput"]
        self.assertEqual(answer["permissionDecision"], "allow")

    def test_project_files_cannot_configure_the_hook(self):
        for name in ("config.json", ".sandboxed-shell.json", "sandbox.json"):
            Path(self.tmp, name).write_text(json.dumps({"permission": "allow", "backend": "host"}))
        done = self.hook({"command": "ls"}, env=dict(os.environ, SBX_CONFIG=os.path.join(self.tmp, "absent.json")))
        answer = json.loads(done.stdout)["hookSpecificOutput"]
        self.assertNotIn("permissionDecision", answer)


class HostShellNeverInterpretsTheCommand(unittest.TestCase):
    """Run the real hook, then the rewritten line in every shell on this machine, with a
    runner that only records its arguments. The canary must never appear."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="sbx-quote-")
        cls.plugin = Path(cls.tmp) / "plugin with space's"
        (cls.plugin / "hooks").mkdir(parents=True)
        (cls.plugin / "bin").mkdir()
        shutil.copy(PLUGIN / "hooks" / "route_bash.py", cls.plugin / "hooks" / "route_bash.py")
        shutil.copy(PLUGIN / "hooks" / "hooks.json", cls.plugin / "hooks" / "hooks.json")
        (cls.plugin / "bin" / "sbx.py").write_text(FAKE_RUNNER)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_every_payload_in_every_shell(self):
        self.assertGreaterEqual(len(SHELLS), 2, "need at least two shells to compare")
        canary = os.path.join(self.tmp, "canary")
        record = os.path.join(self.tmp, "argv.json")
        work = os.path.join(self.tmp, "work dir")
        os.makedirs(work, exist_ok=True)
        checked = 0
        for shell in SHELLS:
            for payload in PAYLOADS:
                command = payload.replace(CANARY, shlex.quote(canary))
                for path in (canary, record):
                    if os.path.exists(path):
                        os.unlink(path)
                result = run_tool(command, work, plugin=self.plugin, shell=shell,
                                  env=dict(os.environ, SBX_TEST_ARGV=record))
                label = f"{shell}: {payload[:60]!r}"
                self.assertFalse(result.blocked, label)
                self.assertFalse(result.hook_failed_open, label)
                self.assertEqual(result.returncode, 0, f"{label}: {result.stderr}")
                self.assertFalse(os.path.exists(canary), f"host shell interpreted the command ({label})")
                with open(record) as handle:
                    argv = json.load(handle)
                self.assertEqual(argv[-1], command, label)
                self.assertEqual(argv[0], "run", label)
                checked += 1
        self.assertEqual(checked, len(SHELLS) * len(PAYLOADS))


class ClaudeCodeFlavour(unittest.TestCase):
    """The Claude Code build differs only in three names; the hook is the same file."""

    def test_built_flavour_registers_the_Bash_tool_and_rewrites(self):
        import importlib.util
        script = PLUGIN.parent.parent / "scripts" / "make_claude_flavor.py"
        spec = importlib.util.spec_from_file_location("make_claude_flavor", script)
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        tmp = os.path.realpath(tempfile.mkdtemp(prefix="sbx-claude-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        flavour = builder.build(Path(tmp) / builder.NAME)
        self.assertFalse((flavour / ".cortex-plugin").exists())
        manifest = json.loads((flavour / ".claude-plugin" / "plugin.json").read_text())
        self.assertEqual(manifest["name"], "sandboxed-shell")
        self.assertNotIn("CoCo", manifest["description"])
        self.assertIn("Claude Code", manifest["description"])
        entry = json.loads((flavour / "hooks" / "hooks.json").read_text())["hooks"]["PreToolUse"][0]
        self.assertEqual(entry["matcher"], "Bash")
        self.assertIn("${CLAUDE_PLUGIN_ROOT}", entry["hooks"][0]["command"])
        self.assertNotIn("CORTEX", entry["hooks"][0]["command"])
        self.assertIsNone(run_hook({"command": "ls"}, tmp, plugin=flavour, tool_name="bash"))  # no entry for the other CLI
        done = run_hook({"command": "ls -la"}, tmp, plugin=flavour, tool_name="Bash", project=tmp)
        self.assertEqual(done.returncode, 0, done.stderr)
        argv = shlex.split(json.loads(done.stdout)["hookSpecificOutput"]["updatedInput"]["command"])
        self.assertEqual(argv[1:3], ["-I", str(flavour / "bin" / "sbx.py")])
        self.assertEqual(argv[argv.index("--root") + 1], tmp)
        self.assertEqual(argv[-1], "ls -la")


if __name__ == "__main__":
    unittest.main()

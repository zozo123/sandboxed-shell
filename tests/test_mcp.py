"""The MCP server: the protocol without a sandbox, and one real command when SBX_E2E=1."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

SERVER = Path(__file__).resolve().parent.parent / "plugins" / "islo" / "mcp" / "server.py"
RUNNER = SERVER.parent.parent / "bin" / "sbx.py"
LIVE = os.environ.get("SBX_E2E") == "1"


class Client:
    def __init__(self, cwd, env):
        self.proc = subprocess.Popen([sys.executable, str(SERVER)], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd, env=env)
        self.next_id = 0

    def notify(self, method):
        self.proc.stdin.write((json.dumps({"jsonrpc": "2.0", "method": method}) + "\n").encode())
        self.proc.stdin.flush()

    def call(self, method, params=None):
        self.next_id += 1
        message = {"jsonrpc": "2.0", "id": self.next_id, "method": method}
        if params is not None:
            message["params"] = params
        self.proc.stdin.write((json.dumps(message) + "\n").encode())
        self.proc.stdin.flush()
        reply = json.loads(self.proc.stdout.readline())
        assert reply["id"] == self.next_id, reply
        return reply

    def close(self):
        self.proc.stdin.close()
        self.proc.wait(timeout=10)
        self.proc.stdout.close()
        self.proc.stderr.close()


class McpServer(unittest.TestCase):
    def setUp(self):
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="sbx-mcp-"))
        self.project = os.path.join(self.tmp, "proj")
        os.makedirs(self.project)
        self.env = dict(os.environ, SBX_STATE_DIR=os.path.join(self.tmp, "state"),
                        SBX_CONFIG=os.path.join(self.tmp, "config.json"), CORTEX_PROJECT_DIR=self.project)
        self.env.pop("CLAUDE_PROJECT_DIR", None)
        self.client = Client(self.project, self.env)
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.addCleanup(self.client.close)

    def test_handshake_and_tool_list(self):
        hello = self.client.call("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                                "clientInfo": {"name": "test", "version": "0"}})["result"]
        self.assertEqual(hello["protocolVersion"], "2025-06-18")
        self.assertIn("tools", hello["capabilities"])
        self.client.notify("notifications/initialized")
        self.assertEqual(self.client.call("ping")["result"], {})
        tools = self.client.call("tools/list")["result"]["tools"]
        self.assertEqual([tool["name"] for tool in tools], ["sandbox_exec", "sandbox_status"])
        self.assertEqual(tools[0]["inputSchema"]["required"], ["command"])
        self.assertIn(self.project, tools[0]["description"])  # the copied folder is visible to the agent
        self.assertEqual(self.client.call("no/such/method")["error"]["code"], -32601)

    def test_bad_arguments_are_reported_not_run(self):
        for arguments in ({}, {"command": 5}, {"command": "a\u0000b"}):
            result = self.client.call("tools/call", {"name": "sandbox_exec", "arguments": arguments})["result"]
            self.assertTrue(result["isError"], arguments)
        result = self.client.call("tools/call", {"name": "host_exec", "arguments": {}})["result"]
        self.assertTrue(result["isError"])

    @unittest.skipUnless(LIVE, "set SBX_E2E=1 with a sandbox backend available")
    def test_command_runs_in_the_sandbox(self):
        self.addCleanup(subprocess.run, [sys.executable, str(RUNNER), "down", "--delete", "--root", self.project],
                        env=self.env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        Path(self.project, "data.txt").write_text("from the laptop\n")
        canary = os.path.join(self.tmp, "host-canary")
        result = self.client.call("tools/call", {"name": "sandbox_exec", "arguments": {
            "command": f"uname -s; cat data.txt; echo made > made.txt; touch '{canary}'; exit 3"}})["result"]
        text = result["content"][0]["text"]
        self.assertFalse(result["isError"])
        self.assertIn("Linux", text)
        self.assertIn("from the laptop", text)
        self.assertTrue(text.rstrip().endswith("[exit code 3]"), text)
        self.assertEqual(Path(self.project, "made.txt").read_text(), "made\n")
        self.assertFalse(os.path.exists(canary))
        status = self.client.call("tools/call", {"name": "sandbox_status", "arguments": {}})["result"]
        self.assertEqual(json.loads(status["content"][0]["text"])["phase"], "ready")

    @unittest.skipUnless(LIVE, "set SBX_E2E=1 with a sandbox backend available")
    def test_long_command_blocks_neither_ping_nor_cancel(self):
        self.addCleanup(subprocess.run, [sys.executable, str(RUNNER), "down", "--delete", "--root", self.project],
                        env=self.env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        Path(self.project, "data.txt").write_text("from the laptop\n")

        def send(message):
            self.client.proc.stdin.write((json.dumps(message) + "\n").encode())
            self.client.proc.stdin.flush()

        send({"jsonrpc": "2.0", "id": 100, "method": "tools/call",
              "params": {"name": "sandbox_exec", "arguments": {"command": "sleep 30"}}})
        time.sleep(4)
        started = time.time()
        self.assertEqual(self.client.call("ping")["result"], {})
        send({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 100}})
        self.assertEqual(json.loads(self.client.proc.stdout.readline())["id"], 100)
        self.assertLess(time.time() - started, 15)

if __name__ == "__main__":
    unittest.main()

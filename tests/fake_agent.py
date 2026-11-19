"""A stand-in for the agent harness (Cortex Code CLI or Claude Code).

It applies the documented PreToolUse contract to one shell tool call the way the real
CLI does: run the plugin's hook command with the event on stdin, block on exit code 2
or {"decision": "block"}, apply hookSpecificOutput.updatedInput, then hand the
resulting command line to a host shell. If the hook fails in any other way the
harness runs the ORIGINAL command on the host, exactly as the real CLIs do, so a
hook that fails open is caught by the tests.
"""
import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PLUGIN = REPO / "plugins" / "islo"


@dataclass
class Result:
    blocked: bool
    reason: str
    command_line: str
    returncode: int
    stdout: str
    stderr: str
    hook_failed_open: bool = False


def hook_entry(plugin=PLUGIN, tool_name="bash"):
    config = json.loads((Path(plugin) / "hooks" / "hooks.json").read_text())
    for entry in config["hooks"]["PreToolUse"]:
        if re.search(entry.get("matcher", ".*"), tool_name):
            return entry["hooks"][0]
    return None


def run_hook(tool_input, cwd, plugin=PLUGIN, tool_name="bash", session="test-session", env=None, project=None):
    entry = hook_entry(plugin, tool_name)
    if entry is None:
        return None
    command = entry["command"]
    for variable in ("CORTEX_PLUGIN_ROOT", "CLAUDE_PLUGIN_ROOT"):
        command = command.replace("${%s}" % variable, str(plugin))
    if project is not None:  # the real CLIs export the project directory to hook commands
        env = dict(os.environ if env is None else env)
        env["CLAUDE_PROJECT_DIR" if tool_name == "Bash" else "CORTEX_PROJECT_DIR"] = str(project)
    event = {
        "session_id": session,
        "transcript_path": "/dev/null",
        "cwd": str(cwd),
        "permission_mode": "default",
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": tool_input,
    }
    return subprocess.run(
        ["/bin/sh", "-c", command], input=json.dumps(event).encode(), cwd=str(cwd),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=entry.get("timeout", 60),
    )


def run_tool(command, cwd, plugin=PLUGIN, tool_name="bash", session="test-session",
             shell="bash", env=None, hook_env=None, timeout=300, project=None):
    """One shell tool call, end to end. Returns what the agent would see."""
    env = dict(os.environ if env is None else env)
    tool_input = {"command": command, "description": "test"}
    hook = run_hook(tool_input, cwd, plugin, tool_name, session,
                    hook_env if hook_env is not None else env, project)
    final, failed_open = command, False
    if hook is not None:
        if hook.returncode == 2:
            return Result(True, hook.stderr.decode("utf-8", "replace"), "", 2, "", "")
        if hook.returncode != 0:
            failed_open = True  # non-blocking hook error: the real CLI carries on with the original command
        elif hook.stdout.strip():
            answer = json.loads(hook.stdout)
            if answer.get("decision") == "block":
                return Result(True, answer.get("reason", ""), "", 2, "", "")
            updated = (answer.get("hookSpecificOutput") or {}).get("updatedInput")
            if updated:
                final = updated["command"]
    done = subprocess.run([shell, "-c", final], cwd=str(cwd), env=env, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    return Result(False, "", final, done.returncode, done.stdout.decode("utf-8", "replace"),
                  done.stderr.decode("utf-8", "replace"), failed_open)

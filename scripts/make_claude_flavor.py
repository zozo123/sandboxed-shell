#!/usr/bin/env python3
"""Build the Claude Code flavour of the plugin from the Cortex Code one.

The two CLIs share the hook contract. They differ in three names: the manifest
directory (.claude-plugin), the plugin-root variable (CLAUDE_PLUGIN_ROOT) and the
shell tool's name ("Bash"). The code is copied unchanged.

  python3 scripts/make_claude_flavor.py [OUTPUT_DIR]     default: dist/claude-code/sandboxed-shell
"""
import json
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SOURCE = REPO / "plugins" / "sandboxed-shell"
NAME = "sandboxed-shell"
DESCRIPTION = (
    "Runs the agent's shell commands in an NVIDIA OpenShell sandbox that holds a copy of the project, "
    "instead of on your machine. If no sandbox can be reached the command does not run (exit code 125). "
    "Claude Code on macOS and Linux. Prereqs: python3 (3.9+) and the openshell CLI with a reachable "
    "gateway. See SETUP.md."
)


def build(target: Path) -> Path:
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(SOURCE, target, ignore=shutil.ignore_patterns("__pycache__", ".cortex-plugin"))

    manifest = json.loads((SOURCE / ".cortex-plugin" / "plugin.json").read_text())
    manifest["name"] = NAME
    manifest["description"] = DESCRIPTION
    manifest["homepage"] = "https://github.com/zozo123/sandboxed-shell"
    manifest["repository"] = "https://github.com/zozo123/sandboxed-shell"
    manifest["license"] = "Apache-2.0"
    (target / ".claude-plugin").mkdir()
    (target / ".claude-plugin" / "plugin.json").write_text(json.dumps(manifest, indent=2) + "\n")

    hooks_file = target / "hooks" / "hooks.json"
    hooks = json.loads(hooks_file.read_text())
    for entry in hooks["hooks"]["PreToolUse"]:
        entry["matcher"] = "Bash"
        for hook in entry["hooks"]:
            hook["command"] = hook["command"].replace("${CORTEX_PLUGIN_ROOT}", "${CLAUDE_PLUGIN_ROOT}")
    hooks_file.write_text(json.dumps(hooks, indent=2) + "\n")
    return target


if __name__ == "__main__":
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO / "dist" / "claude-code" / NAME
    print(build(out))

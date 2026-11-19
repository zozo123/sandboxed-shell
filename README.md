# sandboxed-shell

Run your coding agent's shell commands in a sandbox instead of on your machine. Works with
Snowflake's CoCo CLI and with Claude Code. The sandbox is local with
[OpenShell](https://docs.nvidia.com/openshell/latest/) by default, or an
[Islo](https://islo.dev) cloud sandbox if you choose it.

## Three ways to use it

| Way | What it does | What it guarantees |
|---|---|---|
| Plugin | A hook sends each shell tool call to the sandbox. The project is copied in before the command and changed files are copied back after it | Commands run in the sandbox. See [Limits](#limits) for the cases where the agent's CLI can still run a command locally |
| Team setup (CoCo) | An administrator denies the built-in `bash` tool and deploys the bundled MCP server; the agent's only shell is `sandbox_exec` | The agent has no shell except the sandbox |
| Agent in the sandbox | CoCo itself runs inside an OpenShell sandbox whose network policy allows only your Snowflake account | Everything the agent does, not only shell commands, happens in the sandbox |

## Install

### CoCo CLI (plugin)

```
git clone https://github.com/zozo123/sandboxed-shell
cortex --plugin-dir "$PWD/sandboxed-shell/plugins/islo"
```

Setup, settings and the team setup: [plugins/islo/SETUP.md](plugins/islo/SETUP.md).

### Claude Code (plugin)

```
/plugin install sandboxed-shell --marketplace zozo123/sandboxed-shell
```

On Claude Code older than 2.1.275, add the marketplace first:
`/plugin marketplace add zozo123/sandboxed-shell`, then
`/plugin install sandboxed-shell@sandboxed-shell`.

### A sandbox backend

Install [OpenShell](https://docs.nvidia.com/openshell/latest/) and start a gateway
(`openshell status` should say Connected). For cloud sandboxes, install the Islo CLI, run
`islo login`, and set `{"backend": "islo"}` in `~/.config/sandboxed-shell/config.json`.

## Run CoCo itself inside OpenShell

Once, to keep your token in the OpenShell gateway instead of any sandbox:

```
SNOWFLAKE_ACCOUNT=myorg-myaccount SNOWFLAKE_TOKEN=<token> openshell/snowflake-provider.sh
```

Then, each time:

```
PROVIDER=snowflake SNOWFLAKE_ACCOUNT=myorg-myaccount SNOWFLAKE_USER=me@example.com \
  openshell/coco-in-openshell.sh "Run uname -s and list the files"
```

The script downloads Snowflake's Linux build of the CLI, checks its checksum, and runs your
prompt inside a sandbox. `SNOWFLAKE_USER` is your login name; for users created through
single sign-on that is usually your email.

How the token stays out: the provider profile
([openshell/providers/snowflake.yaml](openshell/providers/snowflake.yaml)) gives the
sandbox a placeholder in `SNOWFLAKE_CONNECTIONS_SNOWFLAKE_TOKEN`. OpenShell's proxy puts the
real token into the body of the sign-in request, and only that request. The only
destination allowed is your account host, and only CoCo may reach it. Tested on OpenShell
0.1.9: CoCo signed in and answered, the token was nowhere on the sandbox's disk, and a
shell in the sandbox could not reach Snowflake.

Two limits. The proxy replaces the placeholder anywhere in the sign-in request, so an agent
that writes its own sign-in request could get the real token echoed back by Snowflake; use a
short-lived token limited to one role. And the session token Snowflake returns after sign-in
is real.

Without the provider, pass `SNOWFLAKE_TOKEN=<token>` instead of `PROVIDER`. The token is
then streamed into a file inside the sandbox (never onto your machine), and commands in the
sandbox can read it.

## Tested

- CoCo CLI 1.2.46 on macOS, against a Snowflake account: commands from the agent, a
  subagent and a background command ran in the sandbox; `kill_shell` and time limits
  stopped them there; a failing hook blocked the call; Git hooks written in the sandbox did
  not reach the machine; with `bash` denied, the MCP tool ran the commands. CoCo itself ran
  inside OpenShell with only the Snowflake host reachable.
- 61 unit tests in CI on Linux and macOS, Python 3.9 and 3.14. They run 32 command strings,
  19 of them injection attempts, through sh, bash, zsh, dash and ksh, with a canary file that
  must never appear on the host.
- 39 end-to-end tests against real OpenShell 0.1.2 and 0.1.9 sandboxes, and the same 39
  through the Islo driver. Run them with
  `SBX_E2E=1 python3 -m unittest tests.test_e2e tests.test_mcp`.
- `openshell/coco-in-openshell.sh` on OpenShell 0.1.2 and 0.1.9: under a minute from nothing to
  an answer, with `pypi.org` blocked and the Snowflake host reachable.

## Limits

Measured in CoCo CLI 1.2.46:

- If the hook does not answer within its time limit (60 s), CoCo runs the original command
  on your machine. The hook normally answers in about 50 ms.
- Permission rules written for specific commands, such as `bash(git *)` or `bash(rm *)`,
  are checked against the rewritten command and stop matching. Rules for the whole `bash`
  tool still work.
- A user can switch a plugin off. Use the team setup or the agent-in-the-sandbox way when
  you need a guarantee.

What is copied, what never comes back, and the full list of limits:
[plugins/islo/README.md](plugins/islo/README.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

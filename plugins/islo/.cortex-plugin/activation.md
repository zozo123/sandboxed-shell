# Islo sandboxed shell

Enable this plugin to run the agent's shell commands in a sandbox instead of on your
machine. Use `/plugin enable islo`, then `/plugin reload`.

It works with CoCo CLI on macOS and Linux (on Windows, use WSL). It needs `python3` and
one sandbox backend: OpenShell (local, the default) or the Islo CLI (cloud, only if you
select it). Project files go to Islo only if you select that backend. If no sandbox can
be reached, shell commands fail with exit code 125 and do not run on your machine. Read,
edit, SQL and web tools are not affected. CoCo CLI also has its own sandbox; see
`/sandbox`.

Check your setup from your own terminal with `python3 <plugin directory>/bin/sbx.py doctor`.

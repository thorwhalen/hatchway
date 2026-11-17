# hatchway: working on it

An SSH forced command (`hatchway gate`) that runs only an allowlist kept as a TOML profile. Read `README.md` first; the security model paragraph is the contract.

- `policy.py` is pure: request string + profile + context -> `Decision`. Every new rule shape gets a test for its use and one for its abuse in `tests/test_policy.py`.
- `gate.py` runs a decision: `subprocess.run(argv)` with no shell, never `shell=True`, never `os.system`. It logs the request, never the output.
- `install.py` edits `authorized_keys`: back up first, keep every other line, refuse a key that does not match the strict regex (the comment is the injection point).
- No runtime dependencies. Every import is code that runs on an outside agent's behalf. The MCP transport (`mcp.py`) is the one exception, behind the optional `[mcp]` extra and imported lazily: the gate never loads it.
- `mcp.py` is an adapter, not a second policy: every tool call becomes request words and goes through a runner to the gate. Never decide anything there that `policy.decide` does not.
- Profiles list flags exactly; argparse in the target CLIs accepts abbreviations, so never match a flag by prefix.
- Bundled skills live in `hatchway/data/skills/` (`.claude/skills/` links to them). Nothing personal in this repo: keys, hostnames, tailnet names and session names go in the user's private config, never here.

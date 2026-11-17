---
name: hatchway
description: >-
  Connect an outside agent (a personal assistant on its own cloud VM such as Meta's Muse, another machine's scheduler, a phone shortcut) to the tools on this machine through one confined SSH key: `hatchway authorize` writes a forced-command authorized_keys line, the gate runs only an allowlist kept as a TOML profile, every call is logged, and a snapshot keeps the answers on disk. Use when asked to "let my assistant read my sessions", "give my assistant access to crowsnest", "set up a bridge", "allow an agent to SSH in but only run X", "forced command", "restricted SSH key", "lock down an agent's access", "what did the agent run", "revoke the agent", and to add a rule, a profile or a gated class. Not for exposing tools over MCP or HTTP (a different surface, not yet built).
---

# hatchway: one confined key for an outside agent

The agent gets a key. The key runs `hatchway gate`, nothing else. The gate runs what the profile allows, without a shell, and logs everything. Read `README.md` in the package for the full model; this skill is the procedure.

## Install a connection (idempotent: rerun any step)

1. **Read the profile first**: `hatchway help` (what the agent will be able to run). The bundled `claude-fleet` profile reads crowsnest and openloops; nothing in it kills, reaps, messages or writes into a session. Copy it to `~/.config/hatchway/profiles/<name>.toml` to change it.
2. **Tell the gate where the commands live**: sshd gives a forced command a minimal PATH. Put the directories of `crowsnest`, `ol`, `claude`, `gh` (from `which`) in `~/.config/hatchway/config.toml` as `path = [...]`.
3. **Prove the gate before any key exists**, with sshd's environment:
   `env -i HOME=$HOME PATH=/usr/bin:/bin SSH_ORIGINAL_COMMAND="crowsnest triage -q" $(which hatchway) gate --agent test`
   and once more with a forbidden request (`cat ~/.ssh/id_ed25519`, expect exit 126). `hatchway check "<request>"` shows the decision without running anything.
4. **Authorise the key**: `hatchway authorize "<the agent's whole public key line>" --agent <name>`. It backs up `authorized_keys`, keeps every other line, adds `restrict` and `from=` Tailscale's ranges. `conflict` means that key is already there with other options: show the user both lines, never pass `--replace` on your own.
5. **Snapshot timer** (optional, for pulling without waiting): `hatchway snapshot` once, then `hatchway schedule --every 300`.
6. **Skills**: `hatchway install-skills --home ~/.claude --home <each other Claude home>`. Report `conflict` rows; never `--force` over a file that is not ours.

## What only the user can do (file it as a `manual-task`, do not hand over steps)

- Turn sshd on if it is off (macOS: Remote Login; Linux: the ssh service). Check with `nc -z localhost 22`.
- Join this machine to the tailnet and approve the agent's device.
- **The Tailscale policy**, which is the other half of the security model: the agent's device may reach **only TCP port 22** of the machines it serves, and gets **no `ssh` rule**. Tailscale SSH authenticates by tailnet identity and never reads `authorized_keys`, so it would bypass the gate. A grant to paste into the tailnet policy file:
  ```json
  {"grants": [{"src": ["tag:agent"], "dst": ["tag:fleet"], "ip": ["tcp:22"]}]}
  ```
  with the agent's device tagged `tag:agent`, the machines `tag:fleet`, and no `ssh` section naming `tag:agent`.
- Switching dispatch on: `touch ~/.config/hatchway/allow-dispatch` plus `[dispatch] roots = [...]` in the config. A started session runs with the user's permissions; never switch it on yourself.

## Operating it

- `hatchway log -n 50`: what the agent asked, allowed or refused, and the exit status (never the output).
- `hatchway revoke --agent <name>`: removes the key's line, after a backup.
- A refused request the agent legitimately needs is a profile change: add a rule with the narrowest flags, a test in `tests/test_policy.py` for the shape and for its abuse, and never a rule whose argv is a shell, an interpreter, `cat`, `rsync`, `scp` or `ssh`.
- Profile rules list flags exactly. Argparse accepts abbreviations (`--out` as `--ou`), so never allow a flag by prefix, and keep writing flags (`--out`, `--backfill`, `--home`) out of read rules.

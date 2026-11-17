# hatchway.install

Putting a hatch on a machine: the `authorized_keys` line, the snapshot timer, the skills.

Every function here is idempotent, backs a file up before changing it (into
`<data>/backups/`), and has a `dry_run` that says what it would do.

### Functions

| [`authorize`](#hatchway.install.authorize)(public_key, \*, agent[, profile, ...])   | Add (or confirm) the gate's line for `public_key`, keeping every other line.                                                                   |
|-----------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------|
| `backup`(path, \*, settings)                                                                        |                                                                                                                                                |
| [`claude_homes`](#hatchway.install.claude_homes)()                                     | Every Claude Code home here: `~/.claude` and `~/.claude-*` with a skills folder.                                                               |
| [`hatchway_bin`](#hatchway.install.hatchway_bin)()                                     | The absolute path of this install's `hatchway` script, for the forced command.                                                                 |
| [`install_schedule`](#hatchway.install.install_schedule)(\*[, every, dry_run])             | Write the units and load them (launchd on macOS, systemd --user on Linux).                                                                     |
| [`install_skills`](#hatchway.install.install_skills)(\*[, homes, force, dry_run])        | Link the bundled skills (and agents, if any) into each Claude home.                                                                            |
| [`key_line`](#hatchway.install.key_line)(public_key, \*, agent[, profile, ...])    | The `authorized_keys` line that confines `public_key` to the gate.                                                                             |
| [`revoke`](#hatchway.install.revoke)(agent, \*[, authorized_keys, dry_run, ...]) | Remove every line whose forced command is the gate for `agent`.                                                                                |
| [`schedule_units`](#hatchway.install.schedule_units)(\*[, every, binary])                | The files that run `hatchway snapshot` every `every` seconds, for this OS.                                                                     |
| [`self_test`](#hatchway.install.self_test)(\*[, settings])                          | Run the gate as sshd would (empty environment) on one allowed and one forbidden request.                                                       |
| [`setup`](#hatchway.install.setup)(public_key, \*, agent[, every, skills, ...]) | Everything a machine needs, in order, stopping before the key if the gate fails: config, self-test, authorize, snapshot and its timer, skills. |
| [`write_config`](#hatchway.install.write_config)(\*[, tools, profile, settings])       | Write `config.toml` with `path` set to where `tools` live, unless one exists.                                                                  |

### hatchway.install.authorize(public_key, , agent, profile=None, from_='100.64.0.0/10,fd7a:115c:a1e0::/48', authorized_keys='~/.ssh/authorized_keys', replace=False, dry_run=False, settings=None)

Add (or confirm) the gate’s line for `public_key`, keeping every other line.

Returns `{"action": "added" | "ok" | "replaced" | "conflict", ...}`. A line for the
same key with different options is a `conflict` unless `replace`.

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)

### hatchway.install.claude_homes()

Every Claude Code home here: `~/.claude` and `~/.claude-*` with a skills folder.

* **Return type:**
  [`list`](https://docs.python.org/3/builtins/stdtypes.html#list)[[`Path`](https://docs.python.org/3/library/pathlib.html#pathlib.Path)]

### hatchway.install.hatchway_bin()

The absolute path of this install’s `hatchway` script, for the forced command.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### hatchway.install.install_schedule(, every=300, dry_run=False)

Write the units and load them (launchd on macOS, systemd –user on Linux).

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)

### hatchway.install.install_skills(, homes=None, force=False, dry_run=False)

Link the bundled skills (and agents, if any) into each Claude home. Idempotent;
something else already at a name is reported as `conflict` and left alone.

* **Return type:**
  [`list`](https://docs.python.org/3/builtins/stdtypes.html#list)[[`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)]

### hatchway.install.key_line(public_key, , agent, profile=None, from_='100.64.0.0/10,fd7a:115c:a1e0::/48', binary=None)

The `authorized_keys` line that confines `public_key` to the gate.

```pycon
>>> key_line("ssh-ed25519 AAAAC3Nz hatch", agent="muse", binary="/b/hatchway")
'command="/b/hatchway gate --agent muse",restrict,from="100.64.0.0/10,fd7a:115c:a1e0::/48" ssh-ed25519 AAAAC3Nz hatch'
```

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### hatchway.install.revoke(agent, , authorized_keys='~/.ssh/authorized_keys', dry_run=False, settings=None)

Remove every line whose forced command is the gate for `agent`.

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)

### hatchway.install.schedule_units(, every=300, binary=None)

The files that run `hatchway snapshot` every `every` seconds, for this OS.

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str), [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]

### hatchway.install.self_test(, settings=None)

Run the gate as sshd would (empty environment) on one allowed and one forbidden
request. `ok` is false if the forbidden one was allowed or the allowed one refused.

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)

### hatchway.install.setup(public_key, , agent, every=300, skills=True, settings=None)

Everything a machine needs, in order, stopping before the key if the gate fails:
config, self-test, authorize, snapshot and its timer, skills. Idempotent.

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)

### hatchway.install.write_config(, tools=('crowsnest', 'ol', 'claude', 'gh'), profile='claude-fleet', settings=None)

Write `config.toml` with `path` set to where `tools` live, unless one exists.

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)

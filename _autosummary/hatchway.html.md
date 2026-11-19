# hatchway

hatchway: a narrow, logged opening through which an outside agent reaches your tools.

An agent that lives elsewhere (a personal assistant on its own cloud VM, a phone
shortcut, another machine’s scheduler) gets one SSH key. That key can do one thing:
run [`gate()`](#hatchway.gate), which reads the requested command line, checks it against a profile
(an allowlist kept as data), logs it, and runs it without a shell, or refuses.

```pycon
>>> from hatchway import decide, load_profile
>>> profile = load_profile("claude-fleet")
>>> decide("crowsnest triage --quiet", profile).allowed
True
>>> decide("crowsnest spawn x --prompt hi", profile).allowed   # gated off by default
False
```

### Functions

| [`authorize`](#hatchway.authorize)(public_key, \*, agent[, profile, ...])   | Add (or confirm) the gate's line for `public_key`, keeping every other line.                        |
|-----------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------|
| [`decide`](#hatchway.decide)(request, profile, \*[, flags_present, ...]) | Decide what to do with `request` (the agent's command line, as SSH hands it).                       |
| [`describe`](#hatchway.describe)(profile)                                  | One line per rule, for the `help` answer an agent gets.                                             |
| [`gate`](#hatchway.gate)([request, agent, profile, settings])          | Decide and run one request.                                                                         |
| [`install_schedule`](#hatchway.install_schedule)(\*[, every, dry_run])             | Write the units and load them (launchd on macOS, systemd --user on Linux).                          |
| [`install_skills`](#hatchway.install_skills)(\*[, homes, force, dry_run])        | Link the bundled skills (and agents, if any) into each Claude home.                                 |
| [`key_line`](#hatchway.key_line)(public_key, \*, agent[, profile, ...])    | The `authorized_keys` line that confines `public_key` to the gate.                                  |
| `load_profile`([name_or_path, settings])                                                            |                                                                                                     |
| [`load_settings`](#hatchway.load_settings)(\*[, config_file])                   | Read `config.toml` (absent is fine) into [`Settings`](#hatchway.Settings). |
| [`revoke`](#hatchway.revoke)(agent, \*[, authorized_keys, dry_run, ...]) | Remove every line whose forced command is the gate for `agent`.                                     |
| [`snapshot`](#hatchway.snapshot)(\*[, profile, settings])                  | Run every snapshot request once; return the index that was written.                                 |

### Classes

| [`Decision`](#hatchway.Decision)(allowed, request[, reason, rule, ...])   | What the gate does with a request: run `argv`, print `path`, or refuse.   |
|----------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------|
| [`Profile`](#hatchway.Profile)(rules[, classes, name, snapshot, ...])    | A named set of rules plus the gating of their classes.                    |
| [`Rule`](#hatchway.Rule)(match[, argv, kind, klass, flags, ...])      | One allowed command shape.                                                |
| [`Settings`](#hatchway.Settings)([profile, path, timeout, roots, ...])    | The resolved configuration the gate and the snapshot run with.            |

### *class* hatchway.Decision(allowed, request, reason='', rule=None, argv=(), path='', stdin=None)

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

What the gate does with a request: run `argv`, print `path`, or refuse.

### *class* hatchway.Profile(rules, classes=dict(), name='', snapshot=(), instructions='')

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

A named set of rules plus the gating of their classes.

#### rule_for(tokens)

The rule with the longest `match` that prefixes `tokens`.

* **Return type:**
  [`Rule`](hatchway.policy.html.md#hatchway.policy.Rule) | [`None`](https://docs.python.org/3/builtins/constants.html#None)

### *class* hatchway.Rule(match, argv=(), kind='exec', klass='read', flags=frozenset({}), value_flags=(), max_positional=0, min_positional=0, positional_pattern='[A-Za-z0-9][A-Za-z0-9._@:+-]{0,127}', root='', help='', tool='', arg='', param='', stdin='', reply='', tail=())

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

One allowed command shape.

`kind` is `exec` (run `argv` plus the checked extras) or `file` (print one
file, named by the single positional argument, from the directory `root`).
`klass` groups rules for gating: a class listed in the profile’s `[classes]`
table with `requires_flag` is refused until that flag file exists.

`tool`, `param` and `arg` only name things for other transports (the MCP
tool’s name, its positional parameter’s name and that parameter’s description); `stdin` names a `free` value flag
whose value is written to the command’s standard input instead of its arguments,
so a body of text (a note to publish) never lands in `argv`. `reply` shapes a
successful answer for those transports: a template whose only field is `{out}`, the
command’s output stripped (a published link turned into a line to paste elsewhere).
`tail` is fixed words placed after the request’s arguments (`-`, for a command
that reads its text from standard input only in that position).

### *class* hatchway.Settings(profile='claude-fleet', path=list(), timeout=120, roots=dict(), dispatch_roots=list(), snapshot_to='', config_dir=config_dir(), data_dir=data_dir())

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

The resolved configuration the gate and the snapshot run with.

#### all_roots()

File-rule roots: `out` (the snapshot) always, plus the configured ones.

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str), [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]

### hatchway.authorize(public_key, , agent, profile=None, from_='100.64.0.0/10,fd7a:115c:a1e0::/48', authorized_keys='~/.ssh/authorized_keys', replace=False, dry_run=False, settings=None)

Add (or confirm) the gate’s line for `public_key`, keeping every other line.

Returns `{"action": "added" | "ok" | "replaced" | "conflict", ...}`. A line for the
same key with different options is a `conflict` unless `replace`.

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)

### hatchway.decide(request, profile, , flags_present=frozenset({}), dispatch_roots=(), roots=None)

Decide what to do with `request` (the agent’s command line, as SSH hands it).

`flags_present` names the flag files that exist (a gated class needs its flag);
`dispatch_roots` are the directories a `path_under_roots` value must sit in;
`roots` maps a file rule’s `root` name to a directory.

```pycon
>>> p = Profile.from_dict({"rule": [
...     {"match": ["snapshot"], "kind": "file", "root": "out"}]})
>>> decide("snapshot ../../.ssh/id_ed25519", p, roots={"out": "/tmp/o"}).allowed
False
```

* **Return type:**
  [`Decision`](hatchway.policy.html.md#hatchway.policy.Decision)

### hatchway.describe(profile)

One line per rule, for the `help` answer an agent gets.

* **Return type:**
  [`list`](https://docs.python.org/3/builtins/stdtypes.html#list)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]

### hatchway.gate(request=None, , agent='agent', profile=None, settings=None)

Decide and run one request. `request` defaults to `$SSH_ORIGINAL_COMMAND`.

* **Return type:**
  [`int`](https://docs.python.org/3/builtins/functions.html#int)

### hatchway.install_schedule(, every=300, dry_run=False)

Write the units and load them (launchd on macOS, systemd –user on Linux).

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)

### hatchway.install_skills(, homes=None, force=False, dry_run=False)

Link the bundled skills (and agents, if any) into each Claude home. Idempotent;
something else already at a name is reported as `conflict` and left alone.

* **Return type:**
  [`list`](https://docs.python.org/3/builtins/stdtypes.html#list)[[`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)]

### hatchway.key_line(public_key, , agent, profile=None, from_='100.64.0.0/10,fd7a:115c:a1e0::/48', binary=None)

The `authorized_keys` line that confines `public_key` to the gate.

```pycon
>>> key_line("ssh-ed25519 AAAAC3Nz hatch", agent="muse", binary="/b/hatchway")
'command="/b/hatchway gate --agent muse",restrict,from="100.64.0.0/10,fd7a:115c:a1e0::/48" ssh-ed25519 AAAAC3Nz hatch'
```

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### hatchway.load_settings(, config_file=None, \*\*overrides)

Read `config.toml` (absent is fine) into [`Settings`](#hatchway.Settings).

* **Return type:**
  [`Settings`](hatchway.config.html.md#hatchway.config.Settings)

### hatchway.revoke(agent, , authorized_keys='~/.ssh/authorized_keys', dry_run=False, settings=None)

Remove every line whose forced command is the gate for `agent`.

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)

### hatchway.snapshot(, profile=None, settings=None)

Run every snapshot request once; return the index that was written.

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)

### Modules

| [`config`](hatchway.config.html.md#module-hatchway.config)   | Where hatchway keeps its configuration and its records, and how a profile is found.            |
|----------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------|
| [`install`](hatchway.install.html.md#module-hatchway.install) | Putting a hatch on a machine: the `authorized_keys` line, the snapshot timer, the skills.      |
| [`mcp`](hatchway.mcp.html.md#module-hatchway.mcp)         | The second transport: a profile served as MCP tools, one tool per rule.                        |
| [`policy`](hatchway.policy.html.md#module-hatchway.policy)   | The allowlist: which command lines an outside agent may run, decided without running anything. |

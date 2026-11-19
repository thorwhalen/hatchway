# hatchway.policy

The allowlist: which command lines an outside agent may run, decided without running anything.

A *profile* is data (a TOML file) listing *rules*. A rule names the words the agent
sends (`match`), what actually runs (`argv`), and exactly which extra flags and
positional arguments it may add. Everything not described is refused. Deciding is a
pure function of the request string, the profile and a little context (which flag
files exist, which directories dispatch may use), so it is tested without a shell.

```pycon
>>> profile = Profile.from_dict({
...     "rule": [
...         {"match": ["crowsnest", "triage"], "argv": ["crowsnest", "triage", "-a"],
...          "flags": ["-q", "--json"]},
...     ]
... })
>>> decide("crowsnest triage -q", profile).argv
('crowsnest', 'triage', '-a', '-q')
>>> decide("crowsnest triage; rm -rf ~", profile).allowed
False
```

### Functions

| [`decide`](#hatchway.policy.decide)(request, profile, \*[, flags_present, ...])   | Decide what to do with `request` (the agent's command line, as SSH hands it).   |
|-------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------|
| [`describe`](#hatchway.policy.describe)(profile)                                    | One line per rule, for the `help` answer an agent gets.                         |

### Classes

| [`Decision`](#hatchway.policy.Decision)(allowed, request[, reason, rule, ...])   | What the gate does with a request: run `argv`, print `path`, or refuse.                                                |
|----------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------|
| [`Profile`](#hatchway.policy.Profile)(rules[, classes, name, snapshot, ...])    | A named set of rules plus the gating of their classes.                                                                 |
| [`Rule`](#hatchway.policy.Rule)(match[, argv, kind, klass, flags, ...])      | One allowed command shape.                                                                                             |
| [`ValueFlag`](#hatchway.policy.ValueFlag)(names[, pattern, free, ...])            | A flag that takes one value, checked against `pattern` (or free text, or a directory under one of the dispatch roots). |

### *class* hatchway.policy.Decision(allowed, request, reason='', rule=None, argv=(), path='', stdin=None)

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

What the gate does with a request: run `argv`, print `path`, or refuse.

### *class* hatchway.policy.Profile(rules, classes=dict(), name='', snapshot=(), instructions='')

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

A named set of rules plus the gating of their classes.

#### rule_for(tokens)

The rule with the longest `match` that prefixes `tokens`.

* **Return type:**
  [`Rule`](#hatchway.policy.Rule) | [`None`](https://docs.python.org/3/builtins/constants.html#None)

### *class* hatchway.policy.Rule(match, argv=(), kind='exec', klass='read', flags=frozenset({}), value_flags=(), max_positional=0, min_positional=0, positional_pattern='[A-Za-z0-9][A-Za-z0-9._@:+-]{0,127}', root='', help='', tool='', arg='', param='', stdin='', reply='', tail=())

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

### *class* hatchway.policy.ValueFlag(names, pattern='[A-Za-z0-9][A-Za-z0-9._@:+-]{0,127}', free=False, path_under_roots=False)

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

A flag that takes one value, checked against `pattern` (or free text, or a
directory under one of the dispatch roots).

### hatchway.policy.decide(request, profile, , flags_present=frozenset({}), dispatch_roots=(), roots=None)

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
  [`Decision`](#hatchway.policy.Decision)

### hatchway.policy.describe(profile)

One line per rule, for the `help` answer an agent gets.

* **Return type:**
  [`list`](https://docs.python.org/3/builtins/stdtypes.html#list)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]

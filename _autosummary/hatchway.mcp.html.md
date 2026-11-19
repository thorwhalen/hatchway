# hatchway.mcp

The second transport: a profile served as MCP tools, one tool per rule.

The SSH gate is the way in for an agent that can open SSH. An agent that speaks MCP but
cannot (a claude.ai custom connector, Claude Desktop, another machine’s MCP client) gets
the same allowlist here: each rule of the profile becomes one tool whose parameters are
the rule’s flags and names, and every call is turned back into the request words and
handed to a *runner*, which takes it through the gate. So the same `decide()`, the same
log, the same gated classes, the same one-call-at-a-time lock, whichever way it arrived.

```pycon
>>> from hatchway.policy import Profile
>>> p = Profile.from_dict({"rule": [{"match": ["crowsnest", "triage"],
...     "argv": ["crowsnest", "triage"], "flags": ["-q", "--quiet"]}]})
>>> calls = []
>>> tools = mk_tools(p, runner=lambda req: calls.append(req) or Result(0, "ok", ""))
>>> [t.__name__ for t in tools]
['crowsnest_triage']
>>> tools[0](quiet=True)
'ok'
>>> calls
['crowsnest triage --quiet']
```

The runner is the seam. [`local_runner()`](#hatchway.mcp.local_runner) (the default) runs the gate on this machine;
[`ssh_runner()`](#hatchway.mcp.ssh_runner) sends the request over SSH to a key whose forced command is the gate,
which is how a process running as its own account reaches a machine’s tools without
holding any of their credentials. Building the server needs `fastmcp`
(`pip install 'hatchway[mcp]'`); nothing else in hatchway imports it.

### Module Attributes

| [`DFLT_MAX_CHARS`](#hatchway.mcp.DFLT_MAX_CHARS)        | how many characters of a command's output one tool call returns; the rest is paged                                                |
|------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------|
| [`DFLT_CLASSES`](#hatchway.mcp.DFLT_CLASSES)          | reading only                                                                                                                      |
| [`REFUSED`](#hatchway.mcp.REFUSED)               | the gate's exit statuses a runner may see                                                                                         |
| [`BUSY`](#hatchway.mcp.BUSY)                  | the gate's exit statuses a runner may see                                                                                         |
| [`DFLT_FAN_OUT_DEADLINE`](#hatchway.mcp.DFLT_FAN_OUT_DEADLINE) | how long one machine of a [`fan_out()`](#hatchway.mcp.fan_out) may take before it is named as not answering |
| [`DFLT_FAN_OUT_TTL`](#hatchway.mcp.DFLT_FAN_OUT_TTL)      | how long a merged answer is reused for the same request, so its pages hold still                                                  |
| [`LATE`](#hatchway.mcp.LATE)                  | the exit status of a part that missed its deadline (the far side may still be running)                                            |

### Functions

| [`fan_out`](#hatchway.mcp.fan_out)(runners, \*[, label, is_down, ...])       | Ask every runner at once and merge their answers, each part labelled with its name.       |
|----------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------|
| [`local_runner`](#hatchway.mcp.local_runner)(\*[, agent, profile, timeout, ...])  | Run each request through `hatchway gate` on this machine, as this user.                   |
| [`mk_server`](#hatchway.mcp.mk_server)([profile, runner, settings, ...])       | A `FastMCP` server over `profile`'s rules.                                                |
| [`mk_tool`](#hatchway.mcp.mk_tool)(rule, \*, runner[, max_chars])            | One callable for `rule`, with a real signature, so any MCP host can type it.              |
| [`mk_tools`](#hatchway.mcp.mk_tools)(profile, \*, runner[, classes, ...])     | The tools for every rule of `profile` in one of `classes`, in profile order.              |
| [`routed_runner`](#hatchway.mcp.routed_runner)(default, routes)                    | Send a request to the runner of the longest leading words it matches in `routes`.         |
| [`ssh_runner`](#hatchway.mcp.ssh_runner)(destination, \*[, identity, ssh, ...]) | Send each request over SSH to `destination`, whose key's forced command is the gate.      |
| [`tag_lines`](#hatchway.mcp.tag_lines)(name, text)                             | Every non-blank line of `text` prefixed with `[name]`, so merged rows say whose they are. |
| [`tool_name`](#hatchway.mcp.tool_name)(rule)                                   | The MCP name of a rule: its `tool` key, else its words joined by underscores.             |
| [`unreachable`](#hatchway.mcp.unreachable)(result)                               | Whether `result` is ssh failing to connect, as opposed to the far side answering.         |
| [`with_fallback`](#hatchway.mcp.with_fallback)(primary, fallback, \*[, note, ...]) | `primary`, unless it could not be reached; then `fallback`, with `note` first.            |

### Classes

| [`Result`](#hatchway.mcp.Result)(status, out, err)   | What came back from the gate: its exit status, standard output and error.   |
|-----------------------------------------------------------------------------|-----------------------------------------------------------------------------|

### hatchway.mcp.BUSY *= 75*

the gate’s exit statuses a runner may see

### hatchway.mcp.DFLT_CLASSES *= ('read',)*

reading only

* **Type:**
  the classes served by default

### hatchway.mcp.DFLT_FAN_OUT_DEADLINE *= 25.0*

how long one machine of a [`fan_out()`](#hatchway.mcp.fan_out) may take before it is named as not answering

### hatchway.mcp.DFLT_FAN_OUT_TTL *= 30.0*

how long a merged answer is reused for the same request, so its pages hold still

### hatchway.mcp.DFLT_MAX_CHARS *= 6000*

how many characters of a command’s output one tool call returns; the rest is paged

### hatchway.mcp.LATE *= 124*

the exit status of a part that missed its deadline (the far side may still be running)

### hatchway.mcp.REFUSED *= 126*

the gate’s exit statuses a runner may see

### *class* hatchway.mcp.Result(status, out, err)

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

What came back from the gate: its exit status, standard output and error.

### hatchway.mcp.fan_out(runners, \*, label=<function tag_lines>, is_down=<function unreachable>, deadline=25.0, ttl=30.0, clock=<built-in function monotonic>)

Ask every runner at once and merge their answers, each part labelled with its name.

Where [`with_fallback()`](#hatchway.mcp.with_fallback) asks a second machine only when the first is down,
`fan_out` asks all of them, for questions every machine answers about itself (its
own sessions). The parts come back in the order of `runners`, each through
`label` (default [`tag_lines()`](#hatchway.mcp.tag_lines)). A part that could not be reached, was refused,
was busy, failed, or took longer than `deadline` seconds does not fail the call: it
is named on a line of its own at the end, so the reader knows whose answer is missing
rather than reading a partial list as whole. A part that answered nothing is named too.

The call fails only when no part answered: then the status is a refusal if any part
refused, else the first part’s that reached its machine, and the error names every part.

The merged answer is reused for `ttl` seconds for the same request, so a long answer
read page by page (`offset`) does not shift under the reader. `ttl=0` turns it off.
Only use `fan_out` for reads: a request that changes something must go to one runner.

```pycon
>>> up = lambda r: Result(0, "busy  a\n", "")
>>> down = lambda r: Result(UNREACHABLE, "", "ssh: connect to host x: Operation timed out")
>>> print(fan_out({"mac": down, "tw": up})("crowsnest roster").out, end="")
[tw] busy  a
[mac] (did not answer: ssh: connect to host x: Operation timed out)
```

* **Return type:**
  [`Callable`](https://docs.python.org/3/library/collections.abc.html#collections.abc.Callable)[[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)], [`Result`](#hatchway.mcp.Result)]

### hatchway.mcp.local_runner(, agent='mcp', profile=None, timeout=150, busy_retries=6)

Run each request through `hatchway gate` on this machine, as this user.

A subprocess rather than a function call, so the gate’s lock, log and timeout behave
exactly as they do behind sshd.

* **Return type:**
  [`Callable`](https://docs.python.org/3/library/collections.abc.html#collections.abc.Callable)[[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)], [`Result`](#hatchway.mcp.Result)]

### hatchway.mcp.mk_server(profile=None, , runner=None, settings=None, classes=('read',), max_chars=6000, name=None, instructions=None, \*\*server_kwargs)

A `FastMCP` server over `profile`’s rules.

`runner` defaults to [`local_runner()`](#hatchway.mcp.local_runner) with the same profile. `server_kwargs`
go to `FastMCP` (`auth=`, `middleware=`): authentication belongs to whoever
serves this over a network, not to hatchway.

### hatchway.mcp.mk_tool(rule, , runner, max_chars=6000)

One callable for `rule`, with a real signature, so any MCP host can type it.

* **Return type:**
  [`Callable`](https://docs.python.org/3/library/collections.abc.html#collections.abc.Callable)

### hatchway.mcp.mk_tools(profile, , runner, classes=('read',), max_chars=6000)

The tools for every rule of `profile` in one of `classes`, in profile order.

A class left out is not offered at all; one offered is still decided by the gate,
so a gated class whose flag is absent answers “refused” rather than running.

* **Return type:**
  [`list`](https://docs.python.org/3/builtins/stdtypes.html#list)[[`Callable`](https://docs.python.org/3/library/collections.abc.html#collections.abc.Callable)]

### hatchway.mcp.routed_runner(default, routes)

Send a request to the runner of the longest leading words it matches in `routes`.

A key is one word or several separated by spaces; the longest key that the request’s
first words match wins, else `default`. So one server can answer about sessions from
every machine and about one store from one: `routed_runner(server, {"crowsnest":
fan_out(...), "crowsnest intent": server})`.

```pycon
>>> run = routed_runner(lambda r: "default", {"a": lambda r: "a", "a b": lambda r: "a b"})
>>> run("a b c"), run("a c"), run("ab"), run("z")
('a b', 'a', 'default', 'default')
```

* **Return type:**
  [`Callable`](https://docs.python.org/3/library/collections.abc.html#collections.abc.Callable)[[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)], [`Result`](#hatchway.mcp.Result)]

### hatchway.mcp.ssh_runner(destination, , identity=None, ssh=('ssh', '-T', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8'), timeout=150, busy_retries=6)

Send each request over SSH to `destination`, whose key’s forced command is the gate.

The request travels as the remote command, which sshd hands to the forced command as
`$SSH_ORIGINAL_COMMAND`; it is never run by a remote shell.

* **Return type:**
  [`Callable`](https://docs.python.org/3/library/collections.abc.html#collections.abc.Callable)[[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)], [`Result`](#hatchway.mcp.Result)]

### hatchway.mcp.tag_lines(name, text)

Every non-blank line of `text` prefixed with `[name]`, so merged rows say whose they are.

```pycon
>>> print(tag_lines("tw", "busy  a\n\nidle  b"), end="")
[tw] busy  a

[tw] idle  b
```

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### hatchway.mcp.tool_name(rule)

The MCP name of a rule: its `tool` key, else its words joined by underscores.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### hatchway.mcp.unreachable(result)

Whether `result` is ssh failing to connect, as opposed to the far side answering.

Only then is it safe to ask someone else: the request never reached the gate, so it
ran nowhere. A timeout is not that (the command may have run), and neither is a
remote command that happened to exit 255.

* **Return type:**
  [`bool`](https://docs.python.org/3/builtins/functions.html#bool)

### hatchway.mcp.with_fallback(primary, fallback, \*, note="(the first machine did not answer; this is the fallback's view)\\n", is_down=<function unreachable>)

`primary`, unless it could not be reached; then `fallback`, with `note` first.

* **Return type:**
  [`Callable`](https://docs.python.org/3/library/collections.abc.html#collections.abc.Callable)[[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)], [`Result`](#hatchway.mcp.Result)]

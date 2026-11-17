"""The second transport: a profile served as MCP tools, one tool per rule.

The SSH gate is the way in for an agent that can open SSH. An agent that speaks MCP but
cannot (a claude.ai custom connector, Claude Desktop, another machine's MCP client) gets
the same allowlist here: each rule of the profile becomes one tool whose parameters are
the rule's flags and names, and every call is turned back into the request words and
handed to a *runner*, which takes it through the gate. So the same ``decide()``, the same
log, the same gated classes, the same one-call-at-a-time lock, whichever way it arrived.

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

The runner is the seam. :func:`local_runner` (the default) runs the gate on this machine;
:func:`ssh_runner` sends the request over SSH to a key whose forced command is the gate,
which is how a process running as its own account reaches a machine's tools without
holding any of their credentials. Building the server needs ``fastmcp``
(``pip install 'hatchway[mcp]'``); nothing else in hatchway imports it.
"""

from __future__ import annotations

import inspect
import keyword
import os
import re
import shlex
import subprocess
import sys
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Annotated

from hatchway.config import Settings, load_profile, load_settings
from hatchway.policy import Profile, Rule

#: how many characters of a command's output one tool call returns; the rest is paged
DFLT_MAX_CHARS = 6000
#: the classes served by default: reading only
DFLT_CLASSES = ("read",)
#: the gate's exit statuses a runner may see
REFUSED, BUSY = 126, 75


@dataclass(frozen=True)
class Result:
    """What came back from the gate: its exit status, standard output and error."""

    status: int
    out: str
    err: str


Runner = Callable[[str], Result]


def _run_gate(argv: Sequence[str], *, env=None, timeout: float, busy_retries: int) -> Result:
    for attempt in range(busy_retries + 1):
        try:
            p = subprocess.run(  # noqa: PLW1510
                list(argv),
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
                timeout=timeout,
                env=env,
            )
        except subprocess.TimeoutExpired:
            return Result(124, "", f"no answer after {timeout:.0f}s")
        if p.returncode != BUSY or attempt == busy_retries:
            return Result(p.returncode, p.stdout, p.stderr)
        time.sleep(0.5 * (attempt + 1))  # one call at a time per agent: wait our turn
    raise AssertionError("unreachable")


def local_runner(
    *,
    agent: str = "mcp",
    profile: str | None = None,
    timeout: float = 150,
    busy_retries: int = 6,
) -> Runner:
    """Run each request through ``hatchway gate`` on this machine, as this user.

    A subprocess rather than a function call, so the gate's lock, log and timeout behave
    exactly as they do behind sshd.
    """
    argv = [sys.executable, "-m", "hatchway", "gate", "--agent", agent]
    if profile:
        argv += ["--profile", profile]

    def run(request: str) -> Result:
        env = {**os.environ, "SSH_ORIGINAL_COMMAND": request}
        return _run_gate(argv, env=env, timeout=timeout, busy_retries=busy_retries)

    return run


def ssh_runner(
    destination: str,
    *,
    identity: str | None = None,
    ssh: Sequence[str] = ("ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8"),
    timeout: float = 150,
    busy_retries: int = 6,
) -> Runner:
    """Send each request over SSH to ``destination``, whose key's forced command is the gate.

    The request travels as the remote command, which sshd hands to the forced command as
    ``$SSH_ORIGINAL_COMMAND``; it is never run by a remote shell.
    """
    base = list(ssh) + (["-i", identity, "-o", "IdentitiesOnly=yes"] if identity else [])

    def run(request: str) -> Result:
        # `--` so neither the destination nor the request can be read as an ssh option
        return _run_gate(
            [*base, "--", destination, request], timeout=timeout, busy_retries=busy_retries
        )

    return run


UNREACHABLE = 255  # what ssh exits with when it cannot connect


def routed_runner(default: Runner, routes: Mapping[str, Runner]) -> Runner:
    """Send a request to the runner its first word names in ``routes``, else ``default``.

    So one server can answer about sessions from the machine that has them and about
    repositories from another: ``routed_runner(server, {"crowsnest": laptop})``.
    """

    def run(request: str) -> Result:
        first = request.split(" ", 1)[0]
        return routes.get(first, default)(request)

    return run


def unreachable(result: Result) -> bool:
    """Whether ``result`` is ssh failing to connect, as opposed to the far side answering.

    Only then is it safe to ask someone else: the request never reached the gate, so it
    ran nowhere. A timeout is not that (the command may have run), and neither is a
    remote command that happened to exit 255.
    """
    err = result.err.lower()
    return result.status == UNREACHABLE and any(
        s in err
        for s in (
            "ssh: connect",
            "connection refused",
            "connection closed",
            "connection reset",
            "connection timed out",
            "kex_exchange",
            "could not resolve",
            "no route to host",
            "operation timed out",
        )
    )


def with_fallback(
    primary: Runner,
    fallback: Runner,
    *,
    note: str = "(the first machine did not answer; this is the fallback's view)\n",
    is_down: Callable[[Result], bool] = unreachable,
) -> Runner:
    """``primary``, unless it could not be reached; then ``fallback``, with ``note`` first."""

    def run(request: str) -> Result:
        result = primary(request)
        if not is_down(result):
            return result
        second = fallback(request)
        return Result(second.status, note + second.out, second.err)

    return run


def _param_name(flag: str) -> str:
    name = re.sub(r"[^0-9A-Za-z_]", "_", flag.lstrip("-"))
    return name + "_" if keyword.iskeyword(name) or not name.isidentifier() else name


def tool_name(rule: Rule) -> str:
    """The MCP name of a rule: its ``tool`` key, else its words joined by underscores."""
    return rule.tool or re.sub(r"[^0-9A-Za-z_]", "_", "_".join(rule.match))


def _bool_flags(rule: Rule) -> list[str]:
    """One parameter per flag, preferring the long spelling when there is one.

    A profile lists ``-q`` and ``--quiet`` separately and cannot say they are the same
    flag, so a short flag is offered only when the rule has no long flag at all.
    """
    long = sorted(f for f in rule.flags if f.startswith("--"))
    return long or sorted(rule.flags)


def _page(text: str, *, offset: int, max_chars: int) -> str:
    total = len(text)
    chunk = text[offset : offset + max_chars]
    rest = total - offset - len(chunk)
    if offset or rest > 0:
        end = offset + len(chunk)
        more = f"; call again with offset={end} for more]" if rest > 0 else "]"
        chunk += f"\n[characters {offset}-{end} of {total}{more}"
    return chunk


def _answer(result: Result, *, offset: int, max_chars: int) -> str:
    if result.status == REFUSED:
        return f"refused: {result.err.strip() or 'not allowed'}"
    if result.status != 0:
        detail = (result.err.strip() or result.out.strip())[-800:]
        return f"failed (exit {result.status}): {detail}"
    return _page(result.out or "(nothing)", offset=offset, max_chars=max_chars)


def _described(tp, text: str):
    """``tp`` carrying ``text`` as its parameter description, where pydantic can see it."""
    try:
        from pydantic import Field
    except ImportError:  # no MCP stack installed: the description is cosmetic
        return tp
    return Annotated[tp, Field(description=text)]


def mk_tool(rule: Rule, *, runner: Runner, max_chars: int = DFLT_MAX_CHARS) -> Callable:
    """One callable for ``rule``, with a real signature, so any MCP host can type it."""
    flags = {_param_name(f): f for f in _bool_flags(rule)}
    value_flags = {}
    for vf in rule.value_flags:
        spelled = next((n for n in vf.names if n.startswith("--")), vf.names[0])
        value_flags[_param_name(spelled)] = spelled
    many = rule.max_positional > 1
    has_args = rule.max_positional > 0
    arg_doc = rule.arg or ("names" if many else "a name")
    params = []
    positional = rule.param or ("args" if many else "name")
    if has_args:
        required = rule.min_positional > 0
        if many:
            ann = _described(list[str], arg_doc)
            default = inspect.Parameter.empty if required else []
        else:
            ann = _described(str, arg_doc)
            default = inspect.Parameter.empty if required else ""
        params.append(inspect.Parameter(positional, _KW, default=default, annotation=ann))
    for pname in flags:
        params.append(inspect.Parameter(pname, _KW, default=False, annotation=bool))
    for pname in value_flags:
        params.append(inspect.Parameter(pname, _KW, default=None, annotation=str | None))
    pages = rule.klass == "read"  # paging re-runs the command: never for one that writes
    if pages:
        params.append(
            inspect.Parameter(
                "offset",
                _KW,
                default=0,
                annotation=_described(int, "where to resume a long answer (it says when)"),
            )
        )

    def tool(**kw) -> str:
        words = list(rule.match)
        words += [flag for p, flag in flags.items() if kw.get(p)]
        for p, flag in value_flags.items():
            if kw.get(p) not in (None, ""):
                words += [flag, str(kw[p])]
        names = kw.get(positional)
        if names:
            words += list(names) if many else [names]
        result = runner(shlex.join(words))
        offset = max(0, int(kw.get("offset") or 0)) if pages else 0
        return _answer(result, offset=offset, max_chars=max_chars)

    tool.__name__ = tool_name(rule)
    tool.__doc__ = rule.help or " ".join(rule.match)
    tool.__signature__ = inspect.Signature(params, return_annotation=str)
    tool.__annotations__ = {p.name: p.annotation for p in params} | {"return": str}
    return tool


_KW = inspect.Parameter.KEYWORD_ONLY


def _served(profile: Profile, classes: Iterable[str]) -> list[Rule]:
    classes = set(classes)
    return [r for r in profile.rules if r.klass in classes]


def mk_tools(
    profile: Profile,
    *,
    runner: Runner,
    classes: Iterable[str] = DFLT_CLASSES,
    max_chars: int = DFLT_MAX_CHARS,
) -> list[Callable]:
    """The tools for every rule of ``profile`` in one of ``classes``, in profile order.

    A class left out is not offered at all; one offered is still decided by the gate,
    so a gated class whose flag is absent answers "refused" rather than running.
    """
    tools = [mk_tool(r, runner=runner, max_chars=max_chars) for r in _served(profile, classes)]
    names = [t.__name__ for t in tools]
    dupes = sorted({n for n in names if names.count(n) > 1})
    if dupes:
        raise ValueError(f"profile {profile.name!r}: two rules make the tool(s) {dupes}")
    return tools


def mk_server(
    profile: str | Profile | None = None,
    *,
    runner: Runner | None = None,
    settings: Settings | None = None,
    classes: Iterable[str] = DFLT_CLASSES,
    max_chars: int = DFLT_MAX_CHARS,
    name: str | None = None,
    instructions: str | None = None,
    **server_kwargs,
):
    """A ``FastMCP`` server over ``profile``'s rules.

    ``runner`` defaults to :func:`local_runner` with the same profile. ``server_kwargs``
    go to ``FastMCP`` (``auth=``, ``middleware=``): authentication belongs to whoever
    serves this over a network, not to hatchway.
    """
    from fastmcp import FastMCP

    settings = settings or load_settings()
    if isinstance(profile, Profile):
        if runner is None:
            # the gate loads profiles by name: tools built from an object it cannot load
            # would be decided against a different profile
            raise ValueError(
                "a Profile object needs an explicit runner; pass its name instead"
            )
    else:
        profile = profile or settings.profile
        runner = runner or local_runner(profile=profile)
        profile = load_profile(profile, settings=settings)
    server = FastMCP(
        name or f"hatchway-{profile.name or 'profile'}",
        instructions=instructions if instructions is not None else profile.instructions,
        **server_kwargs,
    )
    for tool in mk_tools(profile, runner=runner, classes=classes, max_chars=max_chars):
        server.tool(tool, annotations={"readOnlyHint": _read_only(tool, profile)})
    return server


def _read_only(tool: Callable, profile: Profile) -> bool:
    rule = next(r for r in profile.rules if tool_name(r) == tool.__name__)
    return rule.klass == "read"

"""The allowlist: which command lines an outside agent may run, decided without running anything.

A *profile* is data (a TOML file) listing *rules*. A rule names the words the agent
sends (``match``), what actually runs (``argv``), and exactly which extra flags and
positional arguments it may add. Everything not described is refused. Deciding is a
pure function of the request string, the profile and a little context (which flag
files exist, which directories dispatch may use), so it is tested without a shell.

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
"""

from __future__ import annotations

import re
import shlex
import string
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

DFLT_POSITIONAL_PATTERN = r"[A-Za-z0-9][A-Za-z0-9._@:+-]{0,127}"
DFLT_FILE_PATTERN = r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}"
MAX_REQUEST_CHARS = 8192
# Characters a shell would treat specially. The gate never uses a shell, but a request
# carrying any of them is not one a well-behaved agent sends, so it is refused outright
# rather than quoted through: refusing is easier to audit than reasoning about quoting.
# A value flag marked ``free`` (a prompt) is the one place they may appear, inside quotes.
_SHELL_META = set(";&|`$<>\\\n\r\x00")


@dataclass(frozen=True)
class ValueFlag:
    """A flag that takes one value, checked against ``pattern`` (or free text, or a
    directory under one of the dispatch roots)."""

    names: tuple[str, ...]
    pattern: str = DFLT_POSITIONAL_PATTERN
    free: bool = False
    path_under_roots: bool = False

    @classmethod
    def from_dict(cls, d: Mapping) -> ValueFlag:
        names = d["names"]
        names = (names,) if isinstance(names, str) else tuple(names)
        return cls(
            names=names,
            pattern=d.get("pattern", DFLT_POSITIONAL_PATTERN),
            free=bool(d.get("free", False)),
            path_under_roots=bool(d.get("path_under_roots", False)),
        )


@dataclass(frozen=True)
class Rule:
    """One allowed command shape.

    ``kind`` is ``exec`` (run ``argv`` plus the checked extras) or ``file`` (print one
    file, named by the single positional argument, from the directory ``root``).
    ``klass`` groups rules for gating: a class listed in the profile's ``[classes]``
    table with ``requires_flag`` is refused until that flag file exists.

    ``tool``, ``param`` and ``arg`` only name things for other transports (the MCP
    tool's name, its positional parameter's name and that parameter's description); ``stdin`` names a ``free`` value flag
    whose value is written to the command's standard input instead of its arguments,
    so a body of text (a note to publish) never lands in ``argv``. ``reply`` shapes a
    successful answer for those transports: a template whose only field is ``{out}``, the
    command's output stripped (a published link turned into a line to paste elsewhere).
    """

    match: tuple[str, ...]
    argv: tuple[str, ...] = ()
    kind: str = "exec"
    klass: str = "read"
    flags: frozenset[str] = frozenset()
    value_flags: tuple[ValueFlag, ...] = ()
    max_positional: int = 0
    min_positional: int = 0
    positional_pattern: str = DFLT_POSITIONAL_PATTERN
    root: str = ""
    help: str = ""
    tool: str = ""
    arg: str = ""
    param: str = ""
    stdin: str = ""
    reply: str = ""

    @classmethod
    def from_dict(cls, d: Mapping) -> Rule:
        kind = d.get("kind", "exec")
        if kind not in ("exec", "file"):
            raise ValueError(f"rule {d.get('match')!r}: unknown kind {kind!r}")
        if kind == "exec" and not d.get("argv"):
            raise ValueError(f"rule {d.get('match')!r}: an exec rule needs argv")
        value_flags = tuple(ValueFlag.from_dict(v) for v in d.get("value_flags", ()))
        stdin = d.get("stdin", "")
        if stdin and not any(stdin in v.names and v.free for v in value_flags):
            raise ValueError(
                f"rule {d.get('match')!r}: stdin {stdin!r} must name a free value flag"
            )
        reply = d.get("reply", "")
        fields = {f for _, f, _, _ in string.Formatter().parse(reply) if f is not None}
        if fields - {"out"}:
            raise ValueError(
                f"rule {d.get('match')!r}: reply may only use {{out}}, not {sorted(fields - {'out'})}"
            )
        return cls(
            match=tuple(d["match"]),
            argv=tuple(d.get("argv", ())),
            kind=kind,
            klass=d.get("class", "read"),
            flags=frozenset(d.get("flags", ())),
            value_flags=value_flags,
            max_positional=int(d.get("max_positional", 1 if kind == "file" else 0)),
            min_positional=int(d.get("min_positional", 0)),
            positional_pattern=d.get(
                "positional_pattern",
                DFLT_FILE_PATTERN if kind == "file" else DFLT_POSITIONAL_PATTERN,
            ),
            root=d.get("root", ""),
            help=d.get("help", ""),
            tool=d.get("tool", ""),
            arg=d.get("arg", ""),
            param=d.get("param", ""),
            stdin=stdin,
            reply=reply,
        )

    def value_flag(self, name: str) -> ValueFlag | None:
        return next((v for v in self.value_flags if name in v.names), None)


@dataclass(frozen=True)
class Profile:
    """A named set of rules plus the gating of their classes."""

    rules: tuple[Rule, ...]
    classes: Mapping[str, Mapping] = field(default_factory=dict)
    name: str = ""
    snapshot: tuple[Mapping, ...] = ()
    instructions: str = ""

    @classmethod
    def from_dict(cls, d: Mapping, *, name: str = "") -> Profile:
        return cls(
            rules=tuple(Rule.from_dict(r) for r in d.get("rule", ())),
            classes=dict(d.get("classes", {})),
            name=d.get("name", name),
            snapshot=tuple(d.get("snapshot", ())),
            instructions=d.get("instructions", ""),
        )

    def rule_for(self, tokens: Sequence[str]) -> Rule | None:
        """The rule with the longest ``match`` that prefixes ``tokens``."""
        candidates = [r for r in self.rules if tuple(tokens[: len(r.match)]) == r.match]
        return max(candidates, key=lambda r: len(r.match), default=None)


@dataclass(frozen=True)
class Decision:
    """What the gate does with a request: run ``argv``, print ``path``, or refuse."""

    allowed: bool
    request: str
    reason: str = ""
    rule: Rule | None = None
    argv: tuple[str, ...] = ()
    path: str = ""
    stdin: str | None = None

    @property
    def klass(self) -> str:
        return self.rule.klass if self.rule else ""


def _refuse(request: str, reason: str, rule: Rule | None = None) -> Decision:
    return Decision(False, request, reason, rule)


def _under(path: Path, roots: Sequence[Path]) -> bool:
    return any(path == r or r in path.parents for r in roots)


def decide(
    request: str,
    profile: Profile,
    *,
    flags_present: frozenset[str] = frozenset(),
    dispatch_roots: Sequence[str | Path] = (),
    roots: Mapping[str, str | Path] | None = None,
) -> Decision:
    """Decide what to do with ``request`` (the agent's command line, as SSH hands it).

    ``flags_present`` names the flag files that exist (a gated class needs its flag);
    ``dispatch_roots`` are the directories a ``path_under_roots`` value must sit in;
    ``roots`` maps a file rule's ``root`` name to a directory.

    >>> p = Profile.from_dict({"rule": [
    ...     {"match": ["snapshot"], "kind": "file", "root": "out"}]})
    >>> decide("snapshot ../../.ssh/id_ed25519", p, roots={"out": "/tmp/o"}).allowed
    False
    """
    if len(request) > MAX_REQUEST_CHARS:
        return _refuse(request[:200], "request too long")
    try:
        tokens = shlex.split(request)
    except ValueError as e:
        return _refuse(request, f"cannot parse: {e}")
    if not tokens:
        return _refuse(request, "empty request (an interactive shell is never offered)")
    rule = profile.rule_for(tokens)
    if rule is None:
        return _refuse(request, f"no rule allows {' '.join(tokens[:2])[:60]!r}")
    gate = profile.classes.get(rule.klass, {})
    needed = gate.get("requires_flag")
    if needed and needed not in flags_present:
        return _refuse(
            request, f"class {rule.klass!r} is switched off (flag {needed!r} absent)", rule
        )
    extras, positional, stdin = [], [], None
    rest = list(tokens[len(rule.match) :])
    while rest:
        tok = rest.pop(0)
        if tok.startswith("-") and tok != "-":
            name, eq, inline = tok.partition("=")
            if name in rule.flags and not eq:
                extras.append(name)
                continue
            vf = rule.value_flag(name)
            if vf is None:
                return _refuse(request, f"flag {name[:40]!r} is not allowed here", rule)
            if eq:
                value = inline
            elif rest:
                value = rest.pop(0)
            else:
                return _refuse(request, f"flag {name[:40]!r} needs a value", rule)
            to_stdin = bool(rule.stdin) and rule.stdin in vf.names
            # A value written to stdin is never read as an option, so it may start with '-'
            # (a markdown list); it still may not carry a NUL byte.
            problem = (
                ("contains a NUL byte" if "\x00" in value else "")
                if to_stdin
                else _check_value(value, vf, dispatch_roots)
            )
            if problem:
                return _refuse(request, f"{name[:40]}: {problem}", rule)
            if vf.path_under_roots:
                value = str(Path(value).expanduser().resolve())
            if to_stdin:
                stdin = value
                continue
            extras += [name, value]
            continue
        if any(c in _SHELL_META for c in tok):
            return _refuse(request, f"argument {tok[:40]!r} carries shell characters", rule)
        if not re.fullmatch(rule.positional_pattern, tok):
            return _refuse(request, f"argument {tok[:40]!r} is not an allowed name", rule)
        positional.append(tok)
    if not rule.min_positional <= len(positional) <= rule.max_positional:
        return _refuse(
            request,
            f"takes {rule.min_positional}..{rule.max_positional} arguments, "
            f"got {len(positional)}",
            rule,
        )
    if rule.stdin and stdin is None:
        return _refuse(request, f"{rule.stdin} is required", rule)
    if rule.kind == "file":
        return _decide_file(request, rule, positional, roots or {})
    # Positionals go after `--` so a name can never be read as an option by the tool.
    argv = rule.argv + tuple(extras) + (("--", *positional) if positional else ())
    return Decision(True, request, "allowed", rule, argv, stdin=stdin)


def _check_value(value: str, vf: ValueFlag, dispatch_roots: Sequence) -> str:
    if vf.free:
        # A value that starts with '-' could be read as an option by whatever the
        # command passes it on to (a prompt handed to `claude`, say): never allowed.
        if value.lstrip().startswith("-"):
            return "value may not start with '-'"
        return "" if "\x00" not in value else "contains a NUL byte"
    if any(c in _SHELL_META for c in value):
        return "value carries shell characters"
    if vf.path_under_roots:
        if not dispatch_roots:
            return "no dispatch roots are configured"
        resolved = Path(value).expanduser().resolve()
        roots = [Path(r).expanduser().resolve() for r in dispatch_roots]
        return "" if _under(resolved, roots) else "directory is outside the dispatch roots"
    return "" if re.fullmatch(vf.pattern, value) else "value is not allowed"


def _decide_file(
    request: str, rule: Rule, positional: list[str], roots: Mapping[str, str | Path]
) -> Decision:
    base = roots.get(rule.root)
    if not base:
        return _refuse(request, f"no directory configured for root {rule.root!r}", rule)
    base = Path(base).expanduser().resolve()
    if not positional:
        return Decision(True, request, "list", rule, path=str(base))
    name = positional[0]
    if name.startswith("."):
        return _refuse(request, "hidden files are never served", rule)
    target = (base / name).resolve()
    if target.parent != base or not target.is_file():
        return _refuse(request, f"no file {name[:40]!r} under {rule.root}", rule)
    return Decision(True, request, "file", rule, path=str(target))


def describe(profile: Profile) -> list[str]:
    """One line per rule, for the ``help`` answer an agent gets."""
    lines = []
    for r in profile.rules:
        words = " ".join(r.match)
        flags = sorted(r.flags) + [f"{'|'.join(v.names)} VALUE" for v in r.value_flags]
        args = ""
        if r.max_positional:
            args = " NAME" if r.max_positional == 1 else f" NAME...(≤{r.max_positional})"
            if r.min_positional == 0:
                args = f" [{args.strip()}]"
        gated = profile.classes.get(r.klass, {}).get("requires_flag")
        tail = f"  [{r.klass}{', gated' if gated else ''}]"
        opt = f" [{' '.join(flags)}]" if flags else ""
        lines.append(f"{words}{args}{opt}{tail}  {r.help}".rstrip())
    return lines

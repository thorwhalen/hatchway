"""The MCP transport: every tool's request is one the gate allows, and abuse is refused."""

from __future__ import annotations

import asyncio
import shlex

import pytest

from hatchway.config import Settings, load_profile
from hatchway.mcp import Result, _page, mk_tools, tool_name
from hatchway.policy import decide


@pytest.fixture
def claude_ai():
    return load_profile("claude-ai")


def _decided(profile, flags=frozenset()):
    """A runner that decides each request with the profile and records the decision."""
    seen = []

    def run(request):
        d = decide(request, profile, flags_present=frozenset(flags))
        seen.append(d)
        return Result(0 if d.allowed else 126, " ".join(d.argv), d.reason)

    return run, seen


def _tool(tools, name):
    return next(t for t in tools if t.__name__ == name)


def test_every_rule_is_a_uniquely_named_tool(claude_ai):
    tools = mk_tools(
        claude_ai,
        runner=lambda r: Result(0, "", ""),
        classes=("read", "handoff", "work_request"),
    )
    assert [t.__name__ for t in tools] == [tool_name(r) for r in claude_ai.rules]
    assert "post_handoff" not in {t.__name__ for t in mk_tools(claude_ai, runner=None)}


def test_tool_calls_become_allowed_requests(claude_ai):
    run, seen = _decided(claude_ai)
    tools = mk_tools(claude_ai, runner=run, classes=("read", "handoff"))
    assert _tool(tools, "repo_overview")(repo="thorwhalen/hatchway") == (
        "gh repo view -- thorwhalen/hatchway"
    )
    out = _tool(tools, "read_repo_file")(path="repos/thorwhalen/hatchway/contents/docs/a b.md")
    assert out.endswith("-- repos/thorwhalen/hatchway/contents/docs/a b.md")
    out = _tool(tools, "list_issues")(repo="thorwhalen/hatchway", state="open", search="mcp x")
    assert "--search mcp x" in out
    assert _tool(tools, "session_turns")(session="cn-mac", last="3").startswith(
        "crowsnest turns"
    )
    assert all(d.allowed for d in seen)


@pytest.mark.parametrize(
    "tool, kw",
    [
        ("repo_overview", {"repo": "thorwhalen/tw-secrets-backup"}),
        ("repo_overview", {"repo": "thorwhalen/Secrets"}),
        ("read_repo_file", {"path": "repos/thorwhalen/iq-secrets-backup/contents/.env"}),
        ("read_repo_file", {"path": "repos/thorwhalen/x/contents/../../tw-secrets-backup"}),
        ("read_repo_file", {"path": "user"}),
        ("list_issues", {"repo": "thorwhalen/tw-secrets-backup"}),
        ("read_issue", {"number": "1; rm -rf ~"}),
        ("session_recap", {"session": "--all"}),
        ("read_repo_file", {"path": "repos/thorwhalen/dotfiles/contents/.env"}),
        ("read_repo_file", {"path": "repos/thorwhalen/x/contents/a/.github/w.yml"}),
        ("list_issues", {"repo": "a/b", "search": "repo:thorwhalen/x"}),
        ("list_issues", {"repo": "a/b", "search": "my secrets"}),
    ],
)
def test_abuse_is_refused(claude_ai, tool, kw):
    run, _ = _decided(claude_ai)
    tools = mk_tools(claude_ai, runner=run)
    assert _tool(tools, tool)(**kw).startswith("refused:")


def test_handoff_is_off_until_its_flag_exists(claude_ai):
    run, _ = _decided(claude_ai)
    post = _tool(mk_tools(claude_ai, runner=run, classes=("handoff",)), "post_handoff")
    assert "switched off" in post(title="t", text="x")


def test_handoff_text_goes_to_stdin_not_argv(claude_ai):
    run, seen = _decided(claude_ai, flags={"allow-handoff"})
    post = _tool(mk_tools(claude_ai, runner=run, classes=("handoff",)), "post_handoff")
    post(title="From the car", text="- decided: ship v1\n- next: $HOME `x`; rm")
    (d,) = seen
    assert d.allowed and d.stdin == "- decided: ship v1\n- next: $HOME `x`; rm"
    assert d.argv[-2:] == ("--title", "From the car")
    assert "--text" not in d.argv
    assert "handoff,from-claude-ai" in d.argv
    assert "offset" not in post.__signature__.parameters  # paging would publish twice


def test_long_answers_are_paged():
    text = "x" * 25
    first = _page(text, offset=0, max_chars=10)
    assert first.startswith("x" * 10) and "offset=10" in first
    assert "offset" not in _page(text, offset=20, max_chars=10).split("]")[0].split(";")[-1]
    assert _page("short", offset=0, max_chars=10) == "short"


def test_failure_and_refusal_are_said_plainly(claude_ai):
    tools = mk_tools(claude_ai, runner=lambda r: Result(126, "", "hatchway: refused: no\n"))
    assert _tool(tools, "session_triage")() == "refused: hatchway: refused: no"
    tools = mk_tools(claude_ai, runner=lambda r: Result(1, "", "boom"))
    assert _tool(tools, "session_triage")() == "failed (exit 1): boom"


def test_extends_adds_and_replaces_rules(tmp_path):
    (tmp_path / "profiles").mkdir()
    (tmp_path / "profiles" / "mine.toml").write_text(
        'extends = "claude-ai"\n'
        '[[rule]]\nmatch = ["crowsnest", "triage"]\nargv = ["true"]\ntool = "session_triage"\n'
        '[[rule]]\nmatch = ["desk"]\nargv = ["true"]\ntool = "needs_me"\n'
    )
    settings = Settings.from_mapping({}, config_dir=tmp_path, data_dir=tmp_path)
    p = load_profile("mine", settings=settings)
    names = [tool_name(r) for r in p.rules]
    assert names.count("session_triage") == 1 and names[-1] == "needs_me"
    assert next(r for r in p.rules if r.tool == "session_triage").argv == ("true",)
    assert p.instructions and "handoff" in p.classes


def test_served_over_mcp(claude_ai):
    fastmcp = pytest.importorskip("fastmcp")
    from hatchway.mcp import mk_server

    requests = []
    server = mk_server(
        claude_ai,
        runner=lambda r: requests.append(r) or Result(0, "ok", ""),
        classes=("read", "handoff"),
    )

    async def go():
        async with fastmcp.Client(server) as c:
            tools = {t.name: t for t in await c.list_tools()}
            res = await c.call_tool(
                "read_issue", {"number": "7", "repo": "a/b", "comments": True}
            )
            return tools, res

    tools, res = asyncio.run(go())
    assert tools["read_issue"].inputSchema["required"] == ["number"]
    assert tools["read_issue"].annotations.readOnlyHint is True
    assert tools["post_handoff"].annotations.readOnlyHint is False
    assert res.content[0].text == "ok"
    assert shlex.split(requests[0]) == [
        "gh",
        "issue",
        "view",
        "--comments",
        "--repo",
        "a/b",
        "7",
    ]


def test_routing_and_fallback():
    from hatchway.mcp import UNREACHABLE, routed_runner, with_fallback

    laptop = lambda r: Result(UNREACHABLE, "", "ssh: connect: timed out")
    server = lambda r: Result(0, f"server: {r}", "")
    run = routed_runner(server, {"crowsnest": with_fallback(laptop, server, note="[asleep] ")})
    assert run("gh repo view a/b").out == "server: gh repo view a/b"
    assert run("crowsnest triage").out == "[asleep] server: crowsnest triage"
    up = with_fallback(lambda r: Result(126, "", "refused"), server)
    assert up("crowsnest x").status == 126  # a refusal is an answer, not an outage
    ran = with_fallback(lambda r: Result(255, "", "remote command failed"), server)
    assert ran("crowsnest x").status == 255  # it reached the far side: never run twice
    slow = with_fallback(lambda r: Result(124, "", "no answer after 150s"), server)
    assert slow("crowsnest x").status == 124


def test_fan_out_merges_and_names_the_missing():
    from hatchway.mcp import REFUSED, UNREACHABLE, fan_out

    seen = []

    def machine(name, status=0, out="", err=""):
        def run(r):
            seen.append((name, r))
            return Result(status, out, err)

        return run

    run = fan_out(
        {
            "mac": machine(
                "mac", UNREACHABLE, err="ssh: connect to host: Operation timed out"
            ),
            "tw": machine("tw", out="busy  a\nidle  b\n"),
            "iq": machine("iq", out="idle  c\n"),
            "box": machine("box", out=""),
        }
    )
    got = run("crowsnest roster --brief")
    assert got.status == 0
    assert got.out.splitlines() == [
        "[tw] busy  a",
        "[tw] idle  b",
        "[iq] idle  c",
        "[mac] (did not answer: ssh: connect to host: Operation timed out)",
        "[box] (nothing)",
    ]
    assert sorted(seen) == sorted(
        (n, "crowsnest roster --brief") for n in ("mac", "tw", "iq", "box")
    )

    # a session lives on one machine: the others' failures are named, the answer stands
    one = fan_out(
        {"tw": machine("tw", 1, err="no session named x"), "iq": machine("iq", out="x: ok")}
    )
    assert (
        one("crowsnest recap x").out
        == "[iq] x: ok\n[tw] (failed, exit 1: no session named x)\n"
    )

    # nobody answered: the call fails, naming every part; a refusal everywhere stays one
    none = fan_out(
        {"a": machine("a", UNREACHABLE, err="ssh: connect: refused"), "b": machine("b", 2)}
    )
    r = none("crowsnest roster")
    assert (
        r.status == 2  # the first part that reached its machine
        and "[a] (did not answer" in r.err
        and "[b] (failed, exit 2)" in r.err
    )
    assert fan_out({"a": machine("a", REFUSED, err="no rule")})("x").status == REFUSED

    # a part that raises is a missing part, not a failed call
    def boom(r):
        raise OSError("no ssh binary")

    mixed = fan_out({"a": boom, "b": machine("b", out="ok")})("x")
    assert mixed.status == 0 and "[a] (failed, exit 1: OSError: no ssh binary)" in mixed.out


def test_fan_out_deadline_cache_and_refusal():
    import time as _time

    from hatchway.mcp import BUSY, REFUSED, UNREACHABLE, fan_out

    calls = []

    def fast(r):
        calls.append(r)
        return Result(0, f"n={len(calls)}\n", "")

    def slow(r):
        _time.sleep(2)
        return Result(0, "late\n", "")

    t0 = _time.monotonic()
    got = fan_out({"a": fast, "b": slow}, deadline=0.3, ttl=0)("x")
    assert _time.monotonic() - t0 < 1.5  # the late part is not waited for
    assert got.out == "[a] n=1\n[b] (failed, exit 124: no answer within 0s)\n"

    now = [100.0]
    cached = fan_out({"a": fast}, ttl=30, clock=lambda: now[0])
    first = cached("y").out
    assert cached("y").out == first  # pages of one answer hold still
    now[0] += 31
    assert cached("y").out != first  # and expire

    # the Mac asleep does not mask a refusal from the others
    down = lambda r: Result(UNREACHABLE, "", "ssh: connect: refused")
    no = lambda r: Result(REFUSED, "", "no rule")
    assert fan_out({"mac": down, "tw": no}, ttl=0)("x").status == REFUSED
    busy = lambda r: Result(BUSY, "", "another call is running")
    assert (
        "[tw] (busy: another call is running)"
        in fan_out({"tw": busy, "a": fast}, ttl=0)("x").out
    )


def test_reply_template_shapes_a_successful_answer():
    import pytest

    from hatchway.policy import Profile, Rule

    rule = {
        "match": ["annals", "publish"],
        "argv": ["annals", "publish", "-"],
        "class": "handoff",
        "value_flags": [{"names": ["--text"], "free": True}],
        "stdin": "--text",
        "reply": "Paste: read {out}",
    }
    p = Profile.from_dict({"rule": [rule]})
    ok = mk_tools(p, runner=lambda r: Result(0, "https://x/d/1\n", ""), classes=("handoff",))
    assert ok[0](text="hi") == "Paste: read https://x/d/1"
    failed = mk_tools(p, runner=lambda r: Result(1, "", "boom"), classes=("handoff",))
    assert failed[0](text="hi").startswith("failed (exit 1)")
    with pytest.raises(ValueError, match="only use"):
        Rule.from_dict({**rule, "reply": "{out} {secret}"})


def test_bundled_post_handoff_returns_a_paste_line():
    from hatchway.config import load_profile

    p = load_profile("claude-ai")
    (rule,) = [r for r in p.rules if r.tool == "post_handoff"]
    assert "annals aggregate {out}" in rule.reply


def test_bundled_work_request_is_gated_and_narrow():
    from hatchway.config import load_profile
    from hatchway.policy import decide

    p = load_profile("claude-ai")
    ask = "equerry-desk request-work --repo o/r --number 7"
    assert not decide(ask, p, flags_present=set()).allowed  # off until its flag exists
    on = {"allow-work-request"}
    assert decide(ask, p, flags_present=on).argv[-2:] == ("--number", "7")
    assert not decide(ask + " --model fable", p, flags_present=on).allowed
    assert not decide(
        "equerry-desk request-work --repo ../x --number 1", p, flags_present=on
    ).allowed
    assert decide("equerry-desk request-status 0123456789ab", p, flags_present=set()).allowed
    assert not decide("equerry-desk request-status ../../x", p, flags_present=set()).allowed


def test_intent_status_is_read_only_and_routed_alone():
    from hatchway.config import load_profile
    from hatchway.mcp import fan_out, routed_runner
    from hatchway.policy import decide

    p = load_profile("claude-ai")
    ok = "crowsnest intent status 20261119T084800Z-0123abcd"
    assert decide(ok, p, flags_present=set()).allowed
    assert not decide("crowsnest intent put tell x", p, flags_present=set()).allowed
    every = fan_out({"a": lambda r: Result(0, "a\n", ""), "b": lambda r: Result(0, "b\n", "")})
    run = routed_runner(
        lambda r: Result(0, "server", ""),
        {"crowsnest": every, "crowsnest intent": lambda r: Result(0, "one", "")},
    )
    assert run(ok).out == "one" and run("crowsnest roster").out == "[a] a\n[b] b\n"

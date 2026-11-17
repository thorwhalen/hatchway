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


def _decided(profile):
    """A runner that decides each request with the profile and records the decision."""
    seen = []

    def run(request):
        d = decide(request, profile)
        seen.append(d)
        return Result(0 if d.allowed else 126, " ".join(d.argv), d.reason)

    return run, seen


def _tool(tools, name):
    return next(t for t in tools if t.__name__ == name)


def test_every_rule_is_a_uniquely_named_tool(claude_ai):
    tools = mk_tools(
        claude_ai, runner=lambda r: Result(0, "", ""), classes=("read", "handoff")
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
    ],
)
def test_abuse_is_refused(claude_ai, tool, kw):
    run, _ = _decided(claude_ai)
    tools = mk_tools(claude_ai, runner=run)
    assert _tool(tools, tool)(**kw).startswith("refused:")


def test_handoff_text_goes_to_stdin_not_argv(claude_ai):
    run, seen = _decided(claude_ai)
    post = _tool(mk_tools(claude_ai, runner=run, classes=("handoff",)), "post_handoff")
    post(title="From the car", text="- decided: ship v1\n- next: $HOME `x`; rm")
    (d,) = seen
    assert d.allowed and d.stdin == "- decided: ship v1\n- next: $HOME `x`; rm"
    assert d.argv[-2:] == ("--title", "From the car")
    assert "--text" not in d.argv


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

"""The allowlist decides correctly, and refuses everything an attacker would try."""

import pytest

from hatchway import decide, load_profile
from hatchway.policy import Profile

P = load_profile("claude-fleet")


def ok(req, **kw):
    d = decide(req, P, **kw)
    assert d.allowed, d.reason
    return d


def no(req, **kw):
    d = decide(req, P, **kw)
    assert not d.allowed, d.argv
    return d


def test_bare_and_flags():
    assert ok("crowsnest").argv == ("crowsnest", "roster", "--all-homes")
    assert ok("crowsnest --brief").argv[-1] == "--brief"
    assert ok("crowsnest triage -q --json").argv == (
        "crowsnest",
        "triage",
        "--all-homes",
        "-q",
        "--json",
    )


def test_positional_goes_after_double_dash():
    assert ok("crowsnest show muse-integrate").argv[-2:] == ("--", "muse-integrate")
    assert ok("crowsnest turns x --last=5").argv == (
        "crowsnest",
        "turns",
        "--all-homes",
        "--last",
        "5",
        "--",
        "x",
    )


def test_ol_never_verifies():
    assert "--no-verify" in ok("ol owed").argv
    assert ok("ol blocked -l 10").argv == ("ol", "blocked", "-l", "10")


@pytest.mark.parametrize(
    "req",
    [
        "",
        "bash",
        "sh -c id",
        "cat ~/.ssh/id_ed25519",
        "crowsnest; id",
        "crowsnest && id",
        "crowsnest | sh",
        "crowsnest $(id)",
        "crowsnest `id`",
        "crowsnest triage > /tmp/x",
        "crowsnest --home /etc",
        "crowsnest triage --all-homes --home=/",
        "crowsnest reap",
        "crowsnest kill x",
        "crowsnest lineage --backfill",
        "crowsnest report --out /tmp/x",
        "crowsnest show ../../etc/passwd",
        "crowsnest show -",
        "crowsnest show a b",
        "crowsnest show",
        "crowsnest turns x --last 99999",
        "ol dashboard --out /tmp/x",
        "ol owed --owners evil",
        "ol blocked --repos evil/x",
        "crowsnest intent send x hi",
        "rsync --server . /",
        "scp -t /tmp",
        "git-upload-pack x",
        "crowsnest triage\nid",
        "crowsnest 'a;b'",
    ],
)
def test_refused(req):
    no(req)


def test_snapshot_files_stay_inside(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    (out / "triage.md").write_text("hi")
    (tmp_path / "secret").write_text("no")
    (out / ".hidden").write_text("no")
    (out / "link").symlink_to(tmp_path / "secret")
    roots = {"out": str(out)}
    assert ok("snapshot triage.md", roots=roots).path == str(out / "triage.md")
    assert ok("snapshot", roots=roots).reason == "list"
    for bad in (
        "snapshot ../secret",
        "snapshot .hidden",
        "snapshot link",
        "snapshot /etc/passwd",
        "snapshot nope.md",
    ):
        no(bad, roots=roots)


def test_dispatch_is_gated(tmp_path):
    req = f"crowsnest spawn fix-ci --cwd {tmp_path} --prompt 'fix the CI; then stop'"
    assert "switched off" in no(req).reason
    flags = frozenset({"allow-dispatch"})
    assert "no dispatch roots" in no(req, flags_present=flags).reason
    d = ok(req, flags_present=flags, dispatch_roots=[str(tmp_path)])
    assert d.argv[:4] == ("crowsnest", "spawn", "--model", "sonnet")
    assert d.argv[-2:] == ("--", "fix-ci")
    outside = f"crowsnest spawn x1 --cwd {tmp_path.parent} --prompt hi"
    no(outside, flags_present=flags, dispatch_roots=[str(tmp_path)])
    no(
        f"crowsnest spawn x1 --cwd {tmp_path} --model opus",
        flags_present=flags,
        dispatch_roots=[str(tmp_path)],
    )
    for prompt in ("'--settings={\"permissions\": 1}'", "'-p x'", "' --add-dir=/'"):
        no(
            f"crowsnest spawn x1 --cwd {tmp_path} --prompt {prompt}",
            flags_present=flags,
            dispatch_roots=[str(tmp_path)],
        )
        no(
            f"crowsnest spawn x1 --cwd {tmp_path} --prompt={prompt}",
            flags_present=flags,
            dispatch_roots=[str(tmp_path)],
        )
    assert (
        "--permission-mode" in d.argv
        and d.argv[d.argv.index("--permission-mode") + 1] == "default"
    )
    no(
        f"crowsnest spawn x1 --cwd {tmp_path} --permission-mode bypassPermissions",
        flags_present=flags,
        dispatch_roots=[str(tmp_path)],
    )


# --- stdin: a body of text goes to the command's standard input, never its argv ---------

_STDIN = Profile.from_dict(
    {
        "rule": [
            {
                "match": ["note"],
                "argv": ["annals", "publish", "-"],
                "value_flags": [
                    {"names": ["--title"], "free": True},
                    {"names": ["--text"], "free": True},
                ],
                "stdin": "--text",
            }
        ]
    }
)


def test_stdin_use():
    d = decide("note --title T --text '- a list; $HOME `x`'", _STDIN)
    assert d.allowed and d.stdin == "- a list; $HOME `x`"
    assert d.argv == ("annals", "publish", "-", "--title", "T")


def test_stdin_abuse():
    assert not decide("note --title T", _STDIN).allowed  # the body is required
    assert not decide("note --text 'a\x00b'", _STDIN).allowed  # NUL byte
    assert not decide("note --title -x --text t", _STDIN).allowed  # a non-stdin free value
    with pytest.raises(ValueError, match="free value flag"):
        Profile.from_dict(
            {
                "rule": [
                    {
                        "match": ["n"],
                        "argv": ["x"],
                        "stdin": "--text",
                        "value_flags": [{"names": ["--text"]}],
                    }
                ]
            }
        )


def test_message_session_use_and_abuse():
    from hatchway.config import load_profile
    from hatchway.policy import decide

    p = load_profile("claude-ai")
    on = {"allow-session-message"}
    d = decide("crowsnest intent put alpha-1 --text 'stop now'", p, flags_present=on)
    assert d.allowed and d.argv[:4] == ("crowsnest", "intent", "put", "tell")
    assert d.stdin == "stop now" and d.argv[-2:] == ("--", "alpha-1")
    # off without its flag; no other intent kinds; no store override; no odd session names
    assert not decide("crowsnest intent put alpha --text hi", p, flags_present=set()).allowed
    assert not decide(
        "crowsnest intent put start alpha --text hi", p, flags_present=on
    ).allowed
    assert not decide(
        "crowsnest intent put alpha --store /x --text hi", p, flags_present=on
    ).allowed
    assert not decide("crowsnest intent put ../x --text hi", p, flags_present=on).allowed
    assert not decide("crowsnest intent put alpha", p, flags_present=on).allowed


def test_read_issue_asks_for_json_not_the_deprecated_projects_field():
    from hatchway.config import load_profile
    from hatchway.policy import decide

    p = load_profile("claude-ai")
    d = decide("gh issue view 7 --repo a/b", p, flags_present=set())
    assert d.allowed and "--json" in d.argv and "--comments" not in d.argv
    assert not decide("gh issue view 7 --repo a/b --comments", p, flags_present=set()).allowed


def test_claude_ai_owed_never_verifies_and_blocked_gets_no_flag_it_rejects():
    """`ol blocked` has no --no-verify: passing it made blocked_work fail every time."""
    from hatchway.config import load_profile
    from hatchway.policy import decide

    p = load_profile("claude-ai")
    owed = decide("ol owed --limit 200", p, flags_present=set())
    assert owed.allowed and "--no-verify" in owed.argv and "200" in owed.argv
    blocked = decide("ol blocked", p, flags_present=set())
    assert blocked.allowed and "--no-verify" not in blocked.argv


def test_claude_ai_recap_asks_for_whole_lines():
    from hatchway.config import load_profile
    from hatchway.policy import decide

    d = decide("crowsnest recap fixer", load_profile("claude-ai"), flags_present=set())
    assert d.allowed and "--limit" in d.argv

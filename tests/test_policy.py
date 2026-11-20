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


def test_claude_ai_reminders_are_gated_never_revealed_and_take_a_spoken_title():
    import shlex

    from hatchway.config import load_profile
    from hatchway.policy import decide

    p = load_profile("claude-ai")
    on = {"allow-reminder"}
    req = shlex.join(
        ["ol", "remind", "--when", "2026-11-21T09:00", "Call the bank about the card"]
    )
    assert not decide(req, p, flags_present=set()).allowed  # off until its flag exists
    d = decide(req, p, flags_present=on)
    assert d.allowed and "--reveal" not in d.argv and "claude-ai" in d.argv
    assert d.argv[-1] == "Call the bank about the card"
    for when in ("20m", "3h", "1h30m", "15:30", "2026-11-21"):
        assert decide(f"ol remind --when {when} Stretch", p, flags_present=on).allowed, when
    for bad in (
        "ol remind --reveal Stretch",
        "ol remind --when tomorrow Stretch",
        "ol remind -- --help",
        "ol remind 'Stretch; rm -rf ~'",
    ):
        assert not decide(bad, p, flags_present=on).allowed, bad
    assert decide("ol loops --state all", p, flags_present=set()).allowed  # a read
    assert decide("ol done loop-20261120-13f595", p, flags_present=on).allowed
    assert not decide("ol done ../x", p, flags_present=on).allowed
    snooze = decide("ol snooze loop-20261120-13f595 1h", p, flags_present=on)
    assert snooze.allowed and snooze.argv[-2:] == ("loop-20261120-13f595", "1h")
    # pinned guards: its own loops only, a daily cap, a bounded snooze
    assert {"--only-source", "--max-days"} <= set(snooze.argv)
    assert "--only-source" in decide("ol done 20261120-13f5", p, flags_present=on).argv
    assert "--daily-cap" in d.argv


def _pile_profile():
    """The bundled profile with its pile rules narrowed to one pile, as a machine does."""
    import dataclasses

    from hatchway.config import load_profile

    p = load_profile("claude-ai")
    rules = []
    for r in p.rules:
        if r.tool in ("pile_label", "pile_close", "pile_capture"):
            vfs = tuple(
                dataclasses.replace(v, pattern="o/_pile") if "--repo" in v.names else v
                for v in r.value_flags
            )
            r = dataclasses.replace(r, value_flags=vfs)
        rules.append(r)
    return dataclasses.replace(p, rules=tuple(rules))


def test_the_bundled_pile_writes_match_no_repository_until_a_machine_narrows_them():
    from hatchway.config import load_profile
    from hatchway.policy import decide

    p = load_profile("claude-ai")
    for req in (
        "gh issue edit 3 --repo o/_pile --add-label routed",
        "gh issue close 3 --repo o/_pile --reason completed --comment x",
        "gh issue create pile --repo evil/_pile --title T --body x",
    ):
        assert not decide(req, p, flags_present={"allow-pile"}).allowed, req


def test_a_required_value_flag_refuses_a_request_without_it():
    from hatchway.policy import decide

    p = _pile_profile()
    on = {"allow-pile"}
    closing = "gh issue close 12 --repo o/_pile --reason completed"
    assert "--comment is required" in decide(closing, p, flags_present=on).reason
    assert decide(closing + " --comment 'done: merged'", p, flags_present=on).allowed
    for blank in (" --comment ''", " --comment=", " --comment ' '", " --comment '\u200b'"):
        assert not decide(closing + blank, p, flags_present=on).allowed, blank


def test_claude_ai_pile_tools_reach_only_the_pile_and_never_close_silently():
    import shlex

    from hatchway.policy import decide

    p = _pile_profile()
    on = {"allow-pile"}
    # reads change nothing and need no flag; a plan is signed as bosun, with no session
    for req in ("ol pile", "ol pile-show 3", "ol pile-propose"):
        assert decide(req, p, flags_present=set()).allowed, req
    plan = decide(
        shlex.join(["ol", "pile-plan", "3", "drop", "--reading", "a test", "--reason", "dup"]),
        p,
        flags_present=set(),
    )
    assert plan.allowed and plan.argv[2:6] == ("--by", "bosun", "--session", "none")
    assert not decide("ol pile-plan 3 drop --reason dup", p, flags_present=set()).allowed
    # writes: off without the flag, and only on a _pile repository
    edit = "gh issue edit 3 --repo o/_pile --add-label routed --remove-label pile"
    assert not decide(edit, p, flags_present=set()).allowed
    assert decide(edit, p, flags_present=on).allowed
    for bad in (
        "gh issue edit 3 --repo o/equerry --add-label routed",
        "gh issue edit 3 --repo o/_pile --title x",
        "gh issue edit 3 --repo o/_pile --add-label manual-task",
        "gh issue close 3 --repo o/_pile --reason completed",
        "gh issue close 3 --repo o/other --reason completed --comment x",
        "gh issue create pile --repo o/_pile",
        "gh issue create pile --repo evil/_pile --title T --body x",
        "gh issue create pile --repo o/_pile --title T --body x --label manual-task",
    ):
        assert not decide(bad, p, flags_present=on).allowed, bad
    cap = decide(
        shlex.join(
            [
                "gh",
                "issue",
                "create",
                "pile",
                "--repo",
                "o/_pile",
                "--title",
                "T",
                "--body",
                "- the owner's words",
            ]
        ),
        p,
        flags_present=on,
    )
    assert cap.allowed and cap.stdin == "- the owner's words" and "pile" in cap.argv

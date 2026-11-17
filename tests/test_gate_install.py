"""The gate runs what is allowed without a shell, refuses the rest, and logs both;
authorize keeps every other authorized_keys line and is idempotent."""

import json
import os
import stat

import pytest

from hatchway import Profile, Settings, authorize, gate, revoke
from hatchway.install import key_line

KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f test-agent"


@pytest.fixture
def settings(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    tool = bin_dir / "fake"
    tool.write_text('#!/bin/sh\necho "ran:$*"\n')
    tool.chmod(tool.stat().st_mode | stat.S_IEXEC)
    return Settings(
        path=[str(bin_dir)], config_dir=tmp_path / "cfg", data_dir=tmp_path / "data"
    )


PROFILE = Profile.from_dict(
    {
        "rule": [
            {
                "match": ["fake"],
                "argv": ["fake", "fixed"],
                "flags": ["-q"],
                "max_positional": 1,
            }
        ]
    }
)


def test_allowed_runs_without_shell(settings, capfd):
    assert gate("fake -q 'a b'", profile=PROFILE, settings=settings) != 0  # space: not a name
    assert gate("fake -q name", profile=PROFILE, settings=settings) == 0
    assert "ran:fixed -q -- name" in capfd.readouterr().out


def test_refused_and_logged(settings, capfd, monkeypatch):
    monkeypatch.setenv("SSH_ORIGINAL_COMMAND", "fake; id")
    assert gate(profile=PROFILE, settings=settings, agent="muse") == 126
    assert "refused" in capfd.readouterr().err
    calls = [
        json.loads(x) for x in (settings.data_dir / "calls.jsonl").read_text().splitlines()
    ]
    assert calls[-1]["agent"] == "muse" and calls[-1]["decision"] == "refused"


def test_key_line_rejects_option_injection():
    with pytest.raises(ValueError):
        key_line('ssh-ed25519 AAAA x\ncommand="sh"', agent="muse", binary="/b/hatchway")
    with pytest.raises(ValueError):
        key_line('command="sh" ' + KEY, agent="muse", binary="/b/hatchway")
    with pytest.raises(ValueError):
        key_line(KEY, agent="Muse; rm", binary="/b/hatchway")


def test_authorize_idempotent_and_keeps_lines(tmp_path, settings, monkeypatch):
    monkeypatch.setattr("hatchway.install.hatchway_bin", lambda: "/b/hatchway")
    ak = tmp_path / "authorized_keys"
    ak.write_text("ssh-ed25519 AAAAexisting me@laptop\n")
    assert (
        authorize(KEY, agent="muse", authorized_keys=ak, settings=settings)["action"]
        == "added"
    )
    assert (
        authorize(KEY, agent="muse", authorized_keys=ak, settings=settings)["action"] == "ok"
    )
    text = ak.read_text()
    assert "AAAAexisting" in text and text.count("gMEBQYHCAkK") == 1 and "restrict" in text
    assert oct(os.stat(ak).st_mode)[-3:] == "600"
    assert (
        authorize(KEY, agent="muse", profile="x", authorized_keys=ak, settings=settings)[
            "action"
        ]
        == "conflict"
    )
    assert revoke("muse", authorized_keys=ak, settings=settings)["removed"] == 1
    assert ak.read_text() == "ssh-ed25519 AAAAexisting me@laptop\n"
    assert list((settings.data_dir / "backups").iterdir())


def test_write_config_and_self_test(tmp_path):
    from hatchway.install import self_test, write_config

    s = Settings(config_dir=tmp_path / "cfg", data_dir=tmp_path / "data")
    res = write_config(tools=("sh",), settings=s)
    assert res["action"] == "written" and res["path_dirs"]
    assert write_config(tools=("sh",), settings=s)["action"] == "ok"
    test = self_test(settings=s)
    assert test["ok"], test


def test_log_cannot_be_forged(settings):
    gate('fake \u2028{"decision": "allowed"}', profile=PROFILE, settings=settings)
    raw = (settings.data_dir / "calls.jsonl").read_bytes()
    assert raw.isascii() and raw.count(b"\n") == 1


def test_one_call_at_a_time(settings):
    from hatchway.gate import _one_at_a_time

    held = _one_at_a_time("muse", settings)
    try:
        assert gate("fake -q", profile=PROFILE, settings=settings, agent="muse") == 75
        assert gate("fake -q", profile=PROFILE, settings=settings, agent="other") == 0
    finally:
        os.close(held)


def test_child_env_is_an_allowlist(settings, monkeypatch):
    from hatchway.gate import command_env

    monkeypatch.setenv("LC_EVIL", "x")
    monkeypatch.setenv("LD_PRELOAD", "/tmp/x.so")
    env = command_env(settings)
    assert "LC_EVIL" not in env and "LD_PRELOAD" not in env
    assert env["PATH"].startswith(settings.path[0])


def test_from_option_injection():
    with pytest.raises(ValueError):
        key_line(KEY, agent="muse", binary="/b/hatchway", from_='1.2.3.4",command="/bin/sh')


def test_authorize_through_symlink(tmp_path, settings, monkeypatch):
    monkeypatch.setattr("hatchway.install.hatchway_bin", lambda: "/b/hatchway")
    real = tmp_path / "dotfiles" / "authorized_keys"
    real.parent.mkdir()
    real.write_text("ssh-ed25519 AAAAexisting me\n")
    link = tmp_path / "ak"
    link.symlink_to(real)
    authorize(KEY, agent="muse", authorized_keys=link, settings=settings)
    assert link.is_symlink() and "gMEBQYHCAkK" in real.read_text()

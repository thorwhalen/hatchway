"""The forced command: what sshd runs instead of whatever the agent asked for.

An ``authorized_keys`` line such as::

    command="/path/to/hatchway gate --agent muse",restrict,from="100.64.0.0/10" ssh-ed25519 AAAA...

makes every connection with that key run :func:`gate`. It reads the agent's request from
``$SSH_ORIGINAL_COMMAND``, decides it with :mod:`hatchway.policy`, logs the call, and
then either runs the allowed argv directly (never through a shell), prints a file, or
refuses with a reason on stderr and exit status 126.
"""

from __future__ import annotations

import fcntl
import json
import os
import signal
import subprocess
import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from hatchway.config import Settings, load_profile, load_settings
from hatchway.policy import Decision, Profile, decide, describe

REFUSED = 126
TIMED_OUT = 124
HELP_WORDS = ("help", "hatchway help")
BUSY = 75
# What the commands the gate runs may see of its environment. Nothing the connecting
# agent could set (sshd's AcceptEnv passes LANG and LC_* on many systems) beyond LANG.
ENV_KEEP = (
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "TMPDIR",
    "LANG",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
    "XDG_RUNTIME_DIR",
)


def _private_dir(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)  # also when an older install made it with the umask
    return path


def log_call(record: dict, *, settings: Settings) -> None:
    """Append one JSON line to ``calls.jsonl`` (mode 0600). Never the command's output.
    ASCII-escaped, so no character in a request can forge a line of its own."""
    path = _private_dir(settings.data_dir) / "calls.jsonl"
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "a", encoding="ascii") as f:
        f.write(json.dumps(record, ensure_ascii=True) + "\n")


def command_env(settings: Settings) -> dict[str, str]:
    """The environment for the commands the gate runs: an allowlist of the gate's own,
    with ``settings.path`` first on PATH."""
    env = {k: os.environ[k] for k in ENV_KEEP if k in os.environ}
    extra = [os.path.expanduser(p) for p in settings.path]
    env["PATH"] = os.pathsep.join(extra + [os.environ.get("PATH", "/usr/bin:/bin")])
    env["NO_COLOR"] = "1"
    return env


def _one_at_a_time(agent: str, settings: Settings):
    """A non-blocking per-agent lock: a second concurrent call is refused, not queued."""
    path = _private_dir(settings.data_dir) / f".lock-{agent}"
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        return None
    return fd


def _list_dir(path: str) -> str:
    rows = []
    for p in sorted(Path(path).iterdir()):
        if p.is_file() and not p.name.startswith("."):
            mtime = datetime.fromtimestamp(p.stat().st_mtime, UTC)
            rows.append(f"{mtime:%Y-%m-%dT%H:%M:%SZ}  {p.stat().st_size:>8}  {p.name}")
    return "\n".join(rows) + ("\n" if rows else "(empty)\n")


def run_decision(
    decision: Decision,
    *,
    settings: Settings,
    out: Callable[[str], object] | None = None,
) -> int:
    """Carry out an allowed decision; return the exit status."""
    out = out or sys.stdout.write
    if decision.reason == "list":
        out(_list_dir(decision.path))
        return 0
    if decision.reason == "file":
        out(Path(decision.path).read_text(encoding="utf-8", errors="replace"))
        return 0
    try:
        # Its own process group, so a timeout stops the grandchildren (gh, claude) too.
        proc = subprocess.Popen(
            list(decision.argv),
            env=command_env(settings),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
    except FileNotFoundError:
        sys.stderr.write(f"hatchway: {decision.argv[0]!r} is not installed on this machine\n")
        return 127
    try:
        stdout, stderr = proc.communicate(timeout=settings.timeout)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.communicate()
        sys.stderr.write(f"hatchway: stopped after {settings.timeout}s\n")
        return TIMED_OUT
    try:
        out(stdout)
        if stderr:
            sys.stderr.write(stderr)
    except BrokenPipeError:
        pass  # the agent hung up; the command already ran and is logged
    return proc.returncode


def gate(
    request: str | None = None,
    *,
    agent: str = "agent",
    profile: str | Profile | None = None,
    settings: Settings | None = None,
) -> int:
    """Decide and run one request. ``request`` defaults to ``$SSH_ORIGINAL_COMMAND``."""
    settings = settings or load_settings()
    if request is None:
        request = os.environ.get("SSH_ORIGINAL_COMMAND", "")
    if not isinstance(profile, Profile):
        profile = load_profile(profile or settings.profile, settings=settings)
    started = time.time()
    record = {
        "ts": datetime.now(UTC).isoformat(timespec="seconds"),
        "agent": agent,
        "from": (os.environ.get("SSH_CLIENT") or "local").split(" ")[0],
        "request": request[:500],
    }
    if request.strip() in HELP_WORDS:
        sys.stdout.write("\n".join(describe(profile)) + "\n")
        log_call({**record, "decision": "help", "status": 0}, settings=settings)
        return 0
    decision = decide(
        request,
        profile,
        flags_present=settings.flags_present(),
        dispatch_roots=settings.dispatch_roots,
        roots=settings.all_roots(),
    )
    if not decision.allowed:
        sys.stderr.write(
            f"hatchway: refused: {decision.reason}. Send 'help' for what is allowed.\n"
        )
        log_call(
            {**record, "decision": "refused", "reason": decision.reason, "status": REFUSED},
            settings=settings,
        )
        return REFUSED
    allowed = {
        **record,
        "decision": "allowed",
        "class": decision.klass,
        "argv": list(decision.argv) or [decision.path],
    }
    lock = _one_at_a_time(agent, settings)
    if lock is None:
        sys.stderr.write("hatchway: busy: one call at a time; retry when the last one ends\n")
        log_call({**allowed, "decision": "busy", "status": BUSY}, settings=settings)
        return BUSY
    try:
        # Logged before it runs: a call whose connection drops still leaves its line.
        log_call({**allowed, "phase": "start"}, settings=settings)
        status = run_decision(decision, settings=settings)
        log_call(
            {
                **allowed,
                "phase": "end",
                "status": status,
                "seconds": round(time.time() - started, 2),
            },
            settings=settings,
        )
    finally:
        os.close(lock)
    return status

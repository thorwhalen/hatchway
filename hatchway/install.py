"""Putting a hatch on a machine: the ``authorized_keys`` line, the snapshot timer, the skills.

Every function here is idempotent, backs a file up before changing it (into
``<data>/backups/``), and has a ``dry_run`` that says what it would do.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

from hatchway.config import Settings, load_settings

# Tailscale's address ranges (CGNAT IPv4 and its ULA IPv6): with `from=` set to these,
# the key is refused from anywhere but the tailnet, even if sshd is reachable otherwise.
TAILNET_FROM = "100.64.0.0/10,fd7a:115c:a1e0::/48"
_KEY_RE = re.compile(
    r"(ssh-ed25519|sk-ssh-ed25519@openssh\.com|ecdsa-sha2-nistp(256|384|521)"
    r"|sk-ecdsa-sha2-nistp256@openssh\.com|ssh-rsa) [A-Za-z0-9+/]+={0,3}( [\w.@+-]{0,80})?"
)
_AGENT_RE = re.compile(r"[a-z][a-z0-9_-]{0,31}")
_FROM_RE = re.compile(r"[0-9a-fA-F.:/,*?!]{1,512}")
SKILLS_DIR = Path(__file__).parent / "data" / "skills"
AGENTS_DIR = Path(__file__).parent / "data" / "agents"


def hatchway_bin() -> str:
    """The absolute path of this install's ``hatchway`` script, for the forced command."""
    beside = Path(sys.executable).parent / "hatchway"
    if beside.exists():
        return str(beside)
    found = shutil.which("hatchway")
    if not found:
        raise FileNotFoundError("cannot find the hatchway script; is the package installed?")
    return str(Path(found).resolve())


def backup(path: Path, *, settings: Settings) -> Path | None:
    if not path.exists():
        return None
    dest = (
        settings.data_dir
        / "backups"
        / f"{path.name}.{datetime.now().astimezone():%Y%m%d-%H%M%S}"
    )
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(path, dest)
    return dest


def key_line(
    public_key: str,
    *,
    agent: str,
    profile: str | None = None,
    from_: str | None = TAILNET_FROM,
    binary: str | None = None,
) -> str:
    """The ``authorized_keys`` line that confines ``public_key`` to the gate.

    >>> key_line("ssh-ed25519 AAAAC3Nz hatch", agent="muse", binary="/b/hatchway")
    'command="/b/hatchway gate --agent muse",restrict,from="100.64.0.0/10,fd7a:115c:a1e0::/48" ssh-ed25519 AAAAC3Nz hatch'
    """
    public_key = public_key.strip()
    if not _KEY_RE.fullmatch(public_key):
        raise ValueError("not a single OpenSSH public key (type, base64, optional comment)")
    if not _AGENT_RE.fullmatch(agent):
        raise ValueError("agent must be a short lowercase name, e.g. 'muse'")
    binary = binary or hatchway_bin()
    if any(c in binary for c in '"\\ \n'):
        raise ValueError(f"the hatchway path {binary!r} cannot go in a forced command")
    cmd = f"{binary} gate --agent {agent}"
    if profile:
        if not re.fullmatch(r"[\w.-]+", profile):
            raise ValueError("profile must be a bare name")
        cmd += f" --profile {profile}"
    opts = [f'command="{cmd}"', "restrict"]
    if from_:
        if not _FROM_RE.fullmatch(from_):
            raise ValueError("from must be addresses, CIDRs or patterns separated by commas")
        opts.append(f'from="{from_}"')
    return f"{','.join(opts)} {public_key}"


def _blob(line: str) -> str | None:
    m = re.search(r"(?:^|\s)(?:ssh-|ecdsa-|sk-)\S+ ([A-Za-z0-9+/]+={0,3})", line)
    return m.group(1) if m else None


def authorize(
    public_key: str,
    *,
    agent: str,
    profile: str | None = None,
    from_: str | None = TAILNET_FROM,
    authorized_keys: str | Path = "~/.ssh/authorized_keys",
    replace: bool = False,
    dry_run: bool = False,
    settings: Settings | None = None,
) -> dict:
    """Add (or confirm) the gate's line for ``public_key``, keeping every other line.

    Returns ``{"action": "added" | "ok" | "replaced" | "conflict", ...}``. A line for the
    same key with different options is a ``conflict`` unless ``replace``.
    """
    settings = settings or load_settings()
    path = Path(authorized_keys).expanduser()
    line = key_line(public_key, agent=agent, profile=profile, from_=from_)
    blob = _blob(line)
    lines = path.read_text().splitlines() if path.exists() else []
    same = [i for i, ln in enumerate(lines) if _blob(ln) == blob]
    if same and all(lines[i].strip() == line for i in same):
        return {"action": "ok", "path": str(path), "line": line}
    if same and not replace:
        return {
            "action": "conflict",
            "path": str(path),
            "line": line,
            "existing": [lines[i] for i in same],
        }
    action = "replaced" if same else "added"
    kept = [ln for i, ln in enumerate(lines) if i not in same]
    result = {"action": action, "path": str(path), "line": line}
    if dry_run:
        return {**result, "dry_run": True}
    result["backup"] = str(backup(path, settings=settings) or "")
    _write_private(path, "\n".join(kept + [line]) + "\n")
    return result


def _write_private(path: Path, text: str) -> None:
    """Replace ``path`` atomically with a 0600 file. A symlinked ``authorized_keys``
    (a dotfiles setup) is written through, at the file it points to."""
    target = path.resolve() if path.is_symlink() else path
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.")  # 0600, O_EXCL
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.replace(tmp, target)


def revoke(
    agent: str,
    *,
    authorized_keys: str | Path = "~/.ssh/authorized_keys",
    dry_run: bool = False,
    settings: Settings | None = None,
) -> dict:
    """Remove every line whose forced command is the gate for ``agent``."""
    settings = settings or load_settings()
    path = Path(authorized_keys).expanduser()
    lines = path.read_text().splitlines() if path.exists() else []
    marker = re.compile(rf'command="[^"]*hatchway gate --agent {re.escape(agent)}(\s|")')
    drop = [ln for ln in lines if marker.search(ln)]
    if not drop or dry_run:
        return {"removed": len(drop), "dry_run": dry_run, "path": str(path)}
    b = backup(path, settings=settings)
    _write_private(path, "\n".join(ln for ln in lines if ln not in drop) + "\n")
    return {"removed": len(drop), "backup": str(b), "path": str(path)}


# --- the snapshot timer -------------------------------------------------------------

LAUNCHD_LABEL = "io.github.hatchway.snapshot"


def schedule_units(*, every: int = 300, binary: str | None = None) -> dict[str, str]:
    """The files that run ``hatchway snapshot`` every ``every`` seconds, for this OS."""
    binary = binary or hatchway_bin()
    log = load_settings().data_dir / "snapshot.log"
    if sys.platform == "darwin":
        plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>{LAUNCHD_LABEL}</string>
  <key>ProgramArguments</key><array><string>{binary}</string><string>snapshot</string></array>
  <key>StartInterval</key><integer>{every}</integer>
  <key>RunAtLoad</key><true/>
  <key>StandardOutPath</key><string>{log}</string>
  <key>StandardErrorPath</key><string>{log}</string>
</dict></plist>
"""
        return {str(Path(f"~/Library/LaunchAgents/{LAUNCHD_LABEL}.plist").expanduser()): plist}
    unit_dir = Path("~/.config/systemd/user").expanduser()
    service = f"""[Unit]
Description=hatchway snapshot (what an outside agent may read without waiting)

[Service]
Type=oneshot
ExecStart={binary} snapshot
"""
    timer = f"""[Unit]
Description=Run the hatchway snapshot every {every}s

[Timer]
OnBootSec=60
OnUnitActiveSec={every}

[Install]
WantedBy=timers.target
"""
    return {
        str(unit_dir / "hatchway-snapshot.service"): service,
        str(unit_dir / "hatchway-snapshot.timer"): timer,
    }


def install_schedule(*, every: int = 300, dry_run: bool = False) -> dict:
    """Write the units and load them (launchd on macOS, systemd --user on Linux)."""
    units = schedule_units(every=every)
    if dry_run:
        return {"dry_run": True, "files": list(units)}
    for path, text in units.items():
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    if sys.platform == "darwin":
        plist = next(iter(units))
        uid = os.getuid()
        subprocess.run(
            ["launchctl", "bootout", f"gui/{uid}/{LAUNCHD_LABEL}"],
            capture_output=True,
            check=False,
        )
        subprocess.run(["launchctl", "bootstrap", f"gui/{uid}", plist], check=True)
        loaded = f"launchd gui/{uid}/{LAUNCHD_LABEL}"
    elif shutil.which("systemctl"):
        subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)
        subprocess.run(
            ["systemctl", "--user", "enable", "--now", "hatchway-snapshot.timer"], check=True
        )
        loaded = "systemd --user hatchway-snapshot.timer"
    else:
        loaded = f"no launchd or systemd: add to cron: */{max(every // 60, 1)} * * * * {hatchway_bin()} snapshot"
    return {"files": list(units), "loaded": loaded}


# --- skills -------------------------------------------------------------------------


def install_skills(
    *, homes: list[str | Path] | None = None, force: bool = False, dry_run: bool = False
) -> list[dict]:
    """Link the bundled skills (and agents, if any) into each Claude home. Idempotent;
    something else already at a name is reported as ``conflict`` and left alone."""
    homes = homes or [os.environ.get("CLAUDE_CONFIG_DIR", "~/.claude")]
    rows = []
    for home in homes:
        home = Path(home).expanduser()
        assets = [
            (p, home / "skills" / p.name) for p in sorted(SKILLS_DIR.iterdir()) if p.is_dir()
        ]
        if AGENTS_DIR.is_dir():
            assets += [(p, home / "agents" / p.name) for p in sorted(AGENTS_DIR.glob("*.md"))]
        for src, dest in assets:
            here = dest.is_symlink() and Path(os.readlink(dest)).resolve() == src.resolve()
            exists = dest.exists() or dest.is_symlink()
            action = "ok" if here else ("conflict" if exists and not force else "install")
            if action == "install" and not dry_run:
                if exists:
                    dest.unlink() if dest.is_symlink() or dest.is_file() else shutil.rmtree(
                        dest
                    )
                dest.parent.mkdir(parents=True, exist_ok=True)
                os.symlink(src, dest, target_is_directory=src.is_dir())
            rows.append({"home": str(home), "name": src.name, "action": action})
    return rows


def claude_homes() -> list[Path]:
    """Every Claude Code home here: ``~/.claude`` and ``~/.claude-*`` with a skills folder."""
    found = [Path("~/.claude").expanduser(), *sorted(Path.home().glob(".claude-*"))]
    return [h for h in found if (h / "skills").is_dir()]


DFLT_TOOLS = ("crowsnest", "ol", "claude", "gh")


def write_config(
    *,
    tools: tuple[str, ...] = DFLT_TOOLS,
    profile: str = "claude-fleet",
    settings: Settings | None = None,
) -> dict:
    """Write ``config.toml`` with ``path`` set to where ``tools`` live, unless one exists."""
    settings = settings or load_settings()
    path = settings.config_dir / "config.toml"
    if path.exists():
        return {"action": "ok", "path": str(path)}
    dirs = list(dict.fromkeys(str(Path(w).parent) for t in tools if (w := shutil.which(t))))
    missing = [t for t in tools if not shutil.which(t)]
    path.parent.mkdir(parents=True, exist_ok=True)
    body = (
        f'profile = "{profile}"\n'
        f"# sshd hands a forced command a minimal PATH: where {', '.join(tools)} live\n"
        f"path = [{', '.join(repr(d).replace(chr(39), chr(34)) for d in dirs)}]\n"
        f"timeout = 120\n"
    )
    path.write_text(body)
    return {"action": "written", "path": str(path), "path_dirs": dirs, "missing": missing}


def self_test(*, settings: Settings | None = None) -> dict:
    """Run the gate as sshd would (empty environment) on one allowed and one forbidden
    request. ``ok`` is false if the forbidden one was allowed or the allowed one refused."""
    binary = hatchway_bin()
    env = {"HOME": str(Path.home()), "PATH": "/usr/bin:/bin"}
    if settings is not None:
        env |= {
            "HATCHWAY_CONFIG_DIR": str(settings.config_dir),
            "HATCHWAY_DATA_DIR": str(settings.data_dir),
        }

    def run(request):
        p = subprocess.run(
            [binary, "gate", "--agent", "selftest"],
            capture_output=True,
            text=True,
            env={**env, "SSH_ORIGINAL_COMMAND": request},
            timeout=180,
            check=False,
        )
        return {
            "request": request,
            "status": p.returncode,
            "first_line": (p.stdout or p.stderr).strip().splitlines()[:1],
        }

    allowed, forbidden = run("help"), run("cat ~/.ssh/authorized_keys")
    return {
        "ok": allowed["status"] == 0 and forbidden["status"] == 126,
        "allowed": allowed,
        "forbidden": forbidden,
    }


def setup(
    public_key: str,
    *,
    agent: str,
    every: int | None = 300,
    skills: bool = True,
    settings: Settings | None = None,
) -> dict:
    """Everything a machine needs, in order, stopping before the key if the gate fails:
    config, self-test, authorize, snapshot and its timer, skills. Idempotent."""
    from hatchway.snapshot import snapshot

    settings = settings or load_settings()
    report = {"config": write_config(settings=settings)}
    settings = load_settings()
    report["self_test"] = self_test()
    if not report["self_test"]["ok"]:
        report["stopped"] = "the gate self-test failed: no key was installed"
        return report
    report["authorize"] = authorize(public_key, agent=agent, settings=settings)
    if every:
        index = snapshot(settings=settings)
        report["snapshot"] = {k: v.get("status") for k, v in index["files"].items()}
        try:
            report["schedule"] = install_schedule(every=every)
        except (OSError, subprocess.CalledProcessError) as e:
            report["schedule"] = {
                "error": str(e),
                "cron": f"*/{max(every // 60, 1)} * * * * {hatchway_bin()} snapshot",
            }
    if skills:
        report["skills"] = install_skills(homes=claude_homes())
    return report

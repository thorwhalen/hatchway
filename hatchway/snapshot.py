"""The pull fallback: run the profile's snapshot requests and keep their answers on disk.

Each ``[[snapshot]]`` entry of a profile names a request (``crowsnest triage``) and a
file (``triage.md``). The request goes through the same :func:`hatchway.policy.decide`
the gate uses, so a snapshot can never run anything an agent could not ask for itself.
Files are written atomically into ``<data>/out/`` with an ``index.json`` saying when
each was made and how it exited; an agent reads them with the gate's ``snapshot`` rule,
without waiting for the commands to run. ``settings.snapshot_to`` optionally copies the
folder somewhere private (a local directory, or ``host:path`` through rsync).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from hatchway.config import Settings, load_profile, load_settings
from hatchway.gate import command_env
from hatchway.policy import Profile, decide


def write_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _run(argv, settings: Settings) -> tuple[int, str]:
    try:
        p = subprocess.run(  # noqa: PLW1510
            list(argv), env=command_env(settings), capture_output=True,
                           text=True, stdin=subprocess.DEVNULL, timeout=settings.timeout)
        return p.returncode, p.stdout if p.returncode == 0 else p.stdout + p.stderr
    except FileNotFoundError:
        return 127, f"{argv[0]} is not installed\n"
    except subprocess.TimeoutExpired:
        return 124, f"stopped after {settings.timeout}s\n"


def snapshot(
    *, profile: str | Profile | None = None, settings: Settings | None = None
) -> dict:
    """Run every snapshot request once; return the index that was written."""
    settings = settings or load_settings()
    if not isinstance(profile, Profile):
        profile = load_profile(profile or settings.profile, settings=settings)
    out = settings.out_dir
    out.mkdir(parents=True, exist_ok=True)
    os.chmod(out, 0o700)
    index = {"made": datetime.now(UTC).isoformat(timespec="seconds"),
             "profile": profile.name, "files": {}}
    for entry in profile.snapshot:
        request, name = entry["request"], entry["file"]
        d = decide(request, profile, flags_present=settings.flags_present(),
                   roots=settings.all_roots())
        if not d.allowed or d.rule.kind != "exec" or d.klass != "read":
            index["files"][name] = {"request": request, "status": None,
                                    "skipped": d.reason or "not a read command"}
            continue
        status, text = _run(d.argv, settings)
        stamp = datetime.now(UTC).isoformat(timespec="seconds")
        write_atomic(out / name, text)
        index["files"][name] = {"request": request, "status": status, "made": stamp}
    # A file the profile no longer lists would be served stale forever: drop it.
    keep = set(index["files"]) | {"index.json"}
    index["pruned"] = sorted(
        p.name for p in out.iterdir()
        if p.is_file() and not p.name.startswith(".") and p.name not in keep
    )
    for name in index["pruned"]:
        (out / name).unlink()
    write_atomic(out / "index.json", json.dumps(index, indent=2) + "\n")
    if settings.snapshot_to:
        index["copied_to"] = copy_out(out, settings.snapshot_to)
    return index


def copy_out(out: Path, to: str) -> str:
    """Copy the snapshot folder to a local directory or ``host:path`` (rsync over ssh)."""
    if ":" in to and not Path(to).expanduser().exists():
        subprocess.run(["rsync", "-a", "--delete", "-e", "ssh -o BatchMode=yes",
                        f"{out}/", to.rstrip("/") + "/"], check=True, timeout=120)
        return to
    dest = Path(to).expanduser()
    dest.mkdir(parents=True, exist_ok=True)
    for p in out.iterdir():
        if p.is_file() and not p.name.startswith("."):
            shutil.copy2(p, dest / p.name)
    return str(dest)

"""Where hatchway keeps its configuration and its records, and how a profile is found.

Config: ``$HATCHWAY_CONFIG_DIR`` or ``~/.config/hatchway/`` (``config.toml``, the flag
files such as ``allow-dispatch``, optional user profiles in ``profiles/``).
Data: ``$HATCHWAY_DATA_DIR`` or ``~/.local/share/hatchway/`` (``calls.jsonl``, the
snapshot in ``out/``, backups of files hatchway edited in ``backups/``).

The config file is optional; every key has a default::

    profile = "claude-fleet"      # a bundled profile name, or a path to a .toml
    path = ["/opt/bin"]           # prepended to PATH for the commands the gate runs
    timeout = 120                 # seconds before a command is stopped
    [roots]                       # directories file rules may serve, by name
    ledger = "~/.local/share/crowsnest/ledger"
    [dispatch]
    roots = ["~/projects"]        # where a dispatch (spawn) may start a session
    [snapshot]
    to = ""                       # optional extra copy: a local dir or host:path (rsync)
"""

from __future__ import annotations

import os
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from hatchway.policy import Profile

DFLT_PROFILE = "claude-fleet"
DFLT_TIMEOUT = 120
BUNDLED_PROFILES = Path(__file__).parent / "data" / "profiles"


def config_dir() -> Path:
    return Path(os.environ.get("HATCHWAY_CONFIG_DIR", "~/.config/hatchway")).expanduser()


def data_dir() -> Path:
    return Path(os.environ.get("HATCHWAY_DATA_DIR", "~/.local/share/hatchway")).expanduser()


@dataclass
class Settings:
    """The resolved configuration the gate and the snapshot run with."""

    profile: str = DFLT_PROFILE
    path: list[str] = field(default_factory=list)
    timeout: int = DFLT_TIMEOUT
    roots: dict[str, str] = field(default_factory=dict)
    dispatch_roots: list[str] = field(default_factory=list)
    snapshot_to: str = ""
    config_dir: Path = field(default_factory=config_dir)
    data_dir: Path = field(default_factory=data_dir)

    @classmethod
    def from_mapping(cls, d: Mapping, **overrides) -> Settings:
        s = cls(
            profile=d.get("profile", DFLT_PROFILE),
            path=list(d.get("path", [])),
            timeout=int(d.get("timeout", DFLT_TIMEOUT)),
            roots=dict(d.get("roots", {})),
            dispatch_roots=list(d.get("dispatch", {}).get("roots", [])),
            snapshot_to=d.get("snapshot", {}).get("to", ""),
        )
        for k, v in overrides.items():
            if v is not None:
                setattr(s, k, v)
        return s

    @property
    def out_dir(self) -> Path:
        return self.data_dir / "out"

    def all_roots(self) -> dict[str, str]:
        """File-rule roots: ``out`` (the snapshot) always, plus the configured ones."""
        return {"out": str(self.out_dir), **self.roots}

    def flags_present(self) -> frozenset[str]:
        d = self.config_dir
        if not d.is_dir():
            return frozenset()
        return frozenset(
            p.name for p in d.iterdir() if p.is_file() and p.name.startswith("allow-")
        )


def load_settings(*, config_file: str | Path | None = None, **overrides) -> Settings:
    """Read ``config.toml`` (absent is fine) into :class:`Settings`."""
    cdir = config_dir()
    path = Path(config_file) if config_file else cdir / "config.toml"
    d = tomllib.loads(path.read_text()) if path.is_file() else {}
    return Settings.from_mapping(d, config_dir=cdir, data_dir=data_dir(), **overrides)


def profile_path(name_or_path: str, *, settings: Settings | None = None) -> Path:
    """A profile by path, else ``<config>/profiles/<name>.toml``, else a bundled one."""
    p = Path(name_or_path).expanduser()
    if p.suffix == ".toml" and p.is_file():
        return p
    cdir = settings.config_dir if settings else config_dir()
    for candidate in (
        cdir / "profiles" / f"{name_or_path}.toml",
        BUNDLED_PROFILES / f"{name_or_path}.toml",
    ):
        if candidate.is_file():
            return candidate
    known = sorted(q.stem for q in BUNDLED_PROFILES.glob("*.toml"))
    raise FileNotFoundError(f"no profile {name_or_path!r}; bundled: {', '.join(known)}")


def _profile_dict(name_or_path: str, *, settings, seen: tuple = ()) -> dict:
    """A profile's TOML as a dict, with ``extends`` resolved.

    ``extends = "claude-ai"`` takes that profile's rules, classes, snapshot and
    instructions first; this file's rules come after them and replace a rule with the
    same ``match``. So a machine's private profile adds what only it has without copying
    the bundled one.
    """
    path = profile_path(name_or_path, settings=settings)
    if path in seen:
        raise ValueError(f"profile {path.stem!r} extends itself")
    d = tomllib.loads(path.read_text())
    d.setdefault("name", path.stem)
    base_name = d.pop("extends", None)
    if not base_name:
        return d
    base = _profile_dict(base_name, settings=settings, seen=(*seen, path))
    own = {tuple(r["match"]) for r in d.get("rule", ())}
    rules = [r for r in base.get("rule", ()) if tuple(r["match"]) not in own]
    return {
        **base,
        **d,
        "rule": rules + list(d.get("rule", ())),
        "classes": {**base.get("classes", {}), **d.get("classes", {})},
        "snapshot": list(base.get("snapshot", ())) + list(d.get("snapshot", ())),
    }


def load_profile(
    name_or_path: str = DFLT_PROFILE, *, settings: Settings | None = None
) -> Profile:
    path = profile_path(name_or_path, settings=settings)
    return Profile.from_dict(_profile_dict(name_or_path, settings=settings), name=path.stem)

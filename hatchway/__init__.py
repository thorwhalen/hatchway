"""hatchway: a narrow, logged opening through which an outside agent reaches your tools.

An agent that lives elsewhere (a personal assistant on its own cloud VM, a phone
shortcut, another machine's scheduler) gets one SSH key. That key can do one thing:
run :func:`gate`, which reads the requested command line, checks it against a profile
(an allowlist kept as data), logs it, and runs it without a shell, or refuses.

>>> from hatchway import decide, load_profile
>>> profile = load_profile("claude-fleet")
>>> decide("crowsnest triage --quiet", profile).allowed
True
>>> decide("crowsnest spawn x --prompt hi", profile).allowed   # gated off by default
False
"""

from hatchway.config import Settings, load_profile, load_settings
from hatchway.gate import gate
from hatchway.install import authorize, install_schedule, install_skills, key_line, revoke
from hatchway.policy import Decision, Profile, Rule, decide, describe
from hatchway.snapshot import snapshot

__all__ = [
    "Decision", "Profile", "Rule", "Settings", "authorize", "decide", "describe", "gate",
    "install_schedule", "install_skills", "key_line", "load_profile", "load_settings",
    "revoke", "snapshot",
]

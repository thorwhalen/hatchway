"""The ``hatchway`` command line.

    hatchway gate --agent muse          # the forced command sshd runs (reads $SSH_ORIGINAL_COMMAND)
    hatchway check "crowsnest triage"   # what the gate would do, without running it
    hatchway help                       # every allowed request, one per line
    hatchway snapshot                   # run the snapshot requests now
    hatchway authorize KEY --agent muse # add the confined authorized_keys line
    hatchway revoke --agent muse        # remove it
    hatchway schedule --every 300       # run the snapshot on a timer (launchd / systemd)
    hatchway install-skills             # link the bundled skills into Claude homes
    hatchway setup KEY --agent muse     # all of the above, in order, on a new machine
    hatchway log                        # the last calls an agent made
    hatchway mcp --profile claude-ai    # the profile as MCP tools (needs hatchway[mcp])

The CLI is plain ``argparse`` on purpose: a gate should import as little as possible.
"""

from __future__ import annotations

import argparse
import json
import sys

from hatchway.config import load_profile, load_settings


def _print(obj) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False) if not isinstance(obj, str) else obj)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="hatchway", description=__doc__.splitlines()[1])
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gate", help="the forced command: decide and run $SSH_ORIGINAL_COMMAND")
    g.add_argument("--agent", default="agent")
    g.add_argument("--profile")
    g.add_argument("--request", help="use this instead of $SSH_ORIGINAL_COMMAND (testing)")

    c = sub.add_parser("check", help="what the gate would do with a request; runs nothing")
    c.add_argument("request")
    c.add_argument("--profile")

    h = sub.add_parser("help", help="every allowed request")
    h.add_argument("--profile")

    s = sub.add_parser("snapshot", help="run the profile's snapshot requests now")
    s.add_argument("--profile")

    a = sub.add_parser("authorize", help="add the confined authorized_keys line for a key")
    a.add_argument("public_key", help="the whole public key line, quoted")
    a.add_argument("--agent", required=True)
    a.add_argument("--profile")
    a.add_argument(
        "--from",
        dest="from_",
        default=None,
        help="allowed source addresses (default: Tailscale's ranges)",
    )
    a.add_argument("--anywhere", action="store_true", help="no from= restriction")
    a.add_argument("--authorized-keys", default="~/.ssh/authorized_keys")
    a.add_argument("--replace", action="store_true")
    a.add_argument("--dry-run", action="store_true")

    r = sub.add_parser("revoke", help="remove the gate's lines for an agent")
    r.add_argument("--agent", required=True)
    r.add_argument("--authorized-keys", default="~/.ssh/authorized_keys")
    r.add_argument("--dry-run", action="store_true")

    t = sub.add_parser("schedule", help="run the snapshot on a timer")
    t.add_argument("--every", type=int, default=300, help="seconds (default 300)")
    t.add_argument("--dry-run", action="store_true")

    k = sub.add_parser("install-skills", help="link the bundled skills into Claude homes")
    k.add_argument("--home", action="append", help="a Claude home; repeat for several")
    k.add_argument("--force", action="store_true")
    k.add_argument("--dry-run", action="store_true")

    su = sub.add_parser("setup", help="config, self-test, authorize, snapshot timer, skills")
    su.add_argument("public_key")
    su.add_argument("--agent", required=True)
    su.add_argument("--every", type=int, default=300, help="snapshot seconds; 0 for none")
    su.add_argument("--no-skills", action="store_true")

    lg = sub.add_parser("log", help="the last calls made through the gate")
    lg.add_argument("-n", type=int, default=20)

    m = sub.add_parser("mcp", help="serve the profile as MCP tools (needs hatchway[mcp])")
    m.add_argument("--profile")
    m.add_argument("--ssh", help="send each call to this [user@]host's gate instead")
    m.add_argument("--identity", help="the ssh key for --ssh")
    m.add_argument("--classes", default="read", help="comma separated (default: read)")
    m.add_argument("--http", type=int, help="serve streamable HTTP on 127.0.0.1:PORT")
    m.add_argument(
        "--no-auth",
        action="store_true",
        help="required with --http: this serves WITHOUT authentication, to this machine",
    )
    m.add_argument("--list", action="store_true", help="print the tools and exit")

    args = ap.parse_args(argv)
    settings = load_settings()

    if args.cmd == "mcp":
        from hatchway.mcp import local_runner, mk_server, mk_tools, ssh_runner

        classes = [c.strip() for c in args.classes.split(",") if c.strip()]
        runner = (
            ssh_runner(args.ssh, identity=args.identity)
            if args.ssh
            else local_runner(profile=args.profile or settings.profile)
        )
        name = args.profile or settings.profile
        if args.ssh and not args.profile:
            ap.error("--ssh needs --profile: the far gate decides with the profile it is told")
        profile = load_profile(name, settings=settings)
        if args.http and not args.no_auth:
            ap.error(
                "--http serves with no authentication (any process here can call it); "
                "pass --no-auth to accept that, or serve hatchway.mcp.mk_server(auth=...)"
            )
        if args.list:
            for t in mk_tools(profile, runner=runner, classes=classes):
                print(f"{t.__name__}{t.__signature__}  {t.__doc__}")
            return 0
        server = mk_server(profile, runner=runner, settings=settings, classes=classes)
        if args.http:
            server.run(transport="streamable-http", host="127.0.0.1", port=args.http)
        else:
            server.run()
        return 0
    if args.cmd == "gate":
        from hatchway.gate import gate

        return gate(args.request, agent=args.agent, profile=args.profile, settings=settings)
    if args.cmd in ("check", "help"):
        from hatchway.policy import decide, describe

        profile = load_profile(args.profile or settings.profile, settings=settings)
        if args.cmd == "help":
            _print("\n".join(describe(profile)))
            return 0
        d = decide(
            args.request,
            profile,
            flags_present=settings.flags_present(),
            dispatch_roots=settings.dispatch_roots,
            roots=settings.all_roots(),
        )
        _print(
            {
                "allowed": d.allowed,
                "reason": d.reason,
                "class": d.klass,
                "argv": list(d.argv),
                "path": d.path,
            }
        )
        return 0 if d.allowed else 126
    if args.cmd == "snapshot":
        from hatchway.snapshot import snapshot

        _print(snapshot(profile=args.profile, settings=settings))
        return 0
    if args.cmd == "authorize":
        from hatchway.install import TAILNET_FROM, authorize

        from_ = None if args.anywhere else (args.from_ or TAILNET_FROM)
        res = authorize(
            args.public_key,
            agent=args.agent,
            profile=args.profile,
            from_=from_,
            authorized_keys=args.authorized_keys,
            replace=args.replace,
            dry_run=args.dry_run,
            settings=settings,
        )
        _print(res)
        return 1 if res["action"] == "conflict" else 0
    if args.cmd == "revoke":
        from hatchway.install import revoke

        _print(
            revoke(
                args.agent,
                authorized_keys=args.authorized_keys,
                dry_run=args.dry_run,
                settings=settings,
            )
        )
        return 0
    if args.cmd == "schedule":
        from hatchway.install import install_schedule

        _print(install_schedule(every=args.every, dry_run=args.dry_run))
        return 0
    if args.cmd == "install-skills":
        from hatchway.install import install_skills

        rows = install_skills(homes=args.home, force=args.force, dry_run=args.dry_run)
        _print(rows)
        return 1 if any(r["action"] == "conflict" for r in rows) else 0
    if args.cmd == "setup":
        from hatchway.install import setup

        res = setup(
            args.public_key,
            agent=args.agent,
            every=args.every or None,
            skills=not args.no_skills,
            settings=settings,
        )
        _print(res)
        return 0 if "stopped" not in res and res["authorize"]["action"] != "conflict" else 1
    if args.cmd == "log":
        path = settings.data_dir / "calls.jsonl"
        lines = (
            [x for x in path.read_text().split("\n") if x][-args.n :] if path.exists() else []
        )
        _print("\n".join(lines) or "(no calls yet)")
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())

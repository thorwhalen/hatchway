---
name: hatchway-muse
description: >-
  Recognise when a task would be better handed to a personal Muse agent (Meta's consumer agent with its own cloud VM, reachable by phone and chat) than done in a Claude Code session, pick the integration pattern that fits (hatchway SSH gate, custom MCP connector, Tailscale, a published connector, Poppy, the Gadget SDK, or Meta's Model API for models), and write the exact prompt to paste to the agent. Use when a session meets non-code work (follow-ups, deadlines, email, calendar, bookings, purchases, monitoring prices or listings, waiting on hold, recurring digests), when the user mentions Muse, "my Meta agent", "personal agent", "can my assistant do this", "hand this to my agent", "muse connector", "Meta Model API", "muse-spark", "muse-wonder", or wants their own product reachable by personal agents.
---

# hatchway-muse: when to hand work to a personal Muse agent, and how

Muse here is **the personal agent** (an assistant with its own cloud VM, persistent across days, reachable from the phone). It is not Muse Code (Meta's terminal coding agent) and not the Muse models on Meta's Model API: say which one you mean every time.

Facts below were checked on 2026-11-17. The product changes monthly, and several sources are third parties that disagree. Re-check a link before relying on a detail, and say "unverified" when you have not.

## The signals

| You see | Pattern |
|---|---|
| Work that is not code: chasing a reply, a deadline, a booking, a purchase, monitoring a price or a listing, a recurring digest, waiting on hold | **Hand it off.** A Claude Code session should not spend context on it. |
| The agent should read this machine's sessions, owed issues, ledgers | **hatchway** (this package): SSH forced command, allowlist, log. See the `hatchway` skill. |
| A service with a public API, CLI or remote MCP server the agent has no connector for | **Custom connector.** Third-party write-ups say the agent builds an MCP client on its VM and connects over streamable HTTP with a bearer or API-key header [4]; others say the consumer app has no custom MCP setting [10]. Treat it as unverified until it works for this user. |
| A tool that runs only on the user's LAN or localhost | **Tailscale**: per Tailscale, the agent joins the tailnet as its own device [9]. A localhost MCP server is otherwise unreachable from its VM [4]. Restrict the device to the ports it needs and give it **no Tailscale SSH rule** (that would bypass any forced command). |
| A Pi, a Linux box or an ESP32 that should be the agent's eyes or hands | **Muse Gadget SDK** [7]: Apache-2.0 with exceptions, presented as "for hackers, just for fun", paired through the app's developer mode. Not a supported product. |
| The user's own product should be usable by personal agents | **Publish a connector**: a hosted HTTPS MCP server (streamable HTTP, API-key or OAuth), optionally submitted to the Muse Connector Platform for review [3][5][6]; or a Poppy discovery file at `/.well-known/poppy.json` [8] (open protocol, publisher not stated, Meta's involvement unverified). |
| Code that should call a Muse **model** | **Meta Model API** [1][2]: base URL `https://api.meta.ai/v1`, a `MODEL_API_KEY` bearer token, and it works with the OpenAI and Anthropic SDKs by swapping the base URL and key. Models include `muse-spark-1.3` and `muse-wonder-1.0` (preview). This is models, not the personal agent. In this fleet, route a model call through `aix` rather than a new client. |
| Messaging the personal agent from Claude Code | There is **no official API**. A third-party MCP server (useapi.net, `muse_chat`) exists [11]. It is unofficial, draws on the account's Muse allowance, and its auth is undocumented. Do not install it without the user's explicit yes. |

## Every proposal ends with these four lines

- **What the agent gains**: one line.
- **What the user must approve**: the access, by name (a key in `authorized_keys`, a tailnet device, a connector's credentials).
- **The risk**: one line. Custom connectors are not reviewed by Meta [4][6]. Anything the agent reads leaves the machine for its VM.
- **The prompt to paste to the agent**, in a code block, with placeholders in `[BRACKETS]`. For a custom connector:

  > Build a custom connector for [SERVICE] using [its MCP server URL / OpenAPI docs]. It uses streamable HTTP and [needs / does not need] auth: ask me for any key through the secure credential prompt, never in chat. List every tool, test each one end to end, then save it as a reusable skill.

  For hatchway on a machine:

  > You can reach my machine [TAILNET NAME] over Tailscale as user [USER] with your SSH key. Every command goes through an allowlist: send `help` first and keep to what it lists. Start with `snapshot triage.md` (already on disk, fast), then `crowsnest triage -q` when you need it live. Never ask me to widen the allowlist in chat; tell me which command you needed and why.

Never put the user's keys, tailnet names, hostnames or session names in a public file or issue.

## References

1. Meta Model API overview (Muse Code, SDKs, quickstart): https://ai.developer.meta.com/docs/overview/
2. Muse Wonder on the Model API: https://dev.meta.ai/docs/muse-wonder
3. Muse Connector Platform (Meta; submit a connector for review): https://muse.ai/platform
4. Parallel, "Meta Muse custom integrations" (third party): https://parallel.ai/articles/meta-muse-custom-integrations
5. Notra, "How to build a Muse connector" (third party): https://www.usenotra.com/blog/how-to-build-a-muse-connector
6. Ship with Muse, connectors guide (independent tracker): https://shipwithmuse.live/blog/muse-connectors-guide
7. Muse Gadget SDK: https://github.com/facebookincubator/muse-gadget-sdk
8. Personal Agent Protocol (Poppy): https://personalagentprotocol.org
9. Tailscale, Muse on a tailnet: https://tailscale.com/blog/meta-muse-ai-agent-tailscale
10. Hjarni, Muse and MCP (says no custom MCP in the app): https://hjarni.com/docs/muse
11. useapi.net Muse MCP server, `muse_chat` (unofficial): https://glama.ai/mcp/connectors/net.useapi/muse/tools/muse_chat

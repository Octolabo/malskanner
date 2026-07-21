# malskanner

**The safety gate your AI agent runs on a repo before it trusts a single line.**

When you point Claude Code, Cursor, or any coding agent at a repository, the
agent ingests *everything* in it — including the README, docs, and comments. A
malicious repo can hide instructions in those files that hijack your agent the
moment it reads them: read your SSH keys, run a shell command, exfiltrate data.
The scary part is that **these payloads are invisible to humans** — hidden in
zero-width characters, bidirectional overrides, and Unicode tag-smuggling.

`malskanner` scans a repo for exactly those payloads and gives a clear verdict —
**REFUSE / WARN / OK** — as a CLI *and* as an MCP tool your agent calls first.

<!-- TODO before launch: verify + cite the CSA "README injection" figures
     (reported ~84% agent-hijack success; 15/15 human reviewers missed them). -->

## Quick start

```bash
npm install
npm run fixtures      # generate the demo repos
npm run scan:demo     # scan the booby-trapped fixture
```

Scan anything:

```bash
npx tsx src/cli.ts <path-to-repo>      # human report
npx tsx src/cli.ts <path-to-repo> --json
```

Exit codes double as a gate: `2` = REFUSE, `1` = WARN, `0` = OK.

## As an MCP server

Run `npm run mcp` and register it with your agent. It exposes one tool,
`scan_repo`, so the agent can gate itself:

> *scan this repo before you work on it*

## What it detects (Tier 1, deterministic)

| Threat | Example |
| --- | --- |
| **Unicode tag-smuggling** | Invisible U+E0000–E007F chars that decode to a full ASCII instruction |
| **Bidi override (Trojan Source)** | Text that renders differently from how it parses |
| **Zero-width / invisible chars** | Instructions hidden between visible words |

Tier-2 heuristics (agent-directed imperatives, exfil patterns) and an
isolated, non-hijackable classifier are on the roadmap — see [PLAN.md](./PLAN.md).

## Design principle: it can't be turned against you

The detectors are pure, deterministic code — **no model is involved**, so
pointing malskanner at a hostile repo cannot prompt-inject the scanner itself,
and the same input always yields the same verdict.

## License

MIT © octolabo

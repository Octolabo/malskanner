# malskanner — build plan

**Positioning:** the safety gate an AI agent runs on a repo *before* it trusts a
single line. Catches hidden prompt-injection payloads in READMEs/docs/comments —
the ones humans miss. Delivered as a CLI **and** an MCP `scan_repo` tool.

**Stack:** TypeScript / Node — best distribution (`npx`), most mature MCP SDK,
audience lives in Node. Learning payoff lives in the domain: MCP server, AST/
static analysis, unicode-security detection, safe LLM-as-judge.

## Why this lane

MCP *config* tool-poisoning scanners are crowded and now Snyk-owned. Scanning an
arbitrary repo's **prose** (README/CONTRIBUTING/SECURITY/docs/comments) for
agent-hijacking injection — run *by the agent* before trust — is still open.
News hook is hot (CSA README-injection research, Mozilla warning, Shai-Hulud
worm). Window is months, not years — ship fast.

## Threat model (tiered = the false-positive discipline)

- **Tier 1 — Critical, deterministic (near-zero FP):** zero-width/invisible
  chars, tag-block smuggling (U+E0000–E007F), bidi overrides (Trojan Source),
  hidden HTML/markdown text, base64/hex blobs decoding to instructions.
- **Tier 2 — Warning, heuristic + classifier:** agent-directed imperatives
  ("ignore previous instructions", "run…"), exfil references (`~/.ssh`, `.env`,
  `curl | sh`), tool-poisoning in MCP `description` fields.
- **Tier 3 — Info:** risky install hooks (`postinstall`), obfuscation,
  suspicious hosts. Secrets → interop with gitleaks, not our job.

## The moat

1. Whole-repo **prose** scanning, agent-invoked (nobody else does this).
2. **Non-hijackable + deterministic:** Tier-1 is pure code; the Tier-2
   classifier receives text as data only, has **no tools**, runs at temp 0 with
   schema-constrained output. Same repo → same verdict, and it can't be turned
   against you.

## Phases

- [x] **P0 — scaffold:** repo skeleton, unicode/bidi/tag detector, CLI, MCP
      stub, poisoned + clean fixtures, self-scan CI.
- [x] **P1 — Tier-1 complete:** hidden HTML/CSS text, base64/hex decode,
      homoglyph spans; SARIF + JSON output; 7 passing unit tests over fixtures.
- [ ] **P2 — MCP polish + demo:** harden `scan_repo`, record the money GIF
      (agent pwned → agent saved).
- [ ] **P3 — Tier-2 + classifier:** imperative/exfil heuristics + isolated
      classifier; measure false-positive rate on the top ~100 real repos.
- [ ] **P4 — launch:** README + demo GIF + verified CSA stat; submit to
      awesome-lists; Show HN.

## Launch / stars

- **The demo GIF is everything:** split screen — agent reads innocent-looking
  repo and gets pwned (left) vs. malskanner flags it and the agent refuses (right).
- Distribution: `awesome-mcp-security`, `awesome-claude-code-security`,
  `awesome-llm-security`, `awesome-claude-code`; topics `prompt-injection`,
  `mcp`, `ai-security`, `llm-security`; register on mcp.so / glama; Show HN +
  r/ClaudeAI, r/cursor, r/netsec.

## Risks

- False positives kill trust → confidence tiers; measure FP on top-100 pre-launch.
- Window is months → ship the deterministic core first, don't gold-plate.
- Verify the CSA stat before quoting it.
- Name collision → checked; avoid "Tripwire" (established infosec brand).

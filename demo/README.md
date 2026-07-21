# Demo assets

## Auto-rendered GIF (deterministic)

Requires [vhs](https://github.com/charmbracelet/vhs): `brew install vhs`.

From the **repo root**:

```bash
vhs demo/demo.tape
```

This produces `demo/malskanner.gif` — the "innocent-looking README → decoded
payload" reveal. It's fully scripted, so re-running gives the same GIF.

## Use malskanner as an MCP server in Claude Code / Cursor

Register the server so your agent can gate itself on a repo before trusting it.

**With a build (recommended):**

```bash
npm run build
```

```jsonc
// .mcp.json (project) or your agent's MCP config
{
  "mcpServers": {
    "malskanner": {
      "command": "node",
      "args": ["/ABSOLUTE/PATH/TO/malskanner/dist/mcp.js"]
    }
  }
}
```

**Without building (dev, via tsx):**

```jsonc
{
  "mcpServers": {
    "malskanner": {
      "command": "node",
      "args": ["--import", "tsx", "/ABSOLUTE/PATH/TO/malskanner/src/mcp.ts"]
    }
  }
}
```

Or, in Claude Code:

```bash
claude mcp add malskanner -- node /ABSOLUTE/PATH/TO/malskanner/dist/mcp.js
```

Then, in your agent:

> scan this repo before you work on it

It calls `scan_repo` and returns a **REFUSE / WARN / OK** verdict, a
`safeToProceed` flag, and guidance — with the decoded payloads.

## The money shot (live recording, for launch)

Record a split screen:

- **LEFT** — an agent opens the poisoned fixture *without* the scanner and
  starts following the hidden instruction (gets "pwned").
- **RIGHT** — with malskanner registered, the agent calls `scan_repo` first,
  gets `REFUSE`, refuses to act, and surfaces the decoded payload to you.

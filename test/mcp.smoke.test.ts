import { test } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..");

// End-to-end: spin up the real MCP server over stdio and drive it as a client,
// exactly as Claude Code / Cursor would.
test("mcp: scan_repo exposes the tool and REFUSEs the poisoned fixture", async () => {
  const transport = new StdioClientTransport({
    command: "node",
    args: ["--import", "tsx", path.join(repoRoot, "src/mcp.ts")],
    cwd: repoRoot,
  });
  const client = new Client({ name: "malskanner-smoke", version: "0.0.0" });
  await client.connect(transport);

  try {
    const { tools } = await client.listTools();
    assert.ok(tools.some((t) => t.name === "scan_repo"), "scan_repo tool should be listed");

    const res = await client.callTool({
      name: "scan_repo",
      arguments: { path: path.join(repoRoot, "test/fixtures/poisoned") },
    });
    const first = (res.content as Array<{ type: string; text?: string }>)[0];
    assert.equal(first.type, "text");
    const parsed = JSON.parse(first.text ?? "{}");

    assert.equal(parsed.verdict, "REFUSE");
    assert.equal(parsed.safeToProceed, false);
    assert.ok(parsed.findingCount >= 4, `expected >=4 findings, got ${parsed.findingCount}`);
  } finally {
    await client.close();
  }
});

test("mcp: scan_repo returns an error for a missing path", async () => {
  const transport = new StdioClientTransport({
    command: "node",
    args: ["--import", "tsx", path.join(repoRoot, "src/mcp.ts")],
    cwd: repoRoot,
  });
  const client = new Client({ name: "malskanner-smoke", version: "0.0.0" });
  await client.connect(transport);

  try {
    const res = await client.callTool({
      name: "scan_repo",
      arguments: { path: path.join(repoRoot, "does/not/exist") },
    });
    assert.equal(res.isError, true);
  } finally {
    await client.close();
  }
});

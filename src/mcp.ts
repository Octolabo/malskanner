import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { scanRepo } from "./scanner/scan.js";

/**
 * malskanner as an MCP server.
 *
 * This is the differentiating "face": an AI coding agent can call `scan_repo`
 * on a repository BEFORE it reads/trusts the contents, and act on the verdict
 * (REFUSE / WARN / OK). The scanning itself is deterministic and tool-less, so
 * pointing it at a hostile repo cannot turn the scanner against you.
 */
const server = new McpServer({ name: "malskanner", version: "0.1.0" });

server.tool(
  "scan_repo",
  "Scan a local repository or file for hidden prompt-injection payloads (invisible Unicode, bidi overrides, tag-smuggling) BEFORE trusting its contents. Returns a verdict: REFUSE / WARN / OK, a risk score, and the specific findings.",
  { path: z.string().describe("Absolute path to the repository directory or file to scan") },
  async ({ path: target }) => {
    const r = await scanRepo(target);
    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify(
            {
              verdict: r.verdict,
              score: r.score,
              filesScanned: r.filesScanned,
              findings: r.findings,
            },
            null,
            2,
          ),
        },
      ],
    };
  },
);

const transport = new StdioServerTransport();
await server.connect(transport);

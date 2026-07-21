#!/usr/bin/env node
import { Command } from "commander";
import { scanRepo } from "./scanner/scan.js";
import { resolveTarget } from "./scanner/resolve.js";
import { renderHuman, renderJson, renderSarif } from "./scanner/report.js";

const program = new Command();

program
  .name("malskanner")
  .description("Scan a repo for hidden prompt-injection payloads before your AI agent trusts it.")
  .version("0.1.1")
  .argument("<target>", "a repo directory, a file, or a remote git URL (https://…) to scan")
  .option("--json", "emit machine-readable JSON instead of the human report")
  .option("--sarif", "emit SARIF 2.1.0 (for GitHub code scanning)")
  .option("--ai", "also run the optional AI classifier (needs ANTHROPIC_API_KEY)")
  .action(async (target: string, opts: { json?: boolean; sarif?: boolean; ai?: boolean }) => {
    let resolved;
    try {
      resolved = await resolveTarget(target);
    } catch (err) {
      process.stderr.write(`malskanner: ${err instanceof Error ? err.message : String(err)}\n`);
      process.exitCode = 3;
      return;
    }
    try {
      const result = await scanRepo(resolved.dir, { ai: opts.ai });
      if (resolved.cloned) result.root = resolved.source; // show the URL, not the temp dir
      const out = opts.sarif ? renderSarif(result) : opts.json ? renderJson(result) : renderHuman(result);
      process.stdout.write(out + "\n");
      // Exit code doubles as a CI/agent gate: 2 = REFUSE, 1 = WARN, 0 = OK.
      process.exitCode = result.verdict === "REFUSE" ? 2 : result.verdict === "WARN" ? 1 : 0;
    } finally {
      await resolved.cleanup();
    }
  });

program.parseAsync().catch((err) => {
  console.error("malskanner error:", err instanceof Error ? err.message : err);
  process.exitCode = 3;
});

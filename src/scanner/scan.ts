import { walk } from "./walk.js";
import { detectors } from "./detectors/index.js";
import { Finding, ScanResult, Severity, Verdict } from "../types.js";

const WEIGHT: Record<Severity, number> = {
  critical: 100,
  high: 60,
  medium: 30,
  low: 10,
  info: 0,
};

export async function scanRepo(root: string): Promise<ScanResult> {
  const files = await walk(root);
  const findings: Finding[] = [];
  for (const f of files) {
    for (const d of detectors) {
      findings.push(...d.scan(f.rel, f.text));
    }
  }

  findings.sort((a, b) => WEIGHT[b.severity] - WEIGHT[a.severity]);

  // Score is driven by the worst finding: a single critical payload is enough
  // to reject a repo, so we don't dilute it by averaging.
  const score = findings.reduce((max, f) => Math.max(max, WEIGHT[f.severity]), 0);

  const verdict: Verdict = findings.some((f) => f.severity === "critical")
    ? "REFUSE"
    : findings.some((f) => f.severity === "high" || f.severity === "medium")
      ? "WARN"
      : "OK";

  return { root, filesScanned: files.length, findings, score, verdict };
}

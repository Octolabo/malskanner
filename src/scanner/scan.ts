import { walk } from "./walk.js";
import { detectors } from "./detectors/index.js";
import { classifyProse } from "./classify.js";
import { Finding, ScanResult, Severity, Verdict } from "../types.js";

const WEIGHT: Record<Severity, number> = {
  critical: 100,
  high: 60,
  medium: 30,
  low: 10,
  info: 0,
};

const PROSE = /\.(md|markdown|mdx|txt|rst|adoc)$/i;
const PROSE_NAME = /(^|\/)(readme|contributing|security)/i;

export interface ScanOptions {
  /** Run the optional, opt-in AI classifier (needs ANTHROPIC_API_KEY). */
  ai?: boolean;
}

export async function scanRepo(root: string, opts: ScanOptions = {}): Promise<ScanResult> {
  const files = await walk(root);
  const findings: Finding[] = [];
  const notes: string[] = [];

  const linesOf = new Map<string, string[]>();
  for (const f of files) {
    const lines = f.text.split("\n");
    linesOf.set(f.rel, lines);
    for (const d of detectors) {
      for (const finding of d.scan(f.rel, f.text)) {
        if (!isSuppressed(lines, finding.line)) findings.push(finding);
      }
    }
  }

  // Optional AI second opinion (deterministic scan above is unaffected either way).
  if (opts.ai) {
    const prose = files.filter((f) => PROSE.test(f.rel) || PROSE_NAME.test(f.rel));
    const result = await classifyProse(prose);
    for (const finding of result.findings) {
      const lines = linesOf.get(finding.file) ?? [];
      if (!isSuppressed(lines, finding.line)) findings.push(finding);
    }
    if (result.note) notes.push(result.note);
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

  return {
    root,
    filesScanned: files.length,
    findings,
    score,
    verdict,
    notes: notes.length ? notes : undefined,
  };
}

/**
 * Inline suppression, so docs that intentionally show attack examples stay
 * clean: `malskanner-ignore` on the finding's own line, or
 * `malskanner-ignore-next-line` on the line above, drops that finding.
 */
function isSuppressed(lines: string[], line: number): boolean {
  const current = lines[line - 1] ?? "";
  const previous = lines[line - 2] ?? "";
  return /malskanner-ignore\b/.test(current) || /malskanner-ignore-next-line\b/.test(previous);
}

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Verdict = "REFUSE" | "WARN" | "OK";

/** A single problem found in a file. */
export interface Finding {
  ruleId: string;
  severity: Severity;
  title: string;
  file: string; // path relative to the scan root
  line: number; // 1-based
  column: number; // 1-based (counted in code points)
  evidence: string; // the payload, with invisibles made visible
  why: string; // why it is dangerous
  remediation: string;
}

export interface ScanResult {
  root: string;
  filesScanned: number;
  findings: Finding[];
  score: number; // 0-100 risk
  verdict: Verdict;
  notes?: string[]; // non-fatal messages (e.g. AI classifier status)
}

/**
 * A detector inspects one file's text and returns findings.
 * Detectors MUST be pure and deterministic: no I/O, no clock, no model calls.
 * That is what makes their verdicts reproducible and un-hijackable.
 */
export interface Detector {
  id: string;
  scan(file: string, text: string): Finding[];
}

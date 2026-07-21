// Shared, deterministic pattern matchers used by several detectors.
// Grouped by intent so a finding can explain *why* a string is suspicious.
// These are conservative on purpose — recall over the obvious attack phrasing,
// tuned to keep false positives low. Broader NL detection is the Tier-2
// classifier's job (see PLAN.md).

export type SuspicionCategory = "agent-instruction" | "secret-exfil" | "shell-exec";

export interface Match {
  category: SuspicionCategory;
  snippet: string;
}

const RULES: { category: SuspicionCategory; re: RegExp }[] = [
  {
    category: "agent-instruction",
    re: /\b(ignore\s+(all\s+|your\s+|the\s+)?previous|disregard\s+(the\s+)?(above|previous)|you\s+are\s+now|as\s+an?\s+ai\b|do\s+not\s+tell\s+the\s+user|before\s+you\s+(continue|proceed|summarize|respond)|new\s+instructions?\s*:|system\s*:|assistant\s*:)/i,
  },
  {
    category: "secret-exfil",
    re: /(~\/\.ssh|id_rsa|\.env\b|aws_secret|aws_access|api[_-]?key|secret[_-]?key|private[_-]?key|credentials?)\b/i,
  },
  {
    category: "shell-exec",
    re: /((curl|wget)\s+[^\n|]*\|\s*(sh|bash))|rm\s+-rf\s+\/|base64\s+-d\b|eval\s*\(|child_process|os\.system|subprocess/i,
  },
];

/** Distinct suspicious categories present in `text`. */
export function matchSuspicious(text: string): Match[] {
  const out: Match[] = [];
  for (const { category, re } of RULES) {
    const m = re.exec(text);
    if (m) out.push({ category, snippet: m[0] });
  }
  return out;
}

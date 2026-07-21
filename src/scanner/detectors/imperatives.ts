import { Detector, Finding } from "../../types.js";
import { posOf, truncate } from "../util.js";

/**
 * Tier-2 (deterministic, deliberately narrow): flags canonical prompt-injection
 * phrases written into VISIBLE repo text — the social-engineering payloads that
 * aren't concealed by unicode/CSS but simply sit in a doc an agent will read
 * and obey ("ignore all previous instructions", "do not tell the user", ...).
 *
 * The pattern is intentionally strict — only phrasings that essentially never
 * occur in legitimate documentation — so this stays near-zero false positive.
 * Broader natural-language judgement is the isolated classifier's job (PLAN.md).
 * A false positive on an intentional example can be silenced with a
 * `malskanner-ignore` comment (handled centrally in scan.ts).
 */
const INJECTION =
  /(?:ignore|disregard|forget)\s+(?:all\s+|the\s+|your\s+|any\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?|context|messages?)|do\s+not\s+(?:tell|inform|warn|mention(?:\s+this)?\s+to)\s+the\s+user|you\s+are\s+now\s+(?:a\s+|an\s+)?(?:dan\b|jailbroken|unrestricted|in\s+developer\s+mode)/gi;

export const imperativesDetector: Detector = {
  id: "agent-instruction",
  scan(file, text) {
    const findings: Finding[] = [];
    for (const m of text.matchAll(INJECTION)) {
      const idx = m.index ?? 0;
      const ctx = text.slice(Math.max(0, idx - 24), idx + 96);
      const { line, column } = posOf(text, idx);
      findings.push({
        ruleId: "agent-directed-instruction",
        severity: "critical",
        title: "Prompt-injection instruction in repo text",
        file,
        line,
        column,
        evidence: `matched ${JSON.stringify(m[0])} in: ${JSON.stringify(truncate(ctx))}`,
        why: 'Phrases that command an AI agent (e.g. "ignore all previous instructions") do not appear in legitimate docs; they are the classic payload of a repo-based prompt-injection attack.',
        remediation: "Remove the instruction. If it is an intentional example, add a `malskanner-ignore` comment on that line.",
      });
    }
    return findings;
  },
};

import { Detector, Finding } from "../../types.js";
import { inFencedBlock, inInlineCode, posOf, truncate } from "../util.js";

/**
 * Tier-2 (deterministic, deliberately narrow): flags canonical prompt-injection
 * phrases written into VISIBLE repo text — the social-engineering payloads that
 * aren't concealed by unicode/CSS but simply sit in a doc an agent will read
 * and obey ("ignore all previous instructions", "do not tell the user", ...).
 *
 * The hard part is telling an *attack* from a *mention*: security docs, tests,
 * and tutorials legitimately quote these phrases. So we only flag a **bare**
 * imperative — one that is NOT quoted, inline-code, or inside a fenced code
 * block. An attacker issues the command directly; documentation references it in
 * quotes/backticks. This keeps the rule near-zero false positive even on repos
 * that are entirely about prompt injection. Intentional bare examples can still
 * be silenced with a `malskanner-ignore` comment (handled in scan.ts).
 */
const INJECTION =
  /(?:ignore|disregard|forget)\s+(?:all\s+|the\s+|your\s+|any\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?|context|messages?)|do\s+not\s+(?:tell|inform|warn|mention(?:\s+this)?\s+to)\s+the\s+user|you\s+are\s+now\s+(?:a\s+|an\s+)?(?:dan\b|jailbroken|unrestricted|in\s+developer\s+mode)/gi;

const QUOTE = new Set(['"', "'", "`", "“", "”", "‘", "’"]);

export const imperativesDetector: Detector = {
  id: "agent-instruction",
  scan(file, text) {
    const findings: Finding[] = [];
    for (const m of text.matchAll(INJECTION)) {
      const idx = m.index ?? 0;
      if (isReferenced(text, idx)) continue; // a mention (quoted/code), not a live command
      if (isDescribed(text, idx)) continue; // third-person description of an attack, not a command
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
        why: 'Phrases that command an AI agent (e.g. "ignore all previous instructions") do not appear as bare directives in legitimate docs; they are the classic payload of a repo-based prompt-injection attack.',
        remediation: "Remove the instruction. If it is an intentional example, quote/backtick it or add a `malskanner-ignore` comment on that line.",
      });
    }
    return findings;
  },
};

/**
 * True when the match is a *reference* to an injection phrase rather than a live
 * command: immediately quoted, inside an inline-code span, within an open quote,
 * or inside a fenced code block. That is the shape of security docs/tests that
 * discuss prompt injection — not an actual attack.
 */
function isReferenced(text: string, idx: number): boolean {
  // Immediately preceded by a quote or backtick.
  if (idx > 0 && QUOTE.has(text[idx - 1]!)) return true;

  if (inInlineCode(text, idx) || inFencedBlock(text, idx)) return true;

  // Inside an unclosed quote earlier on the same line.
  const lineStart = text.lastIndexOf("\n", idx - 1) + 1;
  return /["'“‘][^"'\n”’]*$/.test(text.slice(lineStart, idx));
}

/**
 * True when the match *describes* an attack on a model rather than issuing one:
 * it follows a third-person AI subject ("...make the model ignore...", "the LLM
 * will disregard..."), an example marker ("e.g., ChatGPT:ignore..."), or sits in
 * markdown link text (a paper/article title). A live injection commands *you* —
 * second-person phrasings ("You will disregard...") still flag, because no AI
 * noun precedes the verb.
 */
const AI_NOUN = "(?:model|llm|ai|agent|assistant|chatbot|system)s?";
const DESCRIBED = new RegExp(
  "(?:" +
    // "makes/tricks/gets the model (to) <verb> ..."
    "\\b(?:make|makes|making|made|cause[sd]?|causing|force[sd]?|forcing|gets?|getting|got|instruct(?:s|ed)?|instructing|tell[s]?|telling|told|convince[sd]?|convincing|trick(?:s|ed)?|tricking)\\s+(?:the\\s+|an?\\s+)?" + AI_NOUN + "\\s+(?:to\\s+)?" +
    // "the model will/can/might <verb> ..."
    "|\\b" + AI_NOUN + "\\s+(?:will|would|can|could|may|might|should|must|to|then)\\s+" +
    // an example marker shortly before the match
    "|\\be\\.g\\.?[,:]?[^\\n]{0,30}" +
  ")$",
  "i",
);

function isDescribed(text: string, idx: number): boolean {
  const lineStart = text.lastIndexOf("\n", idx - 1) + 1;
  if (DESCRIBED.test(text.slice(Math.max(lineStart, idx - 80), idx))) return true;

  // Markdown link text: an unclosed "[" earlier on the line is a title, not a command.
  const line = text.slice(lineStart, idx);
  const open = line.lastIndexOf("[");
  return open !== -1 && !line.includes("]", open);
}

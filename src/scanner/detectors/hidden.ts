import { Detector, Finding } from "../../types.js";
import { matchSuspicious } from "../patterns.js";
import { posOf, truncate } from "../util.js";

/**
 * Tier-1 detector for text that is present in the file but hidden from a human:
 *  - HTML comments (invisible in rendered markdown, read verbatim by an agent)
 *  - inline CSS that conceals rendered text (display:none, white-on-white, ...)
 *
 * Plain HTML comments are extremely common and legitimate, so we only flag a
 * comment when its content matches a suspicious pattern — that keeps this
 * near-zero false positive. Concealing CSS in a doc is itself the red flag, so
 * that is flagged regardless of content.
 */

const HTML_COMMENT = /<!--([\s\S]*?)-->/g;
const HIDDEN_CSS =
  /style\s*=\s*["'][^"']*(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0|color\s*:\s*(?:#fff(?:fff)?|white))[^"']*["']/gi;

export const hiddenDetector: Detector = {
  id: "hidden-text",
  scan(file, text) {
    const findings: Finding[] = [];

    for (const m of text.matchAll(HTML_COMMENT)) {
      const body = (m[1] ?? "").trim();
      const sus = matchSuspicious(body);
      if (sus.length === 0) continue;
      const { line, column } = posOf(text, m.index ?? 0);
      findings.push({
        ruleId: "hidden-html-comment",
        severity: "high",
        title: "Hidden HTML comment with suspicious instruction",
        file,
        line,
        column,
        evidence: `comment (invisible in rendered markdown): ${JSON.stringify(truncate(body))} — matched ${sus.map((s) => s.category).join(", ")}`,
        why: "HTML comments do not render in markdown but are read verbatim by an AI agent, making them a prime channel for hidden instructions.",
        remediation: "Remove the comment or its instruction-like content.",
      });
    }

    for (const m of text.matchAll(HIDDEN_CSS)) {
      const { line, column } = posOf(text, m.index ?? 0);
      findings.push({
        ruleId: "hidden-css-text",
        severity: "high",
        title: "Text concealed via inline CSS",
        file,
        line,
        column,
        evidence: `concealing style: ${JSON.stringify(truncate(m[0]))}`,
        why: "Inline styles like display:none or white-on-white hide text from a human viewer while it remains in the source an AI agent reads.",
        remediation: "Remove the hidden element or the concealing style.",
      });
    }

    return findings;
  },
};

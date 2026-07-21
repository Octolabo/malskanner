import { Detector, Finding } from "../../types.js";
import { posOf } from "../util.js";

/**
 * Tier-1 detector for homoglyph / mixed-script tokens: a word that is mostly
 * Latin but sneaks in a non-Latin lookalike (e.g. Cyrillic 'а' for 'a'). These
 * disguise a command, package name, or URL as a trusted one — a fake "paypal"
 * an agent might install or navigate to.
 *
 * We only flag tokens that mix ASCII Latin WITH a tracked lookalike, so a
 * legitimately non-Latin word (all Cyrillic/Greek) is never flagged.
 */

// Non-ASCII chars that visually mimic ASCII letters, mapped to their lookalike.
const CONFUSABLES: Record<string, string> = {
  "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
  "ѕ": "s", "ԁ": "d", "ј": "j",
  "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "Т": "T", "Н": "H", "К": "K",
  "М": "M", "В": "B", "Х": "X",
  "ο": "o", "α": "a", "ν": "v", "ρ": "p", "τ": "t", "ι": "i", "κ": "k", "ε": "e",
  "Ι": "I", "Ο": "O", "Α": "A",
};
const CONFUSABLE_SET = new Set(Object.keys(CONFUSABLES));

// Word-like runs of Latin + Cyrillic + Greek letters.
const TOKEN = /[A-Za-zЀ-ӿͰ-Ͽ]{2,}/g;

export const homoglyphDetector: Detector = {
  id: "homoglyph",
  scan(file, text) {
    const findings: Finding[] = [];
    for (const m of text.matchAll(TOKEN)) {
      const tok = m[0];
      const chars = [...tok];
      const asciiCount = chars.filter((c) => /[A-Za-z]/.test(c)).length;
      const nonAscii = chars.filter((c) => !/[A-Za-z]/.test(c));
      // Impersonation pattern only: the token is ASCII Latin plus lookalikes,
      // with Latin the majority. A genuine foreign word (containing non-lookalike
      // letters, or mostly non-Latin) is left alone — that kills the multilingual
      // false positives.
      const isImpersonation =
        nonAscii.length > 0 &&
        nonAscii.every((c) => CONFUSABLE_SET.has(c)) &&
        asciiCount >= 1 &&
        asciiCount >= nonAscii.length;
      // Require an INTERIOR lookalike (ASCII letters on both sides): that is the
      // typosquat pattern ("p‑а‑ypal"). A lookalike only at a word boundary is
      // usually a real inflection (e.g. Russian "Pythonу"), not an attack.
      const hasInteriorConfusable = chars.some(
        (c, k) =>
          k > 0 &&
          k < chars.length - 1 &&
          CONFUSABLE_SET.has(c) &&
          /[A-Za-z]/.test(chars[k - 1]) &&
          /[A-Za-z]/.test(chars[k + 1]),
      );
      if (!isImpersonation || !hasInteriorConfusable) continue;

      const skeleton = chars.map((c) => CONFUSABLES[c] ?? c).join("");
      const { line, column } = posOf(text, m.index ?? 0);
      findings.push({
        ruleId: "homoglyph-token",
        severity: "medium",
        title: "Homoglyph / mixed-script token",
        file,
        line,
        column,
        evidence: `${JSON.stringify(tok)} mixes Latin with lookalike characters — reads as ${JSON.stringify(skeleton)}`,
        why: "Characters from other scripts that mimic Latin letters can disguise a command, package name, or URL as a trusted one (e.g. a fake 'paypal').",
        remediation: "Use plain ASCII, or confirm the token is intentionally non-Latin.",
      });
    }
    return findings;
  },
};

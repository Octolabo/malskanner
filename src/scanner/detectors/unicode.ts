import { Detector, Finding } from "../../types.js";

/**
 * Tier-1 deterministic detector for invisible / obfuscating Unicode.
 *
 * No model is involved, so this cannot be prompt-injected and always returns the
 * same verdict for the same input.
 *
 * Precision matters as much as recall: some invisible characters have entirely
 * legitimate uses (emoji ZWJ sequences, Indic/Arabic joiners, CJK spacing,
 * soft-hyphen hyphenation). So tag-smuggling and bidi overrides — which have no
 * legitimate place in documentation — are always flagged, while zero-width
 * characters are only flagged in high-signal contexts (a run of >=3, or a
 * single char wedged between two ASCII letters as keyword-splitting evasion).
 */

// Unicode Tag block (U+E0000–E007F): invisible, decodes 1:1 to ASCII.
const isTag = (cp: number) => cp >= 0xe0000 && cp <= 0xe007f;

// Bidirectional overrides & isolates — the "Trojan Source" family.
const BIDI = new Set<number>([
  0x202a, 0x202b, 0x202c, 0x202d, 0x202e, // LRE, RLE, PDF, LRO, RLO
  0x2066, 0x2067, 0x2068, 0x2069, // LRI, RLI, FSI, PDI
]);

// Zero-width / invisible format chars. SOFT HYPHEN (U+00AD) is deliberately
// excluded — its purpose is between-letter hyphenation, a guaranteed FP source.
const ZERO_WIDTH = new Set<number>([
  0x200b, 0x200c, 0x200d, 0x2060, 0xfeff,
  0x034f, 0x061c, 0x115f, 0x1160, 0x17b4, 0x17b5, 0x180e,
  0x2061, 0x2062, 0x2063, 0x2064, 0x3164, 0xffa0,
]);

const ZW_BULK_MIN = 3; // a run this long has no benign explanation
const isAsciiWord = (cp: number | undefined) =>
  cp !== undefined && ((cp >= 48 && cp <= 57) || (cp >= 65 && cp <= 90) || (cp >= 97 && cp <= 122));

export const unicodeDetector: Detector = {
  id: "unicode",
  scan(file, text) {
    const findings: Finding[] = [];

    // Code points with positions, so we can inspect a run's neighbours.
    const cps: { cp: number; line: number; col: number }[] = [];
    let line = 1;
    let col = 1;
    for (const ch of text) {
      cps.push({ cp: ch.codePointAt(0)!, line, col });
      if (ch === "\n") {
        line++;
        col = 1;
      } else {
        col++;
      }
    }

    let i = 0;
    while (i < cps.length) {
      const { cp, line: L, col: C } = cps[i];

      if (isTag(cp)) {
        let j = i;
        const run: number[] = [];
        while (j < cps.length && isTag(cps[j].cp)) run.push(cps[j++].cp);
        const decoded = decodeTags(run);
        findings.push({
          ruleId: "unicode-tag-smuggling",
          severity: "critical",
          title: "Invisible Unicode-tag smuggled instruction",
          file,
          line: L,
          column: C,
          evidence: `decoded hidden text: ${JSON.stringify(decoded)}  (${run.length} invisible chars)`,
          why: "Unicode Tag characters (U+E0000–E007F) are invisible but decode 1:1 to ASCII. They smuggle instructions past a human reader straight into an AI agent's context.",
          remediation: "Remove the invisible characters, or reject the file. Legitimate documentation never needs them.",
        });
        i = j;
        continue;
      }

      if (BIDI.has(cp)) {
        findings.push({
          ruleId: "bidi-override",
          severity: "critical",
          title: "Bidirectional override (Trojan Source)",
          file,
          line: L,
          column: C,
          evidence: `${nameOf(cp)} — renders as nothing`,
          why: 'Bidirectional override/isolate controls reorder how text renders versus how it is parsed ("Trojan Source"), hiding instructions or disguising malicious code as benign.',
          remediation: "Remove the override characters, or reject the file. Legitimate documentation never needs them.",
        });
        i++;
        continue;
      }

      if (ZERO_WIDTH.has(cp)) {
        let j = i;
        while (j < cps.length && ZERO_WIDTH.has(cps[j].cp)) j++;
        const run = cps.slice(i, j).map((x) => x.cp);
        const prev = i > 0 ? cps[i - 1].cp : undefined;
        const next = j < cps.length ? cps[j].cp : undefined;
        const bulky = run.length >= ZW_BULK_MIN;
        const splitting = isAsciiWord(prev) && isAsciiWord(next);
        if (bulky || splitting) {
          findings.push({
            ruleId: "zero-width-char",
            severity: "high",
            title: `Zero-width / invisible character${run.length > 1 ? "s" : ""}`,
            file,
            line: L,
            column: C,
            evidence: splitting && !bulky
              ? `${run.length}× ${describe(run)} wedged between word characters — splits/hides a token`
              : `${run.length}× ${describe(run)} in a row — renders as nothing`,
            why: "Zero-width / invisible characters render as nothing but are still read by an AI agent — used to hide instructions or split keywords to evade filters.",
            remediation: "Remove the invisible characters, or reject the file.",
          });
        }
        i = j;
        continue;
      }

      i++;
    }

    return findings;
  },
};

function decodeTags(cps: number[]): string {
  return cps
    .map((cp) => {
      const ascii = cp - 0xe0000;
      return ascii >= 0x20 && ascii <= 0x7e ? String.fromCharCode(ascii) : "";
    })
    .join("");
}

function describe(cps: number[]): string {
  return [...new Set(cps.map(nameOf))].join(", ");
}

function nameOf(cp: number): string {
  const names: Record<number, string> = {
    0x200b: "ZERO WIDTH SPACE", 0x200c: "ZWNJ", 0x200d: "ZWJ", 0x2060: "WORD JOINER",
    0xfeff: "ZW NO-BREAK SPACE / BOM", 0x034f: "COMBINING GRAPHEME JOINER",
    0x061c: "ARABIC LETTER MARK", 0x180e: "MONGOLIAN VOWEL SEPARATOR", 0x3164: "HANGUL FILLER",
    0x202a: "LRE", 0x202b: "RLE", 0x202c: "PDF", 0x202d: "LRO", 0x202e: "RLO",
    0x2066: "LRI", 0x2067: "RLI", 0x2068: "FSI", 0x2069: "PDI",
  };
  return names[cp] ?? `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`;
}

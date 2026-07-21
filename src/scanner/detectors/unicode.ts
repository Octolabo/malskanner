import { Detector, Finding, Severity } from "../../types.js";

/**
 * Tier-1 deterministic detector for invisible / obfuscating Unicode.
 *
 * These characters render as nothing (or misleadingly) to a human, but an AI
 * agent reads the raw bytes — so they are the primary vehicle for smuggling
 * instructions into an agent's context via an otherwise innocent-looking file.
 * No model is involved here, so this detector cannot itself be prompt-injected
 * and always returns the same verdict for the same input.
 */

// Zero-width and other invisible/format characters that have no place in prose.
const ZERO_WIDTH = new Set<number>([
  0x200b, 0x200c, 0x200d, 0x2060, 0xfeff, // ZWSP, ZWNJ, ZWJ, WORD JOINER, BOM
  0x00ad, 0x034f, 0x061c, 0x115f, 0x1160, // SOFT HYPHEN, CGJ, ALM, HANGUL FILLERS
  0x17b4, 0x17b5, 0x180e, 0x2061, 0x2062, 0x2063, 0x2064,
  0x3164, 0xffa0, // HANGUL FILLER, HALFWIDTH HANGUL FILLER
]);

// Bidirectional overrides & isolates — the "Trojan Source" family. They let the
// rendered order of text differ from the logical (parsed/agent-read) order.
const BIDI = new Set<number>([
  0x202a, 0x202b, 0x202c, 0x202d, 0x202e, // LRE, RLE, PDF, LRO, RLO
  0x2066, 0x2067, 0x2068, 0x2069, // LRI, RLI, FSI, PDI
]);

// Unicode Tag block (U+E0000–E007F): invisible, but each char maps 1:1 to ASCII.
// This is the cleanest way to smuggle a fully readable instruction past a human.
const isTag = (cp: number) => cp >= 0xe0000 && cp <= 0xe007f;

interface Suspect {
  cls: "unicode-tag-smuggling" | "bidi-override" | "zero-width-char";
  severity: Severity;
  why: string;
}

function classify(cp: number): Suspect | null {
  if (isTag(cp)) {
    return {
      cls: "unicode-tag-smuggling",
      severity: "critical",
      why: "Unicode Tag characters (U+E0000–E007F) are invisible but decode 1:1 to ASCII. They are used to smuggle instructions past a human reader straight into an AI agent's context.",
    };
  }
  if (BIDI.has(cp)) {
    return {
      cls: "bidi-override",
      severity: "critical",
      why: 'Bidirectional override/isolate controls reorder how text renders versus how it is parsed ("Trojan Source"), hiding instructions or disguising malicious code as benign.',
    };
  }
  if (ZERO_WIDTH.has(cp)) {
    return {
      cls: "zero-width-char",
      severity: "high",
      why: "Zero-width / invisible characters render as nothing but are still read by an AI agent. They hide instructions between visible words or encode data.",
    };
  }
  return null;
}

export const unicodeDetector: Detector = {
  id: "unicode",
  scan(file, text) {
    const findings: Finding[] = [];
    let line = 1;
    let col = 1;

    // A "run" groups consecutive suspicious chars of the same class into one
    // finding, so a smuggled instruction shows up as a single decoded payload
    // rather than N separate noise lines.
    let run: { s: Suspect; line: number; col: number; cps: number[] } | null = null;

    const flush = () => {
      if (!run) return;
      const { s, cps } = run;
      const decoded = s.cls === "unicode-tag-smuggling" ? decodeTags(cps) : null;
      findings.push({
        ruleId: s.cls,
        severity: s.severity,
        title: titleFor(s.cls, cps.length),
        file,
        line: run.line,
        column: run.col,
        evidence: decoded
          ? `decoded hidden text: ${JSON.stringify(decoded)}  (${cps.length} invisible chars)`
          : `${cps.length}× ${describe(cps)} — renders as nothing`,
        why: s.why,
        remediation: "Remove the invisible/override characters, or reject the file. Legitimate documentation never needs them.",
      });
      run = null;
    };

    for (const ch of text) {
      const cp = ch.codePointAt(0)!;
      const s = classify(cp);
      if (s) {
        if (run && run.s.cls === s.cls) {
          run.cps.push(cp);
        } else {
          flush();
          run = { s, line, col, cps: [cp] };
        }
      } else {
        flush();
      }
      if (ch === "\n") {
        line++;
        col = 1;
      } else {
        col++;
      }
    }
    flush();
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

function titleFor(cls: Suspect["cls"], n: number): string {
  switch (cls) {
    case "unicode-tag-smuggling":
      return "Invisible Unicode-tag smuggled instruction";
    case "bidi-override":
      return "Bidirectional override (Trojan Source)";
    case "zero-width-char":
      return `Zero-width / invisible character${n > 1 ? "s" : ""}`;
  }
}

function describe(cps: number[]): string {
  return [...new Set(cps.map(nameOf))].join(", ");
}

function nameOf(cp: number): string {
  const names: Record<number, string> = {
    0x200b: "ZERO WIDTH SPACE", 0x200c: "ZWNJ", 0x200d: "ZWJ", 0x2060: "WORD JOINER",
    0xfeff: "ZW NO-BREAK SPACE / BOM", 0x00ad: "SOFT HYPHEN", 0x034f: "COMBINING GRAPHEME JOINER",
    0x061c: "ARABIC LETTER MARK", 0x180e: "MONGOLIAN VOWEL SEPARATOR", 0x3164: "HANGUL FILLER",
    0x202a: "LRE", 0x202b: "RLE", 0x202c: "PDF", 0x202d: "LRO", 0x202e: "RLO",
    0x2066: "LRI", 0x2067: "RLI", 0x2068: "FSI", 0x2069: "PDI",
  };
  return names[cp] ?? `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`;
}

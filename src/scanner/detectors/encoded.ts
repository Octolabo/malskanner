import { Detector, Finding } from "../../types.js";
import { matchSuspicious } from "../patterns.js";
import { posOf, truncate } from "../util.js";

/**
 * Tier-1 detector for instructions/commands smuggled inside base64 or hex
 * blobs. Encoded data is common and legitimate (hashes, keys, data-URIs), so
 * to stay near-zero false positive we only flag a blob when it BOTH decodes to
 * mostly-printable text AND that text matches a suspicious pattern. Random
 * binary (e.g. a real SHA hash) fails the printable check and is ignored.
 */

const B64 = /[A-Za-z0-9+/]{24,}={0,2}/g;
const HEX = /\b(?:0x)?[0-9a-fA-F]{32,}\b/g;

function printableRatio(buf: Buffer): number {
  if (buf.length === 0) return 0;
  let ok = 0;
  for (const b of buf) {
    if (b === 9 || b === 10 || b === 13 || (b >= 32 && b <= 126)) ok++;
  }
  return ok / buf.length;
}

export const encodedDetector: Detector = {
  id: "encoded-payload",
  scan(file, text) {
    const findings: Finding[] = [];

    const report = (index: number, kind: "base64" | "hex", decoded: string) => {
      const sus = matchSuspicious(decoded);
      if (sus.length === 0) return;
      const { line, column } = posOf(text, index);
      findings.push({
        ruleId: `encoded-${kind}`,
        severity: "high",
        title: `Suspicious ${kind}-encoded payload`,
        file,
        line,
        column,
        evidence: `decodes to: ${JSON.stringify(truncate(decoded))} — matched ${sus.map((s) => s.category).join(", ")}`,
        why: `${kind === "base64" ? "Base64" : "Hex"} blobs can smuggle instructions or commands past a casual reader; this one decodes to suspicious content.`,
        remediation: "Remove the encoded payload, or verify what it decodes to before trusting the file.",
      });
    };

    for (const m of text.matchAll(B64)) {
      try {
        const buf = Buffer.from(m[0], "base64");
        if (buf.length >= 8 && printableRatio(buf) >= 0.85) {
          report(m.index ?? 0, "base64", buf.toString("utf8"));
        }
      } catch {
        /* not valid base64 — ignore */
      }
    }

    for (const m of text.matchAll(HEX)) {
      const hex = m[0].replace(/^0x/, "");
      if (hex.length % 2 !== 0) continue;
      const buf = Buffer.from(hex, "hex");
      if (buf.length >= 8 && printableRatio(buf) >= 0.85) {
        report(m.index ?? 0, "hex", buf.toString("utf8"));
      }
    }

    return findings;
  },
};

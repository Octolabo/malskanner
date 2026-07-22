/** 1-based line/column for a character offset into `text`. */
export function posOf(text: string, index: number): { line: number; column: number } {
  let line = 1;
  let lastNewline = -1;
  for (let i = 0; i < index && i < text.length; i++) {
    if (text.charCodeAt(i) === 10) {
      line++;
      lastNewline = i;
    }
  }
  return { line, column: index - lastNewline };
}

/** Collapse whitespace and clip long strings for readable evidence. */
export function truncate(s: string, n = 160): string {
  const one = s.replace(/\s+/g, " ").trim();
  return one.length > n ? one.slice(0, n) + "…" : one;
}

/** True when `idx` falls inside a fenced ``` code block. */
export function inFencedBlock(text: string, idx: number): boolean {
  const lineStart = text.lastIndexOf("\n", idx - 1) + 1;
  return ((text.slice(0, lineStart).match(/^```/gm)?.length ?? 0) % 2) === 1;
}

/** True when `idx` falls inside an inline `code` span on its line. */
export function inInlineCode(text: string, idx: number): boolean {
  const lineStart = text.lastIndexOf("\n", idx - 1) + 1;
  return ((text.slice(lineStart, idx).match(/`/g)?.length ?? 0) % 2) === 1;
}

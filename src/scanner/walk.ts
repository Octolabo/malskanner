import { promises as fs } from "node:fs";
import path from "node:path";

const TEXT_EXT = new Set([
  ".md", ".markdown", ".mdx", ".txt", ".rst", ".adoc",
  ".json", ".yaml", ".yml", ".toml",
  ".mdc", // Cursor rules (.cursor/rules/*.mdc)
]);

// Files worth scanning even without a text extension — these are exactly the
// docs an AI agent reads first, and where README-injection attacks land.
const TEXT_NAMES = ["readme", "contributing", "security", "license", "changelog", "notice", "authors", "codeowners"];

// Extensionless agent rule files — instructions an agent obeys verbatim, so
// the highest-value injection surface of all.
const RULE_NAMES = new Set([".cursorrules", ".clinerules", ".windsurfrules"]);

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", ".next", "vendor", ".venv", "__pycache__"]);

const MAX_BYTES = 1_000_000;

export interface ScannedFile {
  rel: string;
  text: string;
}

/** Recursively collect the text/doc files under `root` (or `root` itself if it is a file). */
export async function walk(root: string): Promise<ScannedFile[]> {
  const abs = path.resolve(root);
  const stat = await fs.stat(abs);

  if (stat.isFile()) {
    const text = await fs.readFile(abs, "utf8");
    return [{ rel: path.basename(abs), text }];
  }

  const out: ScannedFile[] = [];
  async function recurse(dir: string) {
    const entries = await fs.readdir(dir, { withFileTypes: true });
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name)) await recurse(full);
      } else if (e.isFile() && isTextFile(e.name)) {
        const st = await fs.stat(full);
        if (st.size > MAX_BYTES) continue;
        out.push({ rel: path.relative(abs, full), text: await fs.readFile(full, "utf8") });
      }
    }
  }
  await recurse(abs);
  return out;
}

function isTextFile(name: string): boolean {
  const lower = name.toLowerCase();
  if (RULE_NAMES.has(lower)) return true;
  if (TEXT_NAMES.some((n) => lower === n || lower.startsWith(n + "."))) return true;
  return TEXT_EXT.has(path.extname(lower));
}

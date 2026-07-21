import { promises as fs, existsSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

/**
 * Resolve a scan target to a local directory.
 *  - A remote git URL (https://, git@, git://, ssh://) is shallow-cloned into a
 *    temp dir and cleaned up afterwards. Cloning does not execute repo code
 *    (git hooks aren't run on clone), so it's safe to point at an untrusted repo.
 *  - A local path is used as-is; a missing one gets a helpful error.
 */

const URL_RE = /^(https?:\/\/|git@|git:\/\/|ssh:\/\/)/i;

export interface ResolvedTarget {
  dir: string;
  source: string;
  cloned: boolean;
  cleanup: () => Promise<void>;
}

const noop = async () => {};

export async function resolveTarget(target: string): Promise<ResolvedTarget> {
  if (URL_RE.test(target)) {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), "malskanner-"));
    const res = spawnSync("git", ["clone", "--depth", "1", "--quiet", target, tmp], {
      stdio: "pipe",
      encoding: "utf8",
      env: { ...process.env, GIT_TERMINAL_PROMPT: "0" }, // never hang on an auth prompt
    });
    if (res.status !== 0) {
      await fs.rm(tmp, { recursive: true, force: true });
      const msg = (res.stderr || res.error?.message || "git clone failed").trim();
      throw new Error(`could not clone ${target}\n  ${msg}`);
    }
    return {
      dir: tmp,
      source: target,
      cloned: true,
      cleanup: () => fs.rm(tmp, { recursive: true, force: true }),
    };
  }

  if (!existsSync(target)) {
    throw new Error(
      `path not found: ${target}\n  (to scan a remote repo, pass its full URL, e.g. https://github.com/owner/repo)`,
    );
  }
  return { dir: target, source: target, cloned: false, cleanup: noop };
}

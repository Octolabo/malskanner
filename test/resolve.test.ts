import { test } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { resolveTarget } from "../src/scanner/resolve.js";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

test("resolveTarget: an existing local dir passes through (no clone)", async () => {
  const r = await resolveTarget(path.join(repoRoot, "src"));
  assert.equal(r.cloned, false);
  assert.equal(r.dir, path.join(repoRoot, "src"));
});

test("resolveTarget: a missing local path throws a helpful error", async () => {
  await assert.rejects(
    () => resolveTarget(path.join(repoRoot, "no", "such", "path", "xyz")),
    /path not found/,
  );
});

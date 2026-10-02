import { mkdirSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

/**
 * Writes via a temp file + rename, so a crash or interrupted write can never
 * leave a truncated file at `path` — important for caches that later stand in
 * for live vulnerability data.
 */
export function writeFileAtomic(path: string, content: string): void {
  mkdirSync(dirname(path), { recursive: true });
  const temp = `${path}.${process.pid}.tmp`;
  try {
    writeFileSync(temp, content);
    renameSync(temp, path);
  } catch (err) {
    rmSync(temp, { force: true }); // don't leave a stray partial file behind
    throw err;
  }
}

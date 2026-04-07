import { randomBytes } from "node:crypto";
import type { RefToken } from "../shared/types.js";

const refs = new Map<string, RefToken>();

export function issueRef(
  gatewayToken: string,
  credentialKey: string,
  ttlMs: number
): RefToken {
  const nonce = randomBytes(16).toString("hex");
  const ref = `apw-ref:${credentialKey}:${nonce}`;
  const entry: RefToken = {
    ref,
    credentialKey,
    gatewayToken,
    expiresAt: Date.now() + ttlMs,
    consumed: false,
  };
  refs.set(ref, entry);
  return entry;
}

export function consumeRef(ref: string): RefToken | null {
  const entry = refs.get(ref);
  if (!entry) return null;
  if (entry.consumed || entry.expiresAt <= Date.now()) {
    refs.delete(ref);
    return null;
  }
  entry.consumed = true;
  return entry;
}

export function sweepRefs(): number {
  const now = Date.now();
  let removed = 0;
  for (const [key, entry] of refs) {
    if (entry.consumed || entry.expiresAt <= now) {
      refs.delete(key);
      removed++;
    }
  }
  return removed;
}

export function startRefSweep(intervalMs = 60_000): ReturnType<typeof setInterval> {
  return setInterval(sweepRefs, intervalMs);
}

export function clearAllRefs(): void {
  refs.clear();
}

export function refCount(): number {
  return refs.size;
}

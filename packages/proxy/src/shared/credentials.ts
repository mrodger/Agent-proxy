import type { Provider, CachedCredential } from "./types.js";

/** Credential keys must be safe path-like strings — no shell metacharacters. */
const SAFE_KEY_PATTERN = /^[A-Za-z0-9][A-Za-z0-9/_.-]+$/;

function validateKey(key: string): void {
  if (!SAFE_KEY_PATTERN.test(key)) {
    throw new Error(`Invalid credential key: ${key}`);
  }
}

const cache = new Map<string, CachedCredential>();

/**
 * Resolve a credential value by executing the provider's `read` command.
 * Results are cached in memory with the configured TTL.
 */
export async function resolveCredential(
  provider: Provider,
  key: string
): Promise<string> {
  const cached = cache.get(key);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.value;
  }

  validateKey(key);
  const value = await execProviderCommand(provider.read, { key });

  cache.set(key, {
    value,
    expiresAt: Date.now() + provider.cache_ttl * 1000,
  });

  return value;
}

/**
 * Store a credential via the provider's `update` command.
 * Falls back to `write` if update fails.
 */
export async function storeCredential(
  provider: Provider,
  key: string,
  value: string
): Promise<void> {
  validateKey(key);

  try {
    await execProviderCommand(provider.update, { key, value });
  } catch {
    await execProviderCommand(provider.write, { key, value });
  }

  cache.delete(key);
}

export function invalidateCache(key?: string): void {
  if (key) {
    cache.delete(key);
  } else {
    cache.clear();
  }
}

export function getCacheSize(): number {
  return cache.size;
}

/**
 * Execute a provider command with safe variable substitution.
 * Uses array-form exec (no shell) to prevent command injection.
 */
async function execProviderCommand(
  template: string,
  vars: Record<string, string>
): Promise<string> {
  let cmd = template;
  for (const [k, v] of Object.entries(vars)) {
    cmd = cmd.replace(new RegExp(`\\{${k}\\}`, "g"), v);
  }
  const { execa } = await import("execa");
  const parts = cmd.match(/(?:[^\s"]+|"[^"]*")+/g) ?? [];
  const argv = parts.map((p) => p.replace(/^"|"$/g, ""));
  const [bin, ...args] = argv;
  if (!bin) throw new Error("Empty provider command");
  const result = await execa(bin, args);
  return result.stdout.trim();
}

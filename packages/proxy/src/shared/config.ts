import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import yaml from "js-yaml";
import { ProxyConfigFileSchema, type ProxyConfig } from "./types.js";

/**
 * Load and validate proxy.yaml from the given config directory.
 * Fails fast on missing env vars (R-1 fix).
 */
export function loadProxyConfig(configDir: string): ProxyConfig {
  const filePath = resolve(configDir, "proxy.yaml");
  const raw = readFileSync(filePath, "utf-8");

  // Substitute env vars, failing on missing (R-1 fix)
  const substituted = raw.replace(/\$\{(\w+)\}/g, (_match, varName) => {
    const value = process.env[varName];
    if (value === undefined) {
      throw new Error(`Missing required env var: ${varName} (in ${filePath})`);
    }
    return value;
  });

  const parsed = yaml.load(substituted) as Record<string, unknown>;
  const validated = ProxyConfigFileSchema.parse(parsed);
  return validated.proxy;
}

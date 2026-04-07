import { randomBytes } from "node:crypto";
import type { GatewayToken } from "../shared/types.js";
import { globMatch } from "../shared/glob.js";

const tokens = new Map<string, GatewayToken>();

export function issueToken(
  agentId: string,
  credentials: string[],
  storeKeys: string[] | undefined,
  ttl: number
): GatewayToken {
  const token = `apw-${agentId}-${randomBytes(16).toString("hex")}`;
  const entry: GatewayToken = {
    token,
    agentId,
    credentials,
    storeKeys,
    expiresAt: Date.now() + ttl * 1000,
  };
  tokens.set(token, entry);
  return entry;
}

export function validateToken(
  token: string
): Omit<GatewayToken, "token"> | null {
  const entry = tokens.get(token);
  if (!entry) return null;
  if (entry.expiresAt <= Date.now()) {
    tokens.delete(token);
    return null;
  }
  return {
    agentId: entry.agentId,
    credentials: entry.credentials,
    storeKeys: entry.storeKeys,
    expiresAt: entry.expiresAt,
  };
}

export function checkCredentialScope(token: string, key: string): boolean {
  const entry = tokens.get(token);
  if (!entry || entry.expiresAt <= Date.now()) return false;
  return entry.credentials.includes(key);
}

export function checkStoreScope(token: string, key: string): boolean {
  const entry = tokens.get(token);
  if (!entry || entry.expiresAt <= Date.now()) return false;
  if (!entry.storeKeys?.length) return false;
  return entry.storeKeys.some((pattern) => globMatch(pattern, key));
}

export function revokeToken(token: string): void {
  tokens.delete(token);
}

export function clearAllTokens(): void {
  tokens.clear();
}

import { Hono } from "hono";
import { timingSafeEqual } from "node:crypto";
import { serve } from "@hono/node-server";
import type { ProxyConfig, GatewayToken } from "../shared/types.js";
import { storeCredential, invalidateCache } from "../shared/credentials.js";
import {
  issueToken,
  validateToken,
  checkCredentialScope,
  checkStoreScope,
  revokeToken,
} from "./tokens.js";
import { issueRef, startRefSweep } from "./refs.js";

type AppEnv = {
  Variables: {
    tokenData: Omit<GatewayToken, "token">;
    rawToken: string;
  };
};

/**
 * Start the gateway API server.
 * Provides credential storage and token management.
 */
export function startGateway(config: ProxyConfig) {
  const app = new Hono<AppEnv>();

  // ── Auth middleware for agent requests ──────────────────────
  app.use("/gateway/*", async (c, next) => {
    const authHeader = c.req.header("authorization");
    if (!authHeader?.startsWith("Bearer ")) {
      return c.json({ error: "Missing or invalid authorization" }, 401);
    }
    const token = authHeader.slice(7);
    const tokenData = validateToken(token);
    if (!tokenData) {
      return c.json({ error: "Invalid or expired token" }, 401);
    }
    c.set("tokenData", tokenData);
    c.set("rawToken", token);
    await next();
  });

  // ── GET /gateway/ref/* — Issue a credential reference token ──
  app.get("/gateway/ref/*", async (c) => {
    const key = new URL(c.req.url).pathname.replace(/^\/gateway\/ref\//, "");
    const rawToken = c.get("rawToken") as string;

    if (!checkCredentialScope(rawToken, key)) {
      console.log(`[gateway] ref denied: key="${key}"`);
      return c.json({ error: "Credential scope denied for this key" }, 403);
    }

    const ttlMs = config.gateway.ref_ttl * 1000;
    const ref = issueRef(rawToken, key, ttlMs);
    console.log(`[gateway] issued ref for key="${key}"`);
    return c.json({ ref: ref.ref, expiresAt: ref.expiresAt });
  });

  // ── POST /gateway/store/* — Store a credential ──────────────
  app.post("/gateway/store/*", async (c) => {
    const key = new URL(c.req.url).pathname.replace(/^\/gateway\/store\//, "");
    const rawToken = c.get("rawToken") as string;

    if (!checkStoreScope(rawToken, key)) {
      console.log(`[gateway] store denied: key="${key}"`);
      return c.json({ error: "Store scope denied for this key" }, 403);
    }

    const body = await c.req.json<{
      value: string;
      route?: { host: string; header: string; format?: string };
    }>();

    if (!body.value) {
      return c.json({ error: "Missing value" }, 400);
    }

    await storeCredential(config.provider, key, body.value);
    console.log(`[gateway] stored credential: ${key}`);
    return c.json({ ok: true, key });
  });

  // ── POST /token — Issue a new token (orchestrator only) ─────
  app.post("/token", async (c) => {
    const secret = process.env.GATEWAY_SECRET;
    if (!secret) {
      return c.json({ error: "GATEWAY_SECRET not configured" }, 500);
    }
    const provided = c.req.header("x-gateway-secret") ?? "";
    const expected = Buffer.from(secret);
    const actual = Buffer.from(provided);
    if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
      return c.json({ error: "Invalid gateway secret" }, 401);
    }

    const body = await c.req.json<{
      agentId: string;
      credentials: string[];
      storeKeys?: string[];
    }>();

    if (!body.agentId) {
      return c.json({ error: "Missing agentId" }, 400);
    }

    const token = issueToken(
      body.agentId,
      body.credentials ?? [],
      body.storeKeys,
      config.gateway.token_ttl
    );

    console.log(`[gateway] issued token for agent "${body.agentId}"`);
    return c.json({ token: token.token, expiresAt: token.expiresAt });
  });

  // ── DELETE /token/:token — Revoke a token ───────────────────
  app.delete("/token/:token", async (c) => {
    const secret = process.env.GATEWAY_SECRET;
    if (!secret) {
      return c.json({ error: "GATEWAY_SECRET not configured" }, 500);
    }
    const provided = c.req.header("x-gateway-secret") ?? "";
    const expected = Buffer.from(secret);
    const actual = Buffer.from(provided);
    if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
      return c.json({ error: "Invalid gateway secret" }, 401);
    }
    const token = c.req.param("token");
    revokeToken(token);
    console.log(`[gateway] revoked token`);
    return c.json({ ok: true });
  });

  // ── POST /gateway/cache/invalidate ──────────────────────────
  app.post("/gateway/cache/invalidate", async (c) => {
    const body = await c.req.json<{ key?: string }>().catch(() => ({}));
    invalidateCache((body as { key?: string })?.key);
    return c.json({ ok: true });
  });

  const host = config.host ?? "127.0.0.1";
  const server = serve({
    fetch: app.fetch,
    hostname: host,
    port: config.gateway.port,
  });

  const sweepHandle = startRefSweep(60_000);
  server.on("close", () => clearInterval(sweepHandle));

  console.log(`[gateway] listening on ${host}:${config.gateway.port}`);
  return server;
}

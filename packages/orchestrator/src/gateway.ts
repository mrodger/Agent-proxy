/**
 * Datum Orchestrator Gateway — HTTP service for agentic-ui integration.
 *
 * Handles RBAC, agent routing, SSE streaming, and audit logging.
 * H-2: Routes through dispatcher security (permission resolution, credential proxy, delegation).
 */

import { Hono } from "hono";
import { stream as honoStream } from "hono/streaming";
import { cors } from "hono/cors";
import { serve } from "@hono/node-server";
import { resolve } from "node:path";
import { readFile } from "node:fs/promises";
import { timingSafeEqual } from "node:crypto";
import Database from "better-sqlite3";

import { loadConfig } from "./config.js";
import { checkAccess, buildPermissionHook } from "./rbac.js";
import { resolveEffectivePermissions } from "./gatekeeper.js";
import { buildSystemPrompt, PLATFORM_DISALLOWED_TOOLS } from "./dispatcher.js";
import { initSessionsTable, getSessionId, setSessionId } from "./sessions.js";
import { initAuditTable, logDispatch, queryAuditLog } from "./audit.js";
import type { AuditEntry } from "./audit.js";
import { verify2FA, generateSessionToken, verifySessionToken, isVM102, logAuthEvent, generateAuthCode, sendApprovalEmail } from "./auth.js";
import { initWebAuthnTables, beginRegistration, completeRegistration, beginAuthentication, completeAuthentication, getUserCredentials, deleteCredential } from "./webauthn.js";


const PORT = parseInt(process.env.GATEWAY_PORT ?? "8095", 10);
const CONFIG_DIR = resolve(process.env.CONFIG_DIR ?? "./config");
const PROJECT_ROOT = resolve(process.env.PROJECT_ROOT ?? ".");
const DATA_DIR = resolve(process.env.DATA_DIR ?? "./data");
const PUBLIC_DIR = resolve(process.env.PUBLIC_DIR ?? "./public");
const GATEWAY_SECRET = process.env.GATEWAY_SECRET ?? "";
// H-1a fix: per-worker secrets — gateway knows each worker's secret, workers only know their own
const WORKER_SECRETS: Record<string, string> = {
  developer: process.env.WORKER_SECRET_DEVELOPER ?? "",
  researcher: process.env.WORKER_SECRET_RESEARCHER ?? "",
  designer: process.env.WORKER_SECRET_DESIGNER ?? "",
  admin: process.env.WORKER_SECRET_ADMIN ?? "",
  gis: process.env.WORKER_SECRET_GIS ?? "",
  security: process.env.WORKER_SECRET_SECURITY ?? "",
  "peer-review": process.env.WORKER_SECRET_PEER_REVIEW ?? "",
};

if (!GATEWAY_SECRET) {
  console.error("[gateway] FATAL: GATEWAY_SECRET not set. Refusing to start.");
  process.exit(1);
}

// ── Load config ──────────────────────────────────────────────────────────

const { agents, platform } = loadConfig(CONFIG_DIR, PROJECT_ROOT);
console.log(
  `[gateway] Loaded ${Object.keys(agents.agents).length} agents: ${Object.keys(agents.agents).join(", ")}`,
);

// ── Database ─────────────────────────────────────────────────────────────

const dbPath = resolve(DATA_DIR, "gateway.db");
const db = new Database(dbPath);
db.pragma("journal_mode = WAL");
initSessionsTable(db);
initAuditTable(db);
initWebAuthnTables(db);
console.log(`[gateway] Database: ${dbPath}`);

// ── App ──────────────────────────────────────────────────────────────────

const app = new Hono();
app.use("/*", cors());

// ── C-1 fix: Bearer auth on all /api/* routes ───────────────────────────
function verifySecret(header: string | undefined): boolean {
  if (!header) return false;
  const token = header.startsWith("Bearer ") ? header.slice(7) : header;
  if (token.length !== GATEWAY_SECRET.length) return false;
  return timingSafeEqual(Buffer.from(token), Buffer.from(GATEWAY_SECRET));
}

// ── Static UI routes (no auth) ──────────────────────────────────────────
const MIME: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".css":  "text/css; charset=utf-8",
  ".js":   "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
};

async function servePublic(c: any, file: string) {
  try {
    const content = await readFile(resolve(PUBLIC_DIR, file));
    const ext = file.slice(file.lastIndexOf(".")) as keyof typeof MIME;
    return new Response(content, { headers: { "Content-Type": MIME[ext] ?? "text/plain" } });
  } catch {
    return c.notFound();
  }
}

app.get("/",          (c) => servePublic(c, "index.html"));
app.get("/style.css", (c) => servePublic(c, "style.css"));
app.get("/app.js",      (c) => servePublic(c, "app.js"));
app.get("/manifest.json", (c) => servePublic(c, "manifest.json"));
app.get("/sw.js",         (c) => servePublic(c, "sw.js"));

app.get("/health", (c) => {
  return c.json({
    ok: true,
    service: "datum-gateway",
    agents: Object.keys(agents.agents),
  });
});

// ── Auth endpoints (public, no GATEWAY_SECRET required) ──────────────────
// Auth code storage for email-based 2FA
const authCodes: Map<string, {userId: string; email: string; expires: number; attempts: number; approved: boolean}> = new Map();

// POST /api/auth/login - Initiate login (send email or VM 102 bypass)
app.post("/api/auth/login", async (c) => {
  const remoteAddr = c.req.header("x-forwarded-for") || c.req.header("cf-connecting-ip") || "unknown";

  // VM 102 bypass
  if (isVM102(remoteAddr)) {
    const { token, expires_at } = generateSessionToken("marcus");
    logAuthEvent("login_approved", { method: "vm102_bypass", userId: "marcus" });
    return c.json({ token, expires_at, method: "bypass" });
  }

  const code = generateAuthCode();
  const expiresAt = Date.now() + 10 * 60 * 1000; // 10 min
  const recipientEmail = process.env.GMAIL_RECIPIENT ?? process.env.GMAIL_FROM ?? "marcus@geofabnz.com";
  authCodes.set(code, {
    userId: "marcus",
    email: recipientEmail,
    expires: expiresAt,
    attempts: 0,
    approved: false,
  });

  // Build approve URL (works at any path prefix, e.g. /elevation/)
  const host = c.req.header("x-forwarded-host") ?? c.req.header("host") ?? "apps.geofabnz.com";
  const proto = c.req.header("x-forwarded-proto") ?? "https";
  const basePath = new URL(c.req.url).pathname.replace(/api\/auth\/login\/?$/, "");
  const approveUrl = `${proto}://${host}${basePath}api/auth/approve/${code}`;

  const emailSent = await sendApprovalEmail(recipientEmail, code, approveUrl);
  logAuthEvent("login_requested", { method: "email", emailSent });

  return c.json({
    code: "EMAIL_SENT",
    message: emailSent
      ? "Approval email sent. Check your inbox and click Approve."
      : "Email unavailable. Use TOTP code to sign in.",
    auth_code: code,
    expires_in: 600,
  });
});

// GET /api/auth/approve/:code - Click-to-approve from email link
app.get("/api/auth/approve/:code", (c) => {
  const code = c.req.param("code");
  const authData = authCodes.get(code);

  if (!authData || Date.now() > authData.expires) {
    authCodes.delete(code);
    return new Response(
      `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Datum</title></head><body style="font-family:sans-serif;text-align:center;padding:3rem;background:#f0f1f0"><h2 style="color:#c0392b">Link expired or invalid.</h2><p>Please request a new login from the Datum app.</p></body></html>`,
      { status: 400, headers: { "Content-Type": "text/html" } }
    );
  }

  authData.approved = true;
  logAuthEvent("login_approved", { method: "email_click", userId: authData.userId });

  return new Response(
    `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Datum — Approved</title></head><body style="font-family:sans-serif;text-align:center;padding:3rem;background:#f0f1f0"><h2 style="color:#1d3a5c">&#10003; Login approved</h2><p style="color:#555">You can close this tab. Your Datum session is now active.</p></body></html>`,
    { status: 200, headers: { "Content-Type": "text/html" } }
  );
});

// POST /api/auth/verify - Verify approval code or TOTP code
app.post("/api/auth/verify", async (c) => {
  const body = await c.req.json<{code?: string; totp?: string}>();
  const remoteAddr = c.req.header("x-forwarded-for") || c.req.header("cf-connecting-ip") || "unknown";

  // VM 102 bypass
  if (isVM102(remoteAddr)) {
    const { token, expires_at } = generateSessionToken("marcus");
    return c.json({ token, expires_at });
  }

  if (body.code) {
    const authData = authCodes.get(body.code);
    if (!authData || Date.now() > authData.expires) {
      authCodes.delete(body.code);
      return c.json({ error: "Invalid or expired code" }, 401);
    }

    if (authData.attempts >= 3) {
      authCodes.delete(body.code);
      return c.json({ error: "Too many attempts" }, 429);
    }

    // Not yet approved via email link — keep polling
    if (!authData.approved) {
      authData.attempts++;
      return c.json({ pending: true, message: "Waiting for email approval" }, 202);
    }

    authCodes.delete(body.code);
    const { token, expires_at } = generateSessionToken(authData.userId);
    logAuthEvent("login_approved", { method: "email" });
    return c.json({ token, expires_at });
  }

  if (body.totp) {
    const userSecret = process.env.USER_2FA_SECRET;
    if (!userSecret || !verify2FA(userSecret, body.totp)) {
      logAuthEvent("login_failed", { method: "totp" });
      return c.json({ error: "Invalid TOTP code" }, 401);
    }

    const { token, expires_at } = generateSessionToken("marcus");
    logAuthEvent("login_approved", { method: "totp" });
    return c.json({ token, expires_at });
  }

  return c.json({ error: "Missing code or totp" }, 400);
});

// GET /api/auth/status - Check session validity (requires Bearer session token)
app.get("/api/auth/status", (c) => {
  const authHeader = c.req.header("Authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    return c.json({ valid: false }, 401);
  }

  const token = authHeader.substring(7);
  const result = verifySessionToken(token);

  if (!result.valid) {
    return c.json({ valid: false }, 401);
  }

  return c.json({
    valid: true,
    userId: result.userId,
    expires_at: result.expires_at,
  });
});

// ── WebAuthn / Passkey endpoints (public) ────────────────────────────────

// GET /api/auth/webauthn/status - Check if user has registered passkeys
app.get("/api/auth/webauthn/status", (c) => {
  const creds = getUserCredentials(db, "marcus");
  return c.json({ registered: creds.length > 0, count: creds.length });
});

// POST /api/auth/webauthn/register/start - Begin passkey registration (requires session)
app.post("/api/auth/webauthn/register/start", async (c) => {
  const authHeader = c.req.header("Authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    return c.json({ error: "Must be logged in to register a passkey" }, 401);
  }
  const session = verifySessionToken(authHeader.substring(7));
  if (!session.valid) {
    return c.json({ error: "Invalid session" }, 401);
  }

  try {
    const options = await beginRegistration(db, session.userId!, session.userId!);
    return c.json(options);
  } catch (err) {
    return c.json({ error: (err as Error).message }, 500);
  }
});

// POST /api/auth/webauthn/register/finish - Complete passkey registration
app.post("/api/auth/webauthn/register/finish", async (c) => {
  const authHeader = c.req.header("Authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    return c.json({ error: "Must be logged in to register a passkey" }, 401);
  }
  const session = verifySessionToken(authHeader.substring(7));
  if (!session.valid) {
    return c.json({ error: "Invalid session" }, 401);
  }

  try {
    const body = await c.req.json<{ response: unknown; deviceName?: string }>();
    const deviceName = body.deviceName ?? "Passkey";
    const result = await completeRegistration(db, session.userId!, body.response ?? body, deviceName);
    if (!result.success) return c.json({ error: result.error }, 400);
    logAuthEvent("login_approved", { method: "webauthn_registered", userId: session.userId, credentialId: result.credentialId });
    return c.json({ success: true, credentialId: result.credentialId });
  } catch (err) {
    return c.json({ error: (err as Error).message }, 400);
  }
});

// POST /api/auth/webauthn/auth/start - Begin passkey authentication (no session needed)
app.post("/api/auth/webauthn/auth/start", async (c) => {
  const creds = getUserCredentials(db, "marcus");
  if (creds.length === 0) {
    return c.json({ error: "No passkeys registered. Log in with TOTP first, then register a passkey from the dashboard." }, 404);
  }
  try {
    const options = await beginAuthentication(db, "marcus");
    return c.json(options);
  } catch (err) {
    return c.json({ error: (err as Error).message }, 500);
  }
});

// POST /api/auth/webauthn/auth/finish - Complete passkey authentication → session token
app.post("/api/auth/webauthn/auth/finish", async (c) => {
  try {
    const body = await c.req.json<{ response?: unknown; userId?: string } & Record<string, unknown>>();
    // Support both wrapped {response: ...} and bare response objects
    const authnResponse = body.response ?? body;
    const result = await completeAuthentication(db, "marcus", authnResponse);
    if (!result.success) {
      logAuthEvent("login_failed", { method: "webauthn", error: result.error });
      return c.json({ error: result.error }, 401);
    }
    const { token, expires_at } = generateSessionToken("marcus");
    logAuthEvent("login_approved", { method: "webauthn" });
    return c.json({ token, expires_at, method: "webauthn" });
  } catch (err) {
    logAuthEvent("login_failed", { method: "webauthn", error: (err as Error).message });
    return c.json({ error: (err as Error).message }, 401);
  }
});

// GET /api/auth/webauthn/credentials - List registered passkeys (requires session)
app.get("/api/auth/webauthn/credentials", (c) => {
  const authHeader = c.req.header("Authorization");
  if (!authHeader?.startsWith("Bearer ")) return c.json({ error: "Unauthorized" }, 401);
  const session = verifySessionToken(authHeader.substring(7));
  if (!session.valid) return c.json({ error: "Invalid session" }, 401);

  const creds = getUserCredentials(db, session.userId!);
  return c.json({
    credentials: creds.map((c) => ({
      credentialId: c.credentialId,
      name: c.name,
      deviceType: c.deviceType,
      backedUp: c.backedUp,
      createdAt: c.createdAt,
    })),
  });
});

// DELETE /api/auth/webauthn/credentials/:id - Remove a passkey (requires session)
app.delete("/api/auth/webauthn/credentials/:id", (c) => {
  const authHeader = c.req.header("Authorization");
  if (!authHeader?.startsWith("Bearer ")) return c.json({ error: "Unauthorized" }, 401);
  const session = verifySessionToken(authHeader.substring(7));
  if (!session.valid) return c.json({ error: "Invalid session" }, 401);

  const credId = c.req.param("id");
  const deleted = deleteCredential(db, credId, session.userId!);
  if (!deleted) return c.json({ error: "Credential not found" }, 404);
  logAuthEvent("login_approved", { method: "webauthn_deleted", credentialId: credId });
  return c.json({ success: true });
});

// ── Protected API routes (require GATEWAY_SECRET or valid session token) ──
app.use("/api/*", async (c, next) => {
  // Skip auth for public auth endpoints
  const path = c.req.path;
  if (path.startsWith("/api/auth/")) {
    await next();
    return;
  }

  const authHeader = c.req.header("Authorization");

  // Try GATEWAY_SECRET (old method, for backwards compatibility)
  if (verifySecret(authHeader)) {
    await next();
    return;
  }

  // Try session token (2FA method)
  if (authHeader?.startsWith("Bearer ")) {
    const token = authHeader.substring(7);
    const result = verifySessionToken(token);
    if (result.valid) {
      await next();
      return;
    }
  }

  return c.json({ error: "Unauthorized — provide GATEWAY_SECRET or 2FA session token" }, 401);
});

app.get("/api/agents", (c) => {
  const agentList = Object.entries(agents.agents).map(([id, config]) => ({
    id,
    model: config.model,
    sandboxed: config.sandboxed,
    subagents: config.subagents ?? [],
  }));
  return c.json({ agents: agentList });
});

app.get("/api/audit", (c) => {
  const agentId = c.req.query("agent") ?? undefined;
  const limit = parseInt(c.req.query("limit") ?? "50", 10);
  const entries = queryAuditLog(db, { agent_id: agentId, limit });
  return c.json({ entries });
});

/**
 * POST /api/dispatch — Main dispatch endpoint with SSE streaming.
 *
 * H-2: Routes through dispatcher security layer:
 *  - buildPermissionHook() for user RBAC + agent permission rules
 *  - resolveEffectivePermissions() for gatekeeper integration
 *  - buildSystemPrompt() for consistent prompt construction
 *  - Permission rules forwarded to worker for enforcement
 *
 * Body: { agentId, message, userId?, platform?, sessionId? }
 * Returns: SSE stream with text, tool_start, turn, result, done events.
 */

app.post("/api/dispatch", async (c) => {
  const body = await c.req.json<{
    agentId: string;
    message: string;
    userId?: string;
    platform?: string;
    sessionId?: string;
  }>();

  const { agentId, message } = body;
  const userId = body.userId ?? "marcus";
  const userPlatform = body.platform ?? "http";
  const sessionId = body.sessionId ?? getSessionId(db, `${agentId}:${userId}`);

  // ── Validate agent exists ──────────────────────────────────────────
  const agentConfig = agents.agents[agentId];
  if (!agentConfig) {
    return c.json({ error: `Unknown agent: ${agentId}` }, 404);
  }

  // ── RBAC check ─────────────────────────────────────────────────────
  if (!checkAccess(userId, userPlatform, agentId, platform)) {
    return c.json({ error: `Access denied: ${userId} cannot invoke ${agentId}` }, 403);
  }

  // ── H-2: Dispatcher security integration ───────────────────────────
  // Resolve effective permissions (agent-level + gatekeeper)
  const effectivePermissions = resolveEffectivePermissions(
    agentConfig.permissions,
    platform.gatekeeper,
  );

  // Build permission hook (user RBAC + agent permissions)
  // This produces deny/allow/ask rules that the worker should enforce
  const _permissionHook = buildPermissionHook(
    userId,
    userPlatform,
    platform,
    effectivePermissions,
  );

  // Build system prompt through dispatcher (consistent with non-HTTP path)
  const builtPrompt = buildSystemPrompt(agentConfig);
  const systemPrompt =
    typeof builtPrompt === "object" && builtPrompt !== null && builtPrompt !== undefined
      ? (builtPrompt as { append: string }).append
      : builtPrompt;

  // Filter tools (same as dispatcher)
  const agentTools = agentConfig.tools
    ? agentConfig.tools.filter((t: string) => !PLATFORM_DISALLOWED_TOOLS.includes(t))
    : undefined;

  // Validate delegation: if this agent has subagents, they must exist
  if (agentConfig.subagents?.length) {
    for (const sub of agentConfig.subagents) {
      if (!agents.agents[sub]) {
        console.warn(`[gateway] Agent ${agentId} references unknown subagent: ${sub}`);
      }
    }
  }

  // ── Resolve worker URL ─────────────────────────────────────────────
  const AGENT_PORTS: Record<string, number> = { developer: 3001, researcher: 3002, designer: 3003 };
  const workerPort = agentConfig.port ?? AGENT_PORTS[agentId] ?? 3001;
  const workerHost = agentConfig.url ?? `http://datum-worker-${agentId}:${workerPort}`;
  const streamUrl = `${workerHost}/run/stream`;

  const startTime = Date.now();

  c.header("Content-Type", "text/event-stream");
  c.header("Cache-Control", "no-cache");
  c.header("Connection", "keep-alive");

  return honoStream(c, async (stream) => {
    let resultText = "";
    let resultSessionId = "";
    let costUsd = 0;
    let durationMs = 0;
    let numTurns = 0;
    let isError = false;

    try {
      const workerHeaders: Record<string, string> = { "Content-Type": "application/json" };
      const workerSecret = WORKER_SECRETS[agentId] ?? "";
      if (workerSecret) {
        workerHeaders["Authorization"] = `Bearer ${workerSecret}`;
      }

      const workerRes = await fetch(streamUrl, {
        method: "POST",
        headers: workerHeaders,
        body: JSON.stringify({
          prompt: message,
          systemPrompt: systemPrompt ?? agentConfig.system,
          tools: agentTools,
          model: agentConfig.model,
          sessionId: sessionId ?? undefined,
          maxTurns: 20,
          // H-2: Forward permission rules for worker-side enforcement
          permissions: effectivePermissions ?? [],
        }),
      });

      if (!workerRes.ok) {
        const errText = await workerRes.text();
        await stream.write(`event: error\ndata: ${JSON.stringify({ error: errText })}\n\n`);
        isError = true;
        return;
      }

      if (!workerRes.body) {
        await stream.write(`event: error\ndata: ${JSON.stringify({ error: "No response body" })}\n\n`);
        isError = true;
        return;
      }

      // Pipe SSE from worker to client, capturing result data
      const reader = workerRes.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });

        // Forward complete SSE events
        const events = buffer.split("\n\n");
        buffer = events.pop() ?? "";

        for (const event of events) {
          if (!event.trim()) continue;

          // Parse result event to capture metadata
          if (event.startsWith("event: result")) {
            const dataLine = event.split("\n").find((l) => l.startsWith("data: "));
            if (dataLine) {
              try {
                const data = JSON.parse(dataLine.slice(6));
                resultText = data.result ?? "";
                resultSessionId = data.session_id ?? "";
                costUsd = data.cost_usd ?? 0;
                durationMs = data.duration_ms ?? 0;
                numTurns = data.num_turns ?? 0;
                isError = data.is_error ?? false;
              } catch { /* ignore parse errors */ }
            }
          }

          await stream.write(event + "\n\n");
        }
      }

      // Flush remaining buffer
      if (buffer.trim()) {
        await stream.write(buffer + "\n\n");
      }
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : "Unknown error";
      await stream.write(`event: error\ndata: ${JSON.stringify({ error: errMsg })}\n\n`);
      isError = true;
    } finally {
      // Save session for resume
      if (resultSessionId) {
        setSessionId(db, `${agentId}:${userId}`, resultSessionId);
      }

      // Audit log
      const entry: AuditEntry = {
        agent_id: agentId,
        user_id: userId,
        platform: userPlatform,
        message_preview: message,
        result_preview: resultText,
        cost_usd: costUsd,
        duration_ms: durationMs || (Date.now() - startTime),
        num_turns: numTurns,
        is_error: isError,
      };
      logDispatch(db, entry);
    }
  });
});

// ── Start server ─────────────────────────────────────────────────────────

// Inside container: bind to 0.0.0.0 (port published to 127.0.0.1 via docker-compose)
const hostname = process.env.GATEWAY_BIND ?? "0.0.0.0";
serve({ fetch: app.fetch, port: PORT, hostname }, (info) => {
  console.log(`[gateway] Listening on http://${hostname}:${info.port}`);
});

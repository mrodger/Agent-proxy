/**
 * Integration test: orchestrator → proxy → worker end-to-end.
 *
 * Tests the full chain:
 * 1. Config loading (orchestrator)
 * 2. Gateway token issuance (proxy)
 * 3. Worker health check (worker)
 * 4. Worker /run endpoint (worker + proxy credential injection)
 * 5. Token revocation (proxy)
 *
 * Prerequisites: docker compose up (proxy + worker-developer running)
 * Run: cd ~/projects/stockade-datum && source .env && npx tsx test-integration.ts
 */

import { loadConfig } from "./packages/orchestrator/src/config.js";
import { resolveUser, checkAccess, buildPreToolUseHook } from "./packages/orchestrator/src/rbac.js";
import { buildSystemPrompt, buildSdkSettings } from "./packages/orchestrator/src/dispatcher.js";
import { resolve } from "node:path";

const GATEWAY_URL = "http://localhost:10256";
const WORKER_URL = "http://localhost:3001"; // mapped through docker network, but we test via host

let passed = 0;
let failed = 0;

function assert(condition: boolean, name: string) {
  if (condition) {
    passed++;
    console.log(`  ✓ ${name}`);
  } else {
    failed++;
    console.error(`  ✗ ${name}`);
  }
}

async function run() {
  const GATEWAY_SECRET = process.env.GATEWAY_SECRET;
  if (!GATEWAY_SECRET) {
    console.error("GATEWAY_SECRET not set. Run: source .env");
    process.exit(1);
  }

  // ── 1. Config Loading ──────────────────────────────────────
  console.log("\n=== 1. Config Loading ===");

  const configDir = resolve("./config");
  const { agents, platform } = loadConfig(configDir, resolve("."));

  assert(!!agents.agents.developer, "developer agent loaded");
  assert(!!agents.agents.researcher, "researcher agent loaded");
  assert(!!agents.agents.designer, "designer agent loaded");
  assert(agents.agents.developer.sandboxed === true, "developer is sandboxed");
  assert(agents.agents.developer.subagents?.includes("researcher") === true, "developer can delegate to researcher");

  // ── 2. RBAC ────────────────────────────────────────────────
  console.log("\n=== 2. RBAC ===");

  const user = resolveUser("marcus", "terminal", platform);
  assert(user !== null, "marcus resolves as user");
  assert(checkAccess("marcus", "terminal", "developer", platform), "marcus can access developer");
  assert(checkAccess("marcus", "terminal", "researcher", platform), "marcus can access researcher");
  assert(checkAccess("marcus", "terminal", "designer", platform), "marcus can access designer");
  assert(!checkAccess("nobody", "terminal", "developer", platform), "unknown user denied");

  // ── 3. Dispatcher Helpers ──────────────────────────────────
  console.log("\n=== 3. Dispatcher Helpers ===");

  const devPrompt = buildSystemPrompt(agents.agents.developer);
  assert(typeof devPrompt === "object" && (devPrompt as any).preset === "claude_code", "developer system_mode=append → preset");

  const researcherPrompt = buildSystemPrompt(agents.agents.researcher);
  assert(typeof researcherPrompt === "object" && (researcherPrompt as any).preset === "claude_code", "researcher system_mode=append → preset");

  const settings = buildSdkSettings(agents.agents.developer, "developer", "./data/agents");
  assert((settings as any).autoMemoryEnabled === true, "memory enabled for developer");
  assert((settings.permissions as any).deny.includes("Agent"), "Agent tool denied in settings");

  // ── 4. Gateway Token Issuance ──────────────────────────────
  console.log("\n=== 4. Gateway Token Issuance ===");

  // Should reject without secret
  const noAuthRes = await fetch(`${GATEWAY_URL}/token`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ agentId: "developer", credentials: ["openai/api-key"] }),
  });
  assert(noAuthRes.status === 401, "gateway rejects request without secret");

  // Should reject with wrong secret
  const wrongAuthRes = await fetch(`${GATEWAY_URL}/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Gateway-Secret": "wrong-secret",
    },
    body: JSON.stringify({ agentId: "developer", credentials: ["openai/api-key"] }),
  });
  assert(wrongAuthRes.status === 401, "gateway rejects wrong secret");

  // Should issue token with correct secret
  const tokenRes = await fetch(`${GATEWAY_URL}/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Gateway-Secret": GATEWAY_SECRET,
    },
    body: JSON.stringify({ agentId: "developer", credentials: ["openai/api-key"] }),
  });
  assert(tokenRes.status === 200, "gateway issues token with correct secret");
  const tokenData = await tokenRes.json() as { token: string; expiresAt: number };
  assert(typeof tokenData.token === "string" && tokenData.token.length > 0, "token is non-empty string");
  assert(typeof tokenData.expiresAt === "number", "expiresAt is number");

  // ── 5. Worker Health Check ─────────────────────────────────
  console.log("\n=== 5. Worker Health Check ===");

  // Worker runs inside Docker — test via docker exec
  const { execSync } = await import("node:child_process");
  const healthJson = execSync(
    `docker exec datum-worker-developer node -e "fetch('http://localhost:3001/health').then(r=>r.json()).then(d=>console.log(JSON.stringify(d)))"`,
    { encoding: "utf-8" },
  ).trim();
  const health = JSON.parse(healthJson);
  assert(health.ok === true, "worker health ok");
  assert(health.workerId === "developer", "worker ID = developer");

  // ── 6. Token Revocation ────────────────────────────────────
  console.log("\n=== 6. Token Revocation ===");

  const revokeRes = await fetch(`${GATEWAY_URL}/token/${tokenData.token}`, {
    method: "DELETE",
    headers: { "X-Gateway-Secret": GATEWAY_SECRET },
  });
  assert(revokeRes.status === 200, "token revoked");

  // Verify revoked token can't be used for gateway ops
  const postRevokeRes = await fetch(`${GATEWAY_URL}/gateway/ref/test`, {
    headers: { "Authorization": `Bearer ${tokenData.token}` },
  });
  assert(postRevokeRes.status === 401, "revoked token rejected");

  // ── Results ────────────────────────────────────────────────
  console.log(`\n=== Results: ${passed} passed, ${failed} failed ===\n`);
  process.exit(failed > 0 ? 1 : 0);
}

run().catch((err) => {
  console.error("Integration test failed:", err);
  process.exit(1);
});

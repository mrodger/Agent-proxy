/**
 * Orchestrator integration test — validates config loading, RBAC, permissions,
 * queue, and container type schemas end-to-end.
 * Run: cd ~/projects/stockade-datum && npx tsx packages/orchestrator/test-orchestrator.ts
 */

import { loadConfig } from "./src/config.js";
import { resolveUser, checkAccess, buildPreToolUseHook } from "./src/rbac.js";
import { DispatchQueue } from "./src/containers/queue.js";
import { PortAllocator } from "./src/containers/ports.js";
import { resolveEffectivePermissions } from "./src/gatekeeper.js";
import { buildSystemPrompt, buildSdkSettings, PLATFORM_DISALLOWED_TOOLS } from "./src/dispatcher.js";
import { resolve } from "node:path";

let passed = 0;
let failed = 0;
function assert(condition: boolean, name: string) {
  if (condition) {
    passed++;
    console.log(`  \u2713 ${name}`);
  } else {
    failed++;
    console.error(`  \u2717 ${name}`);
  }
}

try {
  console.log("\n=== Config Loading ===");

  const configDir = resolve("./config");
  const { agents, platform } = loadConfig(configDir, resolve("."));

  assert(Object.keys(agents.agents).length === 3, "3 agents defined (developer, researcher, designer)");
  assert(agents.agents.developer.model === "claude-sonnet-4-6", "developer model");
  assert(agents.agents.developer.sandboxed === true, "developer is sandboxed");
  assert(agents.agents.developer.subagents?.includes("researcher") === true, "developer can delegate to researcher");
  assert(agents.agents.researcher.credentials?.includes("tavily/api-key") === true, "researcher has tavily credential");
  assert(agents.agents.designer.system.includes("Datum Design System"), "designer system prompt");
  assert(platform.rbac.users.marcus.roles.includes("admin"), "marcus is admin");
  assert(platform.containers?.network === "datum-net", "container network");
  assert(platform.paths?.data_dir?.endsWith("/data") === true, "data_dir resolved");

  console.log("\n=== RBAC with Config ===");

  const marcus = resolveUser("marcus", "terminal", platform);
  assert(marcus !== null, "marcus resolved from config");
  assert(checkAccess("marcus", "terminal", "developer", platform), "marcus can access developer");
  assert(checkAccess("marcus", "terminal", "researcher", platform), "marcus can access researcher");
  assert(checkAccess("marcus", "terminal", "designer", platform), "marcus can access designer");
  assert(!checkAccess("nobody", "terminal", "developer", platform), "unknown user denied");

  console.log("\n=== PreToolUse Hook with Agent Rules ===");

  const devConfig = agents.agents.developer;
  const devHook = buildPreToolUseHook(
    "marcus",
    "terminal",
    platform,
    devConfig.permissions,
    "/workspace",
    platform.paths?.data_dir,
  );

  const r1 = await devHook({ tool_name: "Read", tool_input: { file_path: "/any" } });
  assert(r1.hookSpecificOutput.permissionDecision === "allow", "developer Read allowed");

  const r2 = await devHook({ tool_name: "Bash", tool_input: { command: "git status" } });
  assert(r2.hookSpecificOutput.permissionDecision === "allow", "developer git allowed");

  const r3 = await devHook({ tool_name: "Bash", tool_input: { command: "rm -rf /" } });
  assert(r3.hookSpecificOutput.permissionDecision === "deny", "developer rm -rf denied");

  const r4 = await devHook({ tool_name: "Write", tool_input: { file_path: "/workspace/.claude/settings.json" } });
  assert(r4.hookSpecificOutput.permissionDecision === "deny", "developer .claude write denied (self-mod prevention)");

  const r5 = await devHook({ tool_name: "Bash", tool_input: { command: "npm install zod" } });
  assert(r5.hookSpecificOutput.permissionDecision === "allow", "developer npm allowed");

  console.log("\n=== Gatekeeper ===");

  const noPerms = resolveEffectivePermissions(undefined, undefined);
  assert(noPerms === undefined, "no gatekeeper + no perms → undefined (allow all)");

  const withGk = resolveEffectivePermissions(undefined, {
    enabled: true,
    agent: "gatekeeper",
    auto_approve_risk: "low",
  });
  assert(withGk?.length === 1 && withGk[0] === "ask:*", "gatekeeper enabled + no perms → ask:*");

  const explicitPerms = resolveEffectivePermissions(["allow:Read", "deny:Bash"], {
    enabled: true,
    agent: "gatekeeper",
    auto_approve_risk: "low",
  });
  assert(explicitPerms?.length === 2, "explicit perms preserved even with gatekeeper");

  console.log("\n=== Dispatcher Helpers ===");

  // buildSystemPrompt
  const appendPrompt = buildSystemPrompt({ ...devConfig, system_mode: "append" });
  assert(typeof appendPrompt === "object" && (appendPrompt as any).preset === "claude_code", "append mode → preset object");

  const replacePrompt = buildSystemPrompt({ ...devConfig, system_mode: "replace" });
  assert(typeof replacePrompt === "string", "replace mode → string");

  // buildSdkSettings
  const settings = buildSdkSettings(devConfig, "developer", "/data/agents");
  assert((settings as any).autoMemoryEnabled === true, "memory enabled by default");
  assert((settings as any).permissions?.deny?.includes("Agent"), "Agent tool denied in settings");

  // PLATFORM_DISALLOWED_TOOLS
  assert(PLATFORM_DISALLOWED_TOOLS.includes("Agent"), "Agent in disallowed tools");

  console.log("\n=== DispatchQueue ===");

  const queue = new DispatchQueue({ maxConcurrent: 2 });

  let processed = 0;
  queue.setProcessMessageFn(async (_key, msg) => {
    processed++;
    msg.resolve(`processed: ${msg.text}`);
    return true;
  });

  const result1 = await queue.enqueue("agent-a", "hello");
  assert(result1 === "processed: hello", "queue processes message");
  assert(processed === 1, "processed count = 1");

  const result2 = await queue.enqueue("agent-a", "world");
  assert(result2 === "processed: world", "queue processes second message");

  assert(queue.active === 0, "no active after completion");

  queue.shutdown();
  assert(queue.isShutDown, "queue shut down");

  console.log("\n=== PortAllocator ===");

  const ports = new PortAllocator([3001, 3005]);
  const p1 = ports.allocate();
  assert(p1 === 3001, "first port = 3001");
  const p2 = ports.allocate();
  assert(p2 === 3002, "second port = 3002");
  ports.release(3001);
  const p3 = ports.allocate();
  assert(p3 === 3001, "released port reused");
  assert(ports.size === 2, "2 ports allocated");

  console.log(`\n=== Results: ${passed} passed, ${failed} failed ===\n`);
  process.exit(failed > 0 ? 1 : 0);
} catch (err) {
  console.error("Fatal:", err);
  process.exit(1);
}

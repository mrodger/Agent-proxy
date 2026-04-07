/**
 * Unit tests for orchestrator permissions + RBAC.
 * Run: cd ~/projects/stockade-datum && npx tsx packages/orchestrator/test-permissions.ts
 */

import {
  parseRule,
  evaluateAgentPermissions,
  matchGlob,
  expandPattern,
  toPosixPath,
} from "./src/permissions.js";
import type { PermissionContext } from "./src/permissions.js";
import {
  resolveUser,
  checkAccess,
  matchesToolRule,
  buildPreToolUseHook,
} from "./src/rbac.js";
import type { PlatformConfig } from "./src/types.js";

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

// ── Test data ──

const ctx: PermissionContext = {
  homeDir: "/home/testuser",
  agentCwd: "/workspace",
  platformRoot: "/home/testuser/.datum",
};

const testConfig: PlatformConfig = {
  channels: {},
  rbac: {
    roles: {
      admin: {
        permissions: ["agent:*"],
        deny: [],
        allow: [],
      },
      developer: {
        permissions: ["agent:developer", "agent:researcher"],
        deny: ["tool:Bash:rm *", "tool:Bash:sudo *"],
        allow: ["tool:Bash:sudo apt *"],
      },
      viewer: {
        permissions: ["agent:researcher"],
        deny: ["tool:*"],
        allow: ["tool:Read", "tool:Grep", "tool:Glob"],
      },
    },
    users: {
      marcus: {
        roles: ["admin"],
        identities: { terminal: "marcus", http: "marcus" },
      },
      dev1: {
        roles: ["developer"],
        identities: { terminal: "dev1", http: "dev1@example.com" },
      },
      viewer1: {
        roles: ["viewer"],
        identities: { http: "viewer1@example.com" },
      },
    },
  },
};

// ── parseRule tests ──

console.log("\n=== parseRule ===");

const r1 = parseRule("allow:*");
assert(r1.action === "allow" && r1.tool === "*" && !r1.pattern, "allow:* wildcard");

const r2 = parseRule("deny:Bash");
assert(r2.action === "deny" && r2.tool === "Bash" && !r2.pattern, "deny:Bash plain tool");

const r3 = parseRule("ask:Write(/config/**)");
assert(r3.action === "ask" && r3.tool === "Write" && r3.pattern === "/config/**", "ask:Write with pattern");

const r4 = parseRule("allow:Bash(git *)");
assert(r4.action === "allow" && r4.tool === "Bash" && r4.pattern === "git *", "allow:Bash with command pattern");

try {
  parseRule("invalid");
  assert(false, "should reject missing colon");
} catch {
  assert(true, "rejects missing colon");
}

try {
  parseRule("bad:Write");
  assert(false, "should reject invalid action");
} catch {
  assert(true, "rejects invalid action");
}

// ── matchGlob tests ──

console.log("\n=== matchGlob ===");

assert(matchGlob("/home/user/file.ts", "/home/user/*.ts"), "single * matches file");
assert(!matchGlob("/home/user/deep/file.ts", "/home/user/*.ts"), "single * does not cross /");
assert(matchGlob("/home/user/deep/file.ts", "/home/user/**"), "** matches deep path");
assert(matchGlob("/home/user/deep/nested/file.ts", "/home/**/file.ts"), "** in middle");
assert(matchGlob("git push origin main", "git *", false), "text mode: git * matches full command");
assert(!matchGlob("rm -rf /", "git *", false), "text mode: git * rejects rm");
assert(matchGlob("sudo apt install vim", "sudo apt *", false), "text mode: sudo apt *");

// ── expandPattern tests ──

console.log("\n=== expandPattern ===");

assert(expandPattern("//etc/hosts", ctx) === "/etc/hosts", "// → absolute path");
assert(expandPattern("~/docs", ctx) === "/home/testuser/docs", "~/ → home dir");
assert(expandPattern("/config/agents", ctx) === "/home/testuser/.datum/config/agents", "/ → platform root");
assert(expandPattern("./src/main.ts", ctx) === "/workspace/src/main.ts", "./ → agent cwd");
assert(expandPattern("src/main.ts", ctx) === "/workspace/src/main.ts", "bare → agent cwd");

// ── evaluateAgentPermissions tests ──

console.log("\n=== evaluateAgentPermissions ===");

const testRules = [
  "deny:Write(.claude/**)",
  "allow:Read",
  "allow:Write(./src/**)",
  "allow:Bash(git *)",
  "deny:Bash(rm *)",
  "ask:*",
];

const evalP = async () => {
  const r1 = await evaluateAgentPermissions(undefined, "Bash", {}, ctx);
  assert(r1 === "allow", "undefined rules → allow all");

  const r2 = await evaluateAgentPermissions([], "Bash", {}, ctx);
  assert(r2 === "ask", "empty rules → ask");

  const r3 = await evaluateAgentPermissions(testRules, "Read", { file_path: "/any/file" }, ctx);
  assert(r3 === "allow", "Read explicitly allowed");

  const r4 = await evaluateAgentPermissions(testRules, "Write", { file_path: "/workspace/src/index.ts" }, ctx);
  assert(r4 === "allow", "Write to ./src/** allowed");

  const r5 = await evaluateAgentPermissions(testRules, "Write", { file_path: "/workspace/.claude/settings.json" }, ctx);
  assert(r5 === "deny", "Write to .claude/** denied (self-modification prevention)");

  const r6 = await evaluateAgentPermissions(testRules, "Bash", { command: "git push origin main" }, ctx);
  assert(r6 === "allow", "Bash git * allowed");

  const r7 = await evaluateAgentPermissions(testRules, "Bash", { command: "rm -rf /" }, ctx);
  assert(r7 === "deny", "Bash rm * denied");

  const r8 = await evaluateAgentPermissions(testRules, "WebSearch", { query: "hello" }, ctx);
  assert(r8 === "ask", "unmatched tool → ask");
};

await evalP();

// ── resolveUser tests ──

console.log("\n=== resolveUser ===");

const marcus = resolveUser("marcus", "terminal", testConfig);
assert(marcus !== null, "marcus found");
assert(marcus!.roles.includes("admin"), "marcus is admin");
assert(marcus!.permissions.includes("agent:*"), "marcus has agent:*");

const dev1 = resolveUser("dev1@example.com", "http", testConfig);
assert(dev1 !== null, "dev1 found via http identity");
assert(dev1!.deny.includes("tool:Bash:rm *"), "dev1 has rm deny rule");
assert(dev1!.allow.includes("tool:Bash:sudo apt *"), "dev1 has sudo apt allow override");

const unknown = resolveUser("nobody", "terminal", testConfig);
assert(unknown === null, "unknown user returns null");

// ── checkAccess tests ──

console.log("\n=== checkAccess ===");

assert(checkAccess("marcus", "terminal", "developer", testConfig), "admin can access developer");
assert(checkAccess("marcus", "terminal", "anything", testConfig), "admin can access any agent");
assert(checkAccess("dev1", "terminal", "developer", testConfig), "dev1 can access developer");
assert(checkAccess("dev1", "terminal", "researcher", testConfig), "dev1 can access researcher");
assert(!checkAccess("dev1", "terminal", "admin-agent", testConfig), "dev1 cannot access admin-agent");
assert(!checkAccess("nobody", "terminal", "developer", testConfig), "unknown user denied");

// ── matchesToolRule tests ──

console.log("\n=== matchesToolRule ===");

assert(matchesToolRule("tool:*", "Bash", {}), "tool:* matches anything");
assert(matchesToolRule("tool:Bash", "Bash", {}), "tool:Bash matches Bash");
assert(!matchesToolRule("tool:Bash", "Read", {}), "tool:Bash rejects Read");
assert(matchesToolRule("tool:Bash:git *", "Bash", { command: "git push" }), "tool:Bash:git * matches git push");
assert(!matchesToolRule("tool:Bash:git *", "Bash", { command: "rm -rf" }), "tool:Bash:git * rejects rm");
assert(matchesToolRule("tool:Bash:sudo apt *", "Bash", { command: "sudo apt install vim" }), "sudo apt * matches");

// ── buildPreToolUseHook tests ──

console.log("\n=== buildPreToolUseHook ===");

const hookTests = async () => {
  // Unknown user → deny all
  const unknownHook = buildPreToolUseHook("nobody", "terminal", testConfig);
  const r1 = await unknownHook({ tool_name: "Read", tool_input: {} });
  assert(r1.hookSpecificOutput.permissionDecision === "deny", "unknown user denied");

  // Admin → allow all (no deny rules, no agent rules)
  const adminHook = buildPreToolUseHook("marcus", "terminal", testConfig);
  const r2 = await adminHook({ tool_name: "Bash", tool_input: { command: "rm -rf /" } });
  assert(r2.hookSpecificOutput.permissionDecision === "allow", "admin allows everything (no agent rules)");

  // Developer with agent rules
  const devHook = buildPreToolUseHook(
    "dev1",
    "terminal",
    testConfig,
    ["allow:Read", "allow:Bash(git *)", "deny:Bash", "ask:*"],
    "/workspace",
    "/home/testuser/.datum",
  );

  const r3 = await devHook({ tool_name: "Read", tool_input: { file_path: "/any" } });
  assert(r3.hookSpecificOutput.permissionDecision === "allow", "dev Read allowed by agent rules");

  const r4 = await devHook({ tool_name: "Bash", tool_input: { command: "git status" } });
  assert(r4.hookSpecificOutput.permissionDecision === "allow", "dev git * allowed");

  const r5 = await devHook({ tool_name: "Bash", tool_input: { command: "ls -la" } });
  assert(r5.hookSpecificOutput.permissionDecision === "deny", "dev non-git Bash denied");

  // Developer: user-level deny overrides
  const r6 = await devHook({ tool_name: "Bash", tool_input: { command: "rm -rf /important" } });
  assert(r6.hookSpecificOutput.permissionDecision === "deny", "dev rm denied by user policy");

  // Developer: user-level allow overrides deny
  const r7 = await devHook({ tool_name: "Bash", tool_input: { command: "sudo apt install vim" } });
  // This passes user layer (deny:sudo * overridden by allow:sudo apt *)
  // Then agent layer: Bash(git *) doesn't match, deny:Bash matches → deny
  assert(r7.hookSpecificOutput.permissionDecision === "deny", "sudo apt: user allows but agent denies non-git Bash");

  // Viewer: tool:* deny with Read/Grep/Glob exceptions
  const viewerHook = buildPreToolUseHook("viewer1@example.com", "http", testConfig);
  const r8 = await viewerHook({ tool_name: "Read", tool_input: { file_path: "/any" } });
  assert(r8.hookSpecificOutput.permissionDecision === "allow", "viewer can Read (allow override)");

  const r9 = await viewerHook({ tool_name: "Bash", tool_input: { command: "ls" } });
  assert(r9.hookSpecificOutput.permissionDecision === "deny", "viewer cannot Bash");

  const r10 = await viewerHook({ tool_name: "Write", tool_input: { file_path: "/any" } });
  assert(r10.hookSpecificOutput.permissionDecision === "deny", "viewer cannot Write");
};

await hookTests();

// ── Summary ──

console.log(`\n=== Results: ${passed} passed, ${failed} failed ===\n`);
process.exit(failed > 0 ? 1 : 0);

import { join } from "node:path";
import { homedir } from "node:os";
import type { PlatformConfig, ResolvedUser, AskApprovalFn } from "./types.js";
import { evaluateAgentPermissions, type PermissionContext } from "./permissions.js";

/**
 * Resolve a platform userId to a config user, their roles, and flattened permissions.
 * Returns null if no matching user is found.
 */
export function resolveUser(
  userId: string,
  platform: string,
  config: PlatformConfig,
): ResolvedUser | null {
  for (const [username, userDef] of Object.entries(config.rbac.users)) {
    if (userDef.identities[platform] === userId) {
      const roles = userDef.roles;
      const permissions = roles.flatMap(
        (r) => config.rbac.roles[r]?.permissions ?? [],
      );
      const deny = roles.flatMap(
        (r) => config.rbac.roles[r]?.deny ?? [],
      );
      const allow = roles.flatMap(
        (r) => config.rbac.roles[r]?.allow ?? [],
      );
      return { username, roles, permissions, deny, allow };
    }
  }
  return null;
}

/**
 * Check if a user can access a given agent.
 */
export function checkAccess(
  userId: string,
  platform: string,
  agentId: string,
  config: PlatformConfig,
): boolean {
  const user = resolveUser(userId, platform, config);
  if (!user) return false;
  return user.permissions.some(
    (p) => p === "agent:*" || p === `agent:${agentId}`,
  );
}

/**
 * Match a tool rule pattern against a tool name and input.
 *
 * Patterns:
 * - "tool:*"           — all tools
 * - "tool:Bash"        — specific tool (all invocations)
 * - "tool:Bash:git *"  — tool + command glob
 */
export function matchesToolRule(
  rule: string,
  tool: string,
  input: Record<string, unknown>,
): boolean {
  if (!rule.startsWith("tool:")) return false;

  const parts = rule.split(":");
  if (parts[1] === "*") return true;
  if (parts.length === 2) return parts[1] === tool;
  if (parts[1] !== tool) return false;

  const pattern = parts.slice(2).join(":");
  const command = String(input.command ?? input.content ?? "");

  const regex = new RegExp(
    "^" +
      pattern
        .replace(/[.+^${}()|[\]\\]/g, "\\$&")
        .replace(/\*/g, ".*")
        .replace(/\?/g, ".") +
      "$",
  );
  return regex.test(command);
}

// ── canUseTool callback (used by dispatcher for sub-agent delegation) ──────

export type CanUseToolResult =
  | { behavior: "allow"; updatedInput?: Record<string, unknown> }
  | { behavior: "deny"; message?: string };

/**
 * Build a canUseTool-compatible permission hook.
 * Used by the dispatcher for sub-agent permission checks.
 */
export function buildPermissionHook(
  userId: string,
  platform: string,
  config: PlatformConfig,
  agentRules?: string[],
  agentCwd?: string,
  platformRoot?: string,
  askApproval?: AskApprovalFn,
): (
  tool: string,
  input: Record<string, unknown>,
) => Promise<CanUseToolResult> {
  const user = resolveUser(userId, platform, config);

  if (!user) {
    return async (): Promise<CanUseToolResult> => ({
      behavior: "deny",
      message: "Permission denied: unknown user",
    });
  }

  const { deny, allow } = user;

  const home = homedir();
  const permCtx: PermissionContext | undefined =
    agentRules !== undefined
      ? {
          homeDir: home,
          agentCwd: agentCwd ?? process.cwd(),
          platformRoot: platformRoot ?? join(home, ".datum"),
        }
      : undefined;

  return async (
    tool: string,
    input: Record<string, unknown>,
  ): Promise<CanUseToolResult> => {
    // Layer 1: User-level RBAC
    const denied = deny.some((rule) => matchesToolRule(rule, tool, input));
    if (denied) {
      const allowed = allow.some((rule) => matchesToolRule(rule, tool, input));
      if (!allowed) {
        return { behavior: "deny", message: `Denied by user policy: ${tool}` };
      }
    }

    // Layer 2: Agent-level permissions
    if (permCtx) {
      const agentResult = await evaluateAgentPermissions(
        agentRules,
        tool,
        input,
        permCtx,
      );
      if (agentResult === "deny") {
        return { behavior: "deny", message: `Denied by agent policy: ${tool}` };
      }
      if (agentResult === "ask") {
        if (askApproval) {
          const approved = await askApproval(tool, input);
          if (!approved) {
            return {
              behavior: "deny",
              message: `Denied by user (HITL): ${tool}`,
            };
          }
          return { behavior: "allow", updatedInput: input };
        }
        return {
          behavior: "deny",
          message: `Denied by agent policy (no HITL callback): ${tool}`,
        };
      }
    }

    return { behavior: "allow", updatedInput: input };
  };
}

// ── PreToolUse Hook (SDK integration point) ────────────────────────────────

export interface PreToolUseHookOutput {
  hookEventName: "PreToolUse";
  permissionDecision: "allow" | "deny";
  permissionDecisionReason?: string;
  updatedInput?: Record<string, unknown>;
}

/**
 * Build a PreToolUse hook for the Agent SDK.
 *
 * Unlike `canUseTool` (which runs last in the permission chain and is skipped
 * when the SDK auto-approves), PreToolUse hooks run FIRST — before deny rules,
 * permission mode, and allow rules. This is the correct integration point.
 *
 * Two-layer evaluation:
 *   Layer 1 — User-level RBAC (allow-by-default, deny rules block, allow rules override)
 *   Layer 2 — Agent-level permissions (first-match-wins ordered rules)
 */
export function buildPreToolUseHook(
  userId: string,
  platform: string,
  config: PlatformConfig,
  agentRules?: string[],
  agentCwd?: string,
  platformRoot?: string,
  askApproval?: AskApprovalFn,
): (input: { tool_name: string; tool_input: unknown }) => Promise<{
  hookSpecificOutput: PreToolUseHookOutput;
}> {
  const user = resolveUser(userId, platform, config);

  if (!user) {
    return async () => ({
      hookSpecificOutput: {
        hookEventName: "PreToolUse" as const,
        permissionDecision: "deny" as const,
        permissionDecisionReason: "Permission denied: unknown user",
      },
    });
  }

  const { deny, allow } = user;

  const home = homedir();
  const permCtx: PermissionContext | undefined =
    agentRules !== undefined
      ? {
          homeDir: home,
          agentCwd: agentCwd ?? process.cwd(),
          platformRoot: platformRoot ?? join(home, ".datum"),
        }
      : undefined;

  return async (hookInput) => {
    const tool = hookInput.tool_name;
    const input = (hookInput.tool_input ?? {}) as Record<string, unknown>;

    // Layer 1: User-level RBAC
    const denied = deny.some((rule) => matchesToolRule(rule, tool, input));
    if (denied) {
      const allowed = allow.some((rule) => matchesToolRule(rule, tool, input));
      if (!allowed) {
        return {
          hookSpecificOutput: {
            hookEventName: "PreToolUse" as const,
            permissionDecision: "deny" as const,
            permissionDecisionReason: `Denied by user policy: ${tool}`,
          },
        };
      }
    }

    // Layer 2: Agent-level permissions
    if (permCtx) {
      const agentResult = await evaluateAgentPermissions(
        agentRules,
        tool,
        input,
        permCtx,
      );
      if (agentResult === "deny") {
        return {
          hookSpecificOutput: {
            hookEventName: "PreToolUse" as const,
            permissionDecision: "deny" as const,
            permissionDecisionReason: `Denied by agent policy: ${tool}`,
          },
        };
      }
      if (agentResult === "ask") {
        if (askApproval) {
          const approved = await askApproval(tool, input);
          if (!approved) {
            return {
              hookSpecificOutput: {
                hookEventName: "PreToolUse" as const,
                permissionDecision: "deny" as const,
                permissionDecisionReason: `Denied by user (HITL): ${tool}`,
              },
            };
          }
        } else {
          return {
            hookSpecificOutput: {
              hookEventName: "PreToolUse" as const,
              permissionDecision: "deny" as const,
              permissionDecisionReason: `Denied by agent policy (no HITL callback): ${tool}`,
            },
          };
        }
      }
    }

    return {
      hookSpecificOutput: {
        hookEventName: "PreToolUse" as const,
        permissionDecision: "allow" as const,
        updatedInput: input,
      },
    };
  };
}

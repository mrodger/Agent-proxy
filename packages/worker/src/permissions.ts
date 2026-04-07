/**
 * Permission enforcement for worker containers.
 *
 * Converts Datum permission rules into Claude Code SDK settings format.
 *
 * Datum rules: first-match-wins, ordered (allow/deny/ask:Tool(pattern))
 * SDK rules: deny-before-allow, pattern matching
 *
 * Strategy:
 * - Tools with ONLY allow rules (no deny) → allow with wildcard: "Tool(*)"
 * - Tools with specific allow patterns + deny → allow with specific patterns only
 * - Tools with ONLY deny (no allow) → deny with wildcard: "Tool"
 * - Deny patterns always go in deny list
 * - permissionMode: 'dontAsk' for anything not covered
 */

interface ParsedRule {
  action: "allow" | "deny" | "ask";
  tool: string;
  pattern?: string;
}

function parseRule(rule: string): ParsedRule | null {
  const match = rule.match(/^(allow|deny|ask):(.+)$/);
  if (!match) return null;
  const action = match[1] as "allow" | "deny" | "ask";
  const toolSpec = match[2];
  const parenMatch = toolSpec.match(/^([^(]+)\((.+)\)$/);
  if (parenMatch) {
    return { action, tool: parenMatch[1], pattern: parenMatch[2] };
  }
  return { action, tool: toolSpec };
}

export function buildPermissionOptions(permissionStrings: string[]): Record<string, unknown> {
  const rules = permissionStrings
    .map(parseRule)
    .filter((r): r is ParsedRule => r !== null);

  // Analyze per-tool rule composition
  const toolInfo = new Map<string, {
    allowPatterns: string[];    // specific allow patterns
    denyPatterns: string[];     // specific deny patterns
    hasUnconditionalAllow: boolean;  // "allow:Tool" (no pattern)
    hasUnconditionalDeny: boolean;   // "deny:Tool" (no pattern)
  }>();

  for (const rule of rules) {
    if (rule.tool === "*") continue; // wildcards handled separately

    const info = toolInfo.get(rule.tool) ?? {
      allowPatterns: [], denyPatterns: [],
      hasUnconditionalAllow: false, hasUnconditionalDeny: false,
    };

    if (rule.action === "allow") {
      if (rule.pattern) {
        info.allowPatterns.push(rule.pattern);
      } else {
        info.hasUnconditionalAllow = true;
      }
    } else if (rule.action === "deny" || rule.action === "ask") {
      if (rule.pattern) {
        info.denyPatterns.push(rule.pattern);
      } else {
        info.hasUnconditionalDeny = true;
      }
    }

    toolInfo.set(rule.tool, info);
  }

  const allow: string[] = [];
  const deny: string[] = [];

  for (const [tool, info] of toolInfo) {
    // Case 1: Unconditional deny, no allow → tool is completely blocked
    // Don't add to either list — dontAsk mode will deny it
    if (info.hasUnconditionalDeny && !info.hasUnconditionalAllow && info.allowPatterns.length === 0) {
      continue;
    }

    // Case 2: Unconditional allow, no deny patterns → wildcard allow
    if (info.hasUnconditionalAllow && info.denyPatterns.length === 0 && !info.hasUnconditionalDeny) {
      allow.push(`${tool}(*)`);
      continue;
    }

    // Case 3: Unconditional allow WITH deny patterns → wildcard allow + specific denies
    if (info.hasUnconditionalAllow && info.denyPatterns.length > 0) {
      allow.push(`${tool}(*)`);
      for (const pattern of info.denyPatterns) {
        deny.push(`${tool}(${pattern})`);
      }
      continue;
    }

    // Case 4: Specific allow patterns only (no unconditional) → add each pattern
    // Also handles: specific allow patterns + unconditional deny
    // The specific patterns override the unconditional deny
    if (info.allowPatterns.length > 0) {
      for (const pattern of info.allowPatterns) {
        allow.push(`${tool}(${pattern})`);
      }
      // Add specific deny patterns too
      for (const pattern of info.denyPatterns) {
        deny.push(`${tool}(${pattern})`);
      }
      continue;
    }
  }

  console.log(`[permissions] SDK allow: [${allow.join(", ")}]`);
  console.log(`[permissions] SDK deny: [${deny.join(", ")}]`);

  return {
    settings: { permissions: { allow, deny } },
    settingSources: [] as string[],
    permissionMode: "dontAsk",
  };
}

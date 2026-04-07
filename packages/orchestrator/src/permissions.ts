/**
 * Agent-level permission engine.
 *
 * Evaluates ordered first-match-wins rules defined per-agent in config.yaml.
 * Each rule is `allow:Selector`, `deny:Selector`, or `ask:Selector`.
 *
 * Selector formats:
 *   - `*`                    — matches all tools
 *   - `ToolName`             — matches specific tool (all invocations)
 *   - `ToolName(pattern)`    — matches tool with path/command glob
 *
 * Path prefix conventions (aligned with Claude Code):
 *   - `//`    — absolute POSIX path
 *   - `~/`    — home directory
 *   - `/`     — platform root (~/.datum)
 *   - `./`    — agent working directory
 *   - bare    — agent working directory (same as `./`)
 */

import { resolve, normalize, dirname, basename, isAbsolute } from "node:path";
import { realpath } from "node:fs/promises";

// ── Types ──────────────────────────────────────────────────────────────────

export interface AgentPermissionRule {
  action: "allow" | "deny" | "ask";
  tool: string;
  pattern?: string;
}

export interface PermissionContext {
  homeDir: string;
  agentCwd: string;
  platformRoot: string;
}

// ── Rule Parsing ───────────────────────────────────────────────────────────

export function parseRule(rule: string): AgentPermissionRule {
  const colonIdx = rule.indexOf(":");
  if (colonIdx === -1) {
    throw new Error(`Invalid permission rule (missing ':'): ${rule}`);
  }

  const action = rule.slice(0, colonIdx);
  if (action !== "allow" && action !== "deny" && action !== "ask") {
    throw new Error(`Invalid action "${action}" in rule: ${rule}`);
  }

  const selector = rule.slice(colonIdx + 1);
  if (!selector) {
    throw new Error(`Empty selector in rule: ${rule}`);
  }

  if (selector === "*") {
    return { action, tool: "*" };
  }

  const parenOpen = selector.indexOf("(");
  if (parenOpen !== -1) {
    if (!selector.endsWith(")")) {
      throw new Error(`Unclosed parenthesis in rule: ${rule}`);
    }
    const tool = selector.slice(0, parenOpen);
    const pattern = selector.slice(parenOpen + 1, -1);
    if (!tool) throw new Error(`Empty tool name in rule: ${rule}`);
    if (!pattern) throw new Error(`Empty pattern in rule: ${rule}`);
    return { action, tool, pattern };
  }

  return { action, tool: selector };
}

// ── POSIX Path Normalization ──────────────────────────────────────────────

export function toPosixPath(nativePath: string): string {
  let p = nativePath.replace(/\\/g, "/");
  const driveMatch = p.match(/^([A-Za-z]):\//);
  if (driveMatch) {
    p = `/${driveMatch[1].toLowerCase()}${p.slice(2)}`;
  }
  return p;
}

// ── Path Handling ──────────────────────────────────────────────────────────

export const FILE_PATH_FIELDS: Record<string, string> = {
  Read: "file_path",
  Write: "file_path",
  Edit: "file_path",
  Glob: "path",
  Grep: "path",
};

export function extractFilePath(
  tool: string,
  input: Record<string, unknown>,
): string | null {
  const field = FILE_PATH_FIELDS[tool];
  if (!field) return null;
  const value = input[field];
  return typeof value === "string" && value ? value : null;
}

export function expandPattern(
  pattern: string,
  ctx: PermissionContext,
): string {
  if (pattern.startsWith("//")) {
    return pattern.slice(1);
  }

  if (pattern === "~") {
    return toPosixPath(resolve(ctx.homeDir));
  }
  if (pattern.startsWith("~/") || pattern.startsWith("~\\")) {
    return toPosixPath(resolve(ctx.homeDir, pattern.slice(2)));
  }

  if (pattern.startsWith("/")) {
    return toPosixPath(resolve(ctx.platformRoot, pattern.slice(1)));
  }

  const rest = pattern.startsWith("./") || pattern.startsWith(".\\")
    ? pattern.slice(2)
    : pattern;
  return toPosixPath(resolve(ctx.agentCwd, rest));
}

export function expandInputPath(
  filePath: string,
  ctx: PermissionContext,
): string {
  if (filePath === "~") {
    return resolve(ctx.homeDir);
  }
  if (filePath.startsWith("~/") || filePath.startsWith("~\\")) {
    return resolve(ctx.homeDir, filePath.slice(2));
  }
  if (!isAbsolute(filePath)) {
    return resolve(ctx.agentCwd, filePath);
  }
  return resolve(filePath);
}

export async function resolveCanonicalPath(nativePath: string): Promise<string> {
  let canonical: string;
  try {
    canonical = await realpath(nativePath);
  } catch {
    const dir = dirname(nativePath);
    const leaf = basename(nativePath);
    try {
      const resolvedDir = await realpath(dir);
      canonical = resolve(resolvedDir, leaf);
    } catch {
      canonical = normalize(nativePath);
    }
  }
  return toPosixPath(canonical);
}

// ── Glob Matching ──────────────────────────────────────────────────────────

/**
 * Match a string against a glob pattern.
 *
 * Path mode (default, for file tools):
 *   - `**`  — matches any path including separators
 *   - `*`   — matches anything except path separators
 *   - `?`   — matches a single non-separator character
 *
 * Text mode (pathMode=false, for Bash commands):
 *   - `*`   — matches anything (including `/` and spaces)
 *   - `?`   — matches any single character
 */
export function matchGlob(
  value: string,
  pattern: string,
  pathMode: boolean = true,
): boolean {
  const v = value.replace(/\\/g, "/");
  const p = pattern.replace(/\\/g, "/");

  let regex = "^";
  let i = 0;
  while (i < p.length) {
    if (p[i] === "*" && p[i + 1] === "*") {
      if (pathMode && p[i + 2] === "/") {
        regex += "(?:.*/)?";
        i += 3;
      } else {
        regex += ".*";
        i += 2;
      }
    } else if (p[i] === "*") {
      regex += pathMode ? "[^/]*" : ".*";
      i++;
    } else if (p[i] === "?") {
      regex += pathMode ? "[^/]" : ".";
      i++;
    } else {
      regex += p[i].replace(/[.+^${}()|[\]\\]/g, "\\$&");
      i++;
    }
  }
  regex += "$";

  return new RegExp(regex).test(v);
}

// ── Rule Evaluation ────────────────────────────────────────────────────────

export async function ruleMatches(
  rule: AgentPermissionRule,
  tool: string,
  input: Record<string, unknown>,
  ctx: PermissionContext,
): Promise<boolean> {
  if (rule.tool !== "*" && rule.tool !== tool) return false;
  if (!rule.pattern) return true;

  const filePath = extractFilePath(tool, input);
  if (filePath !== null) {
    const posixPattern = expandPattern(rule.pattern, ctx);
    const nativeInput = expandInputPath(filePath, ctx);
    const posixInput = await resolveCanonicalPath(nativeInput);
    return matchGlob(posixInput, posixPattern);
  }

  if (tool === "Bash") {
    const command = String(input.command ?? "");
    return matchGlob(command, rule.pattern, false);
  }

  return false;
}

export async function evaluateAgentPermissions(
  rules: string[] | undefined,
  tool: string,
  input: Record<string, unknown>,
  ctx: PermissionContext,
): Promise<"allow" | "deny" | "ask"> {
  if (rules === undefined || rules === null) return "allow";

  const parsed = rules.map(parseRule);

  for (const rule of parsed) {
    if (await ruleMatches(rule, tool, input, ctx)) {
      return rule.action;
    }
  }

  return "ask";
}

export function formatToolApproval(tool: string, input: Record<string, unknown>): string {
  const lines = [`Tool: ${tool}`];

  if (tool === "Bash" && input.command) {
    lines.push(`Command: ${input.command}`);
  } else if (input.file_path) {
    lines.push(`Path: ${input.file_path}`);
  } else if (input.path) {
    lines.push(`Path: ${input.path}`);
  } else if (input.pattern) {
    lines.push(`Pattern: ${input.pattern}`);
  }

  if (input.description && typeof input.description === "string") {
    lines.push(`Description: ${input.description}`);
  }

  return lines.join("\n");
}

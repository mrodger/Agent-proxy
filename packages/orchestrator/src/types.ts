import type { ContainerConfig, ContainersConfig } from "./containers/types.js";

/** Memory configuration for an agent */
export interface MemoryConfig {
  /** Enable auto-memory (Claude Code reads/writes memory files). Default: true */
  enabled?: boolean;
  /** Enable background memory consolidation. Default: false */
  autoDream?: boolean;
}

/** Agent configuration from config.yaml */
export interface AgentConfig {
  model: string;
  system: string;
  /** "append" uses SDK's Claude Code preset + appends system. "replace" uses system as-is. */
  system_mode?: "append" | "replace";
  /** Effort level for reasoning depth: low, medium, high, max. */
  effort?: "low" | "medium" | "high" | "max";
  tools?: string[];
  sandboxed?: boolean;
  port?: number;
  url?: string;
  subagents?: string[];
  credentials?: string[];
  store_keys?: string[];
  container?: ContainerConfig;
  /** Memory configuration. Default: enabled with no autoDream. */
  memory?: MemoryConfig;
  /**
   * Ordered permission rules for this agent.
   * Format: "allow:Selector" or "deny:Selector" — first match wins.
   * If undefined, all tools are allowed (no agent-level restrictions).
   * If defined, implicit deny when no rule matches.
   */
  permissions?: string[];
}

export type { ContainerConfig, ContainersConfig };

/** Top-level agents shape (embedded in unified config) */
export interface AgentsConfig {
  agents: Record<string, AgentConfig>;
}

/**
 * Resolved paths configuration — all directories the platform uses.
 *
 * Default base: `~/.datum` (decoupled from the source repo).
 */
export interface PathsConfig {
  /** Root data directory (default: ~/.datum) */
  data_dir: string;
  /** Per-agent workspace root (default: <data_dir>/agents) */
  agents_dir: string;
  /** Sessions database path (default: <data_dir>/sessions.db) */
  sessions_db: string;
  /** Container provisioning temp files (default: <data_dir>/containers) */
  containers_dir: string;
  /** Config directory (set at runtime from loadConfig's configDir arg) */
  config_dir: string;
}

/** Gatekeeper configuration */
export interface GatekeeperConfig {
  enabled: boolean;
  /** Agent ID to use as the gatekeeper (must be defined in agents section) */
  agent: string;
  /** Risk level at or below which tool invocations are auto-approved */
  auto_approve_risk: "low" | "medium" | "high" | "critical";
}

/** Gatekeeper review result */
export interface GatekeeperReview {
  risk: "low" | "medium" | "high" | "critical";
  reasoning: string;
  suggestion?: string;
}

/** Platform configuration from config.yaml */
export interface PlatformConfig {
  channels: {
    terminal?: { enabled: boolean; agent: string };
    http?: { enabled: boolean; port: number };
  };
  rbac: {
    roles: Record<string, { permissions: string[]; deny?: string[]; allow?: string[] }>;
    users: Record<
      string,
      {
        roles: string[];
        identities: Record<string, string>;
      }
    >;
  };
  containers?: ContainersConfig;
  paths?: PathsConfig;
  gatekeeper?: GatekeeperConfig;
}

/** Unified message from any channel */
export interface ChannelMessage {
  scope: string;
  content: string;
  userId: string;
  platform: string;
  /** File attachments (images, text files, etc.) */
  attachments?: ChannelAttachment[];
}

/** An attachment from a channel message */
export interface ChannelAttachment {
  filename: string;
  contentType: string;
  data: string;
  size: number;
}

/** Result returned from dispatching to an agent */
export interface DispatchResult {
  result: string;
  sessionId: string;
}

/**
 * Callback for HITL (Human-in-the-Loop) approval.
 * @returns true to allow the tool invocation, false to deny
 */
export type AskApprovalFn = (
  tool: string,
  input: Record<string, unknown>,
) => Promise<boolean>;

/**
 * Channel-provided callbacks for the tool approval flow.
 */
export interface ApprovalChannel {
  askUser: (
    tool: string,
    input: Record<string, unknown>,
    review?: GatekeeperReview,
  ) => Promise<boolean>;

  notifyAutoApproved: (
    tool: string,
    input: Record<string, unknown>,
    review: GatekeeperReview,
  ) => Promise<void>;
}

/** Resolved user info from RBAC */
export interface ResolvedUser {
  username: string;
  roles: string[];
  permissions: string[];
  deny: string[];
  allow: string[];
}

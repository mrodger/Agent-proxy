/**
 * Datum Orchestrator — Phase 2
 *
 * Multi-agent orchestration with deterministic permission enforcement,
 * container isolation, and inter-agent delegation.
 */

export { loadConfig, PLATFORM_HOME, substituteEnvVars, resolvePaths } from "./config.js";
export {
  parseRule,
  evaluateAgentPermissions,
  matchGlob,
  expandPattern,
  expandInputPath,
  resolveCanonicalPath,
  toPosixPath,
  extractFilePath,
  formatToolApproval,
} from "./permissions.js";
export type { AgentPermissionRule, PermissionContext } from "./permissions.js";
export { resolveUser, checkAccess, matchesToolRule, buildPermissionHook, buildPreToolUseHook } from "./rbac.js";
export type { CanUseToolResult, PreToolUseHookOutput } from "./rbac.js";
export type {
  AgentConfig,
  AgentsConfig,
  PlatformConfig,
  PathsConfig,
  ChannelMessage,
  DispatchResult,
  AskApprovalFn,
  ApprovalChannel,
  ResolvedUser,
  GatekeeperConfig,
  GatekeeperReview,
  MemoryConfig,
  ContainerConfig,
  ContainersConfig,
} from "./types.js";
export type {
  ContainerState,
  CreateContainerOpts,
  ContainerInspect,
  ContainerInfo,
} from "./containers/types.js";
export { DockerClient } from "./containers/docker.js";
export { PortAllocator } from "./containers/ports.js";
export { resolveDockerfile, resolveImageTag, ensureImage } from "./containers/images.js";
export { provisionContainer } from "./containers/provision.js";
export type { ProvisionResult } from "./containers/provision.js";
export { ContainerManager } from "./containers/manager.js";
export {
  expandPath,
  matchesBlockedPattern,
  mergeBlockedPatterns,
  validateMount,
  validateAdditionalMounts,
} from "./containers/mounts.js";
export type {
  MountAllowlist,
  AllowedRoot,
  MountRequest,
  MountValidationResult,
  ValidatedMount,
} from "./containers/mounts.js";
export { DispatchQueue } from "./containers/queue.js";
export type { QueueConfig, QueuedTask, PendingMessage } from "./containers/queue.js";
export { initSessionsTable, getSessionId, setSessionId, deleteSession } from "./sessions.js";
export {
  shouldAutoApprove,
  resolveEffectivePermissions,
  buildGatedAskApproval,
  reviewToolInvocation,
} from "./gatekeeper.js";
export type { RiskLevel } from "./gatekeeper.js";
export {
  dispatch,
  buildSystemPrompt,
  buildSdkSettings,
  PLATFORM_DISALLOWED_TOOLS,
  SELF_MODIFICATION_DENY_RULES,
} from "./dispatcher.js";
export type { DispatchContext } from "./dispatcher.js";
export { initAuditTable, logDispatch, queryAuditLog } from "./audit.js";
export type { AuditEntry } from "./audit.js";

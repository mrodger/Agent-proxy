import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { homedir } from "node:os";
import yaml from "js-yaml";
import { z } from "zod";
import type { AgentsConfig, PlatformConfig, PathsConfig } from "./types.js";
import {
  containerConfigSchema,
  containersConfigSchema,
} from "./containers/types.js";

/** Default platform home directory */
export const PLATFORM_HOME = join(homedir(), ".datum");

const gatekeeperConfigSchema = z.object({
  enabled: z.boolean().default(false),
  agent: z.string(),
  auto_approve_risk: z
    .enum(["low", "medium", "high", "critical"])
    .default("low"),
});

const memoryConfigSchema = z
  .object({
    enabled: z.boolean().default(true),
    autoDream: z.boolean().default(false),
  })
  .default({ enabled: true, autoDream: false });

const agentConfigSchema = z.object({
  model: z.string(),
  system: z.string(),
  system_mode: z.enum(["append", "replace"]).default("replace"),
  effort: z.enum(["low", "medium", "high", "max"]).optional(),
  tools: z.array(z.string()).optional(),
  sandboxed: z.boolean().default(false),
  port: z.number().optional(),
  url: z.string().optional(),
  subagents: z.array(z.string()).optional(),
  credentials: z.array(z.string()).optional(),
  store_keys: z.array(z.string()).optional(),
  container: containerConfigSchema.optional(),
  memory: memoryConfigSchema.optional(),
  permissions: z.array(z.string()).optional(),
});

const pathsConfigSchema = z.object({
  data_dir: z.string().optional(),
  agents_dir: z.string().optional(),
  sessions_db: z.string().optional(),
  containers_dir: z.string().optional(),
});

/**
 * Unified config schema — single config.yaml with all sections.
 */
const unifiedConfigSchema = z.object({
  agents: z.record(z.string(), agentConfigSchema),
  channels: z.object({
    terminal: z
      .object({
        enabled: z.boolean(),
        agent: z.string(),
      })
      .optional(),
    http: z
      .object({
        enabled: z.boolean(),
        port: z.number().default(8080),
      })
      .optional(),
  }),
  rbac: z.object({
    roles: z.record(
      z.string(),
      z.object({
        permissions: z.array(z.string()),
        deny: z.array(z.string()).optional(),
        allow: z.array(z.string()).optional(),
      }),
    ),
    users: z.record(
      z.string(),
      z.object({
        roles: z.array(z.string()),
        identities: z.record(z.string(), z.string()),
      }),
    ),
  }),
  containers: containersConfigSchema.optional(),
  paths: pathsConfigSchema.optional(),
  gatekeeper: gatekeeperConfigSchema.optional(),
});

// ── Environment variable substitution ──────────────────────────────────────

/**
 * Recursively substitute `${ENV_VAR}` patterns in strings.
 * Fail-fast: throws if a referenced env var is not set (R-1 fix).
 */
export function substituteEnvVars(value: unknown): unknown {
  if (typeof value === "string") {
    return value.replace(/\$\{(\w+)\}/g, (_match, varName: string) => {
      const val = process.env[varName];
      if (val === undefined) {
        throw new Error(
          `Environment variable \${${varName}} is not set (required by config)`,
        );
      }
      return val;
    });
  }
  if (Array.isArray(value)) {
    return value.map(substituteEnvVars);
  }
  if (value !== null && typeof value === "object") {
    const result: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      result[k] = substituteEnvVars(v);
    }
    return result;
  }
  return value;
}

// ── Path Resolution ────────────────────────────────────────────────────────

export function resolvePaths(
  raw:
    | {
        data_dir?: string;
        agents_dir?: string;
        sessions_db?: string;
        containers_dir?: string;
      }
    | undefined,
  configDir: string,
  projectRoot: string,
): PathsConfig {
  const r = (p: string) => resolve(projectRoot, p);

  const dataDir = raw?.data_dir ? r(raw.data_dir) : PLATFORM_HOME;
  const agentsDir = raw?.agents_dir
    ? r(raw.agents_dir)
    : join(dataDir, "agents");
  const sessionsDb = raw?.sessions_db
    ? r(raw.sessions_db)
    : join(dataDir, "sessions.db");
  const containersDir = raw?.containers_dir
    ? r(raw.containers_dir)
    : join(dataDir, "containers");

  return {
    data_dir: dataDir,
    agents_dir: agentsDir,
    sessions_db: sessionsDb,
    containers_dir: containersDir,
    config_dir: resolve(configDir),
  };
}

// ── Loader ─────────────────────────────────────────────────────────────────

/**
 * Load and validate config from a directory containing config.yaml.
 *
 * Performs env-var substitution, Zod validation, and path resolution.
 */
export function loadConfig(
  configDir: string,
  projectRoot?: string,
): {
  agents: AgentsConfig;
  platform: PlatformConfig;
} {
  const root = projectRoot ?? resolve(configDir, "..");
  const configPath = join(configDir, "config.yaml");

  const raw = yaml.load(readFileSync(configPath, "utf-8"));
  const substituted = substituteEnvVars(raw);
  const parsed = unifiedConfigSchema.parse(substituted);

  const agents: AgentsConfig = { agents: parsed.agents };
  const platform: PlatformConfig = {
    channels: parsed.channels,
    rbac: parsed.rbac,
    containers: parsed.containers,
    gatekeeper: parsed.gatekeeper,
  };

  platform.paths = resolvePaths(parsed.paths, configDir, root);

  return { agents, platform };
}

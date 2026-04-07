import { join } from "node:path";
import type {
  AgentConfig,
  AgentsConfig,
  AskApprovalFn,
  ChannelAttachment,
  ChannelMessage,
  DispatchResult,
  PlatformConfig,
} from "./types.js";
import type { CanUseToolResult } from "./rbac.js";
import { checkAccess, buildPermissionHook } from "./rbac.js";
import { resolveEffectivePermissions } from "./gatekeeper.js";
import type { ContainerManager } from "./containers/manager.js";

/** Maximum delegation depth to prevent infinite recursion. */
const MAX_DELEGATION_DEPTH = 2;

/**
 * Context needed for sub-agent dispatch — carries the full agent registry,
 * platform config, and the original caller's identity so RBAC applies
 * through the entire chain.
 */
export interface DispatchContext {
  allAgents: AgentsConfig;
  platform: PlatformConfig;
  userId: string;
  userPlatform: string;
  agentsDir?: string;
  platformRoot?: string;
  askApproval?: AskApprovalFn;
  containerManager?: ContainerManager;
  delegationDepth?: number;
  proxy?: {
    gatewayUrl: string;
    host: string;
    caCertPath: string;
  };
}

/**
 * Dispatch a message to an agent — either in-process via Agent SDK query(),
 * or via HTTP POST to a sandboxed worker container.
 */
export async function dispatch(
  agentId: string,
  message: ChannelMessage,
  agentConfig: AgentConfig,
  sessionId: string | null,
  permissionHook?: (
    tool: string,
    input: Record<string, unknown>,
  ) => Promise<CanUseToolResult>,
  context?: DispatchContext,
  containerManager?: ContainerManager,
): Promise<DispatchResult> {
  if (agentConfig.sandboxed) {
    if (containerManager) {
      const url = await containerManager.ensure(
        agentId,
        agentConfig,
        message.scope,
      );
      return dispatchRemote(
        { ...agentConfig, url },
        agentId,
        message,
        sessionId,
      );
    }
    return dispatchRemote(agentConfig, agentId, message, sessionId);
  }
  return dispatchLocal(
    agentId,
    agentConfig,
    message,
    sessionId,
    permissionHook,
    context,
  );
}

/**
 * Build the system prompt based on agent config and system_mode.
 */
export function buildSystemPrompt(
  agentConfig: AgentConfig,
):
  | string
  | { type: "preset"; preset: "claude_code"; append: string }
  | undefined {
  if (!agentConfig.system) return undefined;

  const mode = agentConfig.system_mode ?? "replace";

  if (mode === "append") {
    return {
      type: "preset" as const,
      preset: "claude_code" as const,
      append: agentConfig.system,
    };
  }

  return agentConfig.system;
}

/** Tools that bypass orchestration — must never be available to agents. */
export const PLATFORM_DISALLOWED_TOOLS = ["Agent"];

/** Deny rules preventing agents from modifying their own config. */
export const SELF_MODIFICATION_DENY_RULES = [
  "Write(.claude/**)",
  "Edit(.claude/**)",
];

/**
 * Build the SDK `settings` object for an agent.
 */
export function buildSdkSettings(
  agentConfig: AgentConfig,
  agentId: string,
  agentsDir?: string,
): Record<string, unknown> {
  const memoryDir = agentsDir
    ? join(agentsDir, agentId, "memory")
    : undefined;

  return {
    autoMemoryEnabled: agentConfig.memory?.enabled ?? true,
    ...(memoryDir ? { autoMemoryDirectory: memoryDir } : {}),
    autoDreamEnabled: agentConfig.memory?.autoDream ?? false,
    permissions: {
      deny: ["Agent", ...SELF_MODIFICATION_DENY_RULES],
    },
  };
}

/** Image MIME types accepted as multimodal content blocks. */
const IMAGE_MIME_TYPES = new Set([
  "image/png",
  "image/jpeg",
  "image/gif",
  "image/webp",
]);

function buildPromptWithAttachments(
  text: string,
  attachments: ChannelAttachment[],
  sessionId: string | null,
):
  | string
  | AsyncIterable<{
      type: "user";
      message: unknown;
      parent_tool_use_id: null;
      session_id: string;
    }> {
  const imageBlocks: unknown[] = [];
  const textParts: string[] = [];

  for (const att of attachments) {
    if (IMAGE_MIME_TYPES.has(att.contentType)) {
      imageBlocks.push({
        type: "image",
        source: {
          type: "base64",
          media_type: att.contentType,
          data: att.data,
        },
      });
    } else {
      textParts.push(`\n--- ${att.filename} ---\n${att.data}\n---`);
    }
  }

  if (imageBlocks.length === 0) {
    return text + textParts.join("");
  }

  const content: unknown[] = [
    ...imageBlocks,
    { type: "text", text: text + textParts.join("") },
  ];

  const userMessage = {
    type: "user" as const,
    message: { role: "user" as const, content },
    parent_tool_use_id: null,
    session_id: sessionId ?? "",
  };

  return (async function* () {
    yield userMessage;
  })();
}

/**
 * In-process dispatch using Agent SDK query().
 */
async function dispatchLocal(
  agentId: string,
  agentConfig: AgentConfig,
  message: ChannelMessage,
  sessionId: string | null,
  permissionHook?: (
    tool: string,
    input: Record<string, unknown>,
  ) => Promise<CanUseToolResult>,
  context?: DispatchContext,
): Promise<DispatchResult> {
  const { query } = await import("@anthropic-ai/claude-agent-sdk");

  let resultText = "";
  let resultSessionId = "";

  const agentTools = agentConfig.tools
    ? agentConfig.tools.filter((t) => t !== "Agent")
    : undefined;

  const options: Record<string, unknown> = {
    model: agentConfig.model,
    maxTurns: 20,
    settingSources: ["project"],
    permissionMode: "acceptEdits" as const,
    disallowedTools: PLATFORM_DISALLOWED_TOOLS,
    settings: buildSdkSettings(agentConfig, agentId, context?.agentsDir),
  };

  if (agentConfig.effort) {
    options.effort = agentConfig.effort;
  }

  if (context?.agentsDir) {
    options.cwd = join(context.agentsDir, agentId);
  }

  // Build ask_agent MCP server for sub-agent delegation
  if (agentConfig.subagents?.length && context) {
    const mcpServer = await buildSubagentMcpServer(
      context,
      agentConfig.subagents,
    );
    options.mcpServers = { orchestrator: mcpServer };
    if (agentTools) {
      agentTools.push("mcp__orchestrator__ask_agent");
    }
  }

  if (agentTools) {
    options.tools = agentTools;
  }

  if (sessionId) {
    options.resume = sessionId;
  }

  const systemPrompt = buildSystemPrompt(agentConfig);
  if (systemPrompt) {
    options.systemPrompt = systemPrompt;
  }

  // Credential proxy integration for local agents
  let proxyToken: string | undefined;
  if (context?.proxy && agentConfig.credentials?.length) {
    try {
      const tokenRes = await fetch(`${context.proxy.gatewayUrl}/token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        signal: AbortSignal.timeout(3000),
        body: JSON.stringify({
          agentId,
          credentials: agentConfig.credentials,
          storeKeys: agentConfig.store_keys,
        }),
      });
      if (tokenRes.ok) {
        const data = (await tokenRes.json()) as {
          token: string;
          expiresAt: number;
        };
        proxyToken = data.token;
        options.env = {
          ...process.env,
          HTTP_PROXY: `http://${context.proxy.host}:10255`,
          HTTPS_PROXY: `http://${context.proxy.host}:10255`,
          NO_PROXY: "localhost,127.0.0.1",
          NODE_EXTRA_CA_CERTS: context.proxy.caCertPath,
          APW_GATEWAY: context.proxy.gatewayUrl,
          APW_TOKEN: data.token,
        };
      }
    } catch {
      // Proxy not running
    }
  }

  // PreToolUse hook — wraps canUseTool callback for SDK integration
  if (permissionHook) {
    options.hooks = {
      PreToolUse: [
        {
          hooks: [
            async (hookInput: Record<string, unknown>) => {
              const result = await permissionHook(
                String(hookInput.tool_name),
                (hookInput.tool_input ?? {}) as Record<string, unknown>,
              );
              if (result.behavior === "deny") {
                return {
                  hookSpecificOutput: {
                    hookEventName: "PreToolUse",
                    permissionDecision: "deny",
                    permissionDecisionReason:
                      result.message ?? "Denied by RBAC",
                  },
                };
              }
              return {
                hookSpecificOutput: {
                  hookEventName: "PreToolUse",
                  permissionDecision: "allow",
                  updatedInput: result.updatedInput,
                },
              };
            },
          ],
        },
      ],
    };
  }

  const prompt = message.attachments?.length
    ? buildPromptWithAttachments(
        message.content,
        message.attachments,
        sessionId,
      )
    : message.content;

  const stream = query({
    prompt: prompt as any,
    options: options as any,
  });

  try {
    for await (const msg of stream) {
      const m = msg as Record<string, unknown>;
      if (m.session_id) resultSessionId = String(m.session_id);
      if ("result" in m) resultText = String(m.result);
    }
  } finally {
    if (proxyToken && context?.proxy) {
      fetch(`${context.proxy.gatewayUrl}/token/${proxyToken}`, {
        method: "DELETE",
      }).catch(() => {});
    }
  }

  return { result: resultText, sessionId: resultSessionId };
}

/**
 * Build an inline MCP server that exposes `ask_agent` for sub-agent delegation.
 */
async function buildSubagentMcpServer(
  context: DispatchContext,
  callerSubagents?: string[],
) {
  const { tool, createSdkMcpServer } = await import(
    "@anthropic-ai/claude-agent-sdk"
  );
  const { z } = await import("zod");

  const allowedTargets = callerSubagents ?? [];

  const askAgentTool = tool(
    "ask_agent",
    "Delegate a task to another agent. Returns the agent's response text.",
    {
      agentId: z
        .string()
        .describe("The ID of the agent to delegate to"),
      task: z
        .string()
        .describe("The task or question to send to the agent"),
    },
    async (args: { agentId: string; task: string }) => {
      const currentDepth = context.delegationDepth ?? 0;
      if (currentDepth >= MAX_DELEGATION_DEPTH) {
        return {
          content: [
            {
              type: "text" as const,
              text: `Delegation denied: max depth of ${MAX_DELEGATION_DEPTH} hops reached`,
            },
          ],
        };
      }

      const targetConfig = context.allAgents.agents[args.agentId];
      if (!targetConfig) {
        return {
          content: [
            {
              type: "text" as const,
              text: `Unknown agent: ${args.agentId}`,
            },
          ],
        };
      }

      if (!allowedTargets.includes(args.agentId)) {
        return {
          content: [
            {
              type: "text" as const,
              text: `Delegation denied: "${args.agentId}" not in allowlist`,
            },
          ],
        };
      }

      if (
        !checkAccess(
          context.userId,
          context.userPlatform,
          args.agentId,
          context.platform,
        )
      ) {
        return {
          content: [
            {
              type: "text" as const,
              text: `Access denied: user cannot invoke "${args.agentId}"`,
            },
          ],
        };
      }

      const subAgentCwd = context.agentsDir
        ? join(context.agentsDir, args.agentId)
        : undefined;
      const subEffectivePermissions = resolveEffectivePermissions(
        targetConfig.permissions,
        context.platform.gatekeeper,
      );
      const subPermissionHook = buildPermissionHook(
        context.userId,
        context.userPlatform,
        context.platform,
        subEffectivePermissions,
        subAgentCwd,
        context.platformRoot,
        context.askApproval,
      );

      const subMessage: ChannelMessage = {
        scope: `subagent:${args.agentId}:${Date.now()}`,
        content: args.task,
        userId: context.userId,
        platform: context.userPlatform,
      };

      const subContext: DispatchContext = {
        ...context,
        delegationDepth: currentDepth + 1,
      };
      const result = await dispatch(
        args.agentId,
        subMessage,
        targetConfig,
        null,
        subPermissionHook,
        subContext,
        context.containerManager,
      );

      return {
        content: [{ type: "text" as const, text: result.result }],
      };
    },
  );

  return createSdkMcpServer({
    name: "orchestrator",
    version: "1.0.0",
    tools: [askAgentTool],
  });
}

/**
 * Remote dispatch via HTTP POST to a worker.
 */
async function dispatchRemote(
  agentConfig: AgentConfig,
  _agentId: string,
  message: ChannelMessage,
  sessionId: string | null,
): Promise<DispatchResult> {
  const baseUrl =
    agentConfig.url ?? `http://localhost:${agentConfig.port}`;
  const url = `${baseUrl}/run`;

  const builtPrompt = buildSystemPrompt(agentConfig);
  const systemPrompt =
    typeof builtPrompt === "object" &&
    builtPrompt !== null &&
    builtPrompt !== undefined
      ? (builtPrompt as { append: string }).append
      : builtPrompt;

  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      prompt: message.content,
      systemPrompt: systemPrompt ?? agentConfig.system,
      tools: agentConfig.tools?.filter((t) => t !== "Agent"),
      model: agentConfig.model,
      sessionId: sessionId ?? undefined,
      maxTurns: 20,
      ...(agentConfig.effort ? { effort: agentConfig.effort } : {}),
    }),
  });

  if (!response.ok) {
    throw new Error(
      `Worker responded with ${response.status}: ${await response.text()}`,
    );
  }

  const data = (await response.json()) as {
    result: string;
    sessionId: string;
  };
  return { result: data.result, sessionId: data.sessionId };
}

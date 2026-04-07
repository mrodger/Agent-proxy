/**
 * Gatekeeper — AI-powered tool invocation risk assessment.
 *
 * Before a tool invocation reaches the user for HITL approval, the Gatekeeper
 * evaluates risk. Based on the threshold:
 *   - Low-risk → auto-approve + notify channel
 *   - Higher-risk → present to user with review attached
 */

import { formatToolApproval } from "./permissions.js";
import type {
  AgentConfig,
  AskApprovalFn,
  ApprovalChannel,
  GatekeeperConfig,
  GatekeeperReview,
} from "./types.js";

export type RiskLevel = "low" | "medium" | "high" | "critical";

const RISK_ORDER: Record<RiskLevel, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

export function shouldAutoApprove(
  review: GatekeeperReview,
  threshold: RiskLevel,
): boolean {
  return RISK_ORDER[review.risk] <= RISK_ORDER[threshold];
}

/**
 * When gatekeeper is enabled and agent has no permissions field,
 * inject `["ask:*"]` so every tool passes through gatekeeper review.
 */
export function resolveEffectivePermissions(
  agentPermissions: string[] | undefined,
  gatekeeperConfig: GatekeeperConfig | undefined,
): string[] | undefined {
  if (agentPermissions !== undefined) return agentPermissions;
  if (gatekeeperConfig?.enabled) return ["ask:*"];
  return undefined;
}

/**
 * Build a gatekeeper-wrapped AskApprovalFn from channel callbacks.
 */
export function buildGatedAskApproval(
  channel: ApprovalChannel,
  config: GatekeeperConfig,
  agentConfig: AgentConfig,
): AskApprovalFn {
  const threshold = config.auto_approve_risk ?? "low";

  return async (
    tool: string,
    input: Record<string, unknown>,
  ): Promise<boolean> => {
    let review: GatekeeperReview | undefined;

    try {
      review = await reviewToolInvocation(tool, input, agentConfig);
    } catch (err) {
      console.error(
        "[gatekeeper] Review failed:",
        err instanceof Error ? err.message : err,
      );
    }

    if (review && shouldAutoApprove(review, threshold)) {
      try {
        await channel.notifyAutoApproved(tool, input, review);
      } catch {
        // Best-effort
      }
      return true;
    }

    return channel.askUser(tool, input, review);
  };
}

// ── Anthropic Messages API call ────────────────────────────────────────────

const DEFAULT_GATEKEEPER_SYSTEM = `You are a security gatekeeper for an AI agent platform. Assess the risk level of tool invocations.

Respond with ONLY a JSON object (no markdown, no code fences):

{
  "risk": "low" | "medium" | "high" | "critical",
  "summary": "One-line description of what this tool invocation does",
  "reasoning": "Brief explanation of why you assigned this risk level"
}

Risk guidelines:
- **low**: Read-only operations, safe searches, non-destructive commands
- **medium**: Writing/editing files, build/test commands, git commits
- **high**: Deleting files, unfamiliar scripts, system config, git push
- **critical**: Root/admin, modifying credentials, destructive git ops, rm -rf`;

export async function reviewToolInvocation(
  tool: string,
  input: Record<string, unknown>,
  agentConfig: AgentConfig,
): Promise<GatekeeperReview> {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    return fallbackReview(tool, "no API key");
  }

  const model = agentConfig.model;
  const systemPrompt = agentConfig.system || DEFAULT_GATEKEEPER_SYSTEM;
  const toolDescription = formatToolApproval(tool, input);

  const userMessage = `Assess the risk of this tool invocation:\n\n${toolDescription}\n\nFull input:\n${JSON.stringify(input, null, 2)}`;

  try {
    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
      },
      body: JSON.stringify({
        model,
        max_tokens: 300,
        system: systemPrompt,
        messages: [{ role: "user", content: userMessage }],
      }),
    });

    if (!response.ok) {
      return fallbackReview(tool, "API error");
    }

    const data = (await response.json()) as {
      content: Array<{ type: string; text?: string }>;
    };

    const text = data.content
      .filter((block) => block.type === "text")
      .map((block) => block.text)
      .join("");

    return parseReview(text);
  } catch (err) {
    return fallbackReview(
      tool,
      err instanceof Error ? err.message : "request failed",
    );
  }
}

function parseReview(text: string): GatekeeperReview {
  try {
    const cleaned = text
      .replace(/^```(?:json)?\s*\n?/m, "")
      .replace(/\n?```\s*$/m, "")
      .trim();
    const parsed = JSON.parse(cleaned);

    if (!isValidRisk(parsed.risk)) {
      return fallbackReview("unknown", "invalid risk level");
    }

    return {
      risk: parsed.risk,
      reasoning: String(parsed.reasoning ?? "No reasoning provided"),
      suggestion: parsed.summary,
    };
  } catch {
    return fallbackReview("unknown", "parse error");
  }
}

function isValidRisk(value: unknown): value is RiskLevel {
  return (
    value === "low" ||
    value === "medium" ||
    value === "high" ||
    value === "critical"
  );
}

function fallbackReview(tool: string, reason: string): GatekeeperReview {
  return {
    risk: "medium",
    reasoning: `Gatekeeper unavailable (${reason}). Defaulting to medium risk.`,
    suggestion: `Could not assess "${tool}"`,
  };
}

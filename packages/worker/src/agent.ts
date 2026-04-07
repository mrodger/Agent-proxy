import { query } from "@anthropic-ai/claude-agent-sdk";
import type { WorkerRunRequest, WorkerRunResponse } from "./types.js";
import { buildPermissionOptions } from "./permissions.js";

const DEFAULT_MODEL = "sonnet";
const DEFAULT_MAX_TURNS = 20;

export async function runAgent(request: WorkerRunRequest): Promise<WorkerRunResponse> {
  let sessionId = "";
  let result = "";

  const options: Record<string, unknown> = {
    model: request.model ?? DEFAULT_MODEL,
    systemPrompt: request.systemPrompt,
    resume: request.sessionId ?? undefined,
    maxTurns: request.maxTurns ?? DEFAULT_MAX_TURNS,
  };

  if (request.tools) {
    options.tools = request.tools;
  }

  if (request.permissions?.length) {
    Object.assign(options, buildPermissionOptions(request.permissions));
  }

  for await (const message of query({
    prompt: request.prompt,
    options: options as any,
  })) {
    if (message.session_id) sessionId = message.session_id;
    if ("result" in message) result = (message as { result: string }).result;
  }

  return { result, sessionId };
}

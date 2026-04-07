import { query } from "@anthropic-ai/claude-agent-sdk";
import type { WorkerRunRequest } from "./types.js";
import { buildPermissionOptions } from "./permissions.js";

const DEFAULT_MODEL = "sonnet";
const DEFAULT_MAX_TURNS = 20;

/**
 * Streaming variant of runAgent — yields SSE-formatted events
 * from the Agent SDK query() stream.
 */
export async function* streamAgent(request: WorkerRunRequest): AsyncGenerator<string> {
  const options: Record<string, unknown> = {
    model: request.model ?? DEFAULT_MODEL,
    systemPrompt: request.systemPrompt,
    resume: request.sessionId ?? undefined,
    maxTurns: request.maxTurns ?? DEFAULT_MAX_TURNS,
  };

  if (request.tools) {
    options.tools = request.tools;
  }

  // Permission enforcement via SDK's native settings-based system.
  // Converts Datum rules to SDK allow/deny lists + dontAsk mode.
  if (request.permissions?.length) {
    Object.assign(options, buildPermissionOptions(request.permissions));
  }

  for await (const message of query({
    prompt: request.prompt,
    options: options as any,
  })) {
    const msg = message as Record<string, unknown>;

    if (msg.type === "stream_event") {
      const event = msg.event as Record<string, unknown>;
      const eventType = event.type as string;

      if (eventType === "content_block_delta") {
        const delta = event.delta as Record<string, unknown>;
        if (delta.type === "text_delta") {
          yield `event: text\ndata: ${JSON.stringify({ text: delta.text })}\n\n`;
        }
      } else if (eventType === "content_block_start") {
        const block = event.content_block as Record<string, unknown>;
        if (block?.type === "tool_use") {
          yield `event: tool_start\ndata: ${JSON.stringify({ id: block.id, name: block.name })}\n\n`;
        }
      }
    } else if (msg.type === "assistant") {
      yield `event: turn\ndata: ${JSON.stringify({ session_id: msg.session_id })}\n\n`;
    } else if (msg.type === "result") {
      const result = msg as Record<string, unknown>;
      yield `event: result\ndata: ${JSON.stringify({
        result: result.result ?? "",
        session_id: result.session_id,
        cost_usd: result.total_cost_usd,
        duration_ms: result.duration_ms,
        num_turns: result.num_turns,
        is_error: result.is_error,
      })}\n\n`;
    }
  }

  yield `event: done\ndata: {}\n\n`;
}

import OpenAI from "openai";
import type { WorkerRunRequest } from "./types.js";

const DEFAULT_MODEL = "gpt-4.1";

const PEER_REVIEW_SYSTEM = `You are a critical code reviewer and bug finder. Your role is to:
- Identify bugs, logic errors, and security vulnerabilities in code
- Check for performance issues, memory leaks, and inefficiencies
- Validate error handling and edge cases
- Ensure code follows best practices and established patterns
- Flag style violations and architectural problems
- Test boundary conditions and potential failure modes

Be thorough, specific, and constructive. Provide clear remediation guidance.
Rate each finding: CRITICAL / HIGH / MEDIUM / LOW.
End with a summary verdict: APPROVE / REQUEST_CHANGES / NEEDS_DISCUSSION.`;

const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

export async function* streamAgent(request: WorkerRunRequest): AsyncGenerator<string> {
  const systemPrompt = request.systemPrompt || PEER_REVIEW_SYSTEM;
  const model = request.model || DEFAULT_MODEL;

  const stream = await client.chat.completions.create({
    model,
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: request.prompt },
    ],
    temperature: 0.2,
    max_tokens: 16384,
    stream: true,
  });

  let fullResult = "";
  for await (const chunk of stream) {
    const text = chunk.choices[0]?.delta?.content;
    if (text) {
      fullResult += text;
      yield `event: text\ndata: ${JSON.stringify({ text })}\n\n`;
    }
  }

  yield `event: result\ndata: ${JSON.stringify({ result: fullResult, session_id: "" })}\n\n`;
  yield `event: done\ndata: {}\n\n`;
}

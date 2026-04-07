import { Hono } from "hono";
import { stream as honoStream } from "hono/streaming";
import { timingSafeEqual } from "node:crypto";
import { WorkerRunRequestSchema } from "./types.js";
import { runAgent } from "./agent.js";
import { streamAgent } from "./stream.js";

export const app = new Hono();

const workerId = process.env.WORKER_ID ?? `peer-review-${process.pid}`;
const WORKER_SECRET = process.env.WORKER_SECRET ?? "";

function verifyWorkerSecret(header: string | undefined): boolean {
  if (!WORKER_SECRET) return true;
  if (!header) return false;
  const token = header.startsWith("Bearer ") ? header.slice(7) : header;
  if (token.length !== WORKER_SECRET.length) return false;
  return timingSafeEqual(Buffer.from(token), Buffer.from(WORKER_SECRET));
}

const authGuard = async (c: any, next: any) => {
  if (!verifyWorkerSecret(c.req.header("Authorization"))) {
    return c.json({ error: "Unauthorized" }, 401);
  }
  await next();
};

app.get("/health", (c) => {
  return c.json({ ok: true, workerId, provider: "openai" });
});

app.post("/run", authGuard, async (c) => {
  const body = await c.req.json();
  const parsed = WorkerRunRequestSchema.safeParse(body);
  if (!parsed.success) {
    return c.json({ error: parsed.error.flatten().fieldErrors }, 400);
  }
  try {
    const response = await runAgent(parsed.data);
    return c.json(response);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unknown error";
    return c.json({ error: message }, 500);
  }
});

app.post("/run/stream", authGuard, async (c) => {
  const body = await c.req.json();
  const parsed = WorkerRunRequestSchema.safeParse(body);
  if (!parsed.success) {
    return c.json({ error: parsed.error.flatten().fieldErrors }, 400);
  }
  c.header("Content-Type", "text/event-stream");
  c.header("Cache-Control", "no-cache");
  c.header("Connection", "keep-alive");
  return honoStream(c, async (stream) => {
    try {
      for await (const chunk of streamAgent(parsed.data)) {
        await stream.write(chunk);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : "Unknown error";
      await stream.write(`event: error\ndata: ${JSON.stringify({ error: message })}\n\n`);
    }
  });
});

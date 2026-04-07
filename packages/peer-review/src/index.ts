import { serve } from "@hono/node-server";
import { app } from "./server.js";

const port = parseInt(process.env.PORT ?? "3001", 10);
const workerId = process.env.WORKER_ID ?? `peer-review-${process.pid}`;

serve({ fetch: app.fetch, port }, () => {
  console.log(`Peer-review worker ${workerId} listening on port ${port} (OpenAI)`);
});

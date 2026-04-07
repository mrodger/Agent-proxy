import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createSecureContext } from "node:tls";
import * as tls from "node:tls";
import * as net from "node:net";
import type { ProxyConfig } from "../shared/types.js";
import { evaluatePolicy } from "../shared/policy.js";
import { resolveCredential } from "../shared/credentials.js";
import { stripHeaders, injectCredential, matchRoute } from "./injector.js";
import { rewriteBody } from "./body-rewriter.js";
import { ensureCA, generateCert, type CaBundle } from "./tls.js";

const MAX_BODY_SIZE = 10 * 1024 * 1024; // 10MB — R-5 fix

/**
 * Start the HTTP forward proxy.
 * Handles both plain HTTP (via request handler) and HTTPS (via CONNECT tunnel).
 */
export function startHttpProxy(config: ProxyConfig): ReturnType<typeof createServer> {
  const ca = ensureCA(config.http.tls.ca_cert, config.http.tls.ca_key);

  const server = createServer((req, res) => {
    handleHttpRequest(req, res, config, ca).catch((err) => {
      console.error("[http-proxy] request error:", err);
      if (!res.headersSent) {
        res.writeHead(502, { "Content-Type": "text/plain" });
        res.end("Bad Gateway");
      }
    });
  });

  server.on("connect", (req, clientSocket: net.Socket, head) => {
    handleConnect(req, clientSocket, head, config, ca).catch((err) => {
      console.error("[http-proxy] CONNECT error:", err);
      clientSocket.end("HTTP/1.1 502 Bad Gateway\r\n\r\n");
    });
  });

  const host = config.host ?? "127.0.0.1";
  server.listen(config.http.port, host, () => {
    console.log(`[http-proxy] listening on ${host}:${config.http.port}`);
  });

  return server;
}

async function handleHttpRequest(
  req: IncomingMessage,
  res: ServerResponse,
  config: ProxyConfig,
  _ca: CaBundle
): Promise<void> {
  const url = new URL(req.url ?? "/", `http://${req.headers.host}`);
  const host = url.hostname;
  const path = url.pathname;
  const method = req.method ?? "GET";

  const action = evaluatePolicy(config.policy, { host, path, method });
  if (action === "deny") {
    res.writeHead(403, { "Content-Type": "text/plain" });
    res.end(`Blocked by policy: ${host}${path}`);
    return;
  }

  let headers = { ...req.headers } as Record<string, string>;
  delete headers.host;

  const route = matchRoute(config.http.routes, host, path, method);
  if (route) {
    headers = stripHeaders(headers, config.http.strip_headers);
    const value = await resolveCredential(config.provider, route.credential);
    headers = injectCredential(headers, route, value);
  }

  const targetUrl = url.toString();
  let body = await collectBody(req);

  if (method !== "GET" && method !== "HEAD") {
    const ct = headers["content-type"] ?? "";
    const rewritten = await rewriteBody(body, ct, config.provider);
    if (rewritten.replaced) {
      body = rewritten.body;
      if (headers["content-length"]) {
        headers["content-length"] = String(body.length);
      }
    }
  }

  const response = await fetch(targetUrl, {
    method,
    headers: { ...headers, host: url.host },
    body: method !== "GET" && method !== "HEAD"
      ? (new Uint8Array(body.buffer, body.byteOffset, body.byteLength) as any)
      : undefined,
    redirect: "manual",
  });

  const responseHeaders: Record<string, string> = {};
  response.headers.forEach((value, key) => {
    responseHeaders[key] = value;
  });

  res.writeHead(response.status, responseHeaders);
  if (response.body) {
    const reader = response.body.getReader();
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      res.write(value);
    }
  }
  res.end();
}

async function handleConnect(
  req: IncomingMessage,
  clientSocket: net.Socket,
  head: Buffer,
  config: ProxyConfig,
  ca: CaBundle
): Promise<void> {
  const [host, portStr] = (req.url ?? "").split(":");
  const port = parseInt(portStr, 10) || 443;

  const action = evaluatePolicy(config.policy, { host, port });
  if (action === "deny") {
    clientSocket.end("HTTP/1.1 403 Forbidden\r\n\r\nBlocked by policy\r\n");
    return;
  }

  clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");

  const { cert, key } = generateCert(host, ca);
  const ctx = createSecureContext({ cert, key });

  const tlsSocket = new tls.TLSSocket(clientSocket, {
    isServer: true,
    secureContext: ctx,
  });

  if (head.length > 0) {
    tlsSocket.unshift(head);
  }

  tlsSocket.on("error", (err) => {
    if ((err as NodeJS.ErrnoException).code !== "ECONNRESET") {
      console.error("[http-proxy] TLS socket error:", err);
    }
  });

  const mitmServer = createServer(async (mitmReq, mitmRes) => {
    try {
      await handleMitmRequest(mitmReq, mitmRes, host, port, config);
    } catch (err) {
      console.error("[http-proxy] MITM error:", err);
      if (!mitmRes.headersSent) {
        mitmRes.writeHead(502, { "Content-Type": "text/plain" });
        mitmRes.end("Bad Gateway");
      }
    }
  });

  mitmServer.emit("connection", tlsSocket);
}

async function handleMitmRequest(
  req: IncomingMessage,
  res: ServerResponse,
  host: string,
  port: number,
  config: ProxyConfig,
): Promise<void> {
  const path = req.url ?? "/";
  const method = req.method ?? "GET";

  let headers = { ...req.headers } as Record<string, string>;
  delete headers.host;
  delete headers["accept-encoding"];

  const route = matchRoute(config.http.routes, host, path, method);
  if (route) {
    headers = stripHeaders(headers, config.http.strip_headers);
    const value = await resolveCredential(config.provider, route.credential);
    headers = injectCredential(headers, route, value);
  }

  let body = await collectBody(req);

  if (method !== "GET" && method !== "HEAD" && body.length > 0) {
    const ct = headers["content-type"] ?? "";
    const rewritten = await rewriteBody(body, ct, config.provider);
    if (rewritten.replaced) {
      body = rewritten.body;
      if (headers["content-length"]) {
        headers["content-length"] = String(body.length);
      }
    }
  }

  const scheme = port === 443 ? "https" : "http";
  const url = `${scheme}://${host}${path}`;

  const response = await fetch(url, {
    method,
    headers: { ...headers, host },
    body: method !== "GET" && method !== "HEAD" && body.length > 0
      ? (new Uint8Array(body.buffer, body.byteOffset, body.byteLength) as any)
      : undefined,
    redirect: "manual",
  });

  const responseHeaders: Record<string, string> = {};
  response.headers.forEach((value, key) => {
    const lk = key.toLowerCase();
    if (lk === "transfer-encoding" || lk === "content-encoding" || lk === "content-length") return;
    responseHeaders[key] = value;
  });

  res.writeHead(response.status, responseHeaders);
  if (response.body) {
    const reader = response.body.getReader();
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      res.write(value);
    }
  }
  res.end();
}

function collectBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY_SIZE) {
        req.destroy();
        reject(new Error(`Body exceeds ${MAX_BODY_SIZE} bytes`));
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

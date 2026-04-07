import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { loadProxyConfig } from "./shared/config.js";
import { startHttpProxy } from "./http/proxy.js";
import { startGateway } from "./gateway/api.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

// Config dir: default to ../../config relative to packages/proxy/src/
const configDir = process.env.CONFIG_DIR ?? resolve(__dirname, "../../../config");
const config = loadProxyConfig(configDir);

console.log("[proxy] starting servers...");

const httpServer = startHttpProxy(config);
const gatewayServer = startGateway(config);

function shutdown() {
  console.log("[proxy] shutting down...");
  httpServer.close();
  gatewayServer.close();
  process.exit(0);
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

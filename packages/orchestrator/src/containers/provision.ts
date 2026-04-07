import {
  mkdirSync,
  writeFileSync,
  rmSync,
  existsSync,
  readFileSync,
} from "node:fs";
import { resolve } from "node:path";
import { homedir } from "node:os";
import type { ContainersConfig } from "./types.js";
import type { AgentConfig } from "../types.js";

export interface ProvisionResult {
  env: Record<string, string>;
  volumes: string[];
  gatewayToken: string;
  cleanup: () => Promise<void>;
}

/**
 * Provision everything a container needs before starting:
 * - Gateway token (via proxy gateway API)
 * - Environment variables (proxy, port, worker ID)
 * - Volume mounts (credentials, CA cert, config)
 *
 * If proxy gateway is unreachable, continues with minimal env.
 */
export async function provisionContainer(
  agentId: string,
  agentConfig: AgentConfig,
  containersConfig: ContainersConfig,
  proxyGatewayUrl: string,
  dataDir: string,
  port: number,
): Promise<ProvisionResult> {
  const containerDir = resolve(dataDir, "containers", agentId);
  mkdirSync(containerDir, { recursive: true });

  // 1. Issue gateway token
  let gatewayToken = "";
  let proxyAvailable = false;

  try {
    const tokenRes = await fetch(`${proxyGatewayUrl}/token`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Gateway-Secret": process.env.GATEWAY_SECRET ?? "",
      },
      signal: AbortSignal.timeout(3000),
      body: JSON.stringify({
        agentId,
        credentials: agentConfig.credentials ?? [],
        storeKeys: agentConfig.store_keys,
      }),
    });

    if (tokenRes.ok) {
      const data = (await tokenRes.json()) as {
        token: string;
        expiresAt: number;
      };
      gatewayToken = data.token;
      proxyAvailable = true;
    }
  } catch {
    // Proxy not running — continue without credential injection
  }

  // 2. Environment variables
  const env: Record<string, string> = {
    PORT: String(port),
    WORKER_ID: agentId,
  };

  if (proxyAvailable) {
    const proxyHost = containersConfig.proxy_host;
    env.HTTP_PROXY = `http://${proxyHost}:10255`;
    env.HTTPS_PROXY = `http://${proxyHost}:10255`;
    env.NO_PROXY = "localhost,127.0.0.1";
    env.NODE_EXTRA_CA_CERTS = containersConfig.proxy_ca_cert;
    env.APW_GATEWAY = `http://${proxyHost}:10256`;
    env.APW_TOKEN = gatewayToken;
  }

  // 3. Volume mounts
  const volumes: string[] = [];

  // Claude SDK OAuth credentials
  const hostCredsPath = resolve(homedir(), ".claude", ".credentials.json");
  if (existsSync(hostCredsPath)) {
    const credsContent = readFileSync(hostCredsPath, "utf-8");
    const containerCredsPath = resolve(containerDir, "credentials.json");
    writeFileSync(containerCredsPath, credsContent);
    volumes.push(
      `${containerCredsPath}:/home/node/.claude/.credentials.json:ro`,
    );
  }

  // Proxy CA cert (shared volume)
  if (proxyAvailable) {
    const caCertPath = resolve(containersConfig.proxy_ca_cert);
    if (existsSync(caCertPath)) {
      volumes.push(`${caCertPath}:/certs/proxy-ca.crt:ro`);
    }
  }

  // Agent-specific volumes — enforce :ro on config mounts
  if (agentConfig.container?.volumes) {
    for (const vol of agentConfig.container.volumes) {
      if (vol.includes("/config") && !vol.endsWith(":ro")) {
        const base = vol.endsWith(":rw") ? vol.slice(0, -3) : vol;
        volumes.push(`${base}:ro`);
      } else {
        volumes.push(vol);
      }
    }
  }

  // 4. Cleanup function
  const cleanup = async () => {
    if (gatewayToken) {
      try {
        await fetch(`${proxyGatewayUrl}/token/${gatewayToken}`, {
          method: "DELETE",
          headers: {
            "X-Gateway-Secret": process.env.GATEWAY_SECRET ?? "",
          },
        });
      } catch {
        // Best-effort
      }
    }

    if (existsSync(containerDir)) {
      rmSync(containerDir, { recursive: true, force: true });
    }
  };

  return { env, volumes, gatewayToken, cleanup };
}

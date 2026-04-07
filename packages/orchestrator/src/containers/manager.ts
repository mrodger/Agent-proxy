import { createHash } from "node:crypto";
import type { DockerClient } from "./docker.js";
import type { ContainersConfig, ContainerState } from "./types.js";
import type { AgentConfig } from "../types.js";
import { PortAllocator } from "./ports.js";
import { provisionContainer, type ProvisionResult } from "./provision.js";
import { resolveDockerfile, ensureImage } from "./images.js";

/**
 * Manages the lifecycle of Docker containers for sandboxed agents.
 *
 * Shared containers (default): one container per agentId, reused across scopes.
 * Session-isolated containers: one container per scope, keyed by agentId:scopeHash.
 */
export class ContainerManager {
  private readonly containers = new Map<string, ContainerState>();
  private readonly cleanups = new Map<string, () => Promise<void>>();
  private readonly inflight = new Map<string, Promise<string>>();
  private readonly portAllocator: PortAllocator;

  constructor(
    private readonly docker: DockerClient,
    private readonly config: ContainersConfig,
    private readonly proxyGatewayUrl: string,
    private readonly dataDir: string,
  ) {
    this.portAllocator = new PortAllocator(config.port_range);
  }

  /**
   * Ensure a container is running for this agent + scope.
   * Deduplicates concurrent calls for the same key.
   */
  async ensure(
    agentId: string,
    agentConfig: AgentConfig,
    scope: string,
  ): Promise<string> {
    const key = this.resolveKey(agentId, agentConfig, scope);

    const inflight = this.inflight.get(key);
    if (inflight) return inflight;

    const promise = this.ensureImpl(key, agentId, agentConfig, scope);
    this.inflight.set(key, promise);
    try {
      return await promise;
    } finally {
      this.inflight.delete(key);
    }
  }

  private async ensureImpl(
    key: string,
    agentId: string,
    agentConfig: AgentConfig,
    scope: string,
  ): Promise<string> {
    const existing = this.containers.get(key);
    if (existing) {
      const alive = await this.checkHealth(key);
      if (alive) {
        existing.lastActivity = Date.now();
        return existing.url;
      }
      await this.teardown(key);
    }

    const dockerfilePath = resolveDockerfile(agentConfig, this.config);
    const imageTag = await ensureImage(
      this.docker,
      dockerfilePath,
      this.config,
    );

    const port = this.portAllocator.allocate();

    let provision: ProvisionResult;
    try {
      provision = await provisionContainer(
        agentId,
        agentConfig,
        this.config,
        this.proxyGatewayUrl,
        this.dataDir,
        port,
      );
    } catch (err) {
      this.portAllocator.release(port);
      throw err;
    }

    this.cleanups.set(key, provision.cleanup);

    const containerName = `datum-${key.replace(/[^a-zA-Z0-9-]/g, "-")}`;
    let containerId: string;
    try {
      containerId = await this.docker.createContainer({
        image: imageTag,
        name: containerName,
        network: this.config.network,
        ports: { [`${port}/tcp`]: String(port) },
        env: provision.env,
        volumes: provision.volumes,
        labels: {
          datum: "true",
          "agent-id": agentId,
          "container-key": key,
          isolation: agentConfig.container?.isolation ?? "shared",
        },
        memory:
          agentConfig.container?.memory ?? this.config.defaults.memory,
        cpus: agentConfig.container?.cpus ?? this.config.defaults.cpus,
      });
    } catch (err) {
      this.portAllocator.release(port);
      await provision.cleanup();
      this.cleanups.delete(key);
      throw err;
    }

    await this.docker.startContainer(containerId);
    await this.waitForHealth(port);

    const url = `http://localhost:${port}`;
    const state: ContainerState = {
      containerId,
      key,
      agentId,
      scope:
        agentConfig.container?.isolation === "session" ? scope : undefined,
      image: imageTag,
      url,
      port,
      gatewayToken: provision.gatewayToken,
      startedAt: Date.now(),
      lastActivity: Date.now(),
    };

    this.containers.set(key, state);
    return url;
  }

  async teardown(key: string): Promise<void> {
    const state = this.containers.get(key);
    if (!state) return;

    try {
      await this.docker.stopContainer(state.containerId, 5);
    } catch {
      /* already stopped */
    }
    try {
      await this.docker.removeContainer(state.containerId);
    } catch {
      /* best effort */
    }

    this.portAllocator.release(state.port);
    this.containers.delete(key);

    const cleanup = this.cleanups.get(key);
    if (cleanup) {
      await cleanup();
      this.cleanups.delete(key);
    }
  }

  async teardownScope(scope: string): Promise<void> {
    const keys = [...this.containers.entries()]
      .filter(([, s]) => s.scope === scope)
      .map(([k]) => k);
    await Promise.all(keys.map((k) => this.teardown(k)));
  }

  async shutdownAll(): Promise<void> {
    const keys = [...this.containers.keys()];
    await Promise.all(keys.map((k) => this.teardown(k)));
  }

  getUrl(
    agentId: string,
    agentConfig: AgentConfig,
    scope: string,
  ): string | null {
    const key = this.resolveKey(agentId, agentConfig, scope);
    return this.containers.get(key)?.url ?? null;
  }

  async checkHealth(key: string): Promise<boolean> {
    const state = this.containers.get(key);
    if (!state) return false;
    try {
      const res = await fetch(`${state.url}/health`, {
        signal: AbortSignal.timeout(2000),
      });
      return res.ok;
    } catch {
      return false;
    }
  }

  async cleanupIdle(): Promise<void> {
    const now = Date.now();

    for (const [key, state] of this.containers) {
      const idleMs = now - state.lastActivity;

      if (state.scope) {
        if (idleMs > this.config.session_idle_minutes * 60_000) {
          await this.teardown(key);
        }
      } else if (this.config.max_age_hours > 0) {
        if (idleMs > this.config.max_age_hours * 3_600_000) {
          await this.teardown(key);
        }
      }
    }
  }

  async cleanupOrphans(): Promise<void> {
    const containers = await this.docker.listContainers({
      datum: "true",
    });

    for (const c of containers) {
      const key = c.labels["container-key"];
      if (!key || !this.containers.has(key)) {
        try {
          await this.docker.stopContainer(c.id, 5);
        } catch {
          /* already stopped */
        }
        try {
          await this.docker.removeContainer(c.id);
        } catch {
          /* best effort */
        }
      }
    }
  }

  get size(): number {
    return this.containers.size;
  }

  // ── Private ──

  private resolveKey(
    agentId: string,
    agentConfig: AgentConfig,
    scope: string,
  ): string {
    if (agentConfig.container?.isolation === "session") {
      const hash = createHash("sha256")
        .update(scope)
        .digest("hex")
        .slice(0, 12);
      return `${agentId}:${hash}`;
    }
    return agentId;
  }

  private async waitForHealth(port: number): Promise<void> {
    const { interval_ms, timeout_ms } = this.config.health_check;
    const deadline = Date.now() + timeout_ms;

    while (Date.now() < deadline) {
      try {
        const res = await fetch(`http://localhost:${port}/health`, {
          signal: AbortSignal.timeout(interval_ms),
        });
        if (res.ok) return;
      } catch {
        // Not ready yet
      }
      await new Promise((r) => setTimeout(r, interval_ms));
    }

    throw new Error(
      `Container health check timed out after ${timeout_ms}ms on port ${port}`,
    );
  }
}

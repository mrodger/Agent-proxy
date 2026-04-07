/**
 * DispatchQueue — Per-scope serialization with global concurrency control.
 *
 * Messages for the same scope are processed sequentially.
 * Global concurrency limit prevents resource exhaustion.
 * Exponential backoff retry on failure.
 */

export interface QueueConfig {
  maxConcurrent: number;
}

export interface QueuedTask {
  id: string;
  agentKey: string;
  fn: () => Promise<void>;
}

export interface PendingMessage {
  text: string;
  resolve: (result: string) => void;
  meta?: Record<string, unknown>;
}

interface AgentState {
  active: boolean;
  idleWaiting: boolean;
  isTask: boolean;
  runningTaskId: string | null;
  pendingMessages: PendingMessage[];
  pendingTasks: QueuedTask[];
  retryCount: number;
  retryScheduled: boolean;
}

const MAX_RETRIES = 5;
const BASE_RETRY_MS = 5000;

export class DispatchQueue {
  private readonly agents = new Map<string, AgentState>();
  private activeCount = 0;
  private readonly waitingAgents: string[] = [];
  private processMessageFn:
    | ((agentKey: string, message: PendingMessage) => Promise<boolean>)
    | null = null;
  private injectMessageFn:
    | ((agentKey: string, text: string) => boolean)
    | null = null;
  private shuttingDown = false;

  constructor(private readonly config: QueueConfig) {}

  setProcessMessageFn(
    fn: (agentKey: string, message: PendingMessage) => Promise<boolean>,
  ): void {
    this.processMessageFn = fn;
  }

  setInjectMessageFn(
    fn: (agentKey: string, text: string) => boolean,
  ): void {
    this.injectMessageFn = fn;
  }

  enqueue(
    agentKey: string,
    text: string,
    meta?: Record<string, unknown>,
  ): Promise<string> {
    return new Promise<string>((resolve) => {
      if (this.shuttingDown) {
        resolve("Queue is shutting down.");
        return;
      }

      const state = this.getAgent(agentKey);
      const pending: PendingMessage = { text, resolve, meta };

      // Inject into idle dispatch if possible
      if (state.active && state.idleWaiting && !state.isTask) {
        if (this.injectMessageFn?.(agentKey, text)) {
          state.idleWaiting = false;
          resolve("(injected into active dispatch)");
          return;
        }
      }

      if (state.active) {
        state.pendingMessages.push(pending);
        return;
      }

      if (
        this.activeCount >= this.config.maxConcurrent ||
        state.retryScheduled
      ) {
        state.pendingMessages.push(pending);
        if (!this.waitingAgents.includes(agentKey)) {
          this.waitingAgents.push(agentKey);
        }
        return;
      }

      state.pendingMessages.push(pending);
      this.runForAgent(agentKey).catch(() => {});
    });
  }

  enqueueMessage(agentKey: string, text?: string): void {
    if (this.shuttingDown) return;

    const state = this.getAgent(agentKey);

    if (state.active && state.idleWaiting && !state.isTask && text) {
      if (this.injectMessageFn?.(agentKey, text)) {
        state.idleWaiting = false;
        return;
      }
    }

    if (state.active) {
      if (text) {
        state.pendingMessages.push({ text, resolve: () => {} });
      }
      return;
    }

    if (
      this.activeCount >= this.config.maxConcurrent ||
      state.retryScheduled
    ) {
      if (text) {
        state.pendingMessages.push({ text, resolve: () => {} });
      }
      if (!this.waitingAgents.includes(agentKey)) {
        this.waitingAgents.push(agentKey);
      }
      return;
    }

    if (text) {
      state.pendingMessages.push({ text, resolve: () => {} });
    }
    this.runForAgent(agentKey).catch(() => {});
  }

  enqueueTask(
    agentKey: string,
    taskId: string,
    fn: () => Promise<void>,
  ): void {
    if (this.shuttingDown) return;

    const state = this.getAgent(agentKey);

    if (state.runningTaskId === taskId) return;
    if (state.pendingTasks.some((t) => t.id === taskId)) return;

    if (state.active) {
      state.pendingTasks.push({ id: taskId, agentKey, fn });
      if (state.idleWaiting) {
        this.notifyClose(agentKey);
      }
      return;
    }

    if (this.activeCount >= this.config.maxConcurrent) {
      state.pendingTasks.push({ id: taskId, agentKey, fn });
      if (!this.waitingAgents.includes(agentKey)) {
        this.waitingAgents.push(agentKey);
      }
      return;
    }

    this.runTask(agentKey, { id: taskId, agentKey, fn }).catch(() => {});
  }

  notifyIdle(agentKey: string): void {
    const state = this.getAgent(agentKey);
    state.idleWaiting = true;
    if (state.pendingTasks.length > 0) {
      this.notifyClose(agentKey);
    }
  }

  notifyClose(agentKey: string): void {
    const state = this.getAgent(agentKey);
    if (!state.active) return;
    this.onClose?.(agentKey);
  }

  onClose: ((agentKey: string) => void) | null = null;

  isActive(agentKey: string): boolean {
    return this.getAgent(agentKey).active;
  }

  isIdle(agentKey: string): boolean {
    const state = this.getAgent(agentKey);
    return state.active && state.idleWaiting;
  }

  hasPending(agentKey: string): boolean {
    const state = this.getAgent(agentKey);
    return (
      state.pendingMessages.length > 0 || state.pendingTasks.length > 0
    );
  }

  get active(): number {
    return this.activeCount;
  }

  get isShutDown(): boolean {
    return this.shuttingDown;
  }

  get agentCount(): number {
    return this.agents.size;
  }

  cleanup(): void {
    for (const [key, state] of this.agents) {
      if (
        !state.active &&
        !state.retryScheduled &&
        state.pendingMessages.length === 0 &&
        state.pendingTasks.length === 0
      ) {
        this.agents.delete(key);
      }
    }
  }

  shutdown(): void {
    this.shuttingDown = true;
    for (const [, state] of this.agents) {
      for (const msg of state.pendingMessages) {
        msg.resolve("Queue is shutting down.");
      }
      state.pendingMessages = [];
      state.pendingTasks = [];
    }
    this.waitingAgents.length = 0;
  }

  // ── Private ──

  private getAgent(agentKey: string): AgentState {
    let state = this.agents.get(agentKey);
    if (!state) {
      state = {
        active: false,
        idleWaiting: false,
        isTask: false,
        runningTaskId: null,
        pendingMessages: [],
        pendingTasks: [],
        retryCount: 0,
        retryScheduled: false,
      };
      this.agents.set(agentKey, state);
    }
    return state;
  }

  private async runForAgent(agentKey: string): Promise<void> {
    const state = this.getAgent(agentKey);
    state.active = true;
    state.idleWaiting = false;
    state.isTask = false;
    this.activeCount++;

    const message = state.pendingMessages.shift();
    try {
      if (message && this.processMessageFn) {
        const success = await this.processMessageFn(agentKey, message);
        if (success) {
          state.retryCount = 0;
        } else {
          state.pendingMessages.unshift(message);
          this.scheduleRetry(agentKey, state);
        }
      } else if (message) {
        message.resolve("Error: no message processor configured.");
      }
    } catch {
      if (message) {
        state.pendingMessages.unshift(message);
      }
      this.scheduleRetry(agentKey, state);
    } finally {
      state.active = false;
      state.idleWaiting = false;
      this.activeCount--;
      this.drainAgent(agentKey);
    }
  }

  private async runTask(
    agentKey: string,
    task: QueuedTask,
  ): Promise<void> {
    const state = this.getAgent(agentKey);
    state.active = true;
    state.idleWaiting = false;
    state.isTask = true;
    state.runningTaskId = task.id;
    this.activeCount++;

    try {
      await task.fn();
    } catch {
      // Task error — logged by caller
    } finally {
      state.active = false;
      state.isTask = false;
      state.runningTaskId = null;
      state.idleWaiting = false;
      this.activeCount--;
      this.drainAgent(agentKey);
    }
  }

  private scheduleRetry(agentKey: string, state: AgentState): void {
    state.retryCount++;
    if (state.retryCount > MAX_RETRIES) {
      state.retryCount = 0;
      for (const msg of state.pendingMessages) {
        msg.resolve("Failed after maximum retries.");
      }
      state.pendingMessages = [];
      return;
    }

    state.retryScheduled = true;
    const delayMs = BASE_RETRY_MS * Math.pow(2, state.retryCount - 1);
    setTimeout(() => {
      state.retryScheduled = false;
      if (!this.shuttingDown && state.pendingMessages.length > 0) {
        this.runForAgent(agentKey).catch(() => {});
      }
    }, delayMs);
  }

  private drainAgent(agentKey: string): void {
    if (this.shuttingDown) return;

    const state = this.getAgent(agentKey);

    if (state.pendingTasks.length > 0) {
      const task = state.pendingTasks.shift()!;
      this.runTask(agentKey, task).catch(() => {});
      return;
    }

    if (state.pendingMessages.length > 0 && !state.retryScheduled) {
      this.runForAgent(agentKey).catch(() => {});
      return;
    }

    this.drainWaiting();
  }

  private drainWaiting(): void {
    while (
      this.waitingAgents.length > 0 &&
      this.activeCount < this.config.maxConcurrent
    ) {
      const nextKey = this.waitingAgents.shift()!;
      const state = this.getAgent(nextKey);

      if (state.pendingTasks.length > 0) {
        const task = state.pendingTasks.shift()!;
        this.runTask(nextKey, task).catch(() => {});
      } else if (state.pendingMessages.length > 0) {
        this.runForAgent(nextKey).catch(() => {});
      }
    }
  }
}

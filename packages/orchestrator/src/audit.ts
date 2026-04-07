import type Database from "better-sqlite3";

export interface AuditEntry {
  agent_id: string;
  user_id: string;
  platform: string;
  message_preview: string;
  result_preview: string;
  cost_usd: number;
  duration_ms: number;
  num_turns: number;
  is_error: boolean;
}

export function initAuditTable(db: Database.Database): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT NOT NULL DEFAULT (datetime('now')),
      agent_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      platform TEXT NOT NULL DEFAULT 'http',
      message_preview TEXT NOT NULL,
      result_preview TEXT NOT NULL DEFAULT '',
      cost_usd REAL NOT NULL DEFAULT 0,
      duration_ms INTEGER NOT NULL DEFAULT 0,
      num_turns INTEGER NOT NULL DEFAULT 0,
      is_error INTEGER NOT NULL DEFAULT 0
    )
  `);
}

export function logDispatch(db: Database.Database, entry: AuditEntry): number {
  const result = db.prepare(`
    INSERT INTO audit_log (agent_id, user_id, platform, message_preview, result_preview, cost_usd, duration_ms, num_turns, is_error)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    entry.agent_id,
    entry.user_id,
    entry.platform,
    entry.message_preview.slice(0, 500),
    entry.result_preview.slice(0, 500),
    entry.cost_usd,
    entry.duration_ms,
    entry.num_turns,
    entry.is_error ? 1 : 0,
  );
  return result.lastInsertRowid as number;
}

export function queryAuditLog(
  db: Database.Database,
  opts?: { agent_id?: string; limit?: number; offset?: number },
): Record<string, unknown>[] {
  const limit = opts?.limit ?? 50;
  const offset = opts?.offset ?? 0;

  if (opts?.agent_id) {
    return db
      .prepare("SELECT * FROM audit_log WHERE agent_id = ? ORDER BY id DESC LIMIT ? OFFSET ?")
      .all(opts.agent_id, limit, offset) as Record<string, unknown>[];
  }

  return db
    .prepare("SELECT * FROM audit_log ORDER BY id DESC LIMIT ? OFFSET ?")
    .all(limit, offset) as Record<string, unknown>[];
}

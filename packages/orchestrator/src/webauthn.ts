/**
 * WebAuthn / FIDO2 module
 * Handles passkey registration (FaceID, TouchID, YubiKey) and authentication.
 * Uses @simplewebauthn/server v11.
 */

import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import type Database from "better-sqlite3";

// RP (Relying Party) config — must match origin the browser sees
export const RP_NAME = "Datum Gateway";
export const RP_ID = process.env.WEBAUTHN_RP_ID ?? "apps.geofabnz.com";
export const RP_ORIGIN = process.env.WEBAUTHN_ORIGIN ?? "https://apps.geofabnz.com";

export type StoredCredential = {
  credentialId: string;        // base64url
  publicKey: string;           // base64url encoded public key
  counter: number;
  deviceType: string;          // "singleDevice" | "multiDevice"
  backedUp: boolean;
  transports: string;          // JSON array
  userId: string;
  name: string;                // human-readable label (e.g. "YubiKey 5")
  createdAt: number;           // unix ms
};

// ── Database init ──────────────────────────────────────────

export function initWebAuthnTables(db: Database.Database): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS webauthn_credentials (
      credential_id TEXT PRIMARY KEY,
      public_key    TEXT NOT NULL,
      counter       INTEGER NOT NULL DEFAULT 0,
      device_type   TEXT NOT NULL DEFAULT 'singleDevice',
      backed_up     INTEGER NOT NULL DEFAULT 0,
      transports    TEXT NOT NULL DEFAULT '[]',
      user_id       TEXT NOT NULL,
      name          TEXT NOT NULL DEFAULT 'Security Key',
      created_at    INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS webauthn_challenges (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id    TEXT NOT NULL,
      challenge  TEXT NOT NULL,
      type       TEXT NOT NULL,  -- 'register' | 'authenticate'
      created_at INTEGER NOT NULL
    );
  `);
}

// ── Challenge storage ──────────────────────────────────────

export function storeChallenge(
  db: Database.Database,
  userId: string,
  challenge: string,
  type: "register" | "authenticate"
): void {
  // Clean old challenges for this user
  db.prepare("DELETE FROM webauthn_challenges WHERE user_id = ? AND type = ?").run(userId, type);
  db.prepare(
    "INSERT INTO webauthn_challenges (user_id, challenge, type, created_at) VALUES (?, ?, ?, ?)"
  ).run(userId, challenge, type, Date.now());
}

export function getAndDeleteChallenge(
  db: Database.Database,
  userId: string,
  type: "register" | "authenticate"
): string | null {
  // Remove challenges older than 5 min
  db.prepare("DELETE FROM webauthn_challenges WHERE created_at < ?").run(Date.now() - 5 * 60 * 1000);

  const row = db
    .prepare("SELECT challenge FROM webauthn_challenges WHERE user_id = ? AND type = ? ORDER BY created_at DESC LIMIT 1")
    .get(userId, type) as { challenge: string } | undefined;

  if (!row) return null;
  db.prepare("DELETE FROM webauthn_challenges WHERE user_id = ? AND type = ?").run(userId, type);
  return row.challenge;
}

// ── Credential storage ─────────────────────────────────────

export function storeCredential(
  db: Database.Database,
  cred: StoredCredential
): void {
  db.prepare(`
    INSERT OR REPLACE INTO webauthn_credentials
    (credential_id, public_key, counter, device_type, backed_up, transports, user_id, name, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    cred.credentialId,
    cred.publicKey,
    cred.counter,
    cred.deviceType,
    cred.backedUp ? 1 : 0,
    cred.transports,
    cred.userId,
    cred.name,
    cred.createdAt,
  );
}

export function getCredential(
  db: Database.Database,
  credentialId: string
): StoredCredential | null {
  const row = db
    .prepare("SELECT * FROM webauthn_credentials WHERE credential_id = ?")
    .get(credentialId) as Record<string, unknown> | undefined;
  if (!row) return null;
  return {
    credentialId: row.credential_id as string,
    publicKey: row.public_key as string,
    counter: row.counter as number,
    deviceType: row.device_type as string,
    backedUp: Boolean(row.backed_up),
    transports: row.transports as string,
    userId: row.user_id as string,
    name: row.name as string,
    createdAt: row.created_at as number,
  };
}

export function updateCredentialCounter(
  db: Database.Database,
  credentialId: string,
  counter: number
): void {
  db.prepare("UPDATE webauthn_credentials SET counter = ? WHERE credential_id = ?").run(counter, credentialId);
}

export function getUserCredentials(
  db: Database.Database,
  userId: string
): StoredCredential[] {
  const rows = db
    .prepare("SELECT * FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at DESC")
    .all(userId) as Record<string, unknown>[];
  return rows.map((row) => ({
    credentialId: row.credential_id as string,
    publicKey: row.public_key as string,
    counter: row.counter as number,
    deviceType: row.device_type as string,
    backedUp: Boolean(row.backed_up),
    transports: row.transports as string,
    userId: row.user_id as string,
    name: row.name as string,
    createdAt: row.created_at as number,
  }));
}

export function deleteCredential(
  db: Database.Database,
  credentialId: string,
  userId: string
): boolean {
  const result = db
    .prepare("DELETE FROM webauthn_credentials WHERE credential_id = ? AND user_id = ?")
    .run(credentialId, userId);
  return result.changes > 0;
}

// ── Registration ───────────────────────────────────────────

export async function beginRegistration(
  db: Database.Database,
  userId: string,
  userName: string
) {
  const existingCreds = getUserCredentials(db, userId);
  const excludeCredentials = existingCreds.map((c) => ({
    id: c.credentialId,
    transports: JSON.parse(c.transports) as AuthenticatorTransport[],
  }));

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userName,
    userDisplayName: userName,
    attestationType: "none",
    excludeCredentials,
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "preferred",
    },
    supportedAlgorithmIDs: [-7, -257], // ES256, RS256
  });

  storeChallenge(db, userId, options.challenge, "register");
  return options;
}

export async function completeRegistration(
  db: Database.Database,
  userId: string,
  response: unknown,
  deviceName: string
): Promise<{ success: boolean; credentialId?: string; error?: string }> {
  const expectedChallenge = getAndDeleteChallenge(db, userId, "register");
  if (!expectedChallenge) {
    return { success: false, error: "No pending registration challenge" };
  }

  let verification: Awaited<ReturnType<typeof verifyRegistrationResponse>>;
  try {
    verification = await verifyRegistrationResponse({
      response: response as Parameters<typeof verifyRegistrationResponse>[0]["response"],
      expectedChallenge,
      expectedOrigin: RP_ORIGIN,
      expectedRPID: RP_ID,
      requireUserVerification: false,
    });
  } catch (err) {
    return { success: false, error: (err as Error).message };
  }

  if (!verification.verified || !verification.registrationInfo) {
    return { success: false, error: "Registration verification failed" };
  }

  const info = verification.registrationInfo;
  const credentialIdB64 = Buffer.from(info.credential.id).toString("base64url");
  const publicKeyB64 = Buffer.from(info.credential.publicKey).toString("base64url");

  storeCredential(db, {
    credentialId: credentialIdB64,
    publicKey: publicKeyB64,
    counter: info.credential.counter,
    deviceType: info.credentialDeviceType,
    backedUp: info.credentialBackedUp,
    transports: JSON.stringify(info.credential.transports ?? []),
    userId,
    name: deviceName,
    createdAt: Date.now(),
  });

  return { success: true, credentialId: credentialIdB64 };
}

// ── Authentication ─────────────────────────────────────────

export async function beginAuthentication(
  db: Database.Database,
  userId: string
) {
  const credentials = getUserCredentials(db, userId);
  const allowCredentials = credentials.map((c) => ({
    id: c.credentialId,
    transports: JSON.parse(c.transports) as AuthenticatorTransport[],
  }));

  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    allowCredentials,
    userVerification: "preferred",
  });

  storeChallenge(db, userId, options.challenge, "authenticate");
  return options;
}

export async function completeAuthentication(
  db: Database.Database,
  userId: string,
  response: unknown
): Promise<{ success: boolean; credentialId?: string; error?: string }> {
  const expectedChallenge = getAndDeleteChallenge(db, userId, "authenticate");
  if (!expectedChallenge) {
    return { success: false, error: "No pending authentication challenge" };
  }

  // Find the credential being used
  const responseObj = response as { id?: string; rawId?: string };
  const credentialId = responseObj.id ?? responseObj.rawId;
  if (!credentialId) {
    return { success: false, error: "Missing credential ID" };
  }

  const stored = getCredential(db, credentialId);
  if (!stored || stored.userId !== userId) {
    return { success: false, error: "Credential not found or user mismatch" };
  }

  try {
    const result = await verifyAuthenticationResponse({
      response: response as Parameters<typeof verifyAuthenticationResponse>[0]["response"],
      expectedChallenge,
      expectedOrigin: RP_ORIGIN,
      expectedRPID: RP_ID,
      requireUserVerification: false,
      credential: {
        id: stored.credentialId,
        publicKey: Buffer.from(stored.publicKey, "base64url"),
        counter: stored.counter,
        transports: JSON.parse(stored.transports) as AuthenticatorTransport[],
      },
    });

    if (!result.verified) {
      return { success: false, error: "Authentication verification failed" };
    }

    updateCredentialCounter(db, stored.credentialId, result.authenticationInfo.newCounter);
    return { success: true, credentialId: stored.credentialId };
  } catch (err) {
    return { success: false, error: (err as Error).message };
  }
}

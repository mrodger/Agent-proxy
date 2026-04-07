/**
 * 2FA Authentication Module
 * TOTP, JWT session tokens, Gmail approval email via googleapis
 */

import speakeasy from "speakeasy";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import QRCode from "qrcode";
import { google } from "googleapis";

const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString("hex");
const JWT_EXPIRY = "8h";

// Gmail via googleapis (lazy-init)
let _gmailClient: ReturnType<typeof google.gmail> | null = null;

function getGmail() {
  if (_gmailClient) return _gmailClient;
  const clientId = process.env.GMAIL_CLIENT_ID;
  const clientSecret = process.env.GMAIL_CLIENT_SECRET;
  const refreshToken = process.env.GMAIL_REFRESH_TOKEN;
  if (!clientId || !clientSecret || !refreshToken) return null;

  const auth = new google.auth.OAuth2(clientId, clientSecret);
  auth.setCredentials({ refresh_token: refreshToken });

  _gmailClient = google.gmail({ version: "v1", auth });
  return _gmailClient;
}

export function verify2FA(secret: string, code: string): boolean {
  try {
    return speakeasy.totp.verify({ secret, encoding: "base32", token: code, window: 1 }) === true;
  } catch (error) {
    console.error("[auth] TOTP verification error:", error);
    return false;
  }
}

export async function generate2FASecret(label: string): Promise<{secret: string; otpauth_url: string; qr_code_url: string}> {
  const secret = speakeasy.generateSecret({ name: label, issuer: "Stockade/Datum", length: 32 });
  if (!secret.base32) throw new Error("Failed to generate 2FA secret");
  const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url || "");
  return { secret: secret.base32, otpauth_url: secret.otpauth_url || "", qr_code_url: qrCodeUrl };
}

export function generateAuthCode(): string {
  return crypto.randomBytes(3).toString("hex").toUpperCase();
}

export function generateSessionToken(userId: string): {token: string; expires_at: number} {
  const payload = { userId, iat: Math.floor(Date.now() / 1000) };
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRY });
  const decoded = jwt.decode(token) as any;
  return { token, expires_at: decoded?.exp || 0 };
}

export function verifySessionToken(token: string): {valid: boolean; userId?: string; expires_at?: number; error?: string} {
  try {
    const decoded = jwt.verify(token, JWT_SECRET) as any;
    return { valid: true, userId: decoded.userId, expires_at: decoded.exp };
  } catch (error) {
    return { valid: false, error: (error as Error).message };
  }
}

export function generateBackupCodes(count: number = 10): string[] {
  return Array.from({ length: count }, () => crypto.randomBytes(4).toString("hex").toUpperCase().substring(0, 8));
}

export function isVM102(remoteAddress: string): boolean {
  return remoteAddress === "192.168.88.102" || remoteAddress === "127.0.0.1";
}

export async function sendApprovalEmail(email: string, code: string, approveUrl: string): Promise<boolean> {
  const gmail = getGmail();
  if (!gmail) {
    console.log("[auth-email] No Gmail config — code:", code, "url:", approveUrl);
    return false;
  }

  const from = process.env.GMAIL_FROM ?? "marcus@geofabnz.com";
  const htmlBody = `
    <div style="font-family:sans-serif;max-width:480px;margin:auto;padding:24px">
      <h2 style="color:#1d3a5c;margin:0 0 12px">Datum login request</h2>
      <p>Someone is requesting access to Datum Gateway.</p>
      <p style="text-align:center;margin:24px 0">
        <a href="${approveUrl}" style="background:#c89632;color:#fff;padding:12px 28px;border-radius:6px;text-decoration:none;font-weight:600">Approve Login</a>
      </p>
      <p style="color:#888;font-size:.85rem">Or enter this code: <strong>${code}</strong></p>
      <p style="color:#aaa;font-size:.8rem">This link expires in 10 minutes. If you did not request this, ignore this email.</p>
    </div>
  `;

  // Build RFC 2822 message
  const message = [
    `From: "Datum Gateway" <${from}>`,
    `To: ${email}`,
    `Subject: Datum login request`,
    `MIME-Version: 1.0`,
    `Content-Type: text/html; charset=utf-8`,
    ``,
    htmlBody,
  ].join("\r\n");

  const encoded = Buffer.from(message).toString("base64url");

  try {
    await gmail.users.messages.send({ userId: "me", requestBody: { raw: encoded } });
    console.log("[auth-email] Approval email sent to", email);
    return true;
  } catch (err) {
    console.error("[auth-email] Send failed:", (err as Error).message);
    return false;
  }
}

export function logAuthEvent(event: string, details?: Record<string, unknown>): void {
  const timestamp = new Date().toISOString();
  console.log("[auth-audit]", JSON.stringify({ timestamp, event, ...details }));
}

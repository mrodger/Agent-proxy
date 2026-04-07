import { consumeRef } from "../gateway/refs.js";
import { validateToken } from "../gateway/tokens.js";
import { resolveCredential } from "../shared/credentials.js";
import type { Provider } from "../shared/types.js";

const REF_PATTERN = /apw-ref:[A-Za-z0-9][A-Za-z0-9/_.-]+:[0-9a-f]{32}/g;
const BINARY_CONTENT_TYPES = /^(image|video|audio|application\/octet-stream|application\/zip|application\/gzip)/;

export interface RewriteResult {
  body: Buffer;
  replaced: boolean;
}

/**
 * Scan a request body for apw-ref tokens and replace with real credentials.
 * One-time-use, scope-validated. Skips binary content.
 */
export async function rewriteBody(
  body: Buffer,
  contentType: string,
  provider: Provider,
): Promise<RewriteResult> {
  if (body.length === 0) return { body, replaced: false };
  if (BINARY_CONTENT_TYPES.test(contentType)) return { body, replaced: false };

  const text = body.toString("utf-8");
  const matches = text.match(REF_PATTERN);
  if (!matches) return { body, replaced: false };

  const uniqueRefs = [...new Set(matches)];
  let result = text;
  let anyReplaced = false;

  for (const refStr of uniqueRefs) {
    const ref = consumeRef(refStr);
    if (!ref) {
      console.warn(`[body-rewriter] invalid/expired/consumed ref: ${refStr.slice(0, 40)}...`);
      continue;
    }

    if (!validateToken(ref.gatewayToken)) {
      console.warn(`[body-rewriter] gateway token revoked for ref: ${refStr.slice(0, 40)}...`);
      continue;
    }

    const value = await resolveCredential(provider, ref.credentialKey);
    result = replaceAll(result, refStr, value);
    anyReplaced = true;
  }

  if (!anyReplaced) return { body, replaced: false };
  return { body: Buffer.from(result, "utf-8"), replaced: true };
}

/** Safe literal string replacement (avoids regex special char issues). */
function replaceAll(source: string, search: string, replacement: string): string {
  let result = "";
  let pos = 0;
  while (true) {
    const idx = source.indexOf(search, pos);
    if (idx === -1) {
      result += source.slice(pos);
      break;
    }
    result += source.slice(pos, idx) + replacement;
    pos = idx + search.length;
  }
  return result;
}

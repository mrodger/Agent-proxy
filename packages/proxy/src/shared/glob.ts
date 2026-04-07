/**
 * Shared glob matching utility.
 * Consolidates the 4 duplicate implementations from Stockade (R-3 fix).
 * Caches compiled patterns for performance (R-2 fix).
 */

const patternCache = new Map<string, RegExp>();

export function globMatch(pattern: string, value: string): boolean {
  if (pattern === "*") return true;

  let regex = patternCache.get(pattern);
  if (!regex) {
    const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
    const regexStr = "^" + escaped.replace(/\*/g, "[^]*") + "$";
    regex = new RegExp(regexStr);
    patternCache.set(pattern, regex);
  }
  return regex.test(value);
}

export function clearPatternCache(): void {
  patternCache.clear();
}

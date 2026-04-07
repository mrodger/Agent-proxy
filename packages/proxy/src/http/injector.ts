import type { HttpRoute } from "../shared/types.js";
import { globMatch } from "../shared/glob.js";

/**
 * Strip sensitive headers from a request.
 */
export function stripHeaders(
  headers: Record<string, string>,
  stripList: string[]
): Record<string, string> {
  const lowerList = new Set(stripList.map((h) => h.toLowerCase()));
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (!lowerList.has(key.toLowerCase())) {
      result[key] = value;
    }
  }
  return result;
}

/**
 * Inject a resolved credential value into headers.
 */
export function injectCredential(
  headers: Record<string, string>,
  route: HttpRoute,
  resolvedValue: string
): Record<string, string> {
  const formatted = route.inject.format
    ? route.inject.format.replace(/\{value\}/g, resolvedValue)
    : resolvedValue;

  return {
    ...headers,
    [route.inject.header]: formatted,
  };
}

/**
 * Find the first matching HTTP route for a given host.
 */
export function matchRoute(
  routes: HttpRoute[],
  host: string,
  path?: string,
  method?: string
): HttpRoute | undefined {
  return routes.find((route) => {
    if (!globMatch(route.host, host)) return false;
    if (route.path !== undefined && path !== undefined) {
      if (!globMatch(route.path, path)) return false;
    }
    if (route.method !== undefined && method !== undefined) {
      if (route.method !== "*" && route.method.toUpperCase() !== method.toUpperCase()) {
        return false;
      }
    }
    return true;
  });
}

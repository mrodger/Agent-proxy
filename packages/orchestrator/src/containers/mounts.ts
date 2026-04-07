import { realpathSync } from "node:fs";
import { resolve, basename, relative, isAbsolute } from "node:path";
import { homedir } from "node:os";

const DEFAULT_BLOCKED_PATTERNS = [
  ".ssh",
  ".gnupg",
  ".gpg",
  ".aws",
  ".azure",
  ".gcloud",
  ".kube",
  ".docker",
  "credentials",
  ".env",
  ".netrc",
  ".npmrc",
  ".pypirc",
  "id_rsa",
  "id_ed25519",
  "private_key",
  ".secret",
];

// ── Types ──

export interface MountAllowlist {
  allowedRoots: AllowedRoot[];
  blockedPatterns: string[];
  nonMainReadOnly: boolean;
}

export interface AllowedRoot {
  path: string;
  allowReadWrite: boolean;
  description?: string;
}

export interface MountRequest {
  hostPath: string;
  containerPath?: string;
  readonly?: boolean;
}

export interface MountValidationResult {
  allowed: boolean;
  reason: string;
  realHostPath?: string;
  resolvedContainerPath?: string;
  effectiveReadonly?: boolean;
}

export interface ValidatedMount {
  hostPath: string;
  containerPath: string;
  readonly: boolean;
}

// ── Helpers ──

export function expandPath(p: string): string {
  const home = process.env.HOME || homedir();
  if (p === "~") return home;
  if (p.startsWith("~/") || p.startsWith("~\\")) {
    return resolve(home, p.slice(2));
  }
  return resolve(p);
}

function getRealPath(p: string): string | null {
  try {
    return realpathSync(p);
  } catch {
    return null;
  }
}

export function matchesBlockedPattern(
  realPath: string,
  blockedPatterns: string[],
): string | null {
  const normalized = realPath.replace(/\\/g, "/");
  const parts = normalized.split("/");

  for (const pattern of blockedPatterns) {
    for (const part of parts) {
      if (part === pattern || part.includes(pattern)) {
        return pattern;
      }
    }
  }
  return null;
}

function findAllowedRoot(
  realPath: string,
  allowedRoots: AllowedRoot[],
): AllowedRoot | null {
  for (const root of allowedRoots) {
    const expandedRoot = expandPath(root.path);
    const realRoot = getRealPath(expandedRoot);
    if (realRoot === null) continue;

    const rel = relative(realRoot, realPath);
    if (!rel.startsWith("..") && !isAbsolute(rel)) {
      return root;
    }
  }
  return null;
}

function isValidContainerPath(containerPath: string): boolean {
  if (containerPath.includes("..")) return false;
  if (containerPath.startsWith("/")) return false;
  if (!containerPath || containerPath.trim() === "") return false;
  return true;
}

export function mergeBlockedPatterns(extra: string[]): string[] {
  return [...new Set([...DEFAULT_BLOCKED_PATTERNS, ...extra])];
}

// ── Validation ──

export function validateMount(
  mount: MountRequest,
  allowlist: MountAllowlist,
  isPrivileged: boolean,
): MountValidationResult {
  const containerPath = mount.containerPath || basename(mount.hostPath);

  if (!isValidContainerPath(containerPath)) {
    return {
      allowed: false,
      reason: `Invalid container path: "${containerPath}"`,
    };
  }

  const expandedPath = expandPath(mount.hostPath);
  const realPath = getRealPath(expandedPath);

  if (realPath === null) {
    return {
      allowed: false,
      reason: `Host path does not exist: "${mount.hostPath}"`,
    };
  }

  const allBlocked = mergeBlockedPatterns(allowlist.blockedPatterns);
  const blockedMatch = matchesBlockedPattern(realPath, allBlocked);
  if (blockedMatch !== null) {
    return {
      allowed: false,
      reason: `Path matches blocked pattern "${blockedMatch}": "${realPath}"`,
    };
  }

  const allowedRoot = findAllowedRoot(realPath, allowlist.allowedRoots);
  if (allowedRoot === null) {
    return {
      allowed: false,
      reason: `Path "${realPath}" is not under any allowed root`,
    };
  }

  const requestedReadWrite = mount.readonly === false;
  let effectiveReadonly = true;

  if (requestedReadWrite) {
    if (!isPrivileged && allowlist.nonMainReadOnly) {
      effectiveReadonly = true;
    } else if (!allowedRoot.allowReadWrite) {
      effectiveReadonly = true;
    } else {
      effectiveReadonly = false;
    }
  }

  return {
    allowed: true,
    reason: `Allowed under root "${allowedRoot.path}"`,
    realHostPath: realPath,
    resolvedContainerPath: containerPath,
    effectiveReadonly,
  };
}

export function validateAdditionalMounts(
  mounts: MountRequest[],
  allowlist: MountAllowlist,
  isPrivileged: boolean,
  onRejected?: (mount: MountRequest, reason: string) => void,
): ValidatedMount[] {
  const validated: ValidatedMount[] = [];

  for (const mount of mounts) {
    const result = validateMount(mount, allowlist, isPrivileged);

    if (result.allowed) {
      validated.push({
        hostPath: result.realHostPath!,
        containerPath: `/workspace/extra/${result.resolvedContainerPath}`,
        readonly: result.effectiveReadonly!,
      });
    } else {
      onRejected?.(mount, result.reason);
    }
  }

  return validated;
}

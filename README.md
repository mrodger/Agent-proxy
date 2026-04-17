# agent-proxy

A credential proxy and deterministic permission engine for multi-agent Claude deployments.

Prevents prompt injection from reaching API keys or the host container runtime. Built and pen-tested as part of the Datum multi-agent platform.

**Status:** Working implementation. Source code being extracted from the Datum monorepo. Architecture documentation and design rationale are complete.

---

## The Problem

When you run Claude agents autonomously — writing code, browsing the web, calling tools — the agent needs credentials to do its job. The standard approach is to mount credentials into the container or pass them as environment variables. This creates a straightforward attack surface:

1. A malicious payload in a web page, code file, or API response instructs the agent to exfiltrate credentials
2. The agent, following instructions, reads its own environment variables and sends them somewhere
3. Your API keys are gone

This is not theoretical. It is the expected behaviour of an instruction-following agent encountering adversarial content. The attack requires no code execution, no container escape — just a sufficiently persuasive string in the agent's context.

The secondary problem: if your agents *can* spin up containers (Docker-in-Docker), a compromised agent that gains access to the host Docker socket can escape isolation entirely.

---

## The Solution

Two components, working together:

### 1. Credential Proxy

Agents never hold credentials. Instead:

- Each agent receives a **short-lived reference token** scoped to specific API routes
- When the agent makes an API call, it presents the reference token
- The proxy intercepts the request, substitutes the real credential, strips the reference token from the outgoing request, and forwards it
- The agent's context never contains a real API key — only a one-time-use reference that expires

Key properties:
- **Reference tokens are one-time-use** — a compromised token can't be replayed
- **Scoped to routes** — a token issued for the Anthropic inference API cannot be used to call the billing API
- **Revocation** — tokens can be revoked immediately; the agent's next request fails cleanly
- **MITM TLS** — the proxy intercepts HTTPS traffic transparently; agents don't need to know the proxy exists

The proxy also enforces **network policy**: each agent has a deny-by-default allowlist of permitted domains. An agent configured for code review cannot reach social media APIs. An agent configured for web research cannot reach your internal services.

### 2. Deterministic Permission Engine

LLM-based permission checks are advisory only. The deterministic engine runs *before* any LLM involvement and cannot be overridden by the model.

Rules are defined in YAML per agent:

```yaml
# agents/developer.yaml
permissions:
  allow:
    - "Bash(git *)"
    - "Bash(npm *)"
    - "Read(**)"
    - "Write(src/**)"
  deny:
    - "Bash(rm -rf *)"
    - "Bash(sudo *)"
    - "Write(.claude/**)"
    - "Write(~/.ssh/**)"
```

**The invariant:** an LLM operating within this system can only restrict permissions further. It cannot grant itself permissions it was not configured with. The deny rules are enforced by the SDK's `PreToolUse` hook before the model's reasoning ever executes.

Tested behaviours (from pen test):
- `ls /tmp` — allowed (as configured)
- `rm -rf /` — denied, never reaches the model
- `sudo apt install` — denied
- Writing to `.claude/**` — denied
- `git status` — allowed

---

## Architecture

```
 ┌─────────────────────────────────────────────────────┐
 │                   Orchestrator                       │
 │  - Issues reference tokens per agent per session    │
 │  - Routes requests to correct worker                │
 │  - Enforces RBAC (which agents can talk to whom)    │
 │  - Audit trail: every tool call, every token event  │
 └────────────────────┬────────────────────────────────┘
                      │ X-Gateway-Secret (bearer)
                      │ bound to 127.0.0.1 only
                      ▼
 ┌─────────────────────────────────────────────────────┐
 │                 Credential Proxy                     │
 │  - Accepts apw-ref: <token> in request body         │
 │  - Validates token (scope, expiry, one-time-use)    │
 │  - Substitutes real credential                      │
 │  - Strips reference from outgoing request           │
 │  - Enforces network policy (deny-by-default)        │
 │  - Bounded cert cache (1000 entries, FIFO evict)    │
 └────────────────────┬────────────────────────────────┘
                      │
          ┌───────────┼───────────┐
          ▼           ▼           ▼
   ┌─────────┐  ┌──────────┐  ┌──────────┐
   │developer│  │researcher│  │ designer │
   │ worker  │  │  worker  │  │  worker  │
   │         │  │          │  │          │
   │ uid=999 │  │  uid=999 │  │  uid=999 │
   │ gVisor  │  │  gVisor  │  │  gVisor  │
   └─────────┘  └──────────┘  └──────────┘
   (datum-internal network — no external egress)
```

Each worker container:
- Runs as non-root user (uid=999)
- Has its own unique `WORKER_SECRET` — cross-worker requests return 401
- Runs under gVisor (`runtime: runsc`) — syscall sandboxing at the kernel level
- Has no access to the host Docker socket
- Holds no credentials — only a reference token valid for the current session

---

## What Was Found in the Pen Test

Initial pen test result: **FAIL** — 3 Critical, 2 High, 3 Medium findings.

| Severity | Finding | Resolution |
|----------|---------|-----------|
| Critical | Gateway exposed on 0.0.0.0 — any container could call it | Bound to 127.0.0.1; bearer auth added |
| Critical | Credentials mount included refresh token and full scope | Minimal mount: access token only, inference scope only |
| Critical | Workers on host network — no egress restriction | Internal Docker network; no external egress |
| High | Single shared WORKER_SECRET — cross-worker requests possible | Per-worker unique secrets; 401 verified on wrong secret |
| High | Gateway bypassed dispatcher security on some routes | All routes now route through buildPermissionHook |
| Medium | Workers running as root | Non-root uid=999 |
| Medium | Cert cache unbounded — memory exhaustion possible | FIFO eviction at 1000 entries |
| Medium | Body size unlimited — DoS possible | Hard limit enforced at proxy ingress |

Post-fix re-test: **Conditional Pass**. All P0/P1/P2 findings resolved.

---

## What This Is Not

This is not a general-purpose API gateway. It is not a WAF. It is not a replacement for proper secrets management in production infrastructure.

It is a targeted solution to one specific problem: **preventing autonomous agents from exfiltrating credentials via prompt injection**, while keeping the agent runtime fully functional.

The security properties hold within the defined threat model. A sufficiently motivated attacker with physical access to the host, or the ability to modify the proxy itself, can defeat these controls. That is out of scope.

---

## Implementation

**Stack:** TypeScript, Node 22, Docker, gVisor

**Packages (Datum monorepo, being extracted):**
- `packages/proxy` — credential proxy, token lifecycle, network policy engine (~800 lines)
- `packages/orchestrator` — gateway, RBAC, dispatcher, audit trail (~1,200 lines)
- `packages/worker` — agent runner, permission enforcement, SSE streaming (~600 lines)

**Tests:** 34 total (24 unit, 10 integration) on the proxy package alone. 91 tests across the full orchestrator.

Source code will be added to `src/` once extracted from the development environment. The architecture documentation above is complete and accurate as of the implementation date.

---

## Background

Built as part of the Datum platform — a homelab multi-agent orchestration system running on a Proxmox VM cluster. The containment architecture was derived from a study of Stockade (a multi-agent Claude orchestrator), redesigned around the specific threat model of autonomous Claude Code agents.

---

*Implementation date: March–April 2026*
*Pen test date: 2026-03-30*
*Platform: Datum, homelab VM 105 (isolated testbed)*

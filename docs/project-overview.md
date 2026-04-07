# Datum Agent Proxy — Project Overview

**As of:** 5 April 2026
**Author:** Marcus
**Status:** Working implementation on isolated homelab testbed (VM 105). Source extraction in progress.

---

## What It Is

A credential proxy and permission enforcement layer for multi-agent Claude deployments. Prevents prompt injection from reaching API keys or the host container runtime.

Built as one component of Datum — a custom multi-agent orchestration platform running on a home server.

---

## The Core Problem It Solves

Autonomous agents need API credentials to function. If you give an agent direct access to credentials (environment variables, mounted files), and that agent processes adversarial content — a web page, a code file, an API response — the agent can be instructed to send those credentials elsewhere. No code execution required. Just a string in context.

The secondary risk: agents with Docker access and a mounted host socket can escape their container. This is a real attack path, not a hypothetical.

---

## What Was Built

**Credential Proxy**
- Agents hold reference tokens, not real API keys
- Reference tokens are one-time-use, scoped to specific API routes, short-lived
- Proxy intercepts outbound requests, substitutes the real credential, strips the reference
- Agent context is clean — exfiltrating it yields nothing usable
- Network policy: deny-by-default per agent; agents can only reach domains explicitly allowed for their role

**Deterministic Permission Engine**
- Per-agent allow/deny rules defined in YAML
- Enforced via SDK `PreToolUse` hook before any model reasoning
- Invariant: the LLM can only restrict its own permissions, never expand them
- Tested: `rm -rf` denied, `sudo` denied, writes to `.ssh/` and `.claude/` denied; `git status`, `npm install` allowed

**Container Isolation**
- Each agent runs in its own container: non-root user (uid=999), gVisor kernel sandbox (`runtime: runsc`), unique `WORKER_SECRET`
- Docker-in-Docker (Sysbox) tested separately — inner Docker has no access to host socket
- Workers on an internal network with no external egress; only the proxy can reach the internet on their behalf

**Pen Test**
Conducted 30 March 2026. Initial result: Fail (3 Critical, 2 High, 3 Medium). All Critical and High findings resolved and re-verified. Conditional pass.

Critical findings resolved:
- Gateway was reachable from any container — restricted to 127.0.0.1 with bearer auth
- Credentials mount included refresh token — stripped to access token, inference scope only
- Workers had unrestricted internet access — isolated to internal Docker network

---

## Scale and Scope

This is homelab infrastructure, not a production deployment. The full platform runs 3 agent workers (developer, designer, researcher) plus orchestrator and proxy, on a single VM with 34 passing integration tests. It handles real tasks — it was used to build most of itself — but it has not been load-tested and has not seen multi-user traffic.

The value is in the architecture and the threat model, not the scale.

---

## What It Is Not

Not a general-purpose API gateway. Not designed for high-throughput production use without further hardening. The security properties hold within the documented threat model — a compromised host or a modified proxy defeats them.

---

## Relevance to Spatial / Geodesy Workflows

The Datum platform includes a GIS demonstration pipeline: an agent is given a species occurrence specification, autonomously loads PostGIS, builds a FastAPI mapping application with Leaflet, runs a peer security audit (as a separate agent), applies the findings, and redeploys — approximately 10 minutes end-to-end, no human code authorship.

The credential proxy and permission enforcement layer is what makes that kind of autonomous workflow safe to run against real infrastructure. Without it, the agent processing arbitrary spatial data (GeoJSON from external APIs, WFS responses, user-submitted geometries) is a credential exfiltration risk.

---

## Current State

- Architecture complete and pen-tested
- Source code on isolated testbed (VM 105) — extraction to standalone repo in progress
- README and architecture documentation at [github.com/mrodger/agent-proxy] (being set up)
- GIS demo video available on request

---

*Marcus — April 2026*
*homelab: Proxmox, Ubuntu VMs, Docker, gVisor*
*platform: Datum (custom multi-agent orchestration)*

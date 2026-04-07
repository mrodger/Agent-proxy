FROM node:22-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends     git     ca-certificates     python3     python3-pip     python3-venv     curl     && rm -rf /var/lib/apt/lists/*

# Python MCP deps (Google Workspace MCP server)
RUN python3 -m pip install --break-system-packages     mcp requests google-api-python-client google-auth

COPY package.json ./
RUN npm install --omit=dev

COPY dist/ ./dist/

# M-1 fix: run as non-root user
RUN groupadd -r worker && useradd -r -g worker -d /home/worker -m worker
RUN mkdir -p /home/worker/.claude && chown -R worker:worker /home/worker
RUN mkdir -p /workspace && chown worker:worker /workspace

USER worker

ENV NODE_ENV=production
ENV PORT=3001
ENV HOME=/home/worker

EXPOSE 3001

HEALTHCHECK --interval=30s --timeout=5s --retries=3   CMD node -e "fetch('http://localhost:3001/health').then(r => r.ok ? process.exit(0) : process.exit(1)).catch(() => process.exit(1))"

CMD ["node", "dist/index.js"]

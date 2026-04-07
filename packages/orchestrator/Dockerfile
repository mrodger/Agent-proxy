FROM node:22-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    make \
    g++ \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY package.json ./
RUN npm install --omit=dev

COPY dist/ ./dist/
COPY public/ ./public/

RUN groupadd -r gateway && useradd -r -g gateway -d /home/gateway -m gateway
RUN mkdir -p /data && chown gateway:gateway /data

USER gateway

ENV NODE_ENV=production
ENV GATEWAY_PORT=8095

EXPOSE 8095

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD node -e "fetch('http://localhost:8095/health').then(r => r.ok ? process.exit(0) : process.exit(1)).catch(() => process.exit(1))"

CMD ["node", "dist/gateway.js"]

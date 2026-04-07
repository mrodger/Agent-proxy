FROM node:22-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY package.json ./
RUN npm install --omit=dev

COPY dist/ ./dist/

ENV NODE_ENV=production
ENV CONFIG_DIR=/config

EXPOSE 10255 10256

CMD ["node", "dist/index.js"]

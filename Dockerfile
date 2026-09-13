# Glama MCP introspection (https://glama.ai/mcp/servers)
# Builds from source (dist/ is gitignored). Stdio only — no ports.
#
# Paste this file into Glama's Dockerfile admin field if the crawler
# does not auto-detect the repo Dockerfile.

FROM node:22-slim

WORKDIR /app

COPY package.json package-lock.json tsconfig.json ./
COPY src ./src
COPY bin ./bin
COPY README.md LICENSE ./

RUN npm ci --no-audit --no-fund \
  && npm run build \
  && npm prune --omit=dev \
  && npm cache clean --force

ENV NODE_ENV=production

# Official node image includes a non-root `node` user (uid 1000).
# Audit ledger defaults to $PWD/data — only that directory needs write.
RUN mkdir -p /app/data && chown node:node /app/data
USER node

CMD ["node", "dist/index.js"]

# Threatready container image. One image, two roles (THREATREADY_ROLE=api | worker), ARM64-friendly (ECS Fargate Graviton).
# Untested on this build machine (Docker is not installed); CI builds it on every push.

FROM node:26.10.0-bookworm-slim AS build
WORKDIR /src
COPY package.json package-lock.json ./
COPY packages/contracts/package.json packages/contracts/
COPY apps/api/package.json apps/api/
COPY apps/web/package.json apps/web/
RUN npm ci --no-audit --no-fund
COPY packages/contracts packages/contracts
COPY apps/api apps/api
COPY apps/web apps/web
RUN npm run build && npm prune --omit=dev --no-audit --no-fund

FROM node:26.10.0-bookworm-slim AS runtime
ENV NODE_ENV=production \
    THREATREADY_ENV=production \
    THREATREADY_HOST=0.0.0.0 \
    THREATREADY_PORT=8000 \
    THREATREADY_ROLE=api \
    THREATREADY_LAB_DATA_DIR=/data/labs \
    THREATREADY_FRONTEND_DIST=/app/apps/web/dist
WORKDIR /app
COPY --from=build /src/package.json ./
COPY --from=build /src/node_modules ./node_modules
COPY --from=build /src/packages/contracts/package.json packages/contracts/
COPY --from=build /src/packages/contracts/dist packages/contracts/dist
COPY --from=build /src/apps/api/package.json apps/api/
COPY --from=build /src/apps/api/dist apps/api/dist
COPY --from=build /src/apps/api/migrations apps/api/migrations
COPY --from=build /src/apps/web/dist apps/web/dist
RUN mkdir -p /data/labs && chown -R node:node /data
USER node
WORKDIR /app/apps/api
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD node -e "fetch('http://127.0.0.1:8000/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))" || exit 1
# Migrations run as a one-off task before a deploy: node dist/cli.js migrate
CMD ["node", "--enable-source-maps", "dist/main.js"]

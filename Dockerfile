FROM node:22-bookworm-slim AS builder
LABEL version="0.0.1"
LABEL x-release-please-version="5.4.4"

RUN corepack enable && corepack prepare pnpm@10.33.0 --activate
RUN npm install -g bun
RUN apt-get update && apt-get install -y openssl ca-certificates git build-essential python3 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN echo "node-linker=hoisted" > .npmrc && \
    echo "shamefully-hoist=true" >> .npmrc && \
    echo "strict-peer-dependencies=false" >> .npmrc

COPY package.json ./package.json
COPY pnpm-lock.yaml ./pnpm-lock.yaml
COPY pnpm-workspace.yaml ./pnpm-workspace.yaml
COPY ../common/package.json ./packages/common/package.json

RUN --mount=type=cache,id=pnpm,target=/root/.local/share/pnpm/store pnpm fetch --frozen-lockfile

COPY . .

RUN sed -i 's/"prepare":/"_prepare":/' packages/common/package.json
RUN --mount=type=cache,id=pnpm,target=/root/.local/share/pnpm/store CI=true pnpm install --frozen-lockfile --offline
RUN sed -i 's/"_prepare":/"prepare":/' packages/common/package.json

RUN pnpm --filter="@hashibutogarasu/common" exec tsc --noEmitOnError false || true

RUN DATABASE_URL="postgresql://build:dummy@localhost:5432/dummy" npx prisma generate

RUN pnpm run build

RUN CI=true pnpm prune --prod --ignore-scripts

FROM node:22-bookworm-slim AS runner

RUN corepack enable && corepack prepare pnpm@10.33.0 --activate

ENV NODE_ENV=production
WORKDIR /app

RUN apt-get update && apt-get install -y openssl ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/packages ./packages
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/package.json ./
COPY --from=builder /app/prisma ./prisma/
COPY --from=builder /app/prisma.config.js ./
COPY --from=builder /app/configs ./configs

COPY scripts/docker-entrypoint.sh ./
RUN sed -i 's/\r$//' docker-entrypoint.sh && chmod +x docker-entrypoint.sh

ENTRYPOINT ["./docker-entrypoint.sh"]

CMD ["pnpm", "run", "start:prod"]

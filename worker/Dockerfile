FROM node:20-alpine AS base
WORKDIR /app

FROM base AS deps
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

FROM base AS build
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
RUN addgroup -g 1001 -S app && adduser -S -G app -u 1001 app
COPY --from=deps /app/node_modules ./node_modules
COPY --from=build /app/worker/dist ./worker/dist
COPY --from=build /app/metrics ./metrics
USER app
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["node", "-e", "const target=new URL(process.env.REDIS_URL || 'redis://redis:6379'); const net=require('node:net'); const socket=net.createConnection({ host: target.hostname, port: Number(target.port) || 6379 }); socket.on('connect', () => { socket.destroy(); process.exit(0); }); socket.on('error', () => { process.exit(1); }); setTimeout(() => { socket.destroy(); process.exit(1); }, 3000);"]
CMD ["node", "worker/dist/worker.js"]

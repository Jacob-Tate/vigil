# Stage 1: Build the React client
FROM node:24-alpine AS client-build
WORKDIR /build
COPY client/package*.json ./client/
RUN npm ci --prefix client
COPY client/ ./client/
RUN npm run build --prefix client

# Stage 2: Build the Express server
FROM node:24-alpine AS server-build
WORKDIR /build
COPY server/package*.json ./server/
RUN npm ci --prefix server
COPY server/ ./server/
RUN npm run build --prefix server
RUN npm prune --omit=dev --prefix server

# Stage 3: Production image
FROM node:24-alpine
WORKDIR /app

COPY --from=server-build /build/server/dist ./server/dist
COPY --from=server-build /build/server/node_modules ./server/node_modules
COPY --from=client-build /build/client/dist ./client/dist

ENV NODE_ENV=production
ENV PORT=3001
# DATA_DIR is relative to cwd (/app), so data lives at /app/data
ENV DATA_DIR=data

EXPOSE 3001
VOLUME ["/app/data"]

CMD ["node", "server/dist/index.js"]

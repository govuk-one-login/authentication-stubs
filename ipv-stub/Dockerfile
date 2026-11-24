# LOCAL RUNNING ONLY.
FROM node:24.19.0-alpine AS builder

WORKDIR /app
COPY package.json ./
COPY package-lock.json ./
COPY .npmrc ./

RUN npm ci --ignore-scripts

COPY tsconfig.json ./
COPY ./src ./src
RUN npm run build:server

FROM node:24.19.0-alpine AS final

WORKDIR /app
COPY --chown=node:node --from=builder /app/build/server/* ./

ENV NODE_ENV="production"
ENV PORT=4405

EXPOSE $PORT
USER node

ENTRYPOINT ["node", "--enable-source-maps", "/app/server.cjs"]

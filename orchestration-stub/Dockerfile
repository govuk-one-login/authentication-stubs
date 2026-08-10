FROM node:24.19.0-alpine@sha256:d32cdf619f63fe0471182d08996dd516c6275bb5fd31ae06e55a570bd9e1ad43 AS builder

WORKDIR /app
COPY package.json ./
COPY package-lock.json ./
COPY .npmrc ./

RUN npm ci --ignore-scripts

COPY tsconfig.json ./
COPY ./src ./src
RUN npm run build
RUN npm ci --omit=dev --ignore-scripts

FROM node:24.19.0-alpine@sha256:d32cdf619f63fe0471182d08996dd516c6275bb5fd31ae06e55a570bd9e1ad43 AS final

WORKDIR /app
COPY --chown=node:node --from=builder /app/build/* ./

ENV NODE_ENV="production"
ENV PORT=4400

EXPOSE $PORT
USER node

ENTRYPOINT ["node", "--enable-source-maps", "/app/server.js"]

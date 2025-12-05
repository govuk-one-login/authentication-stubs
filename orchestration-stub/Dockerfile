FROM node:20.17.0-alpine@sha256:2d07db07a2df6830718ae2a47db6fedce6745f5bcd174c398f2acdda90a11c03 AS builder

WORKDIR /app
COPY package.json ./
COPY package-lock.json ./
COPY .npmrc ./

RUN npm ci --ignore-scripts

COPY tsconfig.json ./
COPY ./src ./src
RUN npm run build
RUN npm ci --omit=dev --ignore-scripts

FROM node:20.17.0-alpine@sha256:2d07db07a2df6830718ae2a47db6fedce6745f5bcd174c398f2acdda90a11c03 AS final

WORKDIR /app
COPY --chown=node:node --from=builder /app/build/* ./

ENV NODE_ENV="production"
ENV PORT=4400

EXPOSE $PORT
USER node

ENTRYPOINT ["node", "--enable-source-maps", "/app/server.js"]

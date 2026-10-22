FROM node:24.22.1-alpine3.24@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53 AS builder

WORKDIR /app
COPY package.json ./
COPY package-lock.json ./
COPY .npmrc ./

RUN npm ci --ignore-scripts

COPY tsconfig.json ./
COPY ./src ./src
RUN npm run build
RUN npm ci --omit=dev --ignore-scripts

FROM node:24.22.1-alpine3.24@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53 AS final

WORKDIR /app
COPY --chown=node:node --from=builder /app/build/* ./

ENV NODE_ENV="production"
ENV PORT=4400

EXPOSE $PORT
USER node

ENTRYPOINT ["node", "--enable-source-maps", "/app/server.js"]

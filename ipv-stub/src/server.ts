// LOCAL RUNNING ONLY.
import express from "express";
import type { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { handler as authorizeHandler } from "./endpoints/ipv-authorize";
import { handler as tokenHandler } from "./endpoints/ipv-token";
import { handler as reverificationHandler } from "./endpoints/ipv-reverification";
import { handler as jwksHandler } from "./endpoints/jwks";
import { apiGatewayRoute } from "./utils/api-gateway-mapper";

type ApiGatewayHandler = (
  event: APIGatewayProxyEvent
) => Promise<APIGatewayProxyResult>;

const PORT = process.env.PORT || 4405;

const app = express();

app.use(express.text({ type: "*/*" }));

app.all("/authorize", apiGatewayRoute(authorizeHandler as ApiGatewayHandler));
app.all("/token", apiGatewayRoute(tokenHandler as ApiGatewayHandler));
app.all(
  "/reverification",
  apiGatewayRoute(reverificationHandler as ApiGatewayHandler)
);
app.all(
  "/.well-known/jwks.json",
  apiGatewayRoute(jwksHandler as ApiGatewayHandler)
);

const server = app.listen(PORT, () =>
  console.log(`ipv-stub listening on ${PORT}`)
);

process.on("SIGTERM", () => server.close());
process.on("SIGINT", () => server.close());

// LOCAL RUNNING ONLY.
import express from "express";
import { apiGatewayRoute } from "./utils/api-gateway-mapper.ts";
import { handler as authorizeHandler } from "./endpoints/amc-authorize.ts";
import { handler as tokenHandler } from "./endpoints/amc-token.ts";
import { handler as journeyOutcomeHandler } from "./endpoints/amc-journey-outcome.ts";
import { handler as jwksHandler } from "./endpoints/amc-jwks.ts";

const PORT = process.env.PORT || 4406;

const app = express();

app.use(express.text({ type: "*/*" }));

app.all("/authorize", apiGatewayRoute(authorizeHandler));
app.all("/token", apiGatewayRoute(tokenHandler));
app.all("/journeyoutcome", apiGatewayRoute(journeyOutcomeHandler));
app.all("/.well-known/jwks.json", apiGatewayRoute(jwksHandler));

const server = app.listen(PORT, () =>
  console.log(`amc-stub listening on ${PORT}`)
);

process.on("SIGTERM", () => server.close());
process.on("SIGINT", () => server.close());

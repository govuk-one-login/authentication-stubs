import express from "express";
import { handler as rootHandler } from "./index";
import { handler as callbackHandler } from "./callback";
import { apiGatewayRoute } from "./utils/api-gateway-mapper";

const PORT = process.env.PORT || 4400;

const app = express();

app.use(express.text({ type: "*/*" }));

app.all("/", apiGatewayRoute(rootHandler));
app.all("/orchestration-redirect", apiGatewayRoute(callbackHandler));

const server = app.listen(PORT, () => console.log(`listening on ${PORT}`));

process.on("SIGTERM", server.close);
process.on("SIGINT", server.close);

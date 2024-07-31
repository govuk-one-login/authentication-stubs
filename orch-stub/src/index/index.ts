import {
  APIGatewayProxyEvent,
  APIGatewayProxyEventHeaders,
  APIGatewayProxyResult,
} from "aws-lambda";
import * as jose from "jose";
import { JWTPayload } from "jose";
import * as querystring from "querystring";
import { ParsedUrlQuery } from "querystring";
import { getCookie, getOrCreatePersistentSessionId } from "../utils/cookie";
import crypto from "node:crypto";
import { downcaseHeaders } from "../utils/headers";
import { Session } from "../types/session";
import { getRedisClient, getSession } from "../services/redis";
import { ClientSession } from "../types/client-session";
import * as process from "node:process";
import { getPrivateKey } from "../utils/key";

export const handler = async (
  event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> => {
  downcaseHeaders(event);
  const method = event.httpMethod.toUpperCase();
  switch (method) {
    case "GET":
      return get(event);
    case "POST":
      return post(event);
    default:
      return {
        statusCode: 405,
        body: JSON.stringify({
          message: "Method not allowed: " + method,
        }),
      };
  }
};

const get = (event: APIGatewayProxyEvent): APIGatewayProxyResult => {
  const form = `<html>
<body><h1>Hello world</h1>
<form method='post'>
    <label for="reauthenticate">Reauthenticate (RP pairwise ID)</label>
    <input name="reauthenticate" id="reauthenticate">
    <button>submit</button>
</form>
</body>
</html>`;
  return {
    statusCode: 200,
    headers: {
      "Content-Type": "text/html",
    },
    body: form,
  };
};

const post = async (
  event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> => {
  const gsCookie = await setUpSession(event.headers);
  const journeyId = gsCookie.split(".")[0];
  const form = querystring.parse(event.body || "");
  const signingPrivKey = await getPrivateKey();
  const payload = jarPayload(form, journeyId);
  const jws = await signRequestObject(payload, signingPrivKey);
  const jwe = await encryptRequestObject(jws, await sandpitFrontendPublicKey());

  const persistentSessionId = getOrCreatePersistentSessionId(event.headers);
  const cookieDomain =
    process.env.DOMAIN === "none" ? "" : `; Domain=${process.env.DOMAIN}`;
  return {
    statusCode: 302,
    multiValueHeaders: {
      Location: [
        `${process.env.AUTHENTICATION_FRONTEND_URL}authorize?request=${jwe}&response_type=code&client_id=orchstub`,
      ],
      "Set-Cookie": [
        `gs=${gsCookie}; max-age=3600${cookieDomain}`,
        `di-persistent-session-id=${persistentSessionId}; max-age=34190000${cookieDomain}`,
      ],
    },
    body: "",
  };
};

const jarPayload = (form: ParsedUrlQuery, journeyId: string): JWTPayload => {
  let payload: JWTPayload = {
    rp_client_id: "a",
    rp_sector_host: "a.example.com",
    rp_redirect_uri: "https://a.example.com/redirect",
    rp_state: "state",
    client_name: "client",
    cookie_consent_shared: true,
    is_one_login_service: false,
    service_type: "essential",
    govuk_signin_journey_id: journeyId,
    confidence: "Cl",
    state: "3",
    client_id: "orchstub",
    redirect_uri: "http://localhost:3000/callback",
    claims: {
      salt: null,
    },
  };
  if (form["reauthenticate"] !== "") {
    payload["reauthenticate"] = form["reauthenticate"];
  }
  return payload;
};

const sandpitFrontendPublicKey = async () =>
  await jose.importSPKI(process.env.AUTH_PUB_KEY!, "RS256");

const signRequestObject = async (
  payload: JWTPayload,
  signingPrivKey: jose.KeyLike,
) => {
  return await new jose.SignJWT(payload)
    .setProtectedHeader({ alg: "ES256" })
    .setIssuer("orchstub")
    .setAudience(process.env.AUTHENTICATION_FRONTEND_URL!!)
    .setNotBefore("-1s")
    .setIssuedAt("-1s")
    .setExpirationTime("2h")
    .setJti("4")
    .sign(signingPrivKey);
};

const encryptRequestObject = async (jws: string, encPubKey: jose.KeyLike) =>
  await new jose.CompactEncrypt(new TextEncoder().encode(jws))
    .setProtectedHeader({ cty: "JWT", alg: "RSA-OAEP-256", enc: "A256GCM" })
    .encrypt(encPubKey);

const setUpSession = async (headers: APIGatewayProxyEventHeaders) => {
  const newSessionId = crypto.randomBytes(20).toString("base64url");
  const newClientSessionId = crypto.randomBytes(20).toString("base64url");
  await createNewClientSession(newClientSessionId);

  const existingGsCookie = getCookie(headers["cookie"], "gs");
  if (existingGsCookie) {
    const idParts = existingGsCookie.split(".");
    const sessionId = idParts[0];
    await renameExistingSession(sessionId, newSessionId);
  } else {
    await createNewSession(newSessionId);
  }
  await attachClientSessionToSession(newClientSessionId, newSessionId);

  return `${newSessionId}.${newClientSessionId}`;
};

const createNewClientSession = async (id: string) => {
  const client = await getRedisClient();
  const clientSession: ClientSession = {
    creation_time: new Date(),
    client_name: "Example RP",
    auth_request_params: {
      client_id: ["rPEUe0hRrHqf0i0es1gYjKxE5ceGN7VK"],
    },
  };
  await client.setEx(
    `client-session-${id}`,
    3600,
    JSON.stringify(clientSession),
  );
};

const createNewSession = async (id: string) => {
  const session: Session = { session_id: id };
  const client = await getRedisClient();
  await client.setEx(id, 3600, JSON.stringify(session));
};

const renameExistingSession = async (
  existingSessionId: string,
  newSessionId: string,
) => {
  const client = await getRedisClient();
  const existingSession = await getSession(existingSessionId);
  await client.del(existingSessionId);
  existingSession.session_id = newSessionId;
  await client.setEx(newSessionId, 3600, JSON.stringify(existingSession));
};

const attachClientSessionToSession = async (
  clientSessionId: string,
  sessionId: string,
) => {
  const client = await getRedisClient();
  const session = await getSession(sessionId);

  session.client_sessions ||= [];
  session.client_sessions.push(clientSessionId);

  await client.setEx(sessionId, 3600, JSON.stringify(session));
};

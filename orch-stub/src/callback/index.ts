import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { downcaseHeaders } from "../utils/headers";
import { JWTPayload } from "jose";
import * as jose from "jose";
import { getPrivateKey } from "../utils/key";

export const handler = async (
  event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> => {
  downcaseHeaders(event);
  const method = event.httpMethod.toUpperCase();
  switch (method) {
    case "GET":
      return get(event);
    default:
      return {
        statusCode: 405,
        body: JSON.stringify({
          message: "Method not allowed: " + method,
        }),
      };
  }
};

const get = async (
  event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> => {
  const authCode = getAuthCode(event);
  const clientAssertion = await buildClientAssertion();
  const tokenResponse = await getToken(authCode, clientAssertion);
  const userInfo = await getUserInfo(tokenResponse);

  return {
    statusCode: 200,
    body: JSON.stringify(userInfo),
  };
};

function getAuthCode(event: APIGatewayProxyEvent) {
  const queryStringParameters = event.queryStringParameters;
  if (queryStringParameters === null) {
    throw new Error("No queryStringParameters provided");
  }
  const authCode = queryStringParameters["code"];
  if (authCode === undefined) {
    throw new Error("No authCode provided");
  }
  return authCode;
}

const buildClientAssertion = async () => {
  let payload: JWTPayload = {};

  const privateKey = await getPrivateKey();
  return await new jose.SignJWT(payload)
    .setProtectedHeader({ alg: "ES256" })
    .setIssuer("orchstub")
    .setSubject("orchstub")
    .setAudience("tokenurl")
    .setNotBefore("-1s")
    .setIssuedAt("-1s")
    .setExpirationTime("5m")
    .setJti("4")
    .sign(privateKey);
};

const getToken = async (authCode: string, clientAssertion: string) => {
  const tokenUrl = new URL("https://www.example.com/token");
  tokenUrl.searchParams.set("grant_type", "authorization_code");
  tokenUrl.searchParams.set("code", authCode);
  tokenUrl.searchParams.set(
    "client_assertion_type",
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
  );
  tokenUrl.searchParams.set("client_assertion", clientAssertion);

  const response = await fetch(tokenUrl);
  if (!response.ok) {
    throw new Error(
      `Error while fetching token. Status code: ${response.status} Message: ${await response.text()}`,
    );
  }

  const tokenResponse: TokenResponse = await response.json();
  return tokenResponse.access_token;
};

const getUserInfo = async (accessToken: string) => {
  const userInfoUrl = new URL("https://www.example.com/userinfo");
  const response = await fetch(userInfoUrl, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!response.ok) {
    throw new Error(
      `Error while fetching user info. Status code: ${response.status} Message: ${await response.text()}`,
    );
  }

  return response.json();
};

type TokenResponse = {
  access_token: string;
};
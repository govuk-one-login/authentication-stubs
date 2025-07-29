import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { downcaseHeaders } from "../utils/headers";
import * as jose from "jose";
import { JWTPayload } from "jose";
import { getPrivateKey } from "../utils/key";
import { renderGovukPage } from "../utils/page";
import { getCookie } from "../utils/cookie";
import { SESSION_ID_HEADER } from "../utils/constants";

const TOKEN_URL = `${process.env.AUTHENTICATION_BACKEND_URL}token`;
const USER_INFO_URL = `${process.env.AUTHENTICATION_BACKEND_URL}userinfo`;

const invalidStateError = `<p class="govuk-error-message">
  <span class="govuk-visually-hidden">Error:</span> Invalid state parameter
</p>`;

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
  const gsCookie = getCookie(event.headers["cookie"], "gs");
  const [sessionId, journeyId] = gsCookie!.split(".");

  const invalidState = event.queryStringParameters?.state !== sessionId;

  const clientAssertion = await buildClientAssertion();
  const tokenResponse = await getToken(authCode, clientAssertion);
  const userInfo = await getUserInfo(tokenResponse, sessionId);

  const content = `<script defer src="https://unpkg.com/pretty-json-custom-element/index.js"></script>
${invalidState ? invalidStateError : ""}
<dl class="govuk-summary-list">
    <div class="govuk-summary-list__row">
        <dt class="govuk-summary-list__key">
            Session ID
        </dt>
        <dd class="govuk-summary-list__value">
            ${sessionId}
        </dd>
    </div>
        <div class="govuk-summary-list__row">
        <dt class="govuk-summary-list__key">
            Journey ID
        </dt>
        <dd class="govuk-summary-list__value">
            ${journeyId}
        </dd>
    </div>
    <div class="govuk-summary-list__row">
        <dt class="govuk-summary-list__key">
            Access Token
        </dt>
        <dd class="govuk-summary-list__value">
            ${tokenResponse}
        </dd>
    </div>
    <div class="govuk-summary-list__row">
        <dt class="govuk-summary-list__key">
            User Info
        </dt>
        <dd class="govuk-summary-list__value">
            <pretty-json>
                ${JSON.stringify(userInfo)}
            </pretty-json>
        </dd>
    </div>
</dl>
<a href="/" role="button" draggable="false" class="govuk-button" data-module="govuk-button">
  Start again
</a>
    `;
  return {
    statusCode: 200,
    headers: {
      "Content-Type": "text/html",
    },
    body: renderGovukPage(content),
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
  const payload: JWTPayload = {};

  const privateKey = await getPrivateKey();
  return await new jose.SignJWT(payload)
    .setProtectedHeader({ alg: "ES256" })
    .setIssuer("orchestrationAuth")
    .setSubject("orchestrationAuth")
    .setAudience(TOKEN_URL)
    .setNotBefore("-1s")
    .setIssuedAt("-1s")
    .setExpirationTime("5m")
    .setJti("4")
    .sign(privateKey);
};

const getToken = async (authCode: string, clientAssertion: string) => {
  const tokenUrl = new URL(TOKEN_URL);

  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: authCode,
    client_assertion_type:
      "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    client_assertion: clientAssertion,
    redirect_uri: "",
    client_id: "orchestrationAuth",
  });

  const response = await fetch(tokenUrl, { method: "POST", body });
  if (!response.ok) {
    throw new Error(
      `Error while fetching token. Status code: ${response.status} Message: ${await response.text()}`,
    );
  }

  const tokenResponse: TokenResponse = await response.json();
  return tokenResponse.access_token;
};

const getUserInfo = async (accessToken: string, sessionId: string) => {
  const userInfoUrl = new URL(USER_INFO_URL);
  const response = await fetch(userInfoUrl, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      [SESSION_ID_HEADER]: sessionId,
    },
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

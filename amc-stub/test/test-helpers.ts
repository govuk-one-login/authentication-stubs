import {
  APIGatewayProxyEvent,
  APIGatewayEventRequestContext,
} from "aws-lambda";
import { amcScopes, HttpMethod, joseAlgorithms } from "../src/types/enums.js";
import {
  CompactJWSHeaderParameters,
  CompactSign,
  importPKCS8,
  JWTPayload,
} from "jose";

const textEncoder = new TextEncoder();

export const TEST_CONSTANTS = {
  SUBJECT: "urn:fdc:gov.uk:2022:7KWZkhSXFYrmMP_SRsZJU-0Z4AQ",
  CLIENT_ID: "auth",
  ISSUER: "https://signin.account.gov.uk/",
  AUDIENCE: "https://manage.api.account.gov.uk",
  REDIRECT_URI: 'https://signin.account.gov.uk/amc/callback/authorize"',
  RESPONSE_TYPE: "code",
  EMAIL: "user@example.gov.uk",
  STATE: "state_xyz789abc123def456ghi789jkl012",
  CLIENT_ASSERTION_JTI: "b2c3d4e5-f6g7-8901-bcde-fg2345678901",
  ACCESS_TOKEN_JTI: "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  SESSION_ID: "sess_abc123def456ghi789jkl012mno345pqr",
  JOURNEY_ID: "journey_abc123def456ghi789jkl012mno345",
  PUBLIC_SUBJECT: "550e8400-e29b-41d4-a716-446655440000"
};

export const createTestEvent = (
  httpMethod: HttpMethod,
  path: string = "/test",
  body: string | null = null,
  queryStringParameters: Record<string, string> | null = null
): APIGatewayProxyEvent => ({
  httpMethod,
  path,
  body,
  queryStringParameters,
  headers: {},
  multiValueHeaders: {},
  pathParameters: null,
  multiValueQueryStringParameters: null,
  stageVariables: null,
  requestContext: {
    requestId: "test-request-id",
    httpMethod,
    path,
    accountId: "123456789012",
    apiId: "test-api-id",
    stage: "test",
    resourceId: "test-resource",
    resourcePath: path,
    identity: {
      sourceIp: "127.0.0.1",
      userAgent: "test-agent",
    },
  } as APIGatewayEventRequestContext,
  resource: path,
  isBase64Encoded: false,
});

const createAccessToken = async (signingKey: string) => {
  const protectedHeader = {
    alg: joseAlgorithms.ES256,
    typ: "at+jwt",
  };

  const now = Math.floor(Date.now() / 1000);
  const accessTokenPayload = {
    sub: TEST_CONSTANTS.SUBJECT,
    scope: [amcScopes.ACCOUNT_DELETE],
    iss: TEST_CONSTANTS.ISSUER,
    aud: TEST_CONSTANTS.AUDIENCE,
    exp: now + 3600,
    iat: now,
    nbf: now,
    client_id: TEST_CONSTANTS.CLIENT_ID,
    jti: TEST_CONSTANTS.ACCESS_TOKEN_JTI,
    sid: TEST_CONSTANTS.SESSION_ID,
  };

  return createSignedJwt(protectedHeader, accessTokenPayload, signingKey);
};

const createSignedJwt = async (
  header: CompactJWSHeaderParameters,
  payload: JWTPayload,
  signingKey: string
) => {
  const privateKey = await importPKCS8(signingKey, joseAlgorithms.ES256);
  return await new CompactSign(textEncoder.encode(JSON.stringify(payload)))
    .setProtectedHeader(header)
    .sign(privateKey);
};

export const createCompositeJWT = async (
  signingKey: string,
  accessTokenSigningKey: string
) => {
  const protectedHeader = {
    alg: joseAlgorithms.ES256,
    typ: "JWT",
  };

  const now = Math.floor(Date.now() / 1000);
  const accessToken = await createAccessToken(accessTokenSigningKey);

  const clientAssertionPayload = {
    iss: TEST_CONSTANTS.ISSUER,
    client_id: TEST_CONSTANTS.CLIENT_ID,
    aud: TEST_CONSTANTS.AUDIENCE,
    response_type: TEST_CONSTANTS.RESPONSE_TYPE,
    redirect_uri: TEST_CONSTANTS.REDIRECT_URI,
    scope: [amcScopes.ACCOUNT_DELETE],
    state: TEST_CONSTANTS.STATE,
    jti: TEST_CONSTANTS.CLIENT_ASSERTION_JTI,
    iat: now,
    nbf: now,
    exp: now + 300,
    access_token: accessToken,
    sub: TEST_CONSTANTS.SUBJECT,
    email: TEST_CONSTANTS.EMAIL,
    govuk_signin_journey_id: TEST_CONSTANTS.JOURNEY_ID,
    public_sub: TEST_CONSTANTS.PUBLIC_SUBJECT
  };

  return createSignedJwt(protectedHeader, clientAssertionPayload, signingKey);
};

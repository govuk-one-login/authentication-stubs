import {
  APIGatewayProxyEvent,
  APIGatewayEventRequestContext,
} from "aws-lambda";
import { AMCScopes, HttpMethod, JoseAlgorithms } from "../src/types/enums.ts";
import {
  CompactJWSHeaderParameters,
  CompactSign,
  importPKCS8,
  JWTPayload,
} from "jose";

const textEncoder = new TextEncoder();

export const TEST_CONSTANTS = {
  SUBJECT: "urn:fdc:gov.uk:2022:7KWZkhSXFYrmMP_SRsZJU-0Z4AQ",
  CLIENT_ID: "auth_amc",
  ISSUER: "https://signin.account.gov.uk/",
  AMC_AUDIENCE: "https://api.manage.account.gov.uk",
  AUTH_AUDIENCE: "https://manage.account.gov.uk",
  REDIRECT_URI: 'https://signin.account.gov.uk/amc/callback/authorize"',
  RESPONSE_TYPE: "code",
  EMAIL: "user@example.gov.uk",
  STATE: "state_xyz789abc123def456ghi789jkl012",
  CLIENT_ASSERTION_JTI: "b2c3d4e5-f6g7-8901-bcde-fg2345678901",
  ACCESS_TOKEN_JTI: "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  SESSION_ID: "sess_abc123def456ghi789jkl012mno345pqr",
  JOURNEY_ID: "journey_abc123def456ghi789jkl012mno345",
  PUBLIC_SUBJECT: "550e8400-e29b-41d4-a716-446655440000",
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

export class AccessTokenBuilder {
  private sub: string | undefined = TEST_CONSTANTS.SUBJECT;
  private scope: string[] | undefined = [AMCScopes.ACCOUNT_DELETE];
  private iss: string | undefined = TEST_CONSTANTS.ISSUER;
  private aud: string | undefined = TEST_CONSTANTS.AUTH_AUDIENCE;
  private clientId: string | undefined = TEST_CONSTANTS.CLIENT_ID;
  private jti: string | undefined = TEST_CONSTANTS.ACCESS_TOKEN_JTI;
  private readonly sid = TEST_CONSTANTS.SESSION_ID;
  private readonly expiresIn = 3600;

  constructor(private readonly signingKey: string) {}

  async build() {
    const protectedHeader = {
      alg: JoseAlgorithms.ES256,
      typ: "at+jwt",
    };

    const now = Math.floor(Date.now() / 1000);
    const accessTokenPayload = {
      sub: this.sub,
      scope: this.scope,
      iss: this.iss,
      aud: this.aud,
      exp: now + this.expiresIn,
      iat: now,
      nbf: now,
      client_id: this.clientId,
      jti: this.jti,
      sid: this.sid,
    };

    return createSignedJwt(
      protectedHeader,
      accessTokenPayload,
      this.signingKey
    );
  }

  withScope(scope: string | string[] | undefined) {
    if (!scope) {
      this.scope = undefined;
    } else if (Array.isArray(scope)) {
      this.scope = scope;
    } else {
      this.scope = [scope];
    }
    return this;
  }

  withIssuer(issuer: string | undefined) {
    this.iss = issuer;
    return this;
  }

  withAudience(audience: string | undefined) {
    this.aud = audience;
    return this;
  }

  withSubject(sub: string | undefined) {
    this.sub = sub;
    return this;
  }

  withClientId(clientId: string | undefined) {
    this.clientId = clientId;
    return this;
  }

  withJti(jti: string | undefined) {
    this.jti = jti;
    return this;
  }
}

const createSignedJwt = async (
  header: CompactJWSHeaderParameters,
  payload: JWTPayload,
  signingKey: string
) => {
  const privateKey = await importPKCS8(signingKey, JoseAlgorithms.ES256);
  return await new CompactSign(textEncoder.encode(JSON.stringify(payload)))
    .setProtectedHeader(header)
    .sign(privateKey);
};

export class CompositeJWTBuilder {
  private iss: string | undefined = TEST_CONSTANTS.ISSUER;
  private clientId: string | undefined = TEST_CONSTANTS.CLIENT_ID;
  private aud: string | undefined = TEST_CONSTANTS.AMC_AUDIENCE;
  private readonly responseType = TEST_CONSTANTS.RESPONSE_TYPE;
  private readonly redirectUri = TEST_CONSTANTS.REDIRECT_URI;
  private scope: string[] | undefined = [AMCScopes.ACCOUNT_DELETE];
  private readonly state = TEST_CONSTANTS.STATE;
  private jti: string | undefined = TEST_CONSTANTS.CLIENT_ASSERTION_JTI;
  private sub: string | undefined = TEST_CONSTANTS.SUBJECT;
  private readonly email = TEST_CONSTANTS.EMAIL;
  private readonly journeyId = TEST_CONSTANTS.JOURNEY_ID;
  private publicSub: string | undefined = TEST_CONSTANTS.PUBLIC_SUBJECT;
  private readonly expiresIn = 300;

  constructor(
    private readonly signingKey: string,
    private readonly accessToken: string
  ) {}

  async build() {
    const protectedHeader = { alg: JoseAlgorithms.ES256, typ: "JWT" };
    const now = Math.floor(Date.now() / 1000);

    const payload = {
      iss: this.iss,
      client_id: this.clientId,
      aud: this.aud,
      response_type: this.responseType,
      redirect_uri: this.redirectUri,
      scope: this.scope,
      state: this.state,
      jti: this.jti,
      iat: now,
      nbf: now,
      exp: now + this.expiresIn,
      access_token: this.accessToken,
      sub: this.sub,
      email: this.email,
      govuk_signin_journey_id: this.journeyId,
      public_sub: this.publicSub,
    };

    return createSignedJwt(protectedHeader, payload, this.signingKey);
  }

  withScope(scope: string | string[] | undefined) {
    if (!scope) {
      this.scope = undefined;
    } else if (Array.isArray(scope)) {
      this.scope = scope;
    } else {
      this.scope = [scope];
    }
    return this;
  }

  withIssuer(issuer: string | undefined) {
    this.iss = issuer;
    return this;
  }

  withAudience(audience: string | undefined) {
    this.aud = audience;
    return this;
  }

  withSubject(sub: string | undefined) {
    this.sub = sub;
    return this;
  }

  withPublicSubject(publicSub: string | undefined) {
    this.publicSub = publicSub;
    return this;
  }

  withClientId(clientId: string | undefined) {
    this.clientId = clientId;
    return this;
  }

  withJti(jti: string | undefined) {
    this.jti = jti;
    return this;
  }
}

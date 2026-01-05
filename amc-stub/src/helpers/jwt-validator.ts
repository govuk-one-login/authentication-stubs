import { getPublicSigningKey } from "./jwks-helper.ts";
import { jwtVerify, JWTVerifyResult } from "jose";
import { AccessTokenPayload, CompositePayload } from "../types/types.ts";
import { AMCScopes } from "../types/enums.ts";

async function validateAccessToken(
  accessTokenJWT: string
): Promise<JWTVerifyResult<AccessTokenPayload> | string> {
  const publicSigningKeyAuthAudience = await getPublicSigningKey(
    accessTokenJWT,
    undefined,
    process.env.AUTH_PUBLIC_SIGNING_KEY_AUTH_AUDIENCE
  );

  const verifiedJWT = await jwtVerify<AccessTokenPayload>(
    accessTokenJWT,
    publicSigningKeyAuthAudience
  );

  const validScopes = Object.values(AMCScopes);
  if (
    !verifiedJWT.payload.scope?.length ||
    !verifiedJWT.payload.scope.every((scope) => validScopes.includes(scope))
  ) {
    return "The access token payload contains invalid scopes";
  }

  if (verifiedJWT.payload.iss !== "https://signin.account.gov.uk/") {
    return "The access token payload issuer is invalid";
  }

  if (verifiedJWT.payload.aud !== "https://manage.api.account.gov.uk") {
    return "The access token payload audience is invalid";
  }

  if (verifiedJWT.payload.sub === undefined) {
    return "The access token payload must contain an internal subject";
  }

  if (verifiedJWT.payload.client_id === undefined) {
    return "The access token payload must contain a client ID";
  }

  if (verifiedJWT.payload.jti === undefined) {
    return "The access token payload must contain a jti";
  }

  return verifiedJWT;
}

async function validateClientAssertionJWT(clientAssertionJWT: string) {
  const publicSigningKeyAMCAudience = await getPublicSigningKey(
    clientAssertionJWT,
    undefined,
    process.env.AUTH_PUBLIC_SIGNING_KEY_AMC_AUDIENCE
  );

  return await jwtVerify(clientAssertionJWT, publicSigningKeyAMCAudience);
}

export async function validateCompositeJWT(
  compositeJWT: string
): Promise<{ payload: CompositePayload } | string> {
  const {
    payload: clientAssertionPayload,
    protectedHeader: clientAssertionHeader,
  } = await validateClientAssertionJWT(compositeJWT);

  // TODO: need to change these to return error strings
  if (clientAssertionHeader.typ !== "JWT") {
    throw new Error("typ must be 'JWT'");
  }

  if (clientAssertionHeader.alg !== "ES256") {
    throw new Error("alg must be ES256");
  }

  if (typeof clientAssertionPayload.access_token !== "string") {
    throw new TypeError("access_token must be a string");
  }

  const accessTokenResultOrError = await validateAccessToken(
    clientAssertionPayload.access_token
  );

  if (typeof accessTokenResultOrError === "string") {
    return accessTokenResultOrError;
  }

  const { payload: accessTokenPayload, protectedHeader: accessTokenHeader } =
    accessTokenResultOrError;

  if (accessTokenHeader.typ !== "at+jwt") {
    throw new Error("typ must be 'at+jwt'");
  }

  return {
    payload: {
      ...clientAssertionPayload,
      access_token: accessTokenPayload,
    } as CompositePayload,
  };
}

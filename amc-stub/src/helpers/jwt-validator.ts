import { getPublicSigningKey } from "./jwks-helper.ts";
import { jwtVerify, JWTVerifyResult } from "jose";
import {
  AccessTokenPayload,
  ClientAssertionPayload,
  CompositePayload,
} from "../types/types.ts";
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

async function validateClientAssertionJWT(
  clientAssertionJWT: string
): Promise<JWTVerifyResult<ClientAssertionPayload> | string> {
  const publicSigningKeyAMCAudience = await getPublicSigningKey(
    clientAssertionJWT,
    undefined,
    process.env.AUTH_PUBLIC_SIGNING_KEY_AMC_AUDIENCE
  );

  const verifiedJWT = await jwtVerify<ClientAssertionPayload>(
    clientAssertionJWT,
    publicSigningKeyAMCAudience
  );

  if (
    verifiedJWT.payload.scope?.length !== 1 ||
    verifiedJWT.payload.scope[0] !== AMCScopes.ACCOUNT_DELETE
  ) {
    return "The client assertion JWT payload scope should be 'ACCOUNT_DELETE'";
  }

  if (verifiedJWT.payload.iss !== "https://signin.account.gov.uk/") {
    return "The client assertion JWT payload issuer is invalid";
  }

  if (verifiedJWT.payload.aud !== "https://manage.api.account.gov.uk") {
    return "The client assertion JWT payload audience is invalid";
  }

  if (verifiedJWT.payload.sub === undefined) {
    return "The client assertion JWT payload must contain an internal subject";
  }

  if (verifiedJWT.payload.public_sub === undefined) {
    return "The client assertion JWT payload must contain a public subject";
  }

  if (verifiedJWT.payload.client_id !== "auth") {
    return "The client assertion JWT client ID must be 'auth'";
  }

  if (verifiedJWT.payload.jti === undefined) {
    return "The client assertion JWT payload must contain a jti";
  }

  return verifiedJWT;
}

export async function validateCompositeJWT(
  compositeJWT: string
): Promise<{ payload: CompositePayload } | string> {
  const clientAssertionResultOrError =
    await validateClientAssertionJWT(compositeJWT);

  if (typeof clientAssertionResultOrError === "string") {
    return clientAssertionResultOrError;
  }

  const {
    payload: clientAssertionPayload,
    protectedHeader: clientAssertionHeader,
  } = clientAssertionResultOrError;

  // TODO: need to change these to return error strings
  if (clientAssertionHeader.typ !== "JWT") {
    throw new Error("typ must be 'JWT'");
  }

  if (clientAssertionHeader.alg !== "ES256") {
    throw new Error("alg must be ES256");
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

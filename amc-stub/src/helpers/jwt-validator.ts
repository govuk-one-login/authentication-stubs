import { getPublicSigningKey } from "./jwks-helper.ts";
import { jwtVerify, JWTVerifyResult } from "jose";
import {
  AccessTokenPayload,
  AuthorizationRequestPayload,
  CompositePayload,
} from "../types/types.ts";
import { AMCScopes } from "../types/enums.ts";
import { logger } from "../../logger.ts";

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
    !verifiedJWT.payload.scope
      ?.split(" ")
      .every((s) => validScopes.includes(s as AMCScopes))
  ) {
    const error = "The access token payload contains invalid scopes";
    logger.error(error, { payload: verifiedJWT.payload });
    return error;
  }

  const environment = process.env.ENVIRONMENT || "local";
  let expectedIssuer: string;
  if (environment === "local") {
    expectedIssuer = "https://signin.account.gov.uk";
  } else if (environment.startsWith("authdev")) {
    expectedIssuer = `https://signin.${environment}.dev.account.gov.uk`;
  } else {
    expectedIssuer = `https://signin.${environment}.account.gov.uk`;
  }

  if (verifiedJWT.payload.iss !== expectedIssuer) {
    const error = "The access token payload issuer is invalid";
    logger.error(error, { payload: verifiedJWT.payload, expectedIssuer });
    return error;
  }

  let expectedAudience: string;
  if (environment === "local") {
    expectedAudience = "https://manage.account.gov.uk";
  } else if (environment.startsWith("authdev")) {
    expectedAudience = `https://manage.${environment}.dev.account.gov.uk`;
  } else {
    expectedAudience = `https://manage.${environment}.account.gov.uk`;
  }

  if (verifiedJWT.payload.aud !== expectedAudience) {
    const error = "The access token payload audience is invalid";
    logger.error(error, { payload: verifiedJWT.payload, expectedAudience });
    return error;
  }

  if (verifiedJWT.payload.sub === undefined) {
    const error = "The access token payload must contain an internal subject";
    logger.error(error, { payload: verifiedJWT.payload });
    return error;
  }

  if (verifiedJWT.payload.client_id === undefined) {
    const error = "The access token payload must contain a client ID";
    logger.error(error, { payload: verifiedJWT.payload });
    return error;
  }

  if (verifiedJWT.payload.jti === undefined) {
    const error = "The access token payload must contain a jti";
    logger.error(error, { payload: verifiedJWT.payload });
    return error;
  }

  return verifiedJWT;
}

async function validateAuthorizationRequestJWT(
  authorizationRequestJWT: string
): Promise<JWTVerifyResult<AuthorizationRequestPayload> | string> {
  const publicSigningKeyAMCAudience = await getPublicSigningKey(
    authorizationRequestJWT,
    undefined,
    process.env.AUTH_PUBLIC_SIGNING_KEY_AMC_AUDIENCE
  );

  const verifiedJWT = await jwtVerify<AuthorizationRequestPayload>(
    authorizationRequestJWT,
    publicSigningKeyAMCAudience
  );

  const validScopes = Object.values(AMCScopes);
  if (!validScopes.includes(verifiedJWT.payload.scope as AMCScopes)) {
    const error = `The authorization request JWT payload scope should be one of ${validScopes.join(", ")}`;
    logger.error(error, { payload: verifiedJWT.payload });
    return error;
  }

  const environment = process.env.ENVIRONMENT || "local";
  let expectedIssuer: string;
  if (environment === "local") {
    expectedIssuer = "https://signin.account.gov.uk";
  } else if (environment.startsWith("authdev")) {
    expectedIssuer = `https://signin.${environment}.dev.account.gov.uk`;
  } else {
    expectedIssuer = `https://signin.${environment}.account.gov.uk`;
  }

  if (verifiedJWT.payload.iss !== expectedIssuer) {
    const error = "The authorization request JWT payload issuer is invalid";
    logger.error(error, { payload: verifiedJWT.payload, expectedIssuer });
    return error;
  }

  let expectedAudience: string;
  if (environment === "local") {
    expectedAudience = "https://api.manage.account.gov.uk";
  } else if (environment.startsWith("authdev")) {
    expectedAudience = `https://api.manage.${environment}.dev.account.gov.uk`;
  } else {
    expectedAudience = `https://api.manage.${environment}.account.gov.uk`;
  }

  if (verifiedJWT.payload.aud !== expectedAudience) {
    const error = "The authorization request JWT payload audience is invalid";
    logger.error(error, { payload: verifiedJWT.payload, expectedAudience });
    return error;
  }

  if (verifiedJWT.payload.sub === undefined) {
    const error =
      "The authorization request JWT payload must contain an internal subject";
    logger.error(error, { payload: verifiedJWT.payload });
    return error;
  }

  if (verifiedJWT.payload.public_sub === undefined) {
    const error =
      "The authorization request JWT payload must contain a public subject";
    logger.error(error, { payload: verifiedJWT.payload });
    return error;
  }

  if (verifiedJWT.payload.client_id !== "auth_amc") {
    const error = "The authorization request JWT client ID must be 'auth_amc'";
    logger.error(error, { payload: verifiedJWT.payload });
    return error;
  }

  if (verifiedJWT.payload.jti === undefined) {
    const error = "The authorization request JWT payload must contain a jti";
    logger.error(error, { payload: verifiedJWT.payload });
    return error;
  }

  return verifiedJWT;
}

export async function validateCompositeJWT(
  compositeJWT: string
): Promise<{ payload: CompositePayload } | string> {
  const authorizationRequestResultOrError =
    await validateAuthorizationRequestJWT(compositeJWT);

  if (typeof authorizationRequestResultOrError === "string") {
    return authorizationRequestResultOrError;
  }

  const { payload: authorizationRequestPayload } =
    authorizationRequestResultOrError;

  const accessTokenResultOrError = await validateAccessToken(
    authorizationRequestPayload.access_token
  );

  if (typeof accessTokenResultOrError === "string") {
    return accessTokenResultOrError;
  }

  const { payload: accessTokenPayload } = accessTokenResultOrError;

  return {
    payload: {
      ...authorizationRequestPayload,
      access_token: accessTokenPayload,
    } as CompositePayload,
  };
}

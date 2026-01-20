import { getPublicSigningKey } from "./jwks-helper.ts";
import { jwtVerify, JWTVerifyResult } from "jose";
import {
  AccessTokenPayload,
  ClientAssertionPayload,
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
    !verifiedJWT.payload.scope?.length ||
    !verifiedJWT.payload.scope.every((scope) => validScopes.includes(scope))
  ) {
    logger.error("Access token validation error", {
      payload: verifiedJWT.payload,
    });
    return "The access token payload contains invalid scopes";
  }

  const environment = process.env.ENVIRONMENT || "local";
  let expectedIssuer: string;
  if (environment === "local") {
    expectedIssuer = "https://signin.account.gov.uk/";
  } else if (environment.startsWith("authdev")) {
    expectedIssuer = `https://signin.${environment}.dev.account.gov.uk/`;
  } else {
    expectedIssuer = `https://signin.${environment}.account.gov.uk/`;
  }

  if (verifiedJWT.payload.iss !== expectedIssuer) {
    logger.error("Access token validation error", {
      payload: verifiedJWT.payload,
      expectedIssuer,
    });
    return "The access token payload issuer is invalid";
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
    logger.error("Access token validation error", {
      payload: verifiedJWT.payload,
      expectedAudience,
    });
    return "The access token payload audience is invalid";
  }

  if (verifiedJWT.payload.sub === undefined) {
    logger.error("Access token validation error", {
      payload: verifiedJWT.payload,
    });
    return "The access token payload must contain an internal subject";
  }

  if (verifiedJWT.payload.client_id === undefined) {
    logger.error("Access token validation error", {
      payload: verifiedJWT.payload,
    });
    return "The access token payload must contain a client ID";
  }

  if (verifiedJWT.payload.jti === undefined) {
    logger.error("Access token validation error", {
      payload: verifiedJWT.payload,
    });
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
    logger.error("Client assertion validation error", {
      payload: verifiedJWT.payload,
    });
    return "The client assertion JWT payload scope should be 'ACCOUNT_DELETE'";
  }

  const environment = process.env.ENVIRONMENT || "local";
  let expectedIssuer: string;
  if (environment === "local") {
    expectedIssuer = "https://signin.account.gov.uk/";
  } else if (environment.startsWith("authdev")) {
    expectedIssuer = `https://signin.${environment}.dev.account.gov.uk/`;
  } else {
    expectedIssuer = `https://signin.${environment}.account.gov.uk/`;
  }

  if (verifiedJWT.payload.iss !== expectedIssuer) {
    logger.error("Client assertion validation error", {
      payload: verifiedJWT.payload,
      expectedIssuer,
    });
    return "The client assertion JWT payload issuer is invalid";
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
    logger.error("Client assertion validation error", {
      payload: verifiedJWT.payload,
      expectedAudience,
    });
    return "The client assertion JWT payload audience is invalid";
  }

  if (verifiedJWT.payload.sub === undefined) {
    logger.error("Client assertion validation error", {
      payload: verifiedJWT.payload,
    });
    return "The client assertion JWT payload must contain an internal subject";
  }

  if (verifiedJWT.payload.public_sub === undefined) {
    logger.error("Client assertion validation error", {
      payload: verifiedJWT.payload,
    });
    return "The client assertion JWT payload must contain a public subject";
  }

  if (verifiedJWT.payload.client_id !== "auth_amc") {
    logger.error("Client assertion validation error", {
      payload: verifiedJWT.payload,
    });
    return "The client assertion JWT client ID must be 'auth_amc'";
  }

  if (verifiedJWT.payload.jti === undefined) {
    logger.error("Client assertion validation error", {
      payload: verifiedJWT.payload,
    });
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

  const { payload: clientAssertionPayload } = clientAssertionResultOrError;

  const accessTokenResultOrError = await validateAccessToken(
    clientAssertionPayload.access_token
  );

  if (typeof accessTokenResultOrError === "string") {
    return accessTokenResultOrError;
  }

  const { payload: accessTokenPayload } = accessTokenResultOrError;

  return {
    payload: {
      ...clientAssertionPayload,
      access_token: accessTokenPayload,
    } as CompositePayload,
  };
}

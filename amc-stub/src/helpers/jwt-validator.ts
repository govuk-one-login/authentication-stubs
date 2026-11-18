import { getPublicSigningKey } from "./jwks-helper.ts";
import { jwtVerify, JWTVerifyResult } from "jose";
import {
  AccessTokenPayload,
  AuthorizationRequestPayload,
  VerifiedAuthorizationRequestPayload,
} from "../types/types.ts";
import {
  ACCOUNT_DELETE_ACCOUNT_DATA_SCOPES,
  AccountDataAccessTokenScopes,
  AMCScopes,
} from "../types/enums.ts";
import { logger } from "../../logger.ts";

async function validateAccessToken(
  accessTokenJWT: string
): Promise<JWTVerifyResult<AccessTokenPayload> | string> {
  const publicSigningKeyAuthAudience = await getPublicSigningKey(
    accessTokenJWT,
    process.env.AD_JWKS_ENDPOINT,
    process.env.AUTH_PUBLIC_SIGNING_KEY_AUTH_AUDIENCE
  );

  const verifiedJWT = await jwtVerify<AccessTokenPayload>(
    accessTokenJWT,
    publicSigningKeyAuthAudience
  );

  const validScopes: string[] = Object.values(AccountDataAccessTokenScopes);

  if (
    !verifiedJWT.payload.scope?.split(" ").every((s) => validScopes.includes(s))
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

  let expectedAudiences: string[];
  if (environment === "local") {
    expectedAudiences = [
      "https://manage.account.gov.uk",
      "https://account.account.gov.uk",
    ];
  } else if (environment.startsWith("authdev")) {
    expectedAudiences = [
      `https://manage.${environment}.dev.account.gov.uk`,
      `https://account.${environment}.dev.account.gov.uk`,
    ];
  } else {
    expectedAudiences = [
      `https://manage.${environment}.account.gov.uk`,
      `https://account.${environment}.account.gov.uk`,
    ];
  }

  if (!expectedAudiences.includes(verifiedJWT.payload.aud as string)) {
    const error = "The access token payload audience is invalid";
    logger.error(error, { payload: verifiedJWT.payload, expectedAudiences });
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

async function validateAuthorizationRequest(
  authorizationRequestJWT: string
): Promise<JWTVerifyResult<AuthorizationRequestPayload> | string> {
  const publicSigningKeyAMCAudience = await getPublicSigningKey(
    authorizationRequestJWT,
    process.env.AMC_JWKS_ENDPOINT,
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

  if (verifiedJWT.payload.iss !== "auth") {
    const error = "The authorization request JWT payload issuer is invalid";
    logger.error(error, {
      payload: verifiedJWT.payload,
      expectedIssuer: "auth",
    });
    return error;
  }

  let expectedAudience: string;
  const environment = process.env.ENVIRONMENT || "local";
  if (environment === "local") {
    expectedAudience = "https://manage.account.gov.uk/authorize";
  } else if (environment.startsWith("authdev")) {
    expectedAudience = `https://manage.${environment}.dev.account.gov.uk/authorize`;
  } else {
    expectedAudience = `https://manage.${environment}.account.gov.uk/authorize`;
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

  if (verifiedJWT.payload.client_id !== "auth") {
    const error = "The authorization request JWT client ID must be 'auth'";
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
): Promise<{ payload: VerifiedAuthorizationRequestPayload } | string> {
  const authorizationRequestResultOrError =
    await validateAuthorizationRequest(compositeJWT);

  if (typeof authorizationRequestResultOrError === "string") {
    return authorizationRequestResultOrError;
  }

  const { payload: authorizationRequestPayload } =
    authorizationRequestResultOrError;

  const { account_management_api_access_token, account_data_api_access_token } =
    authorizationRequestPayload;

  if (account_management_api_access_token && account_data_api_access_token) {
    return "The authorization request JWT payload must contain only one access token";
  }

  if (!account_management_api_access_token && !account_data_api_access_token) {
    return "The authorization request JWT payload must contain an access token";
  }

  if (!account_data_api_access_token) {
    return `The access token field does not match the outer scope. Expected account_data_api_access_token for scope ${authorizationRequestPayload.scope}`;
  }

  const accessTokenResultOrError = await validateAccessToken(
    account_data_api_access_token
  );

  if (typeof accessTokenResultOrError === "string") {
    return accessTokenResultOrError;
  }

  if (authorizationRequestPayload.scope === AMCScopes.ACCOUNT_DELETE) {
    const tokenScopes = accessTokenResultOrError.payload.scope.split(" ");
    if (
      !ACCOUNT_DELETE_ACCOUNT_DATA_SCOPES.every((s) => tokenScopes.includes(s))
    ) {
      const error = `The account data access token must contain the scopes ${ACCOUNT_DELETE_ACCOUNT_DATA_SCOPES.join(", ")} for scope ${AMCScopes.ACCOUNT_DELETE}`;
      logger.error({ payload: accessTokenResultOrError.payload }, error);
      return error;
    }
  }

  return {
    payload: {
      ...authorizationRequestPayload,
      account_data_api_access_token: accessTokenResultOrError.payload,
    } as VerifiedAuthorizationRequestPayload,
  };
}

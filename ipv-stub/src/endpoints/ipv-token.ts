import {
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
  Handler,
} from "aws-lambda";
import { JwtPayload } from "jsonwebtoken";
import {
  handleErrors,
  methodNotAllowedError,
  shouldObfuscate,
  successfulJsonResult,
  truncate,
} from "../helper/result-helper";
import { logger } from "../helper/logger";
import {
  getReverificationWithAuthCode,
  putReverificationWithAccessToken,
} from "../services/dynamodb-form-response-service";
import { base64url, compactVerify } from "jose";
import { randomBytes } from "crypto";
import { PutCommandOutput } from "@aws-sdk/lib-dynamodb";
import { getPublicSigningKey } from "../helper/jwks-helper";
import { processJoseError } from "../helper/error-helper";
import process from "node:process";

type Result<T> =
  | { ok: true; value: T }
  | { ok: false; error: APIGatewayProxyResult };

function ok<T>(value: T): Result<T> {
  return { ok: true, value };
}

function error<T>(message: string): Result<T> {
  return { ok: false, error: { statusCode: 400, body: message } };
}

type ValidatedParams = Record<
  "code" | "client_id" | "client_assertion" | "client_assertion_type",
  string
>;

function parseBody(body: string): Result<Partial<ValidatedParams>> {
  const params = new URLSearchParams(body);
  const requiredParameters: (keyof ValidatedParams)[] = [
    "code",
    "client_id",
    "client_assertion",
    "client_assertion_type",
  ];
  const missingParameters: string[] = [];

  const validParameters: Partial<ValidatedParams> = {};
  for (const param of requiredParameters) {
    const value = params.get(param);
    if (!value || value === "undefined") {
      missingParameters.push(param);
    } else {
      validParameters[param] = value;
    }
  }

  logger.info("Handling token request with parameters:");
  for (const [key, value] of Object.entries(validParameters)) {
    const loggedValue = shouldObfuscate(key) ? truncate(value) : value;
    logger.info(`${key}::${loggedValue}`);
  }

  if (missingParameters.length > 0) {
    const missingParametersErrorMessage = `Missing or empty parameters: ${missingParameters.join(", ")}`;
    logger.info(missingParametersErrorMessage);
    return error(missingParametersErrorMessage);
  }

  return ok(validParameters);
}

type ValidatedClaims = Record<"iss" | "sub" | "aud" | "jti" | "exp", string>;

async function parsePayload(
  clientAssertion: string
): Promise<Result<JwtPayload>> {
  const claims: JwtPayload = await verifyJWT(clientAssertion);
  const obfuscatedClientAssertion = {
    ...claims,
    sub: claims.sub ? `${claims.sub.slice(0, 4)}` : undefined,
  };
  logger.info(
    `decrypted client assertion ${JSON.stringify(obfuscatedClientAssertion, null, 2)}`
  );

  const requiredClaims: (keyof ValidatedClaims)[] = [
    "iss",
    "sub",
    "aud",
    "jti",
    "exp",
  ];
  const missingClaims: string[] = [];

  const validClaims: Partial<ValidatedClaims> = {};
  for (const claim of requiredClaims) {
    const value = claims[claim];
    if (!value || value === "undefined") {
      missingClaims.push(claim);
    } else {
      validClaims[claim] = value as string;
    }
  }

  logger.info("Handling token request with claims:");
  for (const [key, value] of Object.entries(validClaims)) {
    const loggedValue = shouldObfuscate(key) ? truncate(value) : value;
    logger.info(`${key}::${loggedValue}`);
  }

  if (missingClaims.length > 0) {
    const missingClaimsErrorMessage = `Missing or empty parameters: ${missingClaims.join(", ")}`;
    logger.info(missingClaimsErrorMessage);
    return error(missingClaimsErrorMessage);
  }

  return ok(validClaims as JwtPayload);
}

/**
 * Entry point.
 *
 * @param event
 */
export const handler: Handler = async (
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> => {
  logger.info("Reached the token endpoint.");
  return await handleErrors(async () => {
    if (event.httpMethod === "POST") {
      logger.info("POST event");
      return await handle(event);
    } else {
      throw methodNotAllowedError(event.httpMethod);
    }
  });
};

/**
 * Handle the event.
 *
 * @param event
 */
async function handle(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  if (!event.body) {
    return { statusCode: 400, body: "Missing request body." };
  }

  const parsedBody: Result<Partial<ValidatedParams>> = parseBody(event.body);
  if (!parsedBody.ok) return parsedBody.error;

  const validatedParameters: Partial<ValidatedParams> = parsedBody.value;

  const reverificationResult = await getReverificationWithAuthCode(
    validatedParameters["code"] as string
  );

  if (!reverificationResult) {
    logger.info("Did not find reverification result record");
    return { statusCode: 400, body: "Missing reverification record." };
  }

  const accessToken = base64url.encode(randomBytes(32));

  // Claims
  const parsedClaims: Result<JwtPayload> = await parsePayload(
    validatedParameters["client_assertion"] as string
  );
  if (!parsedClaims.ok) return parsedClaims.error;

  const validatedClaims: Partial<JwtPayload> = parsedClaims.value;

  const result: PutCommandOutput = await putReverificationWithAccessToken(
    accessToken,
    reverificationResult
  );
  if (!result || result.$metadata.httpStatusCode != 200) {
    return { statusCode: 500, body: "Failed to write access token record." };
  }

  logger.info(
    `Created access token ${truncate(accessToken)} for ${validatedClaims["sub"]}`
  );

  return successfulJsonResult(200, {
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 3600,
  });
}

const verifyJWT = async (token: string): Promise<JwtPayload> => {
  const signingKey = await getPublicSigningKey(
    token,
    process.env.AUTH_IPV_SIGNING_KEY_JWKS_ENDPOINT,
    process.env.AUTH_PUBLIC_SIGNING_KEY_IPV
  );
  let payload;
  try {
    ({ payload } = await compactVerify(token, signingKey));
  } catch (error) {
    processJoseError(error);
  }

  const decodedPayload = new TextDecoder().decode(payload);
  if (typeof decodedPayload === "object" && decodedPayload !== null) {
    return decodedPayload;
  } else {
    throw new Error("Invalid token payload");
  }
};

import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { HttpMethod } from "../types/enums.ts";
import {
  methodNotAllowedError,
  successfulJsonResult,
} from "../helpers/result-helper.ts";
import { logger } from "../../logger.ts";
import {
  getAMCAuthorizationResult,
  putAMCAuthorizationResultWithToken,
} from "../../services/dynamodb-service.ts";
import { randomBytes } from "crypto";
import { base64url } from "jose";

type Result<T> =
  | { ok: true; value: T }
  | { ok: false; error: APIGatewayProxyResult };

function ok<T>(value: T): Result<T> {
  return { ok: true, value };
}

function error<T>(message: string): Result<T> {
  return { ok: false, error: { statusCode: 400, body: message } };
}
function errorWithStatusCode<T>(
  message: string,
  statusCode: number
): Result<T> {
  return { ok: false, error: { statusCode: statusCode, body: message } };
}

const REQUIRED_GRANT_TYPE = "authorization_code";
const REQUIRED_CLIENT_ASSERTION_TYPE =
  "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

export const handler = async (
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> => {
  switch (event.httpMethod) {
    case HttpMethod.POST:
      return post(event);
    default:
      throw methodNotAllowedError(event.httpMethod);
  }
};

async function post(event: APIGatewayProxyEvent) {
  logger.info("Received POST request to token endpoint");
  if (!event.body) {
    return { statusCode: 400, body: "Missing request body." };
  }

  const parsedBody = parseBody(event.body);

  if (!parsedBody.ok) return parsedBody.error;

  if (!parsedBody.value.code)
    return { statusCode: 400, body: "request missing code" };

  const tokenResult = await exchangeAuthCodeForToken(parsedBody.value.code);

  if (!tokenResult.ok) return tokenResult.error;

  return successfulJsonResult(200, {
    access_token: tokenResult.value,
    token_type: "Bearer",
    expires_in: 3600,
  });
}

async function exchangeAuthCodeForToken(
  authCode: string
): Promise<Result<string>> {
  const authorizationResult = await getAMCAuthorizationResult(authCode);
  if (!authorizationResult) {
    logger.info("Did not find authorization result record");
    return error("Missing reverification record.");
  }

  const accessToken = base64url.encode(randomBytes(32));

  const result = await putAMCAuthorizationResultWithToken(
    accessToken,
    authorizationResult
  );

  if (!result || result.$metadata.httpStatusCode != 200) {
    return errorWithStatusCode("Failed to write access token record.", 500);
  }

  return ok(accessToken);
}

type ValidatedParams = Record<
  | "grant_type"
  | "code"
  | "redirect_uri"
  | "client_assertion_type"
  | "client_assertion",
  string
>;

function parseBody(body: string): Result<Partial<ValidatedParams>> {
  const params = new URLSearchParams(body);
  const requiredParameters: (keyof ValidatedParams)[] = [
    "grant_type",
    "code",
    "redirect_uri",
    "client_assertion_type",
    "client_assertion",
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

  return validateParamValues(validParameters);
}

function validateParamValues(
  params: Partial<ValidatedParams>
): Result<Partial<ValidatedParams>> {
  const invalidParamMessages = [];

  if (!(params.grant_type === REQUIRED_GRANT_TYPE)) {
    invalidParamMessages.push(`Invalid grant_type: ${params.grant_type}`);
  }

  if (!(params.client_assertion_type === REQUIRED_CLIENT_ASSERTION_TYPE)) {
    invalidParamMessages.push(
      `Invalid client assertion type: ${params.client_assertion_type}`
    );
  }

  if (invalidParamMessages.length > 0) {
    invalidParamMessages.forEach((invalidMsg) => logger.info(invalidMsg));
    return error(invalidParamMessages.join(", "));
  }

  return ok(params);
}

export function shouldObfuscate(paramName: string): boolean {
  return ["code", "client_assertion"].includes(paramName);
}

export function truncate(value: string): string {
  if (value.length <= 8) {
    return value; // don't obfuscate if value is very short
  } else {
    return `${value.slice(0, 4)}...${value.slice(-4)}`;
  }
}

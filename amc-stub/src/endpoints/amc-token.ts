import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { HttpMethod } from "../types/enums.ts";
import {
  methodNotAllowedError,
  successfulJsonResult,
} from "../helpers/result-helper.ts";
import { logger } from "../../logger.ts";

type Result<T> =
  | { ok: true; value: T }
  | { ok: false; error: APIGatewayProxyResult };

function ok<T>(value: T): Result<T> {
  return { ok: true, value };
}

function error<T>(message: string): Result<T> {
  return { ok: false, error: { statusCode: 400, body: message } };
}


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

function post(event: APIGatewayProxyEvent) {
  if (!event.body) {
    return { statusCode: 400, body: "Missing request body." };
  }

  const parsedBody = parseBody(event.body)

  if (!parsedBody.ok) return parsedBody.error;

  //TODO: assert on values within the parsed body

  return successfulJsonResult(200, {
    message: "To be updated",
  });
}

type ValidatedParams = Record<"grant_type" | "code" | "redirect_uri" | "client_assertion_type" | "client_assertion", string>;

function parseBody(body: string): Result<Partial<ValidatedParams>> {
  const params = new URLSearchParams(body);
  const requiredParameters: (keyof ValidatedParams)[] = [
    "grant_type",
    "code",
    "redirect_uri",
    "client_assertion_type",
    "client_assertion"
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
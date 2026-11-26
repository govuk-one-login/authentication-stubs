import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { logger } from "../../logger.ts";
import { truncate } from "./truncate-helper.ts";

const REQUIRED_HEADERS = [
  "di-persistent-session-id",
  "client-session-id",
  "txma-audit-encoded",
  "session-id",
  "x-forwarded-for",
  "user-language",
];

const REQUIRED_HEADERS_LOCAL = [
  "di-persistent-session-id",
  "client-session-id",
  "session-id",
  "user-language",
];

export function validateRequiredHeaders(
  event: APIGatewayProxyEvent
): APIGatewayProxyResult | null {
  const headers = event.headers || {};
  const lowerCaseHeaders: Record<string, string> = {};

  for (const [key, value] of Object.entries(headers)) {
    if (value) {
      lowerCaseHeaders[key.toLowerCase()] = value;
    }
  }

  const missingHeaders: string[] = [];
  const requiredHeaders =
    process.env.ENVIRONMENT === "local"
      ? REQUIRED_HEADERS_LOCAL
      : REQUIRED_HEADERS;

  for (const header of requiredHeaders) {
    if (!lowerCaseHeaders[header]) {
      missingHeaders.push(header);
    }
  }

  if (missingHeaders.length > 0) {
    return {
      statusCode: 400,
      body: `Missing required headers: ${missingHeaders.join(", ")}`,
    };
  }

  logger.info("headers are:");
  for (const header of requiredHeaders) {
    logger.info(
      `${header}::${shouldObfuscate(header) ? truncate(lowerCaseHeaders[header]!) : lowerCaseHeaders[header]}`
    );
  }

  return null;
}

function shouldObfuscate(headerName: string): boolean {
  return ["x-forwarded-for"].includes(headerName);
}

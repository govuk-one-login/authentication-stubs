import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";

const REQUIRED_HEADERS = [
  "di-persistent-session-id",
  "client-session-id",
  "txma-audit-encoded",
  "session-id",
  "x-forwarded-for",
  "user-language",
];

export function validateRequiredHeaders(
  event: APIGatewayProxyEvent
): APIGatewayProxyResult | null {
  const headers = event.headers || {};
  const missingHeaders: string[] = [];

  for (const header of REQUIRED_HEADERS) {
    if (!headers[header]) {
      missingHeaders.push(header);
    }
  }

  if (missingHeaders.length > 0) {
    return {
      statusCode: 400,
      body: `Missing required headers: ${missingHeaders.join(", ")}`,
    };
  }

  return null;
}

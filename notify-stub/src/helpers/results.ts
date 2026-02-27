import { APIGatewayProxyResult } from "aws-lambda";

export const successfulJsonResult = (
  statusCode: number,
  body: unknown,
): APIGatewayProxyResult => ({
  statusCode,
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body),
});

export const errorResult = (
  statusCode: number,
  message: string,
): APIGatewayProxyResult => ({
  statusCode,
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    errors: [{ error: "Error", message }],
    status_code: statusCode,
  }),
});

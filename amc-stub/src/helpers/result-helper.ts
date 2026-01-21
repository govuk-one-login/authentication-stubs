import { APIGatewayProxyResult } from "aws-lambda";

type SuccessCode = 200 | 302;
type ErrorCode = 400 | 405 | 500;
type JsonEntity =
  | string
  | number
  | boolean
  | null
  | undefined
  | object
  | JsonEntity[];
type Headers = { [header: string]: boolean | number | string };

export class CodedError extends Error {
  public code: ErrorCode;

  constructor(code: ErrorCode, message: string) {
    super(message);
    this.code = code;
  }
}

export function successfulHtmlResult(
  code: SuccessCode,
  body: string,
  headers?: Headers | undefined
): APIGatewayProxyResult {
  return {
    statusCode: code,
    headers: { ...headers, "Content-Type": "text/html" },
    body: body,
  };
}

export function successfulJsonResult(
  code: SuccessCode,
  body: JsonEntity,
  headers?: Headers
): APIGatewayProxyResult {
  return {
    statusCode: code,
    headers: { ...headers, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  };
}

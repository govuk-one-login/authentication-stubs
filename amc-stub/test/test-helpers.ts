import {
  APIGatewayProxyEvent,
  APIGatewayEventRequestContext,
} from "aws-lambda";
import { HttpMethod } from "../src/types/enums.js";

export const createTestEvent = (
  httpMethod: HttpMethod,
  path: string = "/test",
  body: string | null = null,
  queryStringParameters: Record<string, string> | null = null
): APIGatewayProxyEvent => ({
  httpMethod,
  path,
  body,
  queryStringParameters,
  headers: {},
  multiValueHeaders: {},
  pathParameters: null,
  multiValueQueryStringParameters: null,
  stageVariables: null,
  requestContext: {
    requestId: "test-request-id",
    httpMethod,
    path,
    accountId: "123456789012",
    apiId: "test-api-id",
    stage: "test",
    resourceId: "test-resource",
    resourcePath: path,
    identity: {
      sourceIp: "127.0.0.1",
      userAgent: "test-agent",
    },
  } as APIGatewayEventRequestContext,
  resource: path,
  isBase64Encoded: false,
});

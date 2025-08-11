import type { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import type { Request, RequestHandler, Response } from "express";

const filterSingleValued = (input: object): Record<string, string> =>
  Object.fromEntries(
    Object.entries(input).filter(([, value]) => typeof value === "string"),
  );

const filterMultiValued = (input: object): Record<string, string[]> =>
  Object.fromEntries(
    Object.entries(input).filter(([, value]) => Array.isArray(value)),
  );

// Build an API Gateway event from the express request
const buildApiGatewayEvent = (request: Request): APIGatewayProxyEvent => ({
  body: request.body,
  headers: filterSingleValued(request.headers),
  multiValueHeaders: filterMultiValued(request.headers),
  httpMethod: request.method,
  isBase64Encoded: false,
  path: request.path,
  pathParameters: null,
  queryStringParameters: filterSingleValued(request.query),
  multiValueQueryStringParameters: filterMultiValued(request.query),
  stageVariables: null,
  requestContext: {
    accountId: "stub-account-id",
    apiId: "stub-api-id",
    authorizer: undefined,
    protocol: "http",
    httpMethod: request.method,
    identity: {
      accessKey: null,
      accountId: null,
      apiKey: null,
      apiKeyId: null,
      caller: null,
      clientCert: null,
      cognitoAuthenticationProvider: null,
      cognitoAuthenticationType: null,
      cognitoIdentityId: null,
      cognitoIdentityPoolId: null,
      principalOrgId: null,
      sourceIp: request.ip || "unknown",
      user: null,
      userAgent: null,
      userArn: null,
    },
    path: request.path,
    stage: "stub-stage",
    requestId: "stub-request-id",
    requestTimeEpoch: Date.now(),
    resourceId: "stub-resource-id",
    resourcePath: "stub-resource-path",
  },
  resource: "stub-resource",
});

const handleApiGatewayResult = (
  response: Response,
  result: APIGatewayProxyResult,
): void => {
  response.status(result.statusCode);
  Object.entries(result.headers ?? {}).forEach(([key, value]) =>
    response.header(key, value.toString()),
  );
  Object.entries(result.multiValueHeaders ?? {}).forEach(([key, value]) =>
    response.header(
      key,
      value.map((v) => v.toString()),
    ),
  );
  if (result.isBase64Encoded) {
    response.send(Buffer.from(result.body, "base64"));
  } else {
    response.send(result.body);
  }
};

type APIGatewayHandler = (
  event: APIGatewayProxyEvent,
) => Promise<APIGatewayProxyResult>;

export const apiGatewayRoute =
  (handler: APIGatewayHandler): RequestHandler =>
  async (req, res) => {
    const event = buildApiGatewayEvent(req);
    const result = await handler(event);
    handleApiGatewayResult(res, result);
  };

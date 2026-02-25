import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { HttpMethod } from "../types/enums.ts";
import { logger } from "../../logger.ts";
import {
  invalidAccessTokenResult,
  methodNotAllowedError,
  successfulJsonResult,
} from "../helpers/result-helper.ts";
import { getAMCAuthorizationResultWithAccessToken } from "../../services/dynamodb-service.ts";

export const handler = async (
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> => {
  switch (event.httpMethod) {
    case HttpMethod.GET:
      return get(event);
    default:
      throw methodNotAllowedError(event.httpMethod);
  }
};

async function get(event: APIGatewayProxyEvent) {
  logger.info("AMC journey outcome endpoint invoked!");

  const accessToken = getAccessToken(event);
  if (!accessToken) {
    logger.info("No access token found in event");
    return invalidAccessTokenResult();
  }

  const authorizationResult =
    await getAMCAuthorizationResultWithAccessToken(accessToken);

  if (!authorizationResult) {
    logger.info("No authorization result found for access token");
    return invalidAccessTokenResult();
  }

  return successfulJsonResult(200, authorizationResult);
}

function getAccessToken(event: APIGatewayProxyEvent): string | undefined {
  const authorization = event.headers["Authorization"];
  if (!authorization || !authorization.startsWith("Bearer ")) {
    return undefined;
  }
  return authorization.replace("Bearer ", "");
}

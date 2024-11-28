import {
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
  Handler,
} from "aws-lambda";
import {
  handleErrors,
  invalidAccessTokenResult,
  methodNotAllowedError,
  obfuscate,
  successfulJsonResult,
} from "../helper/result-helper";
import { getReverificationWithAccessToken } from "../services/dynamodb-form-response-service";
import { logger } from "../helper/logger";

export const handler: Handler = async (
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> => {
  return handleErrors(async () => {
    switch (event.httpMethod) {
      case "GET":
        return await get(event);
      default:
        throw methodNotAllowedError(event.httpMethod);
    }
  });
};

async function get(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const accessToken = getAccessToken(event);
  if (!accessToken) {
    logger.info("No access token found in event");
    return invalidAccessTokenResult();
  }

  logger.info(`Acess token: ${obfuscate(accessToken)}`);

  const reverification = await getReverificationWithAccessToken(accessToken);
  if (!reverification) {
    logger.info("No reverification result found for access token");
    return invalidAccessTokenResult();
  }

  return successfulJsonResult(200, reverification);
}

function getAccessToken(event: APIGatewayProxyEvent): string | undefined {
  const authorization = event.headers["Authorization"];
  if (!authorization || !authorization.startsWith("Bearer ")) {
    return undefined;
  }
  return authorization.replace("Bearer ", "");
}

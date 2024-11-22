import {
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
  Handler,
} from "aws-lambda";
import {
  handleErrors,
  invalidAccessTokenResult,
  methodNotAllowedError,
  successfulJsonResult,
} from "../helper/result-helper";
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

  return successfulJsonResult(200, {
    sub: "urn:fdc:gov.uk:2022:fake_common_subject_identifier",
    success: true,
  });
}

function getAccessToken(event: APIGatewayProxyEvent): string | undefined {
  const authorization = event.headers["Authorization"];
  if (!authorization || !authorization.startsWith("Bearer ")) {
    return undefined;
  }
  return authorization.replace("Bearer ", "");
}

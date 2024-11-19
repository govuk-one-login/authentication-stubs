import {
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
  Handler,
} from "aws-lambda";
import {
  handleErrors,
  methodNotAllowedError,
  successfulJsonResult,
} from "../helper/result-helper";

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
  _event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  return successfulJsonResult(200, {});
}

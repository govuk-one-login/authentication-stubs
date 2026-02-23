import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { HttpMethod } from "../types/enums.ts";
import { logger } from "../../logger.ts";
import {
  methodNotAllowedError,
  successfulJsonResult,
} from "../helpers/result-helper.ts";

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

function get(_event: APIGatewayProxyEvent) {
  logger.info("AMC journey outcome endpoint invoked!");

  return successfulJsonResult(200, {});
}

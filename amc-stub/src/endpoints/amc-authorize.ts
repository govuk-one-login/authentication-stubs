import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { logger } from "../../logger.js";
import { CodedError, successfulJsonResult } from "../helpers/result-helper.js";
import { HttpMethod } from "../types/enums.js";

export const handler = async (
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> => {
  switch (event.httpMethod) {
    case HttpMethod.GET:
      return get(event);
    case HttpMethod.POST:
      return post(event);
    default:
      throw methodNotAllowedError(event.httpMethod);
  }
};

function get(_event: APIGatewayProxyEvent) {
  return successfulJsonResult(200, { message: "Great success" });
}

function post(_event: APIGatewayProxyEvent) {
  return successfulJsonResult(200, {
    message: "To be implemented as part of AUT-5006",
  });
}

function methodNotAllowedError(method: string) {
  const sanitizedMethod = method?.replaceAll(/[\r\n\t]/g, "_") || "unknown";
  logger.info(`${sanitizedMethod} not allowed`);
  return new CodedError(405, `Method ${sanitizedMethod} not allowed`);
}

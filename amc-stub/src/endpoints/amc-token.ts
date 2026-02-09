import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { HttpMethod } from "../types/enums.ts";
import {
  methodNotAllowedError,
  successfulJsonResult,
} from "../helpers/result-helper.ts";

export const handler = async (
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> => {
  switch (event.httpMethod) {
    case HttpMethod.POST:
      return post(event);
    default:
      throw methodNotAllowedError(event.httpMethod);
  }
};

function post(_event: APIGatewayProxyEvent) {
  return successfulJsonResult(200, {
    message: "To be updated",
  });
}
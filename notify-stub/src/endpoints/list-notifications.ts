import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { logger } from "../helpers/logger.js";

export const handler = async (
  _event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> => {
  logger.info("List notifications endpoint invoked");
  return {
    statusCode: 200,
    headers: { "Content-Type": "text/html" },
    body: "OK",
  };
};

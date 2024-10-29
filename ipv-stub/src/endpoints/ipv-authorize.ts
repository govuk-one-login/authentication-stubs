import {
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
  Handler,
} from "aws-lambda";
// import { logger } from "./logger";
import renderIPVAuthorize from "./render-ipv-authorize";
import {
  CodedError,
  handleErrors,
  methodNotAllowedError,
  successfulHtmlResult,
} from "../helper/result-helper";

export const handler: Handler = async (
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> => {
  return handleErrors(async () => {
    switch (event.httpMethod) {
      case "GET":
        return await get(event);
      default: //The orch stub also handles posts. I don't know that we need this yet
        throw methodNotAllowedError(event.httpMethod);
    }
  });
};

async function get(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  // logger.info("IPV Authorize GET endpoint invoked!");

  if (event.queryStringParameters == null) {
    throw new CodedError(400, "Query string parameters are null");
  }

  //This is a first pass, will be changed to encrypted
  const plaintextJwt = event.queryStringParameters["request"] as string;
  if (!plaintextJwt) {
    throw new CodedError(400, "Request query string parameter not found");
  }

  const parts = plaintextJwt.split(".");
  if (parts.length !== 3) {
    throw new CodedError(400, "Decrypted JWT is in invalid format");
  }

  const [decodedHeader, decodedPayload, _decodedSignature] = parts.map((part) =>
    Buffer.from(part, "base64url").toString("utf8")
  );

  //here in the orch stub they save a code to dynamo. We don't need to do this yet I don't think

  return successfulHtmlResult(
    200,
    renderIPVAuthorize(decodedHeader, decodedPayload)
  );
}

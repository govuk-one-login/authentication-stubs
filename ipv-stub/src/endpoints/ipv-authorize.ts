import {
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
  Handler,
} from "aws-lambda";
import { logger } from "../helper/logger";
import renderIPVAuthorize from "./render-ipv-authorize";
import {
  CodedError,
  handleErrors,
  methodNotAllowedError,
  successfulHtmlResult,
  successfulJsonResult,
} from "../helper/result-helper";
import { compactDecrypt, importPKCS8 } from "jose";
import { parseRequest } from "../helper/jwt-validator";
import { AUTH_CODE, ROOT_URI } from "../data/ipv-dummy-constants";
import { putStateWithAuthCode } from "../services/dynamodb-form-response-service";

export const handler: Handler = async (
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> => {
  return handleErrors(async () => {
    switch (event.httpMethod) {
      case "GET":
        return await get(event);
      case "POST":
        return await post(event);
      default:
        throw methodNotAllowedError(event.httpMethod);
    }
  });
};

async function get(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  logger.info("IPV Authorize GET endpoint invoked!");

  if (event.queryStringParameters == null) {
    throw new CodedError(400, "Query string parameters are null");
  }

  const encryptedJwt = event.queryStringParameters["request"] as string;
  if (!encryptedJwt) {
    throw new CodedError(400, "Request query string parameter not found");
  }
  const ipvPrivateKeyPem = process.env.IPV_AUTHORIZE_PRIVATE_ENCRYPTION_KEY;
  if (!ipvPrivateKeyPem) {
    throw new CodedError(500, "Private key not found");
  }
  const privateKey = await importPKCS8(ipvPrivateKeyPem, "RSA-OAEP-256");

  const { plaintext } = await compactDecrypt(encryptedJwt, privateKey);
  const encodedJwt = plaintext.toString();

  const parts = encodedJwt.split(".");

  if (parts.length !== 3) {
    throw new CodedError(400, "Decrypted JWT is in invalid format");
  }

  const [decodedHeader, decodedPayload, _decodedSignature] = parts.map((part) =>
    Buffer.from(part, "base64url").toString("utf8")
  );

  const parsedRequestOrError = parseRequest(decodedPayload);

  if (typeof parsedRequestOrError === "string") {
    //here in the orch stub they save a code to dynamo. We don't need to do this yet I don't think
    throw new CodedError(400, parsedRequestOrError);
  } else {
    try {
      await putStateWithAuthCode(AUTH_CODE, parsedRequestOrError.state);
    } catch (error) {
      throw new CodedError(500, `dynamoDb error: ${error}`);
    }

    return successfulHtmlResult(
      200,
      renderIPVAuthorize(decodedHeader, parsedRequestOrError)
    );
  }
}

async function post(
  _event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const redirectUri = `${ROOT_URI}/ipv/callback/authorize`;

  const url = new URL(redirectUri);
  url.searchParams.append("code", AUTH_CODE);

  return Promise.resolve(
    successfulJsonResult(
      302,
      {
        message: `Redirecting to ${url.toString()}`,
      },
      {
        Location: url.toString(),
      }
    )
  );
}

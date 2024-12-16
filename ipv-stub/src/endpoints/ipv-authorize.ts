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
import { base64url, compactDecrypt, importPKCS8 } from "jose";
import { validateNestedJwt } from "../helper/jwt-validator";
import { ROOT_URI } from "../data/ipv-dummy-constants";
import { putReverificationWithAuthCode } from "../services/dynamodb-form-response-service";
import { randomBytes } from "crypto";
import { processJoseError } from "../helper/error-helper";
import { Reverification } from "../interfaces/reverification-interface";

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
  const ipvPrivateEncryptionKey = process.env.IPV_PRIVATE_ENCRYPTION_KEY;
  if (!ipvPrivateEncryptionKey) {
    throw new CodedError(500, "IPV Private Encryption key not found");
  }
  const privateKey = await importPKCS8(ipvPrivateEncryptionKey, "RSA-OAEP-256");

  let plaintext, protectedHeader;
  try {
    ({ plaintext, protectedHeader } = await compactDecrypt(
      encryptedJwt,
      privateKey
    ));
  } catch (error) {
    processJoseError(error);
  }

  if (plaintext === undefined || protectedHeader === undefined) {
    throw new CodedError(500, "compactDecrypt returned undefined values");
  }

  const encodedJwt = plaintext.toString();

  const parsedRequestOrError = await validateNestedJwt(encodedJwt);

  if (typeof parsedRequestOrError === "string") {
    throw new CodedError(400, parsedRequestOrError);
  }

  return successfulHtmlResult(
    200,
    renderIPVAuthorize(protectedHeader.alg, parsedRequestOrError)
  );
}

async function post(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const redirectUri = `${ROOT_URI}/ipv/callback/authorize`;

  if (event.body == null) {
    throw new CodedError(400, "Missing request body");
  }

  const parsedBody = event.body
    ? Object.fromEntries(new URLSearchParams(event.body))
    : {};

  const state = parsedBody["state"];
  if (!state) {
    throw new CodedError(500, "state not found");
  }

  const authCode = base64url.encode(randomBytes(32));
  const sub = parsedBody["sub"];

  const url = new URL(redirectUri);
  url.searchParams.append("state", state);
  url.searchParams.append("code", authCode);

  const response = parsedBody["response"];

  const reverification: Reverification = {
    sub,
    ...(response === "success"
      ? { success: true }
      : {
          success: false,
          failure_code: response,
          failure_description: `${response} error has occurred`,
        }),
  };

  try {
    await putReverificationWithAuthCode(authCode, reverification);
  } catch (error) {
    throw new CodedError(
      500,
      `dynamoDb error on storing reverification with auth code: ${error}`
    );
  }

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

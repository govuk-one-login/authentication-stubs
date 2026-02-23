import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { logger } from "../../logger.ts";
import {
  CodedError,
  successfulHtmlResult,
  successfulJsonResult,
} from "../helpers/result-helper.ts";
import { HttpMethod } from "../types/enums.ts";
import { base64url, compactDecrypt, importPKCS8 } from "jose";
import { processJoseError } from "../helpers/error-helper.ts";
import { validateCompositeJWT } from "../helpers/jwt-validator.ts";
import renderAmcAuthorize from "./render-amc-authorize.ts";
import { randomBytes } from "crypto";
import { AMCAuthorizationResult } from "../types/types.ts";
import { putAMCAuthorizationResultWithAuthCode } from "../../services/dynamodb-service.ts";

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

async function get(event: APIGatewayProxyEvent) {
  logger.info("AMC Authorize GET endpoint invoked!");

  if (event.queryStringParameters == null) {
    throw new CodedError(400, "Query string parameters are null");
  }

  const encryptedJwt = event.queryStringParameters["request"] as string;
  if (!encryptedJwt) {
    throw new CodedError(400, "Request query string parameter not found");
  }

  const amcPrivateEncryptionKey = process.env.AMC_PRIVATE_ENCRYPTION_KEY;
  if (!amcPrivateEncryptionKey) {
    throw new CodedError(500, "Private encryption key not found");
  }
  const privateKey = await importPKCS8(amcPrivateEncryptionKey, "RSA-OAEP-256");

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

  const textDecoder = new TextDecoder();
  const encodedJwt = textDecoder.decode(plaintext);

  const parsedRequestOrError = await validateCompositeJWT(encodedJwt);

  if (typeof parsedRequestOrError === "string") {
    logger.error("JWT validation failed", { error: parsedRequestOrError });
    throw new CodedError(400, parsedRequestOrError);
  }

  return successfulHtmlResult(
    200,
    renderAmcAuthorize(protectedHeader.alg, parsedRequestOrError.payload)
  );
}

async function post(event: APIGatewayProxyEvent) {
  logger.info("AMC Authorize POST endpoint invoked!");

  if (event.body == null) {
    throw new CodedError(400, "Missing request body");
  }

  const parsedBody = event.body
    ? Object.fromEntries(new URLSearchParams(event.body))
    : {};

  const redirectUri = parsedBody["redirect_uri"];
  if (!redirectUri) {
    throw new CodedError(500, "redirect_uri not found");
  }

  const state = parsedBody["state"];
  if (!state) {
    throw new CodedError(500, "state not found");
  }

  const authCode = base64url.encode(randomBytes(32));
  const sub = parsedBody["sub"];
  const response = parsedBody["response"];

  const url = new URL(redirectUri);
  url.searchParams.append("state", state);
  url.searchParams.append("code", authCode);

  const amcAuthorizationResult: AMCAuthorizationResult = {
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
    await putAMCAuthorizationResultWithAuthCode(
      authCode,
      amcAuthorizationResult
    );
  } catch (error) {
    throw new CodedError(
      500,
      `dynamoDb error on storing reverification with auth code: ${error}`
    );
  }

  return successfulJsonResult(
    302,
    {
      message: `Redirecting to ${url.toString()}`,
    },
    {
      Location: url.toString(),
    }
  );
}

function methodNotAllowedError(method: string) {
  const sanitizedMethod = method?.replaceAll(/[\r\n\t]/g, "_") || "unknown";
  logger.info(`${sanitizedMethod} not allowed`);
  return new CodedError(405, `Method ${sanitizedMethod} not allowed`);
}

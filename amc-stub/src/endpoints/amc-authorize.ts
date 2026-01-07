import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { logger } from "../../logger.ts";
import {
  CodedError,
  successfulHtmlResult,
  successfulJsonResult,
} from "../helpers/result-helper.ts";
import { HttpMethod } from "../types/enums.ts";
import { compactDecrypt, importPKCS8 } from "jose";
import { processJoseError } from "../helpers/error-helper.ts";
import { validateCompositeJWT } from "../helpers/jwt-validator.ts";
import renderAmcAuthorize from "./render-amc-authorize.ts";

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
  logger.info("IPV Authorize GET endpoint invoked!");

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
    throw new CodedError(400, parsedRequestOrError);
  }

  return successfulHtmlResult(
    200,
    renderAmcAuthorize(protectedHeader.alg, parsedRequestOrError.payload)
  );
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

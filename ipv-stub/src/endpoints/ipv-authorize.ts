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
import * as jose from "jose";
import { parseRequest } from "../helper/jwt-validator";
import { AUTH_CODE, ROOT_URI } from "../data/ipv-dummy-constants";
import { putStateWithAuthCode } from "../services/dynamodb-form-response-service";
import { randomBytes } from "crypto";
import process from "node:process";

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
  const privateKey = await jose.importPKCS8(ipvPrivateKeyPem, "RSA-OAEP-256");

  const { plaintext } = await jose.compactDecrypt(encryptedJwt, privateKey);
  const encodedJwt = plaintext.toString();

  const authSignaturePublicKey = process.env.AUTH_PUBLIC_SIGNING_KEY;
  if (!authSignaturePublicKey) {
    throw new CodedError(500, "Auth signing public key not found");
  }

  const publicJwk = await jose.importSPKI(authSignaturePublicKey, "RS256")

  let payload, header, decodedHeader, decodedPayload;
  try {
    ({ payload: payload, protectedHeader: header } = await jose.compactVerify(
      encodedJwt,
      publicJwk
    ));
    const textDecoder = new TextDecoder("utf-8");
    decodedPayload = textDecoder.decode(payload);
    decodedHeader = textDecoder.decode(
      new TextEncoder().encode(JSON.stringify(header))
    );

    console.log(decodedPayload);
    console.log(decodedHeader);

  } catch (error) {
    if (error instanceof jose.errors.JOSEError) {
      throw new CodedError(400, error.code);
    } else {
      throw new CodedError(400, "Unknown error.");
    }
  }

  const parsedRequestOrError = parseRequest(decodedPayload);

  const authCode = jose.base64url.encode(randomBytes(32));

  if (typeof parsedRequestOrError === "string") {
    //here in the orch stub they save a code to dynamo. We don't need to do this yet I don't think
    throw new CodedError(400, parsedRequestOrError);
  } else {
    try {
      await putStateWithAuthCode(authCode, parsedRequestOrError.state);
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

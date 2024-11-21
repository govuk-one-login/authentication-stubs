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
import { parseRequest } from "../helper/jwt-validator";
import { ROOT_URI } from "../data/ipv-dummy-constants";
import { putReverificationWithAuthCode } from "../services/dynamodb-form-response-service";
import { randomBytes } from "crypto";

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
    throw new CodedError(400, parsedRequestOrError);
  }

  return successfulHtmlResult(
    200,
    renderIPVAuthorize(decodedHeader, parsedRequestOrError)
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

  const url = new URL(redirectUri);
  url.searchParams.append("state", state);
  url.searchParams.append("code", authCode);

  const reverification = {
    sub: "urn:fdc:gov.uk:2022:fake_common_subject_identifier",
    success: true,
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

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
import { AUTH_CODE, ROOT_URI } from "../data/ipv-dummy-constants";
import {
  getStateWithAuthCode,
  putStateWithAuthCode,
} from "../services/dynamodb-form-response-service";
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

  const authCode = base64url.encode(randomBytes(32));

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
      renderIPVAuthorize(decodedHeader, parsedRequestOrError, authCode)
    );
  }
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
  const authCode = parsedBody["authCode"];

  const url = new URL(redirectUri);
  url.searchParams.append("code", authCode);

  try {
    const state = await getStateWithAuthCode(authCode);
    if (state) {
      logger.info("state: " + state);
      url.searchParams.append("state", state);
    } else {
      logger.info("State not found or is not a string.");
      throw new CodedError(400, "State not found");
    }
  } catch (error) {
    throw new CodedError(500, `dynamoDb error: ${error}`);
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

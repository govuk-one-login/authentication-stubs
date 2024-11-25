import {
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
  Handler,
} from "aws-lambda";
import jwt, { JwtPayload } from "jsonwebtoken";
import {
  handleErrors,
  methodNotAllowedError,
  successfulJsonResult,
} from "../helper/result-helper";
import { logger } from "../helper/logger";
import {
  getReverificationWithAuthCode,
  putReverificationWithAccessToken,
} from "../services/dynamodb-form-response-service";
import { base64url } from "jose";
import { randomBytes } from "crypto";

export const handler: Handler = async (
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> => {
  logger.info("Reached the token endpoint!!!");
  return await handleErrors(async () => {
    switch (event.httpMethod) {
      case "POST":
        logger.info("POST event");
        return await handle(event);
      default:
        throw methodNotAllowedError(event.httpMethod);
    }
  });
};

async function handle(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  logger.info(`handle event: ${event}`);

  var params;
  var client_assertion;
  var code;
  try {
    params = new URLSearchParams(event.body || "");

    code = params.get("code");
    var result = checkDefinedOrError(code, "code");
    if (!result.success) return result.errorResponse;

    const client_id = params.get("client_id");
    result = checkDefinedOrError(client_id, "client_id");
    if (!result.success) return result.errorResponse;

    const client_assertion_type = params.get("client_assertion_type");
    result = checkDefinedOrError(
      client_assertion_type,
      "client_assertion_type"
    );
    if (!result.success) return result.errorResponse;

    client_assertion = params.get("client_assertion");

    if (!client_assertion) {
      return {
        statusCode: 400,
        headers: {},
        body: "Missing client_assertion",
      };
    }
  } catch (e) {
    logger.info(`Error ${e} checking event contents.`);
  }

  if (params) {
    logger.info(">>>PARAMS>>>");
    params.forEach((value, key) => {
      logger.info(`${key}: ${value}`);
    });
    logger.info("<<<PARAMS<<<");
  } else {
    logger.info("no params");
  }

  const decoded = await verifyJWT(client_assertion as string);
  const claims = decoded as JwtPayload;

  if (client_assertion) {
    logger.info(">>>CLAIMS>>>");
    Object.entries(claims).forEach(([key, value]) => {
      logger.info(`${key}: ${value}`);
    });
    logger.info("<<<CLAIMS<<<");
  } else {
    logger.info("no claims");
  }

  const reverificationResult = await getReverificationWithAuthCode(
    code as string
  );

  logger.info(`reverification result: ${reverificationResult}`);

  var accessToken;
  if (reverificationResult) {
    logger.info("Found reverification result record");
    const reverification = {
      sub: claims["sub"] as string,
      success: true,
    };
    accessToken = base64url.encode(randomBytes(32));
    await putReverificationWithAccessToken(accessToken, reverification);
  } else {
    logger.info("Did not find reverification result record");
  }

  // If exists return an access token.

  return successfulJsonResult(200, {
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 3600,
  });
}

const public_key = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDn0sV329oTHdahzIuUSWS2xw5GVE
IKUQ9FPvvEDsNKofkw3n7hy1orQQ0XucyhLAcJy0mofJ3fwbjIZEgKBfUw==
-----END PUBLIC KEY-----
`.trim();

const verifyJWT = async (token: string): Promise<JwtPayload> => {
  const decoded = jwt.verify(token, public_key, { algorithms: ["ES256"] });

  if (typeof decoded === "object" && decoded !== null) {
    return decoded as JwtPayload;
  } else {
    throw new Error("Invalid token payload");
  }
};

type ResultOrError<T> =
  | { success: true; data: T }
  | { success: false; errorResponse: { statusCode: number; body: string } };

function checkDefinedOrError<T>(
  variable: T | undefined,
  name: string
): ResultOrError<T> {
  if (variable === undefined) {
    return {
      success: false,
      errorResponse: { statusCode: 400, body: `${name} is missing.` },
    };
  } else {
    return { success: true, data: variable };
  }
}

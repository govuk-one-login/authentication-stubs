import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { logger } from "../../logger.ts";
import {
  CodedError,
  successfulHtmlResult,
  successfulJsonResult,
} from "../helpers/result-helper.ts";
import { AMCScopes, HttpMethod } from "../types/enums.ts";
import { base64url, compactDecrypt, importPKCS8 } from "jose";
import { processJoseError } from "../helpers/error-helper.ts";
import { validateCompositeJWT } from "../helpers/jwt-validator.ts";
import renderAmcAuthorize from "./render-amc-authorize.ts";
import { randomBytes } from "crypto";
import {
  AMCAuthorizationResult,
  AMCAuthorizeResponse,
  AMCJourney,
  ParsedBody,
} from "../types/types.ts";
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

  if (!event.queryStringParameters["scope"]) {
    throw new CodedError(400, "scope query string parameter not found");
  }

  if (!event.queryStringParameters["redirect_uri"]) {
    throw new CodedError(400, "redirect_uri query string parameter not found");
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

  const scope = parsedRequestOrError.payload.scope as AMCScopes;

  return successfulHtmlResult(
    200,
    renderAmcAuthorize(protectedHeader.alg, parsedRequestOrError.payload, scope)
  );
}

async function post(event: APIGatewayProxyEvent) {
  logger.info("AMC Authorize POST endpoint invoked!");

  if (event.body == null) {
    throw new CodedError(400, "Missing request body");
  }

  const parsedBody = (event.body
    ? Object.fromEntries(new URLSearchParams(event.body))
    : {}) as unknown as ParsedBody;

  const redirectUri = parsedBody["redirect_uri"];
  if (!redirectUri) {
    throw new CodedError(500, "redirect_uri not found");
  }

  const state = parsedBody.state;
  if (!state) {
    throw new CodedError(500, "state not found");
  }

  const authCode = base64url.encode(randomBytes(32));

  const url = new URL(redirectUri);
  url.searchParams.append("state", state);
  url.searchParams.append("code", authCode);

  const amcAuthorizationResult: AMCAuthorizationResult = buildAMCOutcome(
    parsedBody.sub,
    parsedBody.response,
    parsedBody.email,
    parsedBody.scope
  );

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

function buildAMCOutcome(
  sub: string,
  response: AMCAuthorizeResponse,
  email: string,
  scope: AMCScopes
): AMCAuthorizationResult {
  const randomOutcomeId = base64url.encode(randomBytes(32));
  const isSuccess = response === "success";

  let details = {};
  if (!isSuccess) {
    const errorDescription = responseToErrorDescriptionMap[scope]?.[response];
    if (!errorDescription) {
      throw new CodedError(
        500,
        `Cannot find error description for response: ${response}`
      );
    }
    details = {
      error: {
        code: 1001,
        description: errorDescription,
      },
    };
  }

  const journey: AMCJourney = {
    journey: scope,
    timestamp: Date.now(),
    success: isSuccess,
    details,
  };

  return {
    sub: sub,
    outcome_id: randomOutcomeId,
    email,
    scope,
    success: isSuccess,
    journeys: [journey],
  };
}

const responseToErrorDescriptionMap: Record<
  AMCScopes,
  Record<string, string>
> = {
  [AMCScopes.PASSKEY_CREATE]: {
    back: "UserBackedOutOfJourney",
    skip: "UserAbortedJourney",
  },
  [AMCScopes.ACCOUNT_DELETE]: {},
};

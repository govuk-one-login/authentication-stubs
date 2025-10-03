import {
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
  Handler,
} from "aws-lambda";
import { logger } from "../helper/logger";
import {
  handleErrors,
  methodNotAllowedError,
  successfulJsonResult,
  CodedError,
} from "../helper/result-helper";
import { exportJWK, importSPKI } from "jose";

export const handler: Handler = async (
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> => {
  return handleErrors(async () => {
    if (event.httpMethod !== "GET") {
      throw methodNotAllowedError(event.httpMethod);
    }

    logger.info("JWKS endpoint invoked");

    const encryptionPublicKeyPem = process.env.IPV_PUBLIC_ENCRYPTION_KEY;
    if (!encryptionPublicKeyPem) {
      throw new CodedError(500, "Public encryption key not configured");
    }

    const encryptionPublicKeyJwk = await publicKeyPemToJwk(
      encryptionPublicKeyPem,
      "RS256"
    );

    const jwks = {
      keys: [encryptionPublicKeyJwk],
    };

    return successfulJsonResult(200, jwks);
  });
};

async function publicKeyPemToJwk(pemPublicKey: string, algorithm: string) {
  const publicKey = await importSPKI(pemPublicKey, algorithm);

  const publicJwk = await exportJWK(publicKey);
  publicJwk.use = "enc";
  publicJwk.alg = algorithm;
  publicJwk.kid = "ipv-stub-public-encryption-key";

  return publicJwk;
}

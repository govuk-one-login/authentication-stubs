import {
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
  Handler,
} from "aws-lambda";
import { KMSClient, GetPublicKeyCommand } from "@aws-sdk/client-kms";
import { logger } from "../helper/logger";
import {
  CodedError,
  handleErrors,
  methodNotAllowedError,
  successfulJsonResult,
} from "../helper/result-helper";

const kmsClient = new KMSClient({
  region: process.env.AWS_REGION || "eu-west-2",
});

export const handler: Handler = async (
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> => {
  return handleErrors(async () => {
    switch (event.httpMethod) {
      case "GET":
        return await get();
      default:
        throw methodNotAllowedError(event.httpMethod);
    }
  });
};

async function get(): Promise<APIGatewayProxyResult> {
  logger.info("JWKS endpoint invoked");

  const kmsKeyId = process.env.KMS_KEY_ID;
  if (!kmsKeyId) {
    throw new CodedError(500, "KMS key ID not configured");
  }

  try {
    const command = new GetPublicKeyCommand({ KeyId: kmsKeyId });
    const response = await kmsClient.send(command);

    if (!response.PublicKey || !response.KeyUsage || !response.KeySpec) {
      throw new CodedError(500, "Invalid KMS key response");
    }

    // Convert DER to JWK format
    const publicKeyDer = new Uint8Array(response.PublicKey);
    const jwk = await derToJwk(publicKeyDer, response.KeySpec);

    const jwks = {
      keys: [jwk],
    };

    return successfulJsonResult(200, jwks, {
      "Cache-Control": "public, max-age=3600",
      "Content-Type": "application/json",
    });
  } catch (error) {
    logger.error(`Failed to get public key from KMS: ${error}`);
    logger.info("Falling back to empty JWKS response");

    // Return empty JWKS when KMS fails
    const fallbackJwks = {
      keys: [],
    };

    return successfulJsonResult(200, fallbackJwks, {
      "Cache-Control": "public, max-age=300",
      "Content-Type": "application/json",
    });
  }
}

async function derToJwk(
  der: Uint8Array,
  _keySpec: string
): Promise<Record<string, unknown>> {
  // For RSA keys, extract modulus and exponent from DER
  // This is a simplified implementation - in production, use a proper ASN.1 parser
  const base64Der = Buffer.from(der).toString("base64");

  // Generate a key ID based on the DER data
  const crypto = await import("crypto");
  const kid = crypto
    .createHash("sha256")
    .update(der)
    .digest("hex")
    .substring(0, 16);

  return {
    kty: "RSA",
    use: "enc",
    alg: "RSA-OAEP-256",
    kid: kid,
    // In a real implementation, you would parse the DER to extract n and e
    // For now, we'll use the base64-encoded DER as a placeholder
    x5c: [base64Der],
  };
}

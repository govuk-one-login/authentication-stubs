import {
  KMSClient,
  GetPublicKeyCommand,
  DecryptCommand,
} from "@aws-sdk/client-kms";
import { SecretsManagerClient } from "@aws-sdk/client-secrets-manager";
import { importPKCS8, KeyLike } from "jose";
import { CodedError } from "../helper/result-helper";
import { logger } from "../helper/logger";

export class HybridEncryptionService {
  protected static kmsClient = new KMSClient({
    region: process.env.AWS_REGION || "eu-west-2",
  });
  protected static secretsClient = new SecretsManagerClient({});

  public static async getPrivateKey(): Promise<KeyLike> {
    // Check environment variable first (override)
    const envKey = process.env.IPV_PRIVATE_ENCRYPTION_KEY;
    if (envKey) {
      logger.info("Using environment variable for private encryption key");
      return await importPKCS8(envKey, "RSA-OAEP-256");
    }

    // Fall back to KMS
    const kmsKeyId = process.env.KMS_KEY_ID;
    if (!kmsKeyId) {
      throw new CodedError(
        500,
        "No encryption key available - neither environment variable nor KMS key ID configured"
      );
    }

    logger.info("Using KMS for private encryption key");
    // For KMS, we don't actually get the private key - we use KMS decrypt directly
    // This is a placeholder that indicates KMS should be used
    return { type: "kms", keyId: kmsKeyId } as { type: string; keyId: string };
  }

  public static async getPublicKey(): Promise<KeyLike> {
    const kmsKeyId = process.env.KMS_KEY_ID;
    if (!kmsKeyId) {
      throw new CodedError(500, "KMS key ID not configured");
    }

    try {
      const command = new GetPublicKeyCommand({ KeyId: kmsKeyId });
      const response = await this.kmsClient.send(command);

      if (!response.PublicKey) {
        throw new CodedError(500, "No public key returned from KMS");
      }

      // Convert DER to PEM format
      const publicKeyDer = new Uint8Array(response.PublicKey);
      const publicKeyPem = this.derToPem(publicKeyDer, "PUBLIC KEY");

      return await importPKCS8(publicKeyPem, "RSA-OAEP-256");
    } catch (error) {
      logger.error(`Failed to get public key from KMS: ${error}`);
      throw new CodedError(500, `Failed to get public key from KMS: ${error}`);
    }
  }

  public static async decrypt(encryptedData: Uint8Array): Promise<Uint8Array> {
    // Check if we should use environment variable
    const envKey = process.env.IPV_PRIVATE_ENCRYPTION_KEY;
    if (envKey) {
      // Use JOSE for environment variable decryption
      throw new CodedError(
        500,
        "Environment variable decryption should use JOSE directly"
      );
    }

    // Use KMS for decryption
    const kmsKeyId = process.env.KMS_KEY_ID;
    if (!kmsKeyId) {
      throw new CodedError(500, "KMS key ID not configured");
    }

    try {
      const command = new DecryptCommand({
        KeyId: kmsKeyId,
        CiphertextBlob: encryptedData,
        EncryptionAlgorithm: "RSAES_OAEP_SHA_256",
      });

      const response = await this.kmsClient.send(command);

      if (!response.Plaintext) {
        throw new CodedError(500, "No plaintext returned from KMS decrypt");
      }

      return new Uint8Array(response.Plaintext);
    } catch (error) {
      logger.error(`Failed to decrypt with KMS: ${error}`);
      throw new CodedError(500, `Failed to decrypt with KMS: ${error}`);
    }
  }

  private static derToPem(der: Uint8Array, type: string): string {
    const base64 = Buffer.from(der).toString("base64");
    const lines = base64.match(/.{1,64}/g) || [];
    return `-----BEGIN ${type}-----\n${lines.join("\n")}\n-----END ${type}-----`;
  }
}

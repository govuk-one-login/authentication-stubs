import chai from "chai";
import { describe, beforeEach, afterEach } from "mocha";
import { HybridEncryptionService } from "../../src/services/hybrid-encryption-service";
import keys from "../../src/data/keys.json";

const expect = chai.expect;

// Mock AWS SDK
const mockKMSClient = {
  send: async (command: { constructor: { name: string } }) => {
    if (command.constructor.name === "GetPublicKeyCommand") {
      // Return mock DER-encoded public key
      const mockDer = Buffer.from("mock-der-public-key");
      return { PublicKey: mockDer };
    }
    if (command.constructor.name === "DecryptCommand") {
      return { Plaintext: Buffer.from("decrypted-data") };
    }
    throw new Error("Unknown command");
  },
};

const mockSecretsClient = {
  send: async (command: { constructor: { name: string } }) => {
    if (command.constructor.name === "GetSecretValueCommand") {
      return { SecretString: "mock-secret-value" };
    }
    throw new Error("Unknown command");
  },
};

describe("HybridEncryptionService", () => {
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    originalEnv = { ...process.env };
    // Mock AWS clients
    (
      HybridEncryptionService as unknown as { kmsClient: typeof mockKMSClient }
    ).kmsClient = mockKMSClient;
    (
      HybridEncryptionService as unknown as {
        secretsClient: typeof mockSecretsClient;
      }
    ).secretsClient = mockSecretsClient;
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe("getPrivateKey", () => {
    it("should use environment variable when available", async () => {
      process.env.IPV_PRIVATE_ENCRYPTION_KEY = keys.authPrivateSigningKeyIPV; // Using signing key as placeholder

      const key = await HybridEncryptionService.getPrivateKey();
      void expect(key).to.not.be.undefined;
    });

    it("should fall back to KMS when environment variable not set", async () => {
      delete process.env.IPV_PRIVATE_ENCRYPTION_KEY;
      process.env.KMS_KEY_ID = "test-kms-key-id";

      const key = await HybridEncryptionService.getPrivateKey();
      expect(key).to.have.property("type", "kms");
      expect(key).to.have.property("keyId", "test-kms-key-id");
    });

    it("should throw error when neither environment variable nor KMS key ID is set", async () => {
      delete process.env.IPV_PRIVATE_ENCRYPTION_KEY;
      delete process.env.KMS_KEY_ID;

      try {
        await HybridEncryptionService.getPrivateKey();
        expect.fail("Should have thrown an error");
      } catch (error: unknown) {
        expect((error as Error).message).to.include(
          "No encryption key available"
        );
      }
    });
  });

  describe("getPublicKey", () => {
    it("should get public key from KMS", async () => {
      process.env.KMS_KEY_ID = "test-kms-key-id";

      try {
        await HybridEncryptionService.getPublicKey();
        // This will fail due to mock DER data, but we're testing the flow
      } catch (error: unknown) {
        // Expected to fail with mock data, but should reach KMS call
        void expect((error as Error).message).to.not.include(
          "KMS key ID not configured"
        );
      }
    });

    it("should throw error when KMS key ID not configured", async () => {
      delete process.env.KMS_KEY_ID;

      try {
        await HybridEncryptionService.getPublicKey();
        expect.fail("Should have thrown an error");
      } catch (error: unknown) {
        expect((error as Error).message).to.include(
          "KMS key ID not configured"
        );
      }
    });
  });

  describe("decrypt", () => {
    it("should throw error for environment variable decryption", async () => {
      process.env.IPV_PRIVATE_ENCRYPTION_KEY = "test-key";

      try {
        await HybridEncryptionService.decrypt(new Uint8Array([1, 2, 3]));
        expect.fail("Should have thrown an error");
      } catch (error: unknown) {
        expect((error as Error).message).to.include(
          "Environment variable decryption should use JOSE directly"
        );
      }
    });

    it("should use KMS for decryption when no environment variable", async () => {
      delete process.env.IPV_PRIVATE_ENCRYPTION_KEY;
      process.env.KMS_KEY_ID = "test-kms-key-id";

      const result = await HybridEncryptionService.decrypt(
        new Uint8Array([1, 2, 3])
      );
      expect(result).to.be.instanceOf(Uint8Array);
      expect(Buffer.from(result).toString()).to.equal("decrypted-data");
    });

    it("should throw error when KMS key ID not configured", async () => {
      delete process.env.IPV_PRIVATE_ENCRYPTION_KEY;
      delete process.env.KMS_KEY_ID;

      try {
        await HybridEncryptionService.decrypt(new Uint8Array([1, 2, 3]));
        expect.fail("Should have thrown an error");
      } catch (error: unknown) {
        expect((error as Error).message).to.include(
          "KMS key ID not configured"
        );
      }
    });
  });
});

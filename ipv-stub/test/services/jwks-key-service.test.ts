import chai from "chai";
import { describe, beforeEach, afterEach } from "mocha";
import { JwksKeyService, KeyType } from "../../src/services/jwks-key-service";
import { importSPKI, exportJWK, calculateJwkThumbprint } from "jose";
import keys from "../../src/data/keys.json";

const expect = chai.expect;

describe("JwksKeyService", () => {
  let originalFetch: typeof global.fetch;
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    originalFetch = global.fetch;
    originalEnv = { ...process.env };
  });

  afterEach(() => {
    global.fetch = originalFetch;
    process.env = originalEnv;
  });

  describe("getSigningKey", () => {
    it("should use environment variable override for IPV key", async () => {
      process.env.AUTH_PUBLIC_SIGNING_KEY_IPV = keys.authPublicSigningKeyIPV;

      const key = await JwksKeyService.getSigningKey(KeyType.IPV);
      void expect(key).to.not.be.undefined;
    });

    it("should use environment variable override for EVCS key", async () => {
      process.env.AUTH_PUBLIC_SIGNING_KEY_EVCS = keys.authPublicSigningKeyEVCS;

      const key = await JwksKeyService.getSigningKey(KeyType.EVCS);
      void expect(key).to.not.be.undefined;
    });

    it("should fetch from JWKS when no environment variable is set", async () => {
      delete process.env.AUTH_PUBLIC_SIGNING_KEY_IPV;
      process.env.AUTH_IPV_PUBLIC_SIGNING_KEY_JWKS_ENDPOINT =
        "https://example.com/.well-known/jwks.json";

      const publicKey = await exportJWK(
        await importSPKI(keys.authPublicSigningKeyIPV, "ES256")
      );
      const kid = await calculateJwkThumbprint(publicKey, "sha256");
      const mockJwks = { keys: [{ ...publicKey, kid }] };

      global.fetch = async () =>
        ({
          ok: true,
          json: async () => mockJwks,
        }) as Response;

      const key = await JwksKeyService.getSigningKey(KeyType.IPV, kid);
      void expect(key).to.not.be.undefined;
    });

    it("should use first key when no kid is provided", async () => {
      delete process.env.AUTH_PUBLIC_SIGNING_KEY_IPV;
      process.env.AUTH_IPV_PUBLIC_SIGNING_KEY_JWKS_ENDPOINT =
        "https://example.com/.well-known/jwks.json";

      const publicKey = await exportJWK(
        await importSPKI(keys.authPublicSigningKeyIPV, "ES256")
      );
      const mockJwks = { keys: [publicKey] };

      global.fetch = async () =>
        ({
          ok: true,
          json: async () => mockJwks,
        }) as Response;

      const key = await JwksKeyService.getSigningKey(KeyType.IPV);
      void expect(key).to.not.be.undefined;
    });

    it("should throw error when kid not found in JWKS", async () => {
      delete process.env.AUTH_PUBLIC_SIGNING_KEY_IPV;
      process.env.AUTH_IPV_PUBLIC_SIGNING_KEY_JWKS_ENDPOINT =
        "https://example.com/.well-known/jwks.json";

      const mockJwks = { keys: [] };
      global.fetch = async () =>
        ({
          ok: true,
          json: async () => mockJwks,
        }) as Response;

      try {
        await JwksKeyService.getSigningKey(KeyType.IPV, "nonexistent-kid");
        expect.fail("Should have thrown an error");
      } catch (error: unknown) {
        expect((error as Error).message).to.include(
          "No signing key available for IPV"
        );
      }
    });

    it("should throw error when JWKS fetch fails", async () => {
      delete process.env.AUTH_PUBLIC_SIGNING_KEY_IPV;
      process.env.AUTH_IPV_PUBLIC_SIGNING_KEY_JWKS_ENDPOINT =
        "https://example.com/.well-known/jwks.json";

      global.fetch = async () =>
        ({
          ok: false,
          statusText: "Not Found",
        }) as Response;

      try {
        await JwksKeyService.getSigningKey(KeyType.IPV);
        expect.fail("Should have thrown an error");
      } catch (error: unknown) {
        expect((error as Error).message).to.include(
          "No signing key available for IPV"
        );
      }
    });

    it("should throw error when no keys available", async () => {
      delete process.env.AUTH_PUBLIC_SIGNING_KEY_IPV;
      delete process.env.AUTH_IPV_PUBLIC_SIGNING_KEY_JWKS_ENDPOINT;

      try {
        await JwksKeyService.getSigningKey(KeyType.IPV);
        expect.fail("Should have thrown an error");
      } catch (error: unknown) {
        expect((error as Error).message).to.include(
          "No signing key available for IPV"
        );
      }
    });

    it("should prioritize environment variable over JWKS", async () => {
      process.env.AUTH_PUBLIC_SIGNING_KEY_IPV = keys.authPublicSigningKeyIPV;
      process.env.AUTH_IPV_PUBLIC_SIGNING_KEY_JWKS_ENDPOINT =
        "https://example.com/.well-known/jwks.json";

      // Mock JWKS to return different key
      global.fetch = async () =>
        ({
          ok: true,
          json: async () => ({ keys: [] }),
        }) as Response;

      const key = await JwksKeyService.getSigningKey(KeyType.IPV);
      void expect(key).to.not.be.undefined;
    });
  });
});

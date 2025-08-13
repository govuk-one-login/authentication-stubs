import chai from "chai";
import { describe, beforeEach, afterEach } from "mocha";
import { validateAuthorisationJwt } from "../../src/helper/jwt-validator";
import { JwksKeyService, KeyType } from "../../src/services/jwks-key-service";
import {
  importSPKI,
  exportJWK,
  calculateJwkThumbprint,
  importPKCS8,
  CompactSign,
} from "jose";
import keys from "../../src/data/keys.json";

const expect = chai.expect;

const validStorageAccessTokenPayload = {
  scope: "reverification",
  aud: [
    "https://credential-store.test.account.gov.uk",
    "https://identity.test.account.gov.uk",
  ],
  sub: "someSub",
  iss: "https://oidc.test.account.gov.uk/",
  exp: 1709051163,
  iat: 1709047563,
  jti: "dfccf751-be55-4df4-aa3f-a993193d5216",
};

async function createSignedJwt(
  header: string,
  payload: unknown,
  signingKey: string
) {
  const textEncoder = new TextEncoder();
  const privateKey = await importPKCS8(signingKey, header);
  return new CompactSign(textEncoder.encode(JSON.stringify(payload)))
    .setProtectedHeader({ alg: header })
    .sign(privateKey);
}

describe("JWKS Migration Integration Tests", () => {
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

  describe("JWKS-first behavior", () => {
    it("should use JWKS for IPV validation when no environment variable is set", async () => {
      delete process.env.AUTH_PUBLIC_SIGNING_KEY_IPV;
      process.env.AUTH_IPV_PUBLIC_SIGNING_KEY_JWKS_ENDPOINT = "https://example.com/.well-known/jwks.json";

      const publicKey = await exportJWK(await importSPKI(keys.authPublicSigningKeyIPV, "ES256"));
      const mockJwks = { keys: [publicKey] };

      global.fetch = async (url) => {
        expect(url).to.equal("https://example.com/.well-known/jwks.json");
        return {
          ok: true,
          json: async () => mockJwks,
        } as Response;
      };

      const sub = "test-sub";
      const jwt = await createSignedJwt(
        "ES256",
        {
          sub,
          scope: "reverification",
          state: "test-state",
          claims: {
            userinfo: {
              "https://vocab.account.gov.uk/v1/storageAccessToken": {
                values: [
                  await createSignedJwt(
                    "ES256",
                    validStorageAccessTokenPayload,
                    keys.authPrivateSigningKeyEVCS
                  ),
                ],
              },
            },
          },
        },
        keys.authPrivateSigningKeyIPV
      );

      const result = await validateAuthorisationJwt(jwt);
      expect(result).to.not.be.a("string");
      expect(result.sub).to.eq(sub);
    });

    it("should use JWKS for EVCS validation when no environment variable is set", async () => {
      delete process.env.AUTH_PUBLIC_SIGNING_KEY_EVCS;
      process.env.AUTH_EVCS_PUBLIC_SIGNING_KEY_JWKS_ENDPOINT = "https://example.com/.well-known/evcs-jwks.json";

      const ipvPublicKey = await exportJWK(await importSPKI(keys.authPublicSigningKeyIPV, "ES256"));
      const evcsPublicKey = await exportJWK(await importSPKI(keys.authPublicSigningKeyEVCS, "ES256"));
      
      global.fetch = async (url) => {
        if (url === "https://example.com/.well-known/evcs-jwks.json") {
          return {
            ok: true,
            json: async () => ({ keys: [evcsPublicKey] }),
          } as Response;
        }
        return {
          ok: true,
          json: async () => ({ keys: [ipvPublicKey] }),
        } as Response;
      };

      const sub = "test-sub";
      const jwt = await createSignedJwt(
        "ES256",
        {
          sub,
          scope: "reverification",
          state: "test-state",
          claims: {
            userinfo: {
              "https://vocab.account.gov.uk/v1/storageAccessToken": {
                values: [
                  await createSignedJwt(
                    "ES256",
                    validStorageAccessTokenPayload,
                    keys.authPrivateSigningKeyEVCS
                  ),
                ],
              },
            },
          },
        },
        keys.authPrivateSigningKeyIPV
      );

      const result = await validateAuthorisationJwt(jwt);
      expect(result).to.not.be.a("string");
      expect(result.sub).to.eq(sub);
    });
  });

  describe("Environment variable override behavior", () => {
    it("should prioritize environment variable over JWKS for IPV", async () => {
      process.env.AUTH_PUBLIC_SIGNING_KEY_IPV = keys.authPublicSigningKeyIPV;
      process.env.AUTH_IPV_PUBLIC_SIGNING_KEY_JWKS_ENDPOINT = "https://example.com/.well-known/jwks.json";

      // Mock JWKS to return empty keys - should not be called
      global.fetch = async () => {
        throw new Error("JWKS should not be called when environment variable is set");
      };

      const key = await JwksKeyService.getSigningKey(KeyType.IPV);
      expect(key).to.not.be.undefined;
    });

    it("should prioritize environment variable over JWKS for EVCS", async () => {
      process.env.AUTH_PUBLIC_SIGNING_KEY_EVCS = keys.authPublicSigningKeyEVCS;
      process.env.AUTH_EVCS_PUBLIC_SIGNING_KEY_JWKS_ENDPOINT = "https://example.com/.well-known/jwks.json";

      // Mock JWKS to return empty keys - should not be called
      global.fetch = async () => {
        throw new Error("JWKS should not be called when environment variable is set");
      };

      const key = await JwksKeyService.getSigningKey(KeyType.EVCS);
      expect(key).to.not.be.undefined;
    });
  });

  describe("Fallback scenarios", () => {
    it("should handle JWKS unavailable gracefully", async () => {
      delete process.env.AUTH_PUBLIC_SIGNING_KEY_IPV;
      process.env.AUTH_IPV_PUBLIC_SIGNING_KEY_JWKS_ENDPOINT = "https://example.com/.well-known/jwks.json";

      global.fetch = async () => ({
        ok: false,
        statusText: "Service Unavailable",
      }) as Response;

      try {
        await JwksKeyService.getSigningKey(KeyType.IPV);
        expect.fail("Should have thrown an error");
      } catch (error: any) {
        expect(error.message).to.include("No signing key available for IPV");
      }
    });

    it("should handle malformed JWKS response", async () => {
      delete process.env.AUTH_PUBLIC_SIGNING_KEY_IPV;
      process.env.AUTH_IPV_PUBLIC_SIGNING_KEY_JWKS_ENDPOINT = "https://example.com/.well-known/jwks.json";

      global.fetch = async () => ({
        ok: true,
        json: async () => ({ invalid: "response" }),
      }) as Response;

      try {
        await JwksKeyService.getSigningKey(KeyType.IPV);
        expect.fail("Should have thrown an error");
      } catch (error: any) {
        expect(error.message).to.include("No signing key available for IPV");
      }
    });
  });

  describe("Backward compatibility", () => {
    it("should work exactly as before when environment variables are set", async () => {
      process.env.AUTH_PUBLIC_SIGNING_KEY_IPV = keys.authPublicSigningKeyIPV;
      process.env.AUTH_PUBLIC_SIGNING_KEY_EVCS = keys.authPublicSigningKeyEVCS;

      const sub = "test-sub";
      const jwt = await createSignedJwt(
        "ES256",
        {
          sub,
          scope: "reverification",
          state: "test-state",
          claims: {
            userinfo: {
              "https://vocab.account.gov.uk/v1/storageAccessToken": {
                values: [
                  await createSignedJwt(
                    "ES256",
                    validStorageAccessTokenPayload,
                    keys.authPrivateSigningKeyEVCS
                  ),
                ],
              },
            },
          },
        },
        keys.authPrivateSigningKeyIPV
      );

      const result = await validateAuthorisationJwt(jwt);
      expect(result).to.not.be.a("string");
      expect(result.sub).to.eq(sub);
    });
  });
});
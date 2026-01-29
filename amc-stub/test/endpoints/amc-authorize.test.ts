import { expect } from "chai";
import sinon from "sinon";
import { handler } from "../../src/endpoints/amc-authorize.ts";
import {
  AccessTokenBuilder,
  CompositeJWTBuilder,
  createTestEvent,
} from "../test-helpers.js";
import { HttpMethod } from "../../src/types/enums.ts";
import keys from "../../data/keys.json" with { type: "json" };
import { CompactEncrypt, importSPKI } from "jose";
import { DynamoDBDocument } from "@aws-sdk/lib-dynamodb";

const textEncoder = new TextEncoder();

describe("AMC Authorize Stub Test", () => {
  beforeEach(() => {
    process.env.AMC_PRIVATE_ENCRYPTION_KEY = keys.amcPrivateEncryptionKey;
    process.env.AUTH_PUBLIC_SIGNING_KEY_AMC_AUDIENCE =
      keys.authPublicSigningKeyAMCAudience;
    process.env.AUTH_PUBLIC_SIGNING_KEY_AUTH_AUDIENCE =
      keys.authPublicSigningKeyAuthAudience;
    process.env.ENVIRONMENT = "test";

    sinon.stub(DynamoDBDocument.prototype, "put").resolves({});
  });

  afterEach(() => {
    sinon.restore();
  });

  describe("GET handler", () => {
    beforeEach(() => {
      process.env.ENVIRONMENT = "local";
    });

    it("should return 200 with HTML for valid GET request", async () => {
      const accessToken = await new AccessTokenBuilder(
        keys.authPrivateSigningKeyAuthAudience
      ).build();
      const compositeJWT = await new CompositeJWTBuilder(
        keys.authPrivateSigningKeyAMCAudience,
        accessToken
      ).build();

      const publicKey = await importSPKI(
        keys.amcPublicEncryptionKey,
        "RSA-OAEP-256"
      );
      const encryptedJWT = await new CompactEncrypt(
        textEncoder.encode(compositeJWT)
      )
        .setProtectedHeader({ alg: "RSA-OAEP-256", enc: "A256GCM" })
        .encrypt(publicKey);

      const event = createTestEvent(HttpMethod.GET, "/authorize", null, {
        request: encryptedJWT,
      });

      const result = await handler(event);

      expect(result.statusCode).to.eq(200);
      expect(result.headers?.["Content-Type"]).to.eq("text/html");
      expect(result.body).to.include("Decrypted JAR header");
    });

    it("should return 400 when query string parameters are null", async () => {
      const event = createTestEvent(HttpMethod.GET, "/authorize", null, null);

      try {
        await handler(event);
        expect.fail("Should have thrown an error");
      } catch (error: unknown) {
        expect(error).to.be.instanceOf(Error);
        expect((error as { code: number }).code).to.eq(400);
        expect((error as Error).message).to.eq(
          "Query string parameters are null"
        );
      }
    });

    it("should return 400 when request parameter is missing", async () => {
      const event = createTestEvent(HttpMethod.GET, "/authorize", null, {});

      try {
        await handler(event);
        expect.fail("Should have thrown an error");
      } catch (error: unknown) {
        expect(error).to.be.instanceOf(Error);
        expect((error as { code: number }).code).to.eq(400);
        expect((error as Error).message).to.eq(
          "Request query string parameter not found"
        );
      }
    });
  });

  describe("POST handler", () => {
    beforeEach(() => {
      process.env.ENVIRONMENT = "local";
    });

    it("should return 302 redirect with auth code for success response", async () => {
      const body = new URLSearchParams({
        redirect_uri: "https://signin.account.gov.uk/callback",
        state: "test-state-123",
        sub: "urn:fdc:gov.uk:2022:test-subject",
        response: "success",
      }).toString();

      const event = createTestEvent(HttpMethod.POST, "/authorize", body);

      const result = await handler(event);

      expect(result.statusCode).to.eq(302);
      expect(result.headers?.["Location"]).to.include(
        "https://signin.account.gov.uk/callback"
      );
      expect(result.headers?.["Location"]).to.include("state=test-state-123");
      expect(result.headers?.["Location"]).to.include("code=");
    });

    it("should return 302 redirect with auth code for failure response", async () => {
      const body = new URLSearchParams({
        redirect_uri: "https://signin.account.gov.uk/callback",
        state: "test-state-456",
        sub: "urn:fdc:gov.uk:2022:test-subject",
        response: "access_denied",
      }).toString();

      const event = createTestEvent(HttpMethod.POST, "/authorize", body);

      const result = await handler(event);

      expect(result.statusCode).to.eq(302);
      expect(result.headers?.["Location"]).to.include(
        "https://signin.account.gov.uk/callback"
      );
      expect(result.headers?.["Location"]).to.include("state=test-state-456");
      expect(result.headers?.["Location"]).to.include("code=");
    });

    it("should return 400 when body is null", async () => {
      const event = createTestEvent(HttpMethod.POST, "/authorize", null);

      try {
        await handler(event);
        expect.fail("Should have thrown an error");
      } catch (error: unknown) {
        expect(error).to.be.instanceOf(Error);
        expect((error as { code: number }).code).to.eq(400);
        expect((error as Error).message).to.eq("Missing request body");
      }
    });

    it("should return 500 when redirect_uri is missing", async () => {
      const body = new URLSearchParams({
        state: "test-state-123",
        sub: "urn:fdc:gov.uk:2022:test-subject",
        response: "success",
      }).toString();

      const event = createTestEvent(HttpMethod.POST, "/authorize", body);

      try {
        await handler(event);
        expect.fail("Should have thrown an error");
      } catch (error: unknown) {
        expect(error).to.be.instanceOf(Error);
        expect((error as { code: number }).code).to.eq(500);
        expect((error as Error).message).to.eq("redirect_uri not found");
      }
    });

    it("should return 500 when state is missing", async () => {
      const body = new URLSearchParams({
        redirect_uri: "https://signin.account.gov.uk/callback",
        sub: "urn:fdc:gov.uk:2022:test-subject",
        response: "success",
      }).toString();

      const event = createTestEvent(HttpMethod.POST, "/authorize", body);

      try {
        await handler(event);
        expect.fail("Should have thrown an error");
      } catch (error: unknown) {
        expect(error).to.be.instanceOf(Error);
        expect((error as { code: number }).code).to.eq(500);
        expect((error as Error).message).to.eq("state not found");
      }
    });
  });

  const unsupportedMethods = [HttpMethod.PUT, HttpMethod.DELETE];
  unsupportedMethods.forEach((method) => {
    it(`should not allow ${method}`, async () => {
      const event = createTestEvent(method);

      try {
        await handler(event);
        expect.fail("Should have thrown an error");
      } catch (error: unknown) {
        expect(error).to.be.instanceOf(Error);
        expect((error as { code: number }).code).to.eq(405);
      }
    });
  });
});

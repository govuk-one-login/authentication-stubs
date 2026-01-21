import { expect } from "chai";
import { handler } from "../../src/endpoints/amc-authorize.ts";
import {
  AccessTokenBuilder,
  CompositeJWTBuilder,
  createTestEvent,
} from "../test-helpers.js";
import { HttpMethod } from "../../src/types/enums.ts";
import keys from "../../data/keys.json" with { type: "json" };
import { CompactEncrypt, importSPKI } from "jose";

const textEncoder = new TextEncoder();

describe("AMC Authorize Stub Test", () => {
  beforeEach(() => {
    process.env.AMC_PRIVATE_ENCRYPTION_KEY = keys.amcPrivateEncryptionKey;
    process.env.AUTH_PUBLIC_SIGNING_KEY_AMC_AUDIENCE =
      keys.authPublicSigningKeyAMCAudience;
    process.env.AUTH_PUBLIC_SIGNING_KEY_AUTH_AUDIENCE =
      keys.authPublicSigningKeyAuthAudience;
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

  it("should call POST", async () => {
    const event = createTestEvent(HttpMethod.POST);

    const result = await handler(event);

    expect(result.statusCode).to.eq(200);
    expect(result.body).to.eq(
      JSON.stringify({ message: "To be implemented as part of AUT-5006" })
    );
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

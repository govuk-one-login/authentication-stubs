import { expect } from "chai";
import { handler } from "../../src/endpoints/amc-jwks.ts";
import { createTestEvent } from "../test-helpers.js";
import { HttpMethod } from "../../src/types/enums.ts";
import keys from "../../data/keys.json" with { type: "json" };

describe("AMC JWKS Stub Test", () => {
  let event: ReturnType<typeof createTestEvent>;

  beforeEach(() => {
    process.env.AMC_PUBLIC_ENCRYPTION_KEY = keys.amcPublicEncryptionKey;
    event = createTestEvent(HttpMethod.GET, "/.well-known/amc-jwks.json");
  });

  afterEach(() => {
    delete process.env.AMC_PUBLIC_ENCRYPTION_KEY;
  });

  it("should return 200 with JWKS for GET request", async () => {
    const result = await handler(event);

    expect(result.statusCode).to.eq(200);
    const body = JSON.parse(result.body);
    expect(body.keys).to.have.length(1);
    expect(body.keys[0].use).to.eq("enc");
    expect(body.keys[0].alg).to.eq("RS256");
    expect(body.keys[0].kid).to.eq("amc-stub-public-encryption-key");
  });

  it("should return 500 when AMC_PUBLIC_ENCRYPTION_KEY is not set", async () => {
    delete process.env.AMC_PUBLIC_ENCRYPTION_KEY;

    const result = await handler(event);

    expect(result.statusCode).to.eq(500);
  });

  const unsupportedMethods = [
    HttpMethod.POST,
    HttpMethod.PUT,
    HttpMethod.DELETE,
  ];
  unsupportedMethods.forEach((method) => {
    it(`should not allow ${method}`, async () => {
      const result = await handler(
        createTestEvent(method, "/.well-known/amc-jwks.json")
      );

      expect(result.statusCode).to.eq(405);
    });
  });
});

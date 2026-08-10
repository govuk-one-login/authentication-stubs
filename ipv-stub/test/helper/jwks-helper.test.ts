import { exportJWK, importSPKI } from "jose";
import keys from "../../src/data/keys.json" with { type: "json" };
import { getPublicSigningKey } from "../../src/helper/jwks-helper";
import { expect } from "chai";
import { describe } from "mocha";
import { createSignedJwt } from "../test-helpers";
import { CodedError } from "../../src/helper/result-helper";

const validSigningAlg = "ES256";
const mockJwksEndpoint = "https://some-uri.com";
const mockSigningKey = keys.authPublicSigningKeyIPV;

describe("JwksHelper", () => {
  let originalFetch: typeof global.fetch;

  beforeEach(() => {
    originalFetch = global.fetch;
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it("fetches the public key from the JWKS endpoint when kid is present", async () => {
    const kid = "test-kid-123";
    const publicKey = await importSPKI(mockSigningKey, validSigningAlg);
    const jwk = await exportJWK(publicKey);

    const mockJwks = { keys: [{ ...jwk, kid }] };

    let fetchCalledWith: string | undefined;
    global.fetch = async (url) => {
      fetchCalledWith = url.toString();
      return {
        ok: true,
        json: async () => mockJwks,
      } as Response;
    };

    const validJws = await createSignedJwt(
      validSigningAlg,
      { test: "payload" },
      keys.authPrivateSigningKeyIPV,
      kid
    );

    const result = await getPublicSigningKey(validJws, mockJwksEndpoint);

    expect(fetchCalledWith).to.eq(mockJwksEndpoint);
    expect(await exportJWK(result)).to.deep.eq(jwk);
  });

  it("falls back to the backup signing key when no kid is in the JWT", async () => {
    let fetchCalled = false;
    global.fetch = async () => {
      fetchCalled = true;
      return { ok: true, json: async () => ({ keys: [] }) } as Response;
    };

    const jwsWithNoKid = await createSignedJwt(
      validSigningAlg,
      { test: "payload" },
      keys.authPrivateSigningKeyIPV,
      undefined
    );

    const result = await getPublicSigningKey(
      jwsWithNoKid,
      mockJwksEndpoint,
      mockSigningKey
    );

    const expectedKey = await importSPKI(mockSigningKey, validSigningAlg);
    expect(fetchCalled).to.eq(false);
    expect(await exportJWK(result)).to.deep.eq(await exportJWK(expectedKey));
  });

  it("falls back to the backup signing key when no JWKS URI is provided", async () => {
    const validJws = await createSignedJwt(
      validSigningAlg,
      { test: "payload" },
      keys.authPrivateSigningKeyIPV,
      "some-kid"
    );

    const result = await getPublicSigningKey(
      validJws,
      undefined,
      mockSigningKey
    );

    const expectedKey = await importSPKI(mockSigningKey, validSigningAlg);
    expect(await exportJWK(result)).to.deep.eq(await exportJWK(expectedKey));
  });

  it("throws when no kid is present and no backup signing key is provided", async () => {
    const jwsWithNoKid = await createSignedJwt(
      validSigningAlg,
      { test: "payload" },
      keys.authPrivateSigningKeyIPV
    );

    try {
      await getPublicSigningKey(jwsWithNoKid, mockJwksEndpoint);
      expect.fail("Should have thrown an error");
    } catch (error) {
      expect((error as CodedError).message).to.eq(
        "Public signing key not found"
      );
    }
  });

  it("throws when the kid does not match any key in the JWKS response", async () => {
    const publicKey = await importSPKI(mockSigningKey, validSigningAlg);
    const jwk = await exportJWK(publicKey);
    jwk.kid = "someKid";

    const mockJwks = { keys: [jwk] };

    global.fetch = async () =>
      ({
        ok: true,
        json: async () => mockJwks,
      }) as Response;

    const jwsWithDifferentKid = await createSignedJwt(
      validSigningAlg,
      { test: "payload" },
      keys.authPrivateSigningKeyIPV,
      "otherKid"
    );

    try {
      await getPublicSigningKey(jwsWithDifferentKid, mockJwksEndpoint);
      expect.fail("Should have thrown an error");
    } catch (error) {
      expect((error as CodedError).message).to.eq(
        "Key not found in JWKS for provided kid"
      );
    }
  });
});

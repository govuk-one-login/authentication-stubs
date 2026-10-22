import { expect } from "chai";
import { afterEach, describe, it } from "mocha";
import sinon from "sinon";
import { exportJWK, importSPKI } from "jose";
import keys from "../../src/data/keys.json" with { type: "json" };
import { getPublicSigningKey } from "../../src/helper/jwks-helper";
import { createSignedJwt } from "../test-helpers";
import { CodedError } from "../../src/helper/result-helper";

const JWKS_URI = "https://example.com/.well-known/jwks.json";

const jwsWithKid = (kid?: string) =>
  createSignedJwt(
    "ES256",
    { hello: "world" },
    keys.authPrivateSigningKeyIPV,
    kid
  );

describe("jwks-helper fetch error handling", () => {
  afterEach(() => {
    sinon.restore();
  });

  it("should throw a 500 when the JWKS endpoint returns a non-ok response", async () => {
    sinon.stub(global, "fetch").resolves({
      ok: false,
      status: 503,
      statusText: "Service Unavailable",
    } as Response);

    try {
      await getPublicSigningKey(await jwsWithKid("some-kid"), JWKS_URI);
      expect.fail("expected an error");
    } catch (error) {
      expect(error).to.be.instanceOf(CodedError);
      expect((error as CodedError).code).to.eq(500);
      expect((error as CodedError).message).to.contain("Failed to fetch JWKS");
    }
  });

  it("should throw a 500 with a timeout message when the fetch is aborted", async () => {
    const abortError = new Error("aborted");
    abortError.name = "AbortError";
    sinon.stub(global, "fetch").rejects(abortError);

    try {
      await getPublicSigningKey(await jwsWithKid("some-kid"), JWKS_URI);
      expect.fail("expected an error");
    } catch (error) {
      expect((error as CodedError).code).to.eq(500);
      expect((error as CodedError).message).to.contain("timeout");
    }
  });

  it("should throw a 500 network error when the underlying fetch fails", async () => {
    sinon.stub(global, "fetch").rejects(new Error("fetch failed"));

    try {
      await getPublicSigningKey(await jwsWithKid("some-kid"), JWKS_URI);
      expect.fail("expected an error");
    } catch (error) {
      expect((error as CodedError).code).to.eq(500);
      expect((error as CodedError).message).to.contain("Network error");
    }
  });

  it("should throw a 400 when the kid is not present in the JWKS response", async () => {
    const publicJwk = await exportJWK(
      await importSPKI(keys.authPublicSigningKeyIPV, "ES256")
    );
    sinon.stub(global, "fetch").resolves({
      ok: true,
      status: 200,
      json: async () => ({ keys: [{ ...publicJwk, kid: "different-kid" }] }),
    } as Response);

    try {
      await getPublicSigningKey(await jwsWithKid("requested-kid"), JWKS_URI);
      expect.fail("expected an error");
    } catch (error) {
      expect((error as CodedError).code).to.eq(400);
      expect((error as CodedError).message).to.eq(
        "Key not found in JWKS for provided kid"
      );
    }
  });

  it("should use the header alg when the matched JWKS key has no alg", async () => {
    const publicJwk = await exportJWK(
      await importSPKI(keys.authPublicSigningKeyIPV, "ES256")
    );
    delete publicJwk.alg;
    sinon.stub(global, "fetch").resolves({
      ok: true,
      status: 200,
      json: async () => ({ keys: [{ ...publicJwk, kid: "kid-no-alg" }] }),
    } as Response);

    const result = await getPublicSigningKey(
      await jwsWithKid("kid-no-alg"),
      JWKS_URI
    );

    expect(result).to.not.eq(undefined);
  });
});

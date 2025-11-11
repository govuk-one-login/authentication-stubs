import * as jose from "jose";
import keys from "../../src/data/keys.json";
import { getPublicSigningKey } from "../../src/helper/jwks-helper";
import { expect } from "chai";
import sinon from "sinon";
import { describe } from "mocha";
import { createSignedJwt } from "../test-helpers";
import { CodedError } from "../../src/helper/result-helper";

const validSigningAlg = "ES256";
const mockJwksEndpoint = "https://some-uri.com"

const mockImportJWK = sinon.stub();
sinon.stub(jose, "importJWK").value(mockImportJWK);

describe("JwksHelper", async () => {
  describe("Success", async () => {
    it("gets the public signing key from JWKS uri", async () => {
      const mockKeyLike = { type: "public", asymmetricKeyType: "ec" };
      mockImportJWK.resolves(mockKeyLike);

      const kid = "test-kid-123";
      const mockJwks = {
        keys: [
          {
            kty: "EC",
            crv: "P-256",
            x: "test-x",
            y: "test-y",
            kid,
          },
        ],
      };

      global.fetch = async () =>
        ({
          ok: true,
          json: async () => mockJwks,
        }) as Response;

      const validJws = await createSignedJwt(
        validSigningAlg,
        { test: "payload" },
        keys.authPrivateSigningKeyIPV,
        kid
      );

      const result = await getPublicSigningKey(
        validJws,
        "https://some-uri.com"
      );

      expect(result).to.deep.equal(mockKeyLike);
      expect(mockImportJWK.calledOnce).to.eq(true);
    });
  });

  describe("Unsuccessful", async () => {
    it("throws an error if there is no kid", async () => {
      const jwsWithNoKid = await createSignedJwt(
        validSigningAlg,
        { test: "payload" },
        keys.authPrivateSigningKeyIPV,
      );

      try {
        await getPublicSigningKey(jwsWithNoKid, mockJwksEndpoint);
        expect.fail("Should have thrown an error");
      } catch (error) {
        if (error instanceof CodedError) {
          expect(error.message).to.include("kid not found in decoded protected header");
        }
      }
    })

    it("throws an error if there is no jwks uri", async () => {
      const validJws = await createSignedJwt(
        validSigningAlg,
        { test: "payload" },
        keys.authPrivateSigningKeyIPV,
        "someKid"
      );

      try {
        await getPublicSigningKey(validJws);
        expect.fail("Should have thrown an error");
      } catch (error) {
        if (error instanceof CodedError) {
          expect(error.message).to.include("JWKS URI not found");
        }
      }
    })

    it("throws an error if there is no kid in JWKS response", async () => {
      const mockJwks = {
        keys: [
          {
            kty: "EC",
            crv: "P-256",
            x: "test-x",
            y: "test-y",
            kid: "someKid",
          },
        ],
      };

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
        if (error instanceof CodedError) {
          expect(error.message).to.include("Key not found in JWKS for provided kid");
        }
      }
    })
  });
});

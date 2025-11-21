import * as jose from "jose";
import keys from "../../src/data/keys.json";
import { getPublicSigningKey } from "../../src/helper/jwks-helper";
import { expect } from "chai";
import sinon from "sinon";
import { describe } from "mocha";
import { createSignedJwt } from "../test-helpers";
import { CodedError } from "../../src/helper/result-helper";

const validSigningAlg = "ES256";
const mockJwksEndpoint = "https://some-uri.com";
const mockSigningKey = keys.authPublicSigningKeyIPV;

let mockImportJWK: sinon.SinonStub;
let mockImportSPKI: sinon.SinonStub;

describe("JwksHelper", async () => {
  beforeEach(() => {
    mockImportJWK = sinon.stub();
    sinon.stub(jose, "importJWK").value(mockImportJWK);

    mockImportSPKI = sinon.stub();
    sinon.stub(jose, "importSPKI").value(mockImportSPKI);
  });

  afterEach(() => {
    sinon.restore();
  });

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

    const result = await getPublicSigningKey(validJws, mockJwksEndpoint);

    expect(result).to.deep.equal(mockKeyLike);
    expect(mockImportJWK.calledOnce).to.eq(true);
  });

  it("uses backup if there is no kid and a backup signing key present", async () => {
    const jwsWithNoKid = await createSignedJwt(
      validSigningAlg,
      { test: "payload" },
      keys.authPrivateSigningKeyIPV
    );

    await getPublicSigningKey(jwsWithNoKid, mockJwksEndpoint, mockSigningKey);

    expect(mockImportSPKI.calledOnce).to.eq(true);
    expect(mockImportSPKI.calledWith(mockSigningKey)).to.eq(true);
    expect(mockImportJWK.calledOnce).to.eq(false);
  });

  it("uses backup if there is no jwks uri and a backup signing key present", async () => {
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

    await getPublicSigningKey(validJws, undefined, mockSigningKey);

    expect(mockImportSPKI.calledOnce).to.eq(true);
    expect(mockImportSPKI.calledWith(mockSigningKey)).to.eq(true);
    expect(mockImportJWK.calledOnce).to.eq(false);
  });

  it("throws an error if there is no kid and backup signing key", async () => {
    const jwsWithNoKid = await createSignedJwt(
      validSigningAlg,
      { test: "payload" },
      keys.authPrivateSigningKeyIPV
    );

    try {
      await getPublicSigningKey(jwsWithNoKid, mockJwksEndpoint);
      expect.fail("Should have thrown an error");
    } catch (error) {
      if (error instanceof CodedError) {
        expect(error.message).to.include("Public signing public key not found");
      }
    }
  });

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
        expect(error.message).to.include(
          "Key not found in JWKS for provided kid"
        );
      }
    }
  });
});

import chai from "chai";
import { describe } from "mocha";
import {
  importSPKI,
  calculateJwkThumbprint,
  importPKCS8,
  exportJWK,
  CompactSign,
} from "jose";
import keys from "../../src/data/keys.json";
import sinon from "sinon";
import { validateAuthorisationJwt } from "../../src/helper/jwt-validator";
import process from "node:process";

type ProtectedHeader = {
  alg: string;
  kid?: string
}

const expect = chai.expect;

const validSigningAlg = "ES256";

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

async function createJWS(
  sub: string | undefined,
  scope: string | undefined,
  state: string | undefined,
  claims:
    | {
        userinfo: {
          "https://vocab.account.gov.uk/v1/storageAccessToken": {
            values: [string | null];
          };
        };
      }
    | null
    | unknown
) {
  return createSignedJwt(
    validSigningAlg,
    {
      sub: sub,
      scope: scope,
      claims: claims,
      state: state,
    },
    keys.authPrivateSigningKeyIPV
  );
}

describe("isValidJwt", async () => {
  beforeEach(() => {
    process.env.AUTH_PUBLIC_SIGNING_KEY_IPV = keys.authPublicSigningKeyIPV;
    process.env.AUTH_PUBLIC_SIGNING_KEY_EVCS = keys.authPublicSigningKeyEVCS;
  });

  afterEach(() => {
    sinon.restore();
  });

  it("returns true for a valid jwt", async () => {
    const sub = `urn:fdc:gov.uk:2022:fake_common_subject_identifier_${Math.floor(Math.random() * 100000)}`;

    const validSampleJws = await createSignedJwt(
      validSigningAlg,
      {
        sub: sub,
        scope: "reverification",
        claims: {
          userinfo: {
            "https://vocab.account.gov.uk/v1/storageAccessToken": {
              values: [
                await createSignedJwt(
                  validSigningAlg,
                  validStorageAccessTokenPayload,
                  keys.authPrivateSigningKeyEVCS
                ),
              ],
            },
          },
        },
        state: "test-state",
      },
      keys.authPrivateSigningKeyIPV
    );

    const expectedParsedJwt = {
      claims: {
        userinfo: {
          "https://vocab.account.gov.uk/v1/storageAccessToken": {
            values: [
              {
                aud: [
                  "https://credential-store.test.account.gov.uk",
                  "https://identity.test.account.gov.uk",
                ],
                exp: 1709051163,
                iat: 1709047563,
                iss: "https://oidc.test.account.gov.uk/",
                jti: "dfccf751-be55-4df4-aa3f-a993193d5216",
                scope: "reverification",
                sub: "someSub",
              },
            ],
          },
        },
      },
      scope: "reverification",
      state: "test-state",
      sub: sub,
    };

    expect(await validateAuthorisationJwt(validSampleJws)).to.be.deep.eq(
      expectedParsedJwt
    );
  });

  it("returns false if the jwt does not contain a scope field", async () => {
    const jws = await createJWS(
      "commonSubjectIdentifier",
      undefined,
      "test-state",
      {
        userinfo: {
          "https://vocab.account.gov.uk/v1/storageAccessToken": {
            values: [
              await createSignedJwt(
                validSigningAlg,
                validStorageAccessTokenPayload,
                keys.authPrivateSigningKeyEVCS
              ),
            ],
          },
        },
      }
    );
    const expectedErrorMessage =
      "Scope in request payload must be reverification";
    expect(await validateAuthorisationJwt(jws)).to.eq(expectedErrorMessage);
  });

  it("the jwt does not contain a claims field", async () => {
    const jws = await createJWS(
      "commonSubjectIdentifier",
      "reverification",
      "test-state",
      undefined
    );
    const expectedErrorMessage = "Request payload is missing user info claim";
    expect(await validateAuthorisationJwt(jws)).to.eq(expectedErrorMessage);
  });

  it("the jwt does not contain a userinfo claim", async () => {
    const jws = await createJWS(
      "commonSubjectIdentifier",
      "reverification",
      "test-state",
      {}
    );
    const expectedErrorMessage = "Request payload is missing user info claim";
    expect(await validateAuthorisationJwt(jws)).to.eq(expectedErrorMessage);
  });

  it("the payload does not contain a state field", async () => {
    const jws = await createJWS(
      "commonSubjectIdentifier",
      "reverification",
      undefined,
      {
        userinfo: {
          "https://vocab.account.gov.uk/v1/storageAccessToken": {
            values: [
              await createSignedJwt(
                validSigningAlg,
                validStorageAccessTokenPayload,
                keys.authPrivateSigningKeyEVCS
              ),
            ],
          },
        },
      }
    );
    const expectedErrorMessage = "Payload must contain state";
    expect(await validateAuthorisationJwt(jws)).to.eq(expectedErrorMessage);
  });

  it("the payload does not contain a sub field", async () => {
    const jws = await createJWS(undefined, "reverification", "test-state", {
      userinfo: {
        "https://vocab.account.gov.uk/v1/storageAccessToken": {
          values: [
            await createSignedJwt(
              validSigningAlg,
              validStorageAccessTokenPayload,
              keys.authPrivateSigningKeyEVCS
            ),
          ],
        },
      },
    });
    const expectedErrorMessage = "Payload must contain sub";
    expect(await validateAuthorisationJwt(jws)).to.eq(expectedErrorMessage);
  });

  it("should return false if access token payload scope is not reverification", async () => {
    const invalidStorageAccessTokenPayload = {
      scope: "not-reverification",
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

    const expectedError = "Storage access token scope is not reverification";

    const jws = await createJWS("sub", "reverification", "test-state", {
      userinfo: {
        "https://vocab.account.gov.uk/v1/storageAccessToken": {
          values: [
            await createSignedJwt(
              validSigningAlg,
              invalidStorageAccessTokenPayload,
              keys.authPrivateSigningKeyEVCS
            ),
          ],
        },
      },
    });

    expect(await validateAuthorisationJwt(jws)).to.eq(expectedError);
  });

  it("should use correct key from JWKS when kid is present in JWT header", async () => {
    const originalFetch = global.fetch;
    const fetchSpy = sinon.spy()

    try {
      process.env.AUTH_IPV_PUBLIC_SIGNING_KEY_JWKS_ENDPOINT =
        "https://example.com/.well-known/jwks.json";
      process.env.AUTH_IPV_STORAGE_TOKEN_SIGNING_KEY_JWKS_ENDPOINT =
        "https://example.com/.well-known/storage-jwks.json";

      const privateKey = await importPKCS8(
        keys.authPrivateSigningKeyIPV,
        "ES256"
      );
      const publicKey = await exportJWK(
        await importSPKI(keys.authPublicSigningKeyIPV, "ES256")
      );
      const kid = await calculateJwkThumbprint(publicKey, "sha256");
      const mockJwks = {
        keys: [{ ...publicKey, kid }],
      };

      const storagePublicKey = await exportJWK(
        await importSPKI(keys.authPublicSigningKeyEVCS, "ES256")
      );
      const storageKid = await calculateJwkThumbprint(
        storagePublicKey,
        "sha256"
      );
      const storageJwks = { keys: [{ ...storagePublicKey, kid: storageKid }] };

      global.fetch = async (url) => {
        fetchSpy(url.toString())
        if (url.toString().includes("storage-jwks.json")) {
          return {
            ok: true,
            json: () => Promise.resolve(storageJwks),
          } as Response;
        }

        return {
          ok: true,
          headers: new Headers(),
          status: 200,
          json: () => Promise.resolve(mockJwks),
        } as Response;
      }

      const sub = "test-sub";
      const payload = {
        sub,
        scope: "reverification",
        state: "test-state",
        claims: {
          userinfo: {
            "https://vocab.account.gov.uk/v1/storageAccessToken": {
              values: [
                await createSignedJwt(
                  validSigningAlg,
                  validStorageAccessTokenPayload,
                  keys.authPrivateSigningKeyEVCS,
                  storageKid
                ),
              ],
            },
          },
        },
      };

      const textEncoder = new TextEncoder();
      const jwt = await new CompactSign(
        textEncoder.encode(JSON.stringify(payload))
      )
        .setProtectedHeader({ alg: "ES256", kid })
        .sign(privateKey);

      const result = await validateAuthorisationJwt(jwt);
      expect(result).to.not.be.a("string");
      expect(result.sub).to.eq(sub);

      expect(fetchSpy.calledTwice).to.eq(true);
      expect(fetchSpy.firstCall.args[0]).to.include("jwks.json");
      expect(fetchSpy.secondCall.args[0]).to.include("storage-jwks.json");
    } finally {
      global.fetch = originalFetch;
      delete process.env.AUTH_IPV_PUBLIC_SIGNING_KEY_JWKS_ENDPOINT;
      delete process.env.AUTH_IPV_STORAGE_TOKEN_SIGNING_KEY_JWKS_ENDPOINT
    }
  });
});

async function createSignedJwt(
  header: string,
  payload: unknown,
  signingKey: string,
  kid?: string
) {
  const textEncoder = new TextEncoder();
  const privateKey = await importPKCS8(signingKey, header);
  const protectedHeader: ProtectedHeader = { alg: header };
  if (kid) {
    protectedHeader.kid = kid;
  }
  return new CompactSign(textEncoder.encode(JSON.stringify(payload)))
    .setProtectedHeader(protectedHeader)
    .sign(privateKey);
}

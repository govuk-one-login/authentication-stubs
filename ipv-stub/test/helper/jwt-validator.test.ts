import chai from "chai";
import { describe } from "mocha";
import { validateNestedJwt } from "../../src/helper/jwt-validator";
import * as jose from "jose";
import { CompactSign } from "jose";

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

const authPrivateSigningKeyEVCS = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgksszURcCxE4v8xSA
O9uwvvKDnntEb+2OBxQnsPs7vfKhRANCAAQnVd6isHfIQ7MlVbiy0wjl0gERdnca
j0qCr6EzRoVnxYW0/4WJVr0Pz5kd2wJkSVPsX/vKDEanPgh7XmH+rehn
-----END PRIVATE KEY-----
`;

const authPrivateSigningKeyIPV = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgSaOnCpAfj31OwM9+
IPuc+xPQZ6iCJHP+c3n4gOof+kihRANCAASZgtxRT+cjvTXQvGCl6Kst6k5m95C8
E66Lggy4GZsCn3tNfuUpbdbSeBRdiNs2J1wif/VGcj+6o/RoTa+IzP3C
-----END PRIVATE KEY-----
`;

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
    authPrivateSigningKeyIPV
  );
}

describe("isValidJwt", async () => {
  beforeEach(() => {
    process.env.AUTH_PUBLIC_SIGNING_KEY_IPV =
      "-----BEGIN PUBLIC KEY-----MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmYLcUU/nI7010LxgpeirLepOZveQvBOui4IMuBmbAp97TX7lKW3W0ngUXYjbNidcIn/1RnI/uqP0aE2viMz9wg==-----END PUBLIC KEY-----";
    process.env.AUTH_PUBLIC_SIGNING_KEY_EVCS =
      "-----BEGIN PUBLIC KEY-----MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJ1XeorB3yEOzJVW4stMI5dIBEXZ3Go9Kgq+hM0aFZ8WFtP+FiVa9D8+ZHdsCZElT7F/7ygxGpz4Ie15h/q3oZw==-----END PUBLIC KEY-----";
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
                  authPrivateSigningKeyEVCS
                ),
              ],
            },
          },
        },
        state: "test-state",
      },
      authPrivateSigningKeyIPV
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

    expect(await validateNestedJwt(validSampleJws)).to.be.deep.eq(
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
                authPrivateSigningKeyEVCS
              ),
            ],
          },
        },
      }
    );
    const expectedErrorMessage =
      "Scope in request payload must be verification";
    expect(await validateNestedJwt(jws)).to.eq(expectedErrorMessage);
  });

  it("the jwt does not contain a claims field", async () => {
    const jws = await createJWS(
      "commonSubjectIdentifier",
      "reverification",
      "test-state",
      undefined
    );
    const expectedErrorMessage = "Request payload is missing user info claim";
    expect(await validateNestedJwt(jws)).to.eq(expectedErrorMessage);
  });

  it("the jwt does not contain a userinfo claim", async () => {
    const jws = await createJWS(
      "commonSubjectIdentifier",
      "reverification",
      "test-state",
      {}
    );
    const expectedErrorMessage = "Request payload is missing user info claim";
    expect(await validateNestedJwt(jws)).to.eq(expectedErrorMessage);
  });

  it("the storage access token is not a string or Uint8Array", async () => {
    const jws = await createJWS(
      "commonSubjectIdentifier",
      "reverification",
      "test-state",
      {
        userinfo: {
          "https://vocab.account.gov.uk/v1/storageAccessToken": {
            values: [undefined],
          },
        },
      }
    );
    try {
      await validateNestedJwt(jws);
    } catch (e) {
      if (e instanceof jose.errors.JOSEError) {
        expect(e.message).to.eq(jose.errors.JWSInvalid.code);
      }
    }
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
                authPrivateSigningKeyEVCS
              ),
            ],
          },
        },
      }
    );
    const expectedErrorMessage = "Payload must contain state";
    expect(await validateNestedJwt(jws)).to.eq(expectedErrorMessage);
  });

  it("the payload does not contain a sub field", async () => {
    const jws = await createJWS(undefined, "reverification", "test-state", {
      userinfo: {
        "https://vocab.account.gov.uk/v1/storageAccessToken": {
          values: [
            await createSignedJwt(
              validSigningAlg,
              validStorageAccessTokenPayload,
              authPrivateSigningKeyEVCS
            ),
          ],
        },
      },
    });
    const expectedErrorMessage = "Payload must contain sub";
    expect(await validateNestedJwt(jws)).to.eq(expectedErrorMessage);
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
              authPrivateSigningKeyEVCS
            ),
          ],
        },
      },
    });

    expect(await validateNestedJwt(jws)).to.eq(expectedError);
  });
});

async function createSignedJwt(
  header: string,
  payload: unknown,
  signingKey: string
) {
  const textEncoder = new TextEncoder();
  const privateKey = await jose.importPKCS8(signingKey, header);
  return new CompactSign(textEncoder.encode(JSON.stringify(payload)))
    .setProtectedHeader({ alg: header })
    .sign(privateKey);
}

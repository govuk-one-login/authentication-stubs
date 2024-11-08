import chai from "chai";
import { describe } from "mocha";
import { isValidRequest } from "../../src/helper/jwt-validator";

const expect = chai.expect;

const storageAccessTokenPayload = {
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

const encodedStorageAccessTokenPayload = base64Encode(
  storageAccessTokenPayload
);
const encodedStorageAccessHeader =
  "eyJraWQiOiIwOWRkYjY1ZWIzY2U0MWEzYjczYTJhOTM0ZTM5NDg4NmQyYTIyYjU0ZmQwMzVmYWJlZWM3YWMxYzllYzliNzBiIiwiYWxnIjoiRVMyNTYifQ";
const encodedSignature =
  "rpZ2IqMwlFLbZ8a7En-EuQ480zcorvNd-GZcwjlxlK3Twq9J1GNiuj9teSLINP_zmeirx7Y8p3DUYWk_hyRhww";

const validClaims = {
  userinfo: {
    "https://vocab.account.gov.uk/v1/storageAccessToken": {
      values: [
        `${encodedStorageAccessHeader}.${encodedStorageAccessTokenPayload}.${encodedSignature}`,
      ],
    },
  },
};

const validSampleJwt = {
  sub: "commonSubjectIdentifier",
  iss: "https://signin.account.gov.uk",
  response_type: "code",
  client_id: "authReverification",
  govuk_signin_journey_id: "journey-id",
  aud: "https://identity.account.gov.uk",
  nbf: 1196676930,
  scope: "reverification",
  claims: validClaims,
  state: "test-state",
  redirect_uri: "https://signin.account.gov.uk/reverification-callback",
  exp: 1196677110,
  iat: 1196676930,
  jti: "uuid",
};

describe("isValidJwt", () => {
  it("returns true for a valid jwt", () => {
    expect(isValidRequest(JSON.stringify(validSampleJwt))).to.be.true;
  });

  const INVALID_CLAIMS_AND_DESCRIPTIONS = [
    {
      claims: { claims: validClaims },
      invalidCaseDescription: "the jwt does not contain a scope field",
    },
    {
      claims: { scope: "reverification" },
      invalidCaseDescription: "the jwt does not contain a claims field",
    },
    {
      claims: {
        scope: "reverification",
        claims: {},
      },
      invalidCaseDescription: "the jwt does not contain a userinfo claim",
    },
    {
      claims: {
        scope: "reverification",
        claims: {
          userinfo: {},
        },
      },
      invalidCaseDescription:
        "the jwt does not contain a storage access token field",
    },
  ];

  INVALID_CLAIMS_AND_DESCRIPTIONS.forEach((testCase) => {
    it(`returns false if ${testCase.invalidCaseDescription}`, () => {
      expect(isValidRequest(JSON.stringify(testCase.claims))).to.be.false;
    });
  });

  it("returns false if the jwt contains an invalid storage access token field", () => {
    const invalidStorageAccessTokenValues = [
      "no-dot-separation",
      "not.enough-parts",
      "too.many.parts.to.be.valid",
      "not.base64.encoded",
      `${encodedStorageAccessHeader}.${base64Encode({ foo: "bar" })}.${encodedSignature}`,
    ];
    invalidStorageAccessTokenValues.forEach((invalidStorageAccessToken) => {
      const jwtWithInvalidStorageAccessToken = {
        scope: "reverification",
        claims: {
          userinfo: {
            "https://vocab.account.gov.uk/v1/storageAccessToken": {
              values: [invalidStorageAccessToken],
            },
          },
        },
      };

      expect(isValidRequest(JSON.stringify(jwtWithInvalidStorageAccessToken)))
        .to.be.false;
    });
  });
});

function base64Encode(json: Object): String {
  return Buffer.from(JSON.stringify(json), "utf-8").toString("base64");
}

import chai from "chai";
import { describe } from "mocha";
import { parseRequest } from "../../src/helper/jwt-validator";

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
    const expectedParsedJwt = {
      sub: "commonSubjectIdentifier",
      scope: "reverification",
      state: "test-state",
      claims: {
        userinfo: {
          "https://vocab.account.gov.uk/v1/storageAccessToken": {
            values: [storageAccessTokenPayload],
          },
        },
      },
    };
    expect(parseRequest(JSON.stringify(validSampleJwt))).to.be.deep.eq(
      expectedParsedJwt
    );
  });

  const INVALID_CLAIMS_AND_DESCRIPTIONS = [
    {
      claims: {
        sub: "commonSubjectIdentifier",
        claims: validClaims,
        state: "test-state",
      },
      invalidCaseDescription: "the jwt does not contain a scope field",
      expectedErrorMessage: "Scope in request payload must be verification",
    },
    {
      claims: {
        sub: "commonSubjectIdentifier",
        scope: "reverification",
        state: "test-state",
      },
      invalidCaseDescription: "the jwt does not contain a claims field",
      expectedErrorMessage: "Request payload is missing user info claim",
    },
    {
      claims: {
        sub: "commonSubjectIdentifier",
        scope: "reverification",
        state: "test-state",
        claims: {},
      },
      invalidCaseDescription: "the jwt does not contain a userinfo claim",
      expectedErrorMessage: "Request payload is missing user info claim",
    },
    {
      claims: {
        sub: "commonSubjectIdentifier",
        scope: "reverification",
        state: "test-state",
        claims: {
          userinfo: {},
        },
      },
      invalidCaseDescription:
        "the jwt does not contain a storage access token field",
      expectedErrorMessage:
        "Storage access token does not contain values field",
    },
    {
      claims: {
        sub: "commonSubjectIdentifier",
        scope: "reverification",
        claims: validClaims,
      },
      invalidCaseDescription: "the payload does not contain a state field",
      expectedErrorMessage: "Payload must contain state",
    },
    {
      claims: {
        scope: "reverification",
        state: "test-state",
        claims: validClaims,
      },
      invalidCaseDescription: "the payload does not contain a sub field",
      expectedErrorMessage: "Payload must contain sub",
    },
  ];

  INVALID_CLAIMS_AND_DESCRIPTIONS.forEach((testCase) => {
    it(`returns false if ${testCase.invalidCaseDescription}`, () => {
      expect(parseRequest(JSON.stringify(testCase.claims))).to.eq(
        testCase.expectedErrorMessage
      );
    });
  });

  it("returns false if the jwt contains an invalid storage access token field", () => {
    const invalidStorageAccessTokenValues = [
      {
        value: "no-dot-separation",
        expectedError:
          "Storage access token is not a valid jwt (does not contain three parts)",
      },
      {
        value: "not.enough-parts",
        expectedError:
          "Storage access token is not a valid jwt (does not contain three parts)",
      },
      {
        value: "too.many.parts.to.be.valid",
        expectedError:
          "Storage access token is not a valid jwt (does not contain three parts)",
      },
      {
        value: "not.base64.encoded",
        expectedError: "Storage access token payload is not valid json",
      },
      {
        value: `${encodedStorageAccessHeader}.${base64Encode({ foo: "bar" })}.${encodedSignature}`,
        expectedError: "Storage access token scope is not reverification",
      },
    ];
    invalidStorageAccessTokenValues.forEach((testCase) => {
      const jwtWithInvalidStorageAccessToken = {
        sub: "commonSubjectIdentifier",
        scope: "reverification",
        state: "test-state",
        claims: {
          userinfo: {
            "https://vocab.account.gov.uk/v1/storageAccessToken": {
              values: [testCase.value],
            },
          },
        },
      };

      expect(
        parseRequest(JSON.stringify(jwtWithInvalidStorageAccessToken))
      ).to.eq(testCase.expectedError);
    });
  });
});

function base64Encode(json: object): string {
  return Buffer.from(JSON.stringify(json), "utf-8").toString("base64");
}

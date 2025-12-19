import { describe } from "mocha";
import "node:process";
import keys from "../../data/keys.json" with { type: "json" };
import sinon from "sinon";
import { createCompositeJWT, TEST_CONSTANTS } from "../test-helpers.ts";
import { validateCompositeJWT } from "../../src/helpers/jwt-validator.ts";
import { expect } from "chai";
import { amcScopes } from "../../src/types/enums.ts";

describe("jwt validator tests", async () => {
  beforeEach(() => {
    process.env.AUTH_PUBLIC_SIGNING_KEY_AMC_AUDIENCE =
      keys.authPublicSigningKeyAMCAudience;
    process.env.AUTH_PUBLIC_SIGNING_KEY_AUTH_AUDIENCE =
      keys.authPublicSigningKeyAuthAudience;
  });

  afterEach(() => {
    sinon.restore();
  });

  it("should validate the composite JWT", async () => {
    const JWT = await createCompositeJWT(
      keys.authPrivateSigningKeyAMCAudience,
      keys.authPrivateSigningKeyAuthAudience
    );

    const { payload } = await validateCompositeJWT(JWT);

    const now = Math.floor(Date.now() / 1000);

    // Client Assertion JWT assertions
    expect(payload.iss).to.equal(TEST_CONSTANTS.ISSUER);
    expect(payload.client_id).to.equal(TEST_CONSTANTS.CLIENT_ID);
    expect(payload.aud).to.equal(TEST_CONSTANTS.AUDIENCE);
    expect(payload.response_type).to.equal(TEST_CONSTANTS.RESPONSE_TYPE);
    expect(payload.redirect_uri).to.equal(TEST_CONSTANTS.REDIRECT_URI);
    expect(payload.scope).to.deep.equal([amcScopes.ACCOUNT_DELETE]);
    expect(payload.state).to.equal(TEST_CONSTANTS.STATE);
    expect(payload.jti).to.equal(TEST_CONSTANTS.CLIENT_ASSERTION_JTI);
    expect(payload.iat).to.be.closeTo(now, 10);
    expect(payload.nbf).to.be.closeTo(now, 10);
    expect(payload.exp).to.equal(payload.iat! + 300);
    expect(payload.sub).to.equal(TEST_CONSTANTS.SUBJECT);
    expect(payload.email).to.equal(TEST_CONSTANTS.EMAIL);
    expect(payload.govuk_signin_journey_id).to.equal(TEST_CONSTANTS.JOURNEY_ID);
    expect(payload.public_sub).to.equal(TEST_CONSTANTS.PUBLIC_SUBJECT)

    // Access Token JWT assertions
    expect(payload.access_token.sub).to.equal(TEST_CONSTANTS.SUBJECT);
    expect(payload.access_token.iat).to.be.closeTo(now, 10);
    expect(payload.access_token.nbf).to.be.closeTo(now, 10);
    expect(payload.access_token.exp).to.equal(payload.iat! + 3600);
    expect(payload.access_token.scope).to.deep.equal([amcScopes.ACCOUNT_DELETE]);
    expect(payload.access_token.iss).to.equal(TEST_CONSTANTS.ISSUER);
    expect(payload.access_token.aud).to.equal(TEST_CONSTANTS.AUDIENCE);
    expect(payload.access_token.client_id).to.equal(TEST_CONSTANTS.CLIENT_ID);
    expect(payload.access_token.sid).to.equal(TEST_CONSTANTS.SESSION_ID);
    expect(payload.access_token.jti).to.equal(TEST_CONSTANTS.ACCESS_TOKEN_JTI);
  });
});

import { describe } from "mocha";
import "node:process";
import keys from "../../data/keys.json" with { type: "json" };
import sinon from "sinon";
import {
  AccessTokenBuilder,
  CompositeJWTBuilder,
  TEST_CONSTANTS,
} from "../test-helpers.ts";
import { validateCompositeJWT } from "../../src/helpers/jwt-validator.ts";
import { AMCScopes } from "../../src/types/enums.ts";
import { CompositePayload } from "../../src/types/types.ts";
import { expect } from "chai";

describe("jwt validator tests", () => {
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
    const JWT = await new CompositeJWTBuilder(
      keys.authPrivateSigningKeyAMCAudience,
      await new AccessTokenBuilder(
        keys.authPrivateSigningKeyAuthAudience
      ).build()
    ).build();

    const result = await validateCompositeJWT(JWT);
    expect(result).to.not.be.a("string");
    const { payload } = result as { payload: CompositePayload };

    const now = Math.floor(Date.now() / 1000);

    // Client Assertion JWT assertions
    expect(payload.iss).to.equal(TEST_CONSTANTS.ISSUER);
    expect(payload.client_id).to.equal(TEST_CONSTANTS.CLIENT_ID);
    expect(payload.aud).to.equal(TEST_CONSTANTS.AMC_AUDIENCE);
    expect(payload.response_type).to.equal(TEST_CONSTANTS.RESPONSE_TYPE);
    expect(payload.redirect_uri).to.equal(TEST_CONSTANTS.REDIRECT_URI);
    expect(payload.scope).to.deep.equal([AMCScopes.ACCOUNT_DELETE]);
    expect(payload.state).to.equal(TEST_CONSTANTS.STATE);
    expect(payload.jti).to.equal(TEST_CONSTANTS.CLIENT_ASSERTION_JTI);
    expect(payload.iat).to.be.closeTo(now, 10);
    expect(payload.nbf).to.be.closeTo(now, 10);
    expect(payload.exp).to.equal(payload.iat! + 300);
    expect(payload.sub).to.equal(TEST_CONSTANTS.SUBJECT);
    expect(payload.email).to.equal(TEST_CONSTANTS.EMAIL);
    expect(payload.govuk_signin_journey_id).to.equal(TEST_CONSTANTS.JOURNEY_ID);
    expect(payload.public_sub).to.equal(TEST_CONSTANTS.PUBLIC_SUBJECT);

    // Access Token JWT assertions
    expect(payload.access_token.sub).to.equal(TEST_CONSTANTS.SUBJECT);
    expect(payload.access_token.iat).to.be.closeTo(now, 10);
    expect(payload.access_token.nbf).to.be.closeTo(now, 10);
    expect(payload.access_token.exp).to.equal(payload.iat! + 3600);
    expect(payload.access_token.scope).to.deep.equal([
      AMCScopes.ACCOUNT_DELETE,
    ]);
    expect(payload.access_token.iss).to.equal(TEST_CONSTANTS.ISSUER);
    expect(payload.access_token.aud).to.equal(TEST_CONSTANTS.AUTH_AUDIENCE);
    expect(payload.access_token.client_id).to.equal(TEST_CONSTANTS.CLIENT_ID);
    expect(payload.access_token.sid).to.equal(TEST_CONSTANTS.SESSION_ID);
    expect(payload.access_token.jti).to.equal(TEST_CONSTANTS.ACCESS_TOKEN_JTI);
  });

  // ====================================
  //   Access Token Tests
  // ====================================

  [
    "INVALID_SCOPE",
    undefined,
    [],
    [AMCScopes.ACCOUNT_DELETE, "EXTRA_SCOPE"],
  ].forEach((scope) => {
    it(`should return an error string if the access token scope is ${scope}`, async () => {
      const JWT = await new CompositeJWTBuilder(
        keys.authPrivateSigningKeyAMCAudience,
        await new AccessTokenBuilder(keys.authPrivateSigningKeyAuthAudience)
          .withScope(scope)
          .build()
      ).build();

      expect(await validateCompositeJWT(JWT)).to.equal(
        "The access token payload contains invalid scopes"
      );
    });
  });

  ["INVALID_ISSUER", undefined].forEach((issuer) => {
    it(`should return an error string if the access token issuer is ${issuer}`, async () => {
      const JWT = await new CompositeJWTBuilder(
        keys.authPrivateSigningKeyAMCAudience,
        await new AccessTokenBuilder(keys.authPrivateSigningKeyAuthAudience)
          .withIssuer(issuer)
          .build()
      ).build();

      expect(await validateCompositeJWT(JWT)).to.equal(
        "The access token payload issuer is invalid"
      );
    });
  });

  ["INVALID_AUDIENCE", undefined].forEach((audience) => {
    it(`should return an error string if the access token audience is ${audience}`, async () => {
      const JWT = await new CompositeJWTBuilder(
        keys.authPrivateSigningKeyAMCAudience,
        await new AccessTokenBuilder(keys.authPrivateSigningKeyAuthAudience)
          .withAudience(audience)
          .build()
      ).build();

      expect(await validateCompositeJWT(JWT)).to.equal(
        "The access token payload audience is invalid"
      );
    });
  });

  it("should return an error string if the access token payload internal subject is not present", async () => {
    const JWT = await new CompositeJWTBuilder(
      keys.authPrivateSigningKeyAMCAudience,
      await new AccessTokenBuilder(keys.authPrivateSigningKeyAuthAudience)
        .withSubject(undefined)
        .build()
    ).build();

    expect(await validateCompositeJWT(JWT)).to.equal(
      "The access token payload must contain an internal subject"
    );
  });

  it("should return an error string if the access token payload client ID is not present", async () => {
    const JWT = await new CompositeJWTBuilder(
      keys.authPrivateSigningKeyAMCAudience,
      await new AccessTokenBuilder(keys.authPrivateSigningKeyAuthAudience)
        .withClientId(undefined)
        .build()
    ).build();

    expect(await validateCompositeJWT(JWT)).to.equal(
      "The access token payload must contain a client ID"
    );
  });

  it("should return an error string if the access token payload jti is not present", async () => {
    const JWT = await new CompositeJWTBuilder(
      keys.authPrivateSigningKeyAMCAudience,
      await new AccessTokenBuilder(keys.authPrivateSigningKeyAuthAudience)
        .withJti(undefined)
        .build()
    ).build();

    expect(await validateCompositeJWT(JWT)).to.equal(
      "The access token payload must contain a jti"
    );
  });

  // ====================================
  //   Client Assertion JWT Tests
  // ====================================

  [
    "INVALID_SCOPE",
    undefined,
    [],
    [AMCScopes.ACCOUNT_DELETE, "EXTRA_SCOPE"],
  ].forEach((scope) => {
    it(`should return an error string when the client assertion payload ${scope} is invalid`, async () => {
      const JWT = await new CompositeJWTBuilder(
        keys.authPrivateSigningKeyAMCAudience,
        await new AccessTokenBuilder(
          keys.authPrivateSigningKeyAuthAudience
        ).build()
      )
        .withScope(scope)
        .build();

      expect(await validateCompositeJWT(JWT)).to.equal(
        "The client assertion JWT payload scope should be 'ACCOUNT_DELETE'"
      );
    });
  });

  ["INVALID_ISSUER", undefined].forEach((issuer) => {
    it(`should return an error string if the client assertion issuer is ${issuer}`, async () => {
      const JWT = await new CompositeJWTBuilder(
        keys.authPrivateSigningKeyAMCAudience,
        await new AccessTokenBuilder(
          keys.authPrivateSigningKeyAuthAudience
        ).build()
      )
        .withIssuer(issuer)
        .build();

      expect(await validateCompositeJWT(JWT)).to.equal(
        "The client assertion JWT payload issuer is invalid"
      );
    });
  });

  ["INVALID_AUDIENCE", undefined].forEach((audience) => {
    it(`should return an error string if the client assertion audience is ${audience}`, async () => {
      const JWT = await new CompositeJWTBuilder(
        keys.authPrivateSigningKeyAMCAudience,
        await new AccessTokenBuilder(
          keys.authPrivateSigningKeyAuthAudience
        ).build()
      )
        .withAudience(audience)
        .build();

      expect(await validateCompositeJWT(JWT)).to.equal(
        "The client assertion JWT payload audience is invalid"
      );
    });
  });

  it("should return an error string if the client assertion payload internal subject is not present", async () => {
    const JWT = await new CompositeJWTBuilder(
      keys.authPrivateSigningKeyAMCAudience,
      await new AccessTokenBuilder(
        keys.authPrivateSigningKeyAuthAudience
      ).build()
    )
      .withSubject(undefined)
      .build();

    expect(await validateCompositeJWT(JWT)).to.equal(
      "The client assertion JWT payload must contain an internal subject"
    );
  });

  it("should return an error string if the client assertion payload public subject is not present", async () => {
    const JWT = await new CompositeJWTBuilder(
      keys.authPrivateSigningKeyAMCAudience,
      await new AccessTokenBuilder(
        keys.authPrivateSigningKeyAuthAudience
      ).build()
    )
      .withPublicSubject(undefined)
      .build();

    expect(await validateCompositeJWT(JWT)).to.equal(
      "The client assertion JWT payload must contain a public subject"
    );
  });

  ["INVALID_CLIENT_ID", undefined].forEach((clientId) => {
    it(`should return an error string if the client assertion client ID is ${clientId}`, async () => {
      const JWT = await new CompositeJWTBuilder(
        keys.authPrivateSigningKeyAMCAudience,
        await new AccessTokenBuilder(
          keys.authPrivateSigningKeyAuthAudience
        ).build()
      )
        .withClientId(clientId)
        .build();

      expect(await validateCompositeJWT(JWT)).to.equal(
        "The client assertion JWT client ID must be 'auth'"
      );
    });
  });

  it("should return an error string if the client assertion payload jti is not present", async () => {
    const JWT = await new CompositeJWTBuilder(
      keys.authPrivateSigningKeyAMCAudience,
      await new AccessTokenBuilder(
        keys.authPrivateSigningKeyAuthAudience
      ).build()
    )
      .withJti(undefined)
      .build();

    expect(await validateCompositeJWT(JWT)).to.equal(
      "The client assertion JWT payload must contain a jti"
    );
  });
});

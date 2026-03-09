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
import { VerifiedAuthorizationRequestPayload } from "../../src/types/types.ts";
import { expect } from "chai";

describe("jwt validator tests", () => {
  beforeEach(() => {
    process.env.ENVIRONMENT = "local";
    process.env.AUTH_PUBLIC_SIGNING_KEY_AMC_AUDIENCE =
      keys.authPublicSigningKeyAMCAudience;
    process.env.AUTH_PUBLIC_SIGNING_KEY_AUTH_AUDIENCE =
      keys.authPublicSigningKeyAuthAudience;
  });

  afterEach(() => {
    sinon.restore();
    delete process.env.ENVIRONMENT;
  });

  [AMCScopes.ACCOUNT_DELETE, AMCScopes.PASSKEY_CREATE].forEach((scope) => {
    it(`should validate the composite JWT for scope ${scope}`, async () => {
      const JWT = await new CompositeJWTBuilder(
        keys.authPrivateSigningKeyAMCAudience,
        await new AccessTokenBuilder(keys.authPrivateSigningKeyAuthAudience)
          .withScope(scope)
          .build()
      )
        .withScope(scope)
        .build();

      const result = await validateCompositeJWT(JWT);
      expect(result).to.not.be.a("string");
      const { payload } = result as {
        payload: VerifiedAuthorizationRequestPayload;
      };

      const now = Math.floor(Date.now() / 1000);

      // Authorization Request JWT assertions
      expect(payload.iss).to.equal(TEST_CONSTANTS.ISSUER);
      expect(payload.client_id).to.equal(TEST_CONSTANTS.CLIENT_ID);
      expect(payload.aud).to.equal(TEST_CONSTANTS.AMC_AUDIENCE);
      expect(payload.response_type).to.equal(TEST_CONSTANTS.RESPONSE_TYPE);
      expect(payload.redirect_uri).to.equal(TEST_CONSTANTS.REDIRECT_URI);
      expect(payload.scope).to.equal(scope);
      expect(payload.state).to.equal(TEST_CONSTANTS.STATE);
      expect(payload.jti).to.equal(TEST_CONSTANTS.AUTHORIZATION_REQUEST_JTI);
      expect(payload.iat).to.be.closeTo(now, 10);
      expect(payload.nbf).to.be.closeTo(now, 10);
      expect(payload.exp).to.equal(payload.iat! + 300);
      expect(payload.sub).to.equal(TEST_CONSTANTS.SUBJECT);
      expect(payload.email).to.equal(TEST_CONSTANTS.EMAIL);
      expect(payload.public_sub).to.equal(TEST_CONSTANTS.PUBLIC_SUBJECT);

      // Access Token JWT assertions
      expect(payload.account_management_api_access_token!.sub).to.equal(
        TEST_CONSTANTS.SUBJECT
      );
      expect(payload.account_management_api_access_token!.iat).to.be.closeTo(
        now,
        10
      );
      expect(payload.account_management_api_access_token!.nbf).to.be.closeTo(
        now,
        10
      );
      expect(payload.account_management_api_access_token!.exp).to.equal(
        payload.iat! + 3600
      );
      expect(payload.account_management_api_access_token!.scope).to.equal(
        scope
      );
      expect(payload.account_management_api_access_token!.iss).to.equal(
        TEST_CONSTANTS.ISSUER
      );
      expect(payload.account_management_api_access_token!.aud).to.equal(
        TEST_CONSTANTS.AUTH_AUDIENCE
      );
      expect(payload.account_management_api_access_token!.client_id).to.equal(
        TEST_CONSTANTS.CLIENT_ID
      );
      expect(payload.account_management_api_access_token!.sid).to.equal(
        TEST_CONSTANTS.SESSION_ID
      );
      expect(payload.account_management_api_access_token!.jti).to.equal(
        TEST_CONSTANTS.ACCESS_TOKEN_JTI
      );
    });
  });

  // ====================================
  //   Access Token Tests
  // ====================================

  [
    "INVALID_SCOPE",
    undefined,
    "",
    `${AMCScopes.ACCOUNT_DELETE} EXTRA_SCOPE`,
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

  it("should return an error string if no access token is present", async () => {
    const JWT = await new CompositeJWTBuilder(
      keys.authPrivateSigningKeyAMCAudience,
      ""
    )
      .withAccountManagementApiAccessToken(undefined)
      .build();

    expect(await validateCompositeJWT(JWT)).to.equal(
      "The authorization request JWT payload must contain an access token"
    );
  });

  it("should return an error string if both access token fields are present", async () => {
    const accessToken = await new AccessTokenBuilder(
      keys.authPrivateSigningKeyAuthAudience
    ).build();
    const JWT = await new CompositeJWTBuilder(
      keys.authPrivateSigningKeyAMCAudience,
      accessToken
    )
      .withAccountDataApiAccessToken(accessToken)
      .build();

    expect(await validateCompositeJWT(JWT)).to.equal(
      "The authorization request JWT payload must contain only one access token"
    );
  });

  // ====================================
  //   Authorization Request JWT Tests
  // ====================================

  [
    "INVALID_SCOPE",
    undefined,
    "",
    `${AMCScopes.ACCOUNT_DELETE} EXTRA_SCOPE`,
  ].forEach((scope) => {
    it(`should return an error string when the authorization request payload ${scope} is invalid`, async () => {
      const JWT = await new CompositeJWTBuilder(
        keys.authPrivateSigningKeyAMCAudience,
        await new AccessTokenBuilder(
          keys.authPrivateSigningKeyAuthAudience
        ).build()
      )
        .withScope(scope)
        .build();

      expect(await validateCompositeJWT(JWT)).to.equal(
        "The authorization request JWT payload scope should be one of account-delete, passkey-create"
      );
    });
  });

  ["INVALID_ISSUER", undefined].forEach((issuer) => {
    it(`should return an error string if the authorization request issuer is ${issuer}`, async () => {
      const JWT = await new CompositeJWTBuilder(
        keys.authPrivateSigningKeyAMCAudience,
        await new AccessTokenBuilder(
          keys.authPrivateSigningKeyAuthAudience
        ).build()
      )
        .withIssuer(issuer)
        .build();

      expect(await validateCompositeJWT(JWT)).to.equal(
        "The authorization request JWT payload issuer is invalid"
      );
    });
  });

  ["INVALID_AUDIENCE", undefined].forEach((audience) => {
    it(`should return an error string if the authorization request audience is ${audience}`, async () => {
      const JWT = await new CompositeJWTBuilder(
        keys.authPrivateSigningKeyAMCAudience,
        await new AccessTokenBuilder(
          keys.authPrivateSigningKeyAuthAudience
        ).build()
      )
        .withAudience(audience)
        .build();

      expect(await validateCompositeJWT(JWT)).to.equal(
        "The authorization request JWT payload audience is invalid"
      );
    });
  });

  it("should return an error string if the authorization request payload internal subject is not present", async () => {
    const JWT = await new CompositeJWTBuilder(
      keys.authPrivateSigningKeyAMCAudience,
      await new AccessTokenBuilder(
        keys.authPrivateSigningKeyAuthAudience
      ).build()
    )
      .withSubject(undefined)
      .build();

    expect(await validateCompositeJWT(JWT)).to.equal(
      "The authorization request JWT payload must contain an internal subject"
    );
  });

  it("should return an error string if the authorization request payload public subject is not present", async () => {
    const JWT = await new CompositeJWTBuilder(
      keys.authPrivateSigningKeyAMCAudience,
      await new AccessTokenBuilder(
        keys.authPrivateSigningKeyAuthAudience
      ).build()
    )
      .withPublicSubject(undefined)
      .build();

    expect(await validateCompositeJWT(JWT)).to.equal(
      "The authorization request JWT payload must contain a public subject"
    );
  });

  ["INVALID_CLIENT_ID", undefined].forEach((clientId) => {
    it(`should return an error string if the authorization request client ID is ${clientId}`, async () => {
      const JWT = await new CompositeJWTBuilder(
        keys.authPrivateSigningKeyAMCAudience,
        await new AccessTokenBuilder(
          keys.authPrivateSigningKeyAuthAudience
        ).build()
      )
        .withClientId(clientId)
        .build();

      expect(await validateCompositeJWT(JWT)).to.equal(
        "The authorization request JWT client ID must be 'auth_amc'"
      );
    });
  });

  it("should return an error string if the authorization request payload jti is not present", async () => {
    const JWT = await new CompositeJWTBuilder(
      keys.authPrivateSigningKeyAMCAudience,
      await new AccessTokenBuilder(
        keys.authPrivateSigningKeyAuthAudience
      ).build()
    )
      .withJti(undefined)
      .build();

    expect(await validateCompositeJWT(JWT)).to.equal(
      "The authorization request JWT payload must contain a jti"
    );
  });
});

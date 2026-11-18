import { expect } from "chai";
import sinon from "sinon";
import { handler } from "../../src/endpoints/amc-authorize.ts";
import {
  AccessTokenBuilder,
  CompositeJWTBuilder,
  createTestEvent,
  TEST_CONSTANTS,
} from "../test-helpers.js";
import {
  ACCOUNT_DELETE_ACCOUNT_DATA_SCOPES,
  AccountDataAccessTokenScopes,
  AMCScopes,
  HttpMethod,
} from "../../src/types/enums.ts";
import keys from "../../data/keys.json" with { type: "json" };
import { CompactEncrypt, importSPKI } from "jose";
import { DynamoDBDocument } from "@aws-sdk/lib-dynamodb";

const textEncoder = new TextEncoder();

describe("AMC Authorize Stub Test", () => {
  beforeEach(() => {
    process.env.AMC_PRIVATE_ENCRYPTION_KEY = keys.amcPrivateEncryptionKey;
    process.env.AUTH_PUBLIC_SIGNING_KEY_AMC_AUDIENCE =
      keys.authPublicSigningKeyAMCAudience;
    process.env.AUTH_PUBLIC_SIGNING_KEY_AUTH_AUDIENCE =
      keys.authPublicSigningKeyAuthAudience;
    process.env.ENVIRONMENT = "test";

    sinon.stub(DynamoDBDocument.prototype, "put").resolves({});
  });

  afterEach(() => {
    sinon.restore();
  });

  describe("GET handler", () => {
    beforeEach(() => {
      process.env.ENVIRONMENT = "local";
    });

    [AMCScopes.PASSKEY_CREATE, AMCScopes.ACCOUNT_DELETE].forEach((scope) => {
      it(`should return 200 with HTML for valid GET request with scope ${scope}`, async () => {
        const event = await createSuccessfulTestEventForAMCScope(scope);

        const result = await handler(event);

        expect(result.statusCode).to.eq(200);
        expect(result.headers?.["Content-Type"]).to.eq("text/html");
        expect(result.body).to.include(`AMC stub (${scope.replace("-", " ")})`);
        expect(result.body).to.include("Decrypted JAR header");
      });
    });

    it("should render Success, Back and Abort options for account-delete", async () => {
      const event = await createSuccessfulTestEventForAMCScope(
        AMCScopes.ACCOUNT_DELETE
      );

      const result = await handler(event);

      expect(result.body).to.include('value="success"');
      expect(result.body).to.include('value="back"');
      expect(result.body).to.include('value="abort"');
    });

    it("should render the delete checkbox ticked, the warning and the hidden fields for account-delete with an account data access token", async () => {
      const { event, accountDataApiAccessToken } =
        await createAccountDeleteTestEventWithAccountDataToken();

      const result = await handler(event);

      expect(result.body).to.include(
        "Delete this account and all its data in DynamoDB"
      );
      expect(result.body).to.include(
        'name="delete-account" type="checkbox" value="yes" checked'
      );
      expect(result.body).to.include("deletes the account you signed in with");
      expect(result.body).to.include(
        `<input type="hidden" name="public_sub" value="${TEST_CONSTANTS.PUBLIC_SUBJECT}">`
      );
      expect(result.body).to.include(
        `<input type="hidden" name="account_data_api_access_token" value="${accountDataApiAccessToken}">`
      );
    });

    it("should not render the delete checkbox for passkey-create", async () => {
      const event = await createSuccessfulTestEventForAMCScope(
        AMCScopes.PASSKEY_CREATE
      );

      const result = await handler(event);

      expect(result.body).to.not.include(
        "Delete this account and all its data in DynamoDB"
      );
      expect(result.body).to.not.include("Success will not delete the account");
    });

    it("should return 400 when query string parameters are null", async () => {
      const event = createTestEvent(HttpMethod.GET, "/authorize", null, null);

      try {
        await handler(event);
        expect.fail("Should have thrown an error");
      } catch (error: unknown) {
        expect(error).to.be.instanceOf(Error);
        expect((error as { code: number }).code).to.eq(400);
        expect((error as Error).message).to.eq(
          "Query string parameters are null"
        );
      }
    });

    it("should return 400 when kid is missing from JWE header", async () => {
      const accessToken = await new AccessTokenBuilder(
        keys.authPrivateSigningKeyAuthAudience
      ).build();
      const compositeJWT = await new CompositeJWTBuilder(
        keys.authPrivateSigningKeyAMCAudience,
        accessToken
      ).build();

      const publicKey = await importSPKI(
        keys.amcPublicEncryptionKey,
        "RSA-OAEP-256"
      );
      const encryptedJWT = await new CompactEncrypt(
        textEncoder.encode(compositeJWT)
      )
        .setProtectedHeader({ alg: "RSA-OAEP-256", enc: "A256GCM" })
        .encrypt(publicKey);

      const event = createTestEvent(HttpMethod.GET, "/authorize", null, {
        request: encryptedJWT,
        scope: "account-delete",
        redirect_uri: "https://example.com/callback",
      });

      try {
        await handler(event);
        expect.fail("Should have thrown an error");
      } catch (error: unknown) {
        expect(error).to.be.instanceOf(Error);
        expect((error as { code: number }).code).to.eq(400);
        expect((error as Error).message).to.eq("JAR header is missing kid");
      }
    });

    it("should return 400 when request parameter is missing", async () => {
      const event = createTestEvent(HttpMethod.GET, "/authorize", null, {});

      try {
        await handler(event);
        expect.fail("Should have thrown an error");
      } catch (error: unknown) {
        expect(error).to.be.instanceOf(Error);
        expect((error as { code: number }).code).to.eq(400);
        expect((error as Error).message).to.eq(
          "Request query string parameter not found"
        );
      }
    });

    it("should return 400 when scope parameter is missing", async () => {
      const event = createTestEvent(HttpMethod.GET, "/authorize", null, {
        request: "some-encrypted-jwt",
      });

      try {
        await handler(event);
        expect.fail("Should have thrown an error");
      } catch (error: unknown) {
        expect(error).to.be.instanceOf(Error);
        expect((error as { code: number }).code).to.eq(400);
        expect((error as Error).message).to.eq(
          "scope query string parameter not found"
        );
      }
    });

    it("should return 400 when redirect_uri parameter is missing", async () => {
      const event = createTestEvent(HttpMethod.GET, "/authorize", null, {
        request: "some-encrypted-jwt",
        scope: "passkey-create",
      });

      try {
        await handler(event);
        expect.fail("Should have thrown an error");
      } catch (error: unknown) {
        expect(error).to.be.instanceOf(Error);
        expect((error as { code: number }).code).to.eq(400);
        expect((error as Error).message).to.eq(
          "redirect_uri query string parameter not found"
        );
      }
    });
  });

  describe("POST handler", () => {
    beforeEach(() => {
      process.env.ENVIRONMENT = "local";
    });

    it("should return 302 redirect with auth code for success response", async () => {
      const body = new URLSearchParams({
        redirect_uri: "https://signin.account.gov.uk/callback",
        state: "test-state-123",
        sub: "urn:fdc:gov.uk:2022:test-subject",
        response: "success",
      }).toString();

      const event = createTestEvent(HttpMethod.POST, "/authorize", body);

      const result = await handler(event);

      expect(result.statusCode).to.eq(302);
      expect(result.headers?.["Location"]).to.include(
        "https://signin.account.gov.uk/callback"
      );
      expect(result.headers?.["Location"]).to.include("state=test-state-123");
      expect(result.headers?.["Location"]).to.include("code=");
    });

    it("should return 302 redirect with auth code for valid failure response", async () => {
      const body = new URLSearchParams({
        redirect_uri: "https://signin.account.gov.uk/callback",
        state: "test-state-456",
        sub: "urn:fdc:gov.uk:2022:test-subject",
        response: "skip",
        scope: "passkey-create",
      }).toString();

      const event = createTestEvent(HttpMethod.POST, "/authorize", body);

      const result = await handler(event);

      expect(result.statusCode).to.eq(302);
      expect(result.headers?.["Location"]).to.include(
        "https://signin.account.gov.uk/callback"
      );
      expect(result.headers?.["Location"]).to.include("state=test-state-456");
      expect(result.headers?.["Location"]).to.include("code=");
    });

    it("should return 400 when body is null", async () => {
      const event = createTestEvent(HttpMethod.POST, "/authorize", null);

      try {
        await handler(event);
        expect.fail("Should have thrown an error");
      } catch (error: unknown) {
        expect(error).to.be.instanceOf(Error);
        expect((error as { code: number }).code).to.eq(400);
        expect((error as Error).message).to.eq("Missing request body");
      }
    });

    it("should return 500 when redirect_uri is missing", async () => {
      const body = new URLSearchParams({
        state: "test-state-123",
        sub: "urn:fdc:gov.uk:2022:test-subject",
        response: "success",
      }).toString();

      const event = createTestEvent(HttpMethod.POST, "/authorize", body);

      try {
        await handler(event);
        expect.fail("Should have thrown an error");
      } catch (error: unknown) {
        expect(error).to.be.instanceOf(Error);
        expect((error as { code: number }).code).to.eq(500);
        expect((error as Error).message).to.eq("redirect_uri not found");
      }
    });

    it("should return 500 when state is missing", async () => {
      const body = new URLSearchParams({
        redirect_uri: "https://signin.account.gov.uk/callback",
        sub: "urn:fdc:gov.uk:2022:test-subject",
        response: "success",
      }).toString();

      const event = createTestEvent(HttpMethod.POST, "/authorize", body);

      try {
        await handler(event);
        expect.fail("Should have thrown an error");
      } catch (error: unknown) {
        expect(error).to.be.instanceOf(Error);
        expect((error as { code: number }).code).to.eq(500);
        expect((error as Error).message).to.eq("state not found");
      }
    });

    it("should return 302 and store account intervention details for failure with intervention", async () => {
      const putStub = DynamoDBDocument.prototype.put as sinon.SinonStub;

      const params = new URLSearchParams();
      params.append("redirect_uri", "https://signin.account.gov.uk/callback");
      params.append("state", "test-state-789");
      params.append("sub", "urn:fdc:gov.uk:2022:test-subject");
      params.append("response", "failure");
      params.append("scope", "passkey-create");
      params.append("email", "testuser@test.null.local");
      params.append("account-interventions", "suspended");
      const body = params.toString();

      const event = createTestEvent(HttpMethod.POST, "/authorize", body);

      const result = await handler(event);

      expect(result.statusCode).to.eq(302);
      expect(result.headers?.["Location"]).to.include("state=test-state-789");

      const storedItem = putStub.firstCall.args[0].Item.authorization;
      expect(storedItem.success).to.eq(false);
      expect(storedItem.actions[0].success).to.eq(false);
      expect(storedItem.actions[0].details.error.code).to.eq(1004);
      expect(storedItem.actions[0].details.error.description).to.eq(
        "AccountHasInterventions"
      );
      expect(
        storedItem.actions[0].details.accountInterventionsStatus.state
      ).to.deep.eq({
        blocked: false,
        reproveIdentity: false,
        resetPassword: false,
        suspended: true,
      });
    });

    it("should return 302 and store multiple account intervention details for failure with multiple interventions", async () => {
      const putStub = DynamoDBDocument.prototype.put as sinon.SinonStub;

      const params = new URLSearchParams();
      params.append("redirect_uri", "https://signin.account.gov.uk/callback");
      params.append("state", "test-state-multi");
      params.append("sub", "urn:fdc:gov.uk:2022:test-subject");
      params.append("response", "failure");
      params.append("scope", "passkey-create");
      params.append("email", "testuser@test.null.local");
      params.append("account-interventions", "blocked");
      params.append("account-interventions", "suspended");
      const body = params.toString();

      const event = createTestEvent(HttpMethod.POST, "/authorize", body);

      const result = await handler(event);

      expect(result.statusCode).to.eq(302);
      expect(result.headers?.["Location"]).to.include("state=test-state-multi");

      const storedItem = putStub.firstCall.args[0].Item.authorization;
      expect(storedItem.success).to.eq(false);
      expect(storedItem.actions[0].success).to.eq(false);
      expect(storedItem.actions[0].details.error.code).to.eq(1004);
      expect(storedItem.actions[0].details.error.description).to.eq(
        "AccountHasInterventions"
      );
      expect(
        storedItem.actions[0].details.accountInterventionsStatus.state
      ).to.deep.eq({
        blocked: true,
        reproveIdentity: false,
        resetPassword: false,
        suspended: true,
      });
    });

    it("should return 302 with standard error when failure has no account intervention", async () => {
      const putStub = DynamoDBDocument.prototype.put as sinon.SinonStub;

      const params = new URLSearchParams();
      params.append("redirect_uri", "https://signin.account.gov.uk/callback");
      params.append("state", "test-state-101");
      params.append("sub", "urn:fdc:gov.uk:2022:test-subject");
      params.append("response", "failure");
      params.append("scope", "passkey-create");
      params.append("email", "testuser@test.null.local");
      params.append("account-interventions", "none");
      const body = params.toString();

      const event = createTestEvent(HttpMethod.POST, "/authorize", body);

      const result = await handler(event);

      expect(result.statusCode).to.eq(302);

      const storedItem = putStub.firstCall.args[0].Item.authorization;
      expect(storedItem.success).to.eq(false);
      expect(storedItem.actions[0].details.error.code).to.eq(1001);
      expect(storedItem.actions[0].details.error.description).to.eq(
        "JourneyFailed"
      );
      expect(storedItem.actions[0].details.accountInterventionsStatus).to.eq(
        undefined
      );
    });

    [
      { response: "back", description: "UserBackedOutOfJourney" },
      { response: "abort", description: "UserAbortedJourney" },
    ].forEach(({ response, description }) => {
      it(`should return 302 and store ${description} for account-delete ${response} response`, async () => {
        const putStub = DynamoDBDocument.prototype.put as sinon.SinonStub;

        const body = new URLSearchParams({
          redirect_uri: "https://signin.account.gov.uk/callback",
          state: "test-state-delete",
          sub: "urn:fdc:gov.uk:2022:test-subject",
          response,
          scope: AMCScopes.ACCOUNT_DELETE,
          email: "testuser@test.null.local",
        }).toString();

        const event = createTestEvent(HttpMethod.POST, "/authorize", body);

        const result = await handler(event);

        expect(result.statusCode).to.eq(302);
        expect(result.headers?.["Location"]).to.include(
          "state=test-state-delete"
        );

        const storedItem = putStub.firstCall.args[0].Item.authorization;
        expect(storedItem.success).to.eq(false);
        expect(storedItem.scope).to.eq(AMCScopes.ACCOUNT_DELETE);
        expect(storedItem.actions[0].action).to.eq(AMCScopes.ACCOUNT_DELETE);
        expect(storedItem.actions[0].success).to.eq(false);
        expect(storedItem.actions[0].details.error.code).to.eq(1001);
        expect(storedItem.actions[0].details.error.description).to.eq(
          description
        );
      });
    });

    describe("account-delete success", () => {
      const ACCOUNT_MANAGEMENT_API_URL = "https://amapi.example.com/test-stage";
      let fetchStub: sinon.SinonStub;

      beforeEach(() => {
        process.env.ACCOUNT_MANAGEMENT_API_URL = ACCOUNT_MANAGEMENT_API_URL;
        fetchStub = sinon
          .stub(globalThis, "fetch")
          .resolves(new Response(null, { status: 204 }));
      });

      afterEach(() => {
        delete process.env.ACCOUNT_MANAGEMENT_API_URL;
      });

      const buildBody = async (
        response: string,
        deleteAccount: string | undefined
      ) => {
        const accountDataApiAccessToken =
          await buildAccountDeleteAccountDataApiAccessToken();
        const params = new URLSearchParams({
          redirect_uri: "https://signin.account.gov.uk/callback",
          state: "test-state-delete",
          sub: "urn:fdc:gov.uk:2022:test-subject",
          response,
          scope: AMCScopes.ACCOUNT_DELETE,
          email: "testuser@test.null.local",
          public_sub: TEST_CONSTANTS.PUBLIC_SUBJECT,
          account_data_api_access_token: accountDataApiAccessToken,
        });
        if (deleteAccount) {
          params.append("delete-account", deleteAccount);
        }
        return { body: params.toString(), accountDataApiAccessToken };
      };

      it("should delete the account through the Account Management API and store a successful outcome when the checkbox is ticked", async () => {
        const putStub = DynamoDBDocument.prototype.put as sinon.SinonStub;
        const { body, accountDataApiAccessToken } = await buildBody(
          "success",
          "yes"
        );

        const result = await handler(
          createTestEvent(HttpMethod.POST, "/authorize", body)
        );

        expect(result.statusCode).to.eq(302);
        expect(fetchStub.calledOnce).to.eq(true);
        const [url, init] = fetchStub.firstCall.args;
        expect(url).to.eq(
          `${ACCOUNT_MANAGEMENT_API_URL}/v1/accounts/${TEST_CONSTANTS.PUBLIC_SUBJECT}`
        );
        expect(init.method).to.eq("DELETE");
        expect(init.headers).to.deep.eq({
          "Content-Type": "application/json",
          "X-ADAPI-AccessToken": accountDataApiAccessToken,
          "Session-Id": TEST_CONSTANTS.SESSION_ID,
        });
        expect(JSON.parse(init.body)).to.deep.eq({
          clientId: "amc",
          reason: "USER_INITIATED",
        });
        const storedItem = putStub.firstCall.args[0].Item.authorization;
        expect(storedItem.success).to.eq(true);
      });

      it("should not delete the account and should store a successful outcome when the checkbox is not ticked", async () => {
        const putStub = DynamoDBDocument.prototype.put as sinon.SinonStub;
        const { body } = await buildBody("success", undefined);

        const result = await handler(
          createTestEvent(HttpMethod.POST, "/authorize", body)
        );

        expect(result.statusCode).to.eq(302);
        expect(fetchStub.called).to.eq(false);
        const storedItem = putStub.firstCall.args[0].Item.authorization;
        expect(storedItem.success).to.eq(true);
      });

      it("should return a 500 response when the Account Management API request fails", async () => {
        fetchStub.rejects(new Error("connection reset"));
        const { body } = await buildBody("success", "yes");

        const result = await handler(
          createTestEvent(HttpMethod.POST, "/authorize", body)
        );

        expect(result.statusCode).to.eq(500);
        expect(JSON.parse(result.body)).to.deep.eq({
          message: "Account deletion request failed: Error: connection reset",
        });
      });

      ["back", "abort"].forEach((response) => {
        it(`should not delete the account for ${response} when the checkbox is ticked`, async () => {
          const { body } = await buildBody(response, "yes");

          const result = await handler(
            createTestEvent(HttpMethod.POST, "/authorize", body)
          );

          expect(result.statusCode).to.eq(302);
          expect(fetchStub.called).to.eq(false);
        });
      });

      it("should return a 500 response and not store an outcome when the Account Management API does not return 204", async () => {
        const putStub = DynamoDBDocument.prototype.put as sinon.SinonStub;
        fetchStub.resolves(new Response("error", { status: 500 }));
        const { body } = await buildBody("success", "yes");

        const result = await handler(
          createTestEvent(HttpMethod.POST, "/authorize", body)
        );

        expect(result.statusCode).to.eq(500);
        expect(JSON.parse(result.body)).to.deep.eq({
          message: "Account deletion failed with status 500",
        });
        expect(putStub.called).to.eq(false);
      });

      it("should return a 500 response when the Account Management API URL is not set", async () => {
        delete process.env.ACCOUNT_MANAGEMENT_API_URL;
        const { body } = await buildBody("success", "yes");

        const result = await handler(
          createTestEvent(HttpMethod.POST, "/authorize", body)
        );

        expect(result.statusCode).to.eq(500);
        expect(JSON.parse(result.body)).to.deep.eq({
          message: "ACCOUNT_MANAGEMENT_API_URL not set",
        });
        expect(fetchStub.called).to.eq(false);
      });
    });

    it("should return 500 when account-delete response is skip", async () => {
      const body = new URLSearchParams({
        redirect_uri: "https://signin.account.gov.uk/callback",
        state: "test-state-delete",
        sub: "urn:fdc:gov.uk:2022:test-subject",
        response: "skip",
        scope: AMCScopes.ACCOUNT_DELETE,
      }).toString();

      const event = createTestEvent(HttpMethod.POST, "/authorize", body);

      try {
        await handler(event);
        expect.fail("Should have thrown an error");
      } catch (error: unknown) {
        expect(error).to.be.instanceOf(Error);
        expect((error as { code: number }).code).to.eq(500);
        expect((error as Error).message).to.eq(
          "Cannot find error description for response: skip"
        );
      }
    });

    it("should return 500 when failure response is invalid", async () => {
      const body = new URLSearchParams({
        redirect_uri: "https://signin.account.gov.uk/callback",
        state: "test-state-456",
        sub: "urn:fdc:gov.uk:2022:test-subject",
        response: "invalid response",
      }).toString();

      const event = createTestEvent(HttpMethod.POST, "/authorize", body);

      try {
        await handler(event);
        expect.fail("Should have thrown an error");
      } catch (error: unknown) {
        expect(error).to.be.instanceOf(Error);
        expect((error as { code: number }).code).to.eq(500);
        expect((error as Error).message).to.eq(
          "Cannot find error description for response: invalid response"
        );
      }
    });
  });

  const unsupportedMethods = [HttpMethod.PUT, HttpMethod.DELETE];
  unsupportedMethods.forEach((method) => {
    it(`should not allow ${method}`, async () => {
      const event = createTestEvent(method);

      try {
        await handler(event);
        expect.fail("Should have thrown an error");
      } catch (error: unknown) {
        expect(error).to.be.instanceOf(Error);
        expect((error as { code: number }).code).to.eq(405);
      }
    });
  });
});

async function createSuccessfulTestEventForAMCScope(amcScope: AMCScopes) {
  if (amcScope === AMCScopes.ACCOUNT_DELETE) {
    return (await createAccountDeleteTestEventWithAccountDataToken()).event;
  }

  const accessToken = await new AccessTokenBuilder(
    keys.authPrivateSigningKeyAuthAudience
  )
    .withScope(Object.values(AccountDataAccessTokenScopes))
    .build();

  const compositeJWT = await new CompositeJWTBuilder(
    keys.authPrivateSigningKeyAMCAudience,
    accessToken
  )
    .withScope(amcScope)
    .build();

  return encryptIntoTestEvent(compositeJWT, amcScope);
}

async function encryptIntoTestEvent(compositeJWT: string, amcScope: AMCScopes) {
  const publicKey = await importSPKI(
    keys.amcPublicEncryptionKey,
    "RSA-OAEP-256"
  );
  const encryptedJWT = await new CompactEncrypt(
    textEncoder.encode(compositeJWT)
  )
    .setProtectedHeader({
      alg: "RSA-OAEP-256",
      enc: "A256GCM",
      kid: "test-key-id",
    })
    .encrypt(publicKey);

  return createTestEvent(HttpMethod.GET, "/authorize", null, {
    request: encryptedJWT,
    scope: amcScope,
    redirect_uri: "https://example.com/callback",
  });
}

function buildAccountDeleteAccountDataApiAccessToken() {
  return new AccessTokenBuilder(keys.authPrivateSigningKeyAuthAudience)
    .withScope(ACCOUNT_DELETE_ACCOUNT_DATA_SCOPES)
    .build();
}

async function createAccountDeleteTestEventWithAccountDataToken() {
  const accountDataApiAccessToken =
    await buildAccountDeleteAccountDataApiAccessToken();

  const compositeJWT = await new CompositeJWTBuilder(
    keys.authPrivateSigningKeyAMCAudience,
    accountDataApiAccessToken
  )
    .withScope(AMCScopes.ACCOUNT_DELETE)
    .build();

  const event = await encryptIntoTestEvent(
    compositeJWT,
    AMCScopes.ACCOUNT_DELETE
  );
  return { event, accountDataApiAccessToken };
}

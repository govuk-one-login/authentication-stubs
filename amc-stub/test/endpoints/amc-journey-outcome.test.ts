import { expect } from "chai";
import { handler } from "../../src/endpoints/amc-journey-outcome.ts";
import { HttpMethod } from "../../src/types/enums.ts";
import { createTestEvent } from "../test-helpers.ts";
import { APIGatewayProxyEventHeaders } from "aws-lambda";
import sinon from "sinon";
import { DynamoDBDocument } from "@aws-sdk/lib-dynamodb";
import { AMCAuthorizationResult } from "../../src/types/types.ts";

describe("AMC Journey Outcome Stub Test", () => {
  beforeEach(() => {
    sinon.restore();
  });

  const SUCCESSFUL_AUTHORIZATION_RESULT = {
    outcome_id: "9cd4c45f8f33cced99cfaa48394e1acf5e90f6e2616bba40",
    sub: "urn:fdc:gov.uk:2022:JG0RJI1pYbnanbvPs-j4j5-a-PFcmhry9Qu9NCEp5d4",
    email: "user@example.com",
    scope: "account-delete",
    success: true,
    journeys: [
      {
        journey: "account-delete",
        timestamp: 1760718467000,
        success: true,
        details: {},
      },
    ],
  };

  describe("GET handler", () => {
    it("should return 200 with HTML for valid GET request", async () => {
      const headers: APIGatewayProxyEventHeaders = {
        Authorization: "Bearer 123456",
      };
      stubDynamoGet("123456", SUCCESSFUL_AUTHORIZATION_RESULT);
      const event = createTestEvent(
        HttpMethod.GET,
        "/journeyoutcome",
        null,
        null,
        headers
      );

      const result = await handler(event);

      expect(result.statusCode).to.eq(200);
      expect(result.headers?.["Content-Type"]).to.eq("application/json");
      expect(JSON.parse(result.body)).to.deep.eq(
        SUCCESSFUL_AUTHORIZATION_RESULT
      );
    });

    it("should return 401 for an access token which is not in the database", async () => {
      const unknownAccessToken = "bearer-token-not-in-database";
      const headers: APIGatewayProxyEventHeaders = {
        Authorization: `Bearer ${unknownAccessToken}`,
      };
      stubDynamoGet(unknownAccessToken);
      const event = createTestEvent(
        HttpMethod.GET,
        "/journeyoutcome",
        null,
        null,
        headers
      );

      const result = await handler(event);

      expect(result.statusCode).to.eq(401);
    });

    it("should return 401 for invalid HTTP method", async () => {
      const headersWithoutBearerAccess = { foo: "bar" };
      const event = createTestEvent(
        HttpMethod.GET,
        "/journeyoutcome",
        null,
        null,
        headersWithoutBearerAccess
      );

      const result = await handler(event);

      expect(result.statusCode).to.eq(401);
    });
  });

  const stubDynamoGet = (
    token: string,
    authorizationResult?: AMCAuthorizationResult
  ) => {
    let result;
    if (authorizationResult) {
      result = { Item: { authorization: authorizationResult } };
    } else {
      result = { Item: undefined };
    }
    sinon
      .stub(DynamoDBDocument.prototype, "get")
      .withArgs(
        sinon.match({
          Key: sinon.match({ AuthorizationId: `token-${token}` }),
        })
      )
      .resolves(result);
  };
});

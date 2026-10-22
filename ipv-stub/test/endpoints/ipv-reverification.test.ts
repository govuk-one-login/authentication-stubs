import { expect } from "chai";
import { afterEach, describe, it } from "mocha";
import sinon from "sinon";
import { DynamoDBDocument } from "@aws-sdk/lib-dynamodb";
import type { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { handler } from "../../src/endpoints/ipv-reverification";

const invoke = (
  event: Partial<APIGatewayProxyEvent>
): Promise<APIGatewayProxyResult> =>
  handler(
    { httpMethod: "GET", headers: {}, ...event } as APIGatewayProxyEvent,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    {} as any,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    () => {}
  ) as Promise<APIGatewayProxyResult>;

describe("ipv-reverification endpoint", () => {
  afterEach(() => {
    sinon.restore();
  });

  it("should return 405 for a non-GET method", async () => {
    const result = await invoke({ httpMethod: "DELETE" });

    expect(result.statusCode).to.eq(405);
  });

  it("should return 401 when there is no Authorization header", async () => {
    const result = await invoke({ headers: {} });

    expect(result.statusCode).to.eq(401);
    expect(result.headers?.["WWW-Authenticate"]).to.contain("invalid_token");
  });

  it("should return 401 when the Authorization header is not a Bearer token", async () => {
    const result = await invoke({ headers: { Authorization: "Basic abc" } });

    expect(result.statusCode).to.eq(401);
  });

  it("should return 401 when no reverification record is found", async () => {
    sinon.stub(DynamoDBDocument.prototype, "get").resolves({ Item: undefined });

    const result = await invoke({
      headers: { Authorization: "Bearer some-access-token" },
    });

    expect(result.statusCode).to.eq(401);
  });

  it("should return 200 with the reverification result when found", async () => {
    const reverification = { sub: "user-sub", success: true };
    sinon
      .stub(DynamoDBDocument.prototype, "get")
      .resolves({ Item: { reverification } });

    const result = await invoke({
      headers: { Authorization: "Bearer some-access-token" },
    });

    expect(result.statusCode).to.eq(200);
    expect(JSON.parse(result.body)).to.deep.eq(reverification);
  });
});

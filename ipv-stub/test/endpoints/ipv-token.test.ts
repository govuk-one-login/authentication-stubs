import { expect } from "chai";
import { afterEach, beforeEach, describe, it } from "mocha";
import sinon from "sinon";
import { DynamoDBDocument } from "@aws-sdk/lib-dynamodb";
import type { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import keys from "../../src/data/keys.json" with { type: "json" };
import { createSignedJwt } from "../test-helpers";
import { handler } from "../../src/endpoints/ipv-token";

const invoke = (
  event: Partial<APIGatewayProxyEvent>
): Promise<APIGatewayProxyResult> =>
  handler(
    {
      httpMethod: "POST",
      headers: {},
      body: null,
      ...event,
    } as APIGatewayProxyEvent,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    {} as any,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    () => {}
  ) as Promise<APIGatewayProxyResult>;

const form = (fields: Record<string, string>) =>
  new URLSearchParams(fields).toString();

const validClientAssertion = () =>
  createSignedJwt(
    "ES256",
    {
      iss: "client-id",
      sub: "client-id",
      aud: "https://ipv.example.com/token",
      jti: "unique-jti",
      exp: Math.floor(Date.now() / 1000) + 300,
    },
    keys.authPrivateSigningKeyIPV
  );

describe("ipv-token endpoint", () => {
  beforeEach(() => {
    process.env.AUTH_PUBLIC_SIGNING_KEY_IPV = keys.authPublicSigningKeyIPV;
  });

  afterEach(() => {
    sinon.restore();
    delete process.env.AUTH_PUBLIC_SIGNING_KEY_IPV;
  });

  it("should return 405 for a non-POST method", async () => {
    const result = await invoke({ httpMethod: "GET" });

    expect(result.statusCode).to.eq(405);
  });

  it("should return 400 when the body is missing", async () => {
    const result = await invoke({ body: null });

    expect(result.statusCode).to.eq(400);
    expect(result.body).to.eq("Missing request body.");
  });

  it("should return 400 when required parameters are missing", async () => {
    const result = await invoke({ body: form({ code: "the-code" }) });

    expect(result.statusCode).to.eq(400);
    expect(result.body).to.contain("Missing or empty parameters");
  });

  it("should return 400 when no reverification record matches the code", async () => {
    sinon.stub(DynamoDBDocument.prototype, "get").resolves({ Item: undefined });

    const result = await invoke({
      body: form({
        code: "the-code",
        client_id: "client-id",
        client_assertion: await validClientAssertion(),
        client_assertion_type: "jwt-bearer",
      }),
    });

    expect(result.statusCode).to.eq(400);
    expect(result.body).to.eq("Missing reverification record.");
  });

  it("should return 500 when writing the access token record fails", async () => {
    sinon
      .stub(DynamoDBDocument.prototype, "get")
      .resolves({ Item: { reverification: { sub: "s", success: true } } });
    sinon
      .stub(DynamoDBDocument.prototype, "put")
      .resolves({ $metadata: { httpStatusCode: 500 } });

    const result = await invoke({
      body: form({
        code: "the-code",
        client_id: "client-id",
        client_assertion: await validClientAssertion(),
        client_assertion_type: "jwt-bearer",
      }),
    });

    expect(result.statusCode).to.eq(500);
    expect(result.body).to.eq("Failed to write access token record.");
  });

  it("should return 200 with an access token on success", async () => {
    sinon
      .stub(DynamoDBDocument.prototype, "get")
      .resolves({ Item: { reverification: { sub: "s", success: true } } });
    sinon
      .stub(DynamoDBDocument.prototype, "put")
      .resolves({ $metadata: { httpStatusCode: 200 } });

    const result = await invoke({
      body: form({
        code: "the-code",
        client_id: "client-id",
        client_assertion: await validClientAssertion(),
        client_assertion_type: "jwt-bearer",
      }),
    });

    expect(result.statusCode).to.eq(200);
    const body = JSON.parse(result.body);
    expect(body.access_token).to.be.a("string");
    expect(body.token_type).to.eq("Bearer");
    expect(body.expires_in).to.eq(3600);
  });
});

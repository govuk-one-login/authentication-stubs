import { expect } from "chai";
import { afterEach, beforeEach, describe, it } from "mocha";
import type { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import keys from "../../src/data/keys.json" with { type: "json" };
import { handler } from "../../src/endpoints/jwks";

const invoke = (httpMethod: string): Promise<APIGatewayProxyResult> =>
  handler(
    { httpMethod } as APIGatewayProxyEvent,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    {} as any,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    () => {}
  ) as Promise<APIGatewayProxyResult>;

describe("jwks endpoint", () => {
  beforeEach(() => {
    process.env.IPV_PUBLIC_ENCRYPTION_KEY = keys.ipv_public_key;
  });

  afterEach(() => {
    delete process.env.IPV_PUBLIC_ENCRYPTION_KEY;
  });

  it("should return the public encryption key as a JWKS on GET", async () => {
    const result = await invoke("GET");

    expect(result.statusCode).to.eq(200);
    expect(result.headers?.["Content-Type"]).to.eq("application/json");
    const body = JSON.parse(result.body);
    expect(body.keys).to.have.length(1);
    expect(body.keys[0].use).to.eq("enc");
    expect(body.keys[0].alg).to.eq("RS256");
    expect(body.keys[0].kid).to.eq("ipv-stub-public-encryption-key");
  });

  it("should return 405 for a non-GET method", async () => {
    const result = await invoke("POST");

    expect(result.statusCode).to.eq(405);
    expect(JSON.parse(result.body).message).to.eq("Method POST not allowed");
  });

  it("should return 500 when the public encryption key is not configured", async () => {
    delete process.env.IPV_PUBLIC_ENCRYPTION_KEY;

    const result = await invoke("GET");

    expect(result.statusCode).to.eq(500);
    expect(JSON.parse(result.body).message).to.eq(
      "Public encryption key not configured"
    );
  });
});

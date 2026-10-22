import { expect } from "chai";
import { afterEach, before, describe, it } from "mocha";
import sinon from "sinon";
import * as jose from "jose";
import { DynamoDBDocument } from "@aws-sdk/lib-dynamodb";
import type { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import keys from "../../src/data/keys.json" with { type: "json" };
import { createSignedJwt } from "../test-helpers";
import { handler } from "../../src/endpoints/ipv-authorize";

const invoke = (
  event: Partial<APIGatewayProxyEvent>
): Promise<APIGatewayProxyResult> =>
  handler(
    {
      httpMethod: "POST",
      headers: {},
      body: null,
      queryStringParameters: null,
      ...event,
    } as APIGatewayProxyEvent,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    {} as any,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    () => {}
  ) as Promise<APIGatewayProxyResult>;

const form = (fields: Record<string, string>) =>
  new URLSearchParams(fields).toString();

describe("ipv-authorize endpoint", () => {
  let encryptionPublicKey: jose.CryptoKey;

  before(async () => {
    // Fresh RSA keypair for the JAR encryption/decryption round-trip.
    const encKeyPair = await jose.generateKeyPair("RSA-OAEP-256", {
      extractable: true,
    });
    encryptionPublicKey = encKeyPair.publicKey;
    process.env.IPV_PRIVATE_ENCRYPTION_KEY = await jose.exportPKCS8(
      encKeyPair.privateKey
    );
    process.env.AUTH_PUBLIC_SIGNING_KEY_IPV = keys.authPublicSigningKeyIPV;
    process.env.AUTH_PUBLIC_SIGNING_KEY_EVCS = keys.authPublicSigningKeyEVCS;
  });

  afterEach(() => {
    sinon.restore();
  });

  const buildEncryptedJar = async () => {
    const storageAccessToken = await createSignedJwt(
      "ES256",
      {
        scope: "reverification",
        aud: ["https://credential-store.test.account.gov.uk"],
        sub: "someSub",
        iss: "https://oidc.test.account.gov.uk/",
        exp: 1709051163,
        iat: 1709047563,
        jti: "dfccf751-be55-4df4-aa3f-a993193d5216",
      },
      keys.authPrivateSigningKeyEVCS
    );

    const innerJws = await createSignedJwt(
      "ES256",
      {
        sub: "test-sub",
        scope: "reverification",
        state: "test-state",
        claims: {
          userinfo: {
            "https://vocab.account.gov.uk/v1/storageAccessToken": {
              values: [storageAccessToken],
            },
          },
        },
      },
      keys.authPrivateSigningKeyIPV
    );

    return new jose.CompactEncrypt(new TextEncoder().encode(innerJws))
      .setProtectedHeader({ alg: "RSA-OAEP-256", enc: "A256GCM" })
      .encrypt(encryptionPublicKey);
  };

  describe("GET", () => {
    const getEvent = (query: Record<string, string> | null) =>
      invoke({ httpMethod: "GET", queryStringParameters: query });

    it("should return 400 when query string parameters are null", async () => {
      const result = await getEvent(null);

      expect(result.statusCode).to.eq(400);
      expect(JSON.parse(result.body).message).to.eq(
        "Query string parameters are null"
      );
    });

    it("should return 400 when the request parameter is missing", async () => {
      const result = await getEvent({ other: "x" });

      expect(result.statusCode).to.eq(400);
      expect(JSON.parse(result.body).message).to.eq(
        "Request query string parameter not found"
      );
    });

    it("should return 500 when the private key is not configured", async () => {
      const original = process.env.IPV_PRIVATE_ENCRYPTION_KEY;
      delete process.env.IPV_PRIVATE_ENCRYPTION_KEY;
      try {
        const result = await getEvent({ request: "anything" });

        expect(result.statusCode).to.eq(500);
        expect(JSON.parse(result.body).message).to.eq("Private key not found");
      } finally {
        process.env.IPV_PRIVATE_ENCRYPTION_KEY = original;
      }
    });

    it("should return 400 when the request cannot be decrypted", async () => {
      const result = await getEvent({ request: "not-a-valid-jwe" });

      expect(result.statusCode).to.eq(400);
    });

    it("should decrypt, validate and render the authorize page on success", async () => {
      const result = await getEvent({ request: await buildEncryptedJar() });

      expect(result.statusCode).to.eq(200);
      expect(result.headers?.["Content-Type"]).to.eq("text/html");
      expect(result.body).to.contain("IPV stub");
      expect(result.body).to.contain("test-state");
      expect(result.body).to.contain("test-sub");
    });

    it("should return 400 when the decrypted payload fails validation", async () => {
      // Inner JWS with a non-reverification scope fails validateAuthorisationJwt.
      const badJws = await createSignedJwt(
        "ES256",
        { sub: "s", scope: "wrong-scope", state: "st", claims: {} },
        keys.authPrivateSigningKeyIPV
      );
      const jwe = await new jose.CompactEncrypt(
        new TextEncoder().encode(badJws)
      )
        .setProtectedHeader({ alg: "RSA-OAEP-256", enc: "A256GCM" })
        .encrypt(encryptionPublicKey);

      const result = await getEvent({ request: jwe });

      expect(result.statusCode).to.eq(400);
      expect(JSON.parse(result.body).message).to.eq(
        "Scope in request payload must be reverification"
      );
    });
  });

  it("should return 405 for an unsupported method", async () => {
    const result = await invoke({ httpMethod: "DELETE" });

    expect(result.statusCode).to.eq(405);
  });

  describe("POST", () => {
    it("should return 400 when the body is missing", async () => {
      const result = await invoke({ body: null });

      expect(result.statusCode).to.eq(400);
      expect(JSON.parse(result.body).message).to.eq("Missing request body");
    });

    it("should return 500 when redirect_uri is missing", async () => {
      const result = await invoke({ body: form({ state: "s" }) });

      expect(result.statusCode).to.eq(500);
      expect(JSON.parse(result.body).message).to.eq("redirect_uri not found");
    });

    it("should return 500 when state is missing", async () => {
      const result = await invoke({
        body: form({ redirect_uri: "https://rp.example.com/cb" }),
      });

      expect(result.statusCode).to.eq(500);
      expect(JSON.parse(result.body).message).to.eq("state not found");
    });

    it("should store a success reverification and return a 302 redirect", async () => {
      const putStub = sinon
        .stub(DynamoDBDocument.prototype, "put")
        .resolves({ $metadata: { httpStatusCode: 200 } });

      const result = await invoke({
        body: form({
          redirect_uri: "https://rp.example.com/cb",
          state: "the-state",
          sub: "the-sub",
          response: "success",
        }),
      });

      expect(result.statusCode).to.eq(302);
      const location = result.headers?.Location as string;
      expect(location).to.contain("https://rp.example.com/cb");
      expect(location).to.contain("state=the-state");
      expect(location).to.contain("code=");

      const storedItem = putStub.firstCall.args[0].Item;
      expect(storedItem?.reverification).to.deep.eq({
        sub: "the-sub",
        success: true,
      });
    });

    it("should store a failure reverification for a non-success response", async () => {
      const putStub = sinon
        .stub(DynamoDBDocument.prototype, "put")
        .resolves({ $metadata: { httpStatusCode: 200 } });

      const result = await invoke({
        body: form({
          redirect_uri: "https://rp.example.com/cb",
          state: "the-state",
          sub: "the-sub",
          response: "identity_check_failed",
        }),
      });

      expect(result.statusCode).to.eq(302);
      expect(putStub.firstCall.args[0].Item?.reverification).to.deep.eq({
        sub: "the-sub",
        success: false,
        failure_code: "identity_check_failed",
        failure_description: "identity_check_failed error has occurred",
      });
    });

    it("should return 500 when the dynamo put fails", async () => {
      sinon
        .stub(DynamoDBDocument.prototype, "put")
        .rejects(new Error("dynamo down"));

      const result = await invoke({
        body: form({
          redirect_uri: "https://rp.example.com/cb",
          state: "the-state",
          sub: "the-sub",
          response: "success",
        }),
      });

      expect(result.statusCode).to.eq(500);
      expect(JSON.parse(result.body).message).to.contain(
        "dynamoDb error on storing reverification"
      );
    });
  });
});

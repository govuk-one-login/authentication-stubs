import { expect } from "chai";
import { before, describe, it } from "mocha";
import * as jose from "jose";
import type { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { buildEvent, setupHandlerEnv, TestKeys } from "../test-setup";

type Handler = (event: APIGatewayProxyEvent) => Promise<APIGatewayProxyResult>;

describe("index handler", () => {
  let handler: Handler;
  let keys: TestKeys;

  before(async () => {
    keys = await setupHandlerEnv();
    // Imported after env is set because module-level constants read env.
    ({ handler } = await import("../../src/index/index"));
  });

  describe("method routing", () => {
    it("should return the stub form on GET", async () => {
      const result = await handler(buildEvent({ httpMethod: "GET" }));

      expect(result.statusCode).to.eq(200);
      expect(result.headers?.["Content-Type"]).to.eq("text/html");
      expect(result.body).to.contain("Orchestration stub");
      expect(result.body).to.contain("<form method='post'>");
    });

    it("should be case-insensitive on the method", async () => {
      const result = await handler(buildEvent({ httpMethod: "get" }));

      expect(result.statusCode).to.eq(200);
    });

    it("should return 405 for an unsupported method", async () => {
      const result = await handler(buildEvent({ httpMethod: "DELETE" }));

      expect(result.statusCode).to.eq(405);
      expect(JSON.parse(result.body).message).to.eq(
        "Method not allowed: DELETE",
      );
    });
  });

  describe("POST", () => {
    const postEvent = (
      body: string,
      headers: Record<string, string | undefined> = {},
    ) => buildEvent({ httpMethod: "POST", body, headers });

    it("should redirect with a 302 to the frontend authorize endpoint", async () => {
      const result = await handler(postEvent("level=Cl&channel=web"));

      expect(result.statusCode).to.eq(302);
      const location = result.multiValueHeaders?.Location?.[0] as string;
      expect(location).to.contain(
        "https://frontend.example.com/authorize?request=",
      );
      expect(location).to.contain("response_type=code");
      expect(location).to.contain("client_id=orchestrationAuth");
    });

    it("should set gs and di-persistent-session-id cookies", async () => {
      const result = await handler(postEvent("level=Cl&channel=web"));

      const cookies = result.multiValueHeaders?.["Set-Cookie"] as string[];
      expect(cookies).to.have.length(2);
      expect(cookies[0]).to.match(/^gs=.+\..+; max-age=3600$/);
      expect(cookies[1]).to.match(
        /^di-persistent-session-id=.+; max-age=34190000$/,
      );
    });

    it("should reuse the persistent session id from the request cookie", async () => {
      const result = await handler(
        postEvent("level=Cl&channel=web", {
          cookie: "di-persistent-session-id=existing-persistent-id",
        }),
      );

      const cookies = result.multiValueHeaders?.["Set-Cookie"] as string[];
      expect(cookies[1]).to.contain(
        "di-persistent-session-id=existing-persistent-id",
      );
    });

    it("should append the cookie domain when COOKIE_DOMAIN is a real domain", async () => {
      const original = process.env.COOKIE_DOMAIN;
      process.env.COOKIE_DOMAIN = "account.gov.uk";
      try {
        const result = await handler(postEvent("level=Cl&channel=web"));

        const cookies = result.multiValueHeaders?.["Set-Cookie"] as string[];
        expect(cookies[0]).to.contain("; Domain=account.gov.uk");
        expect(cookies[1]).to.contain("; Domain=account.gov.uk");
      } finally {
        process.env.COOKIE_DOMAIN = original;
      }
    });

    it("should produce a JAR that decrypts and verifies to the expected claims", async () => {
      const result = await handler(
        postEvent("level=Cl.Cm&channel=web&authenticated=yes"),
      );

      const location = result.multiValueHeaders?.Location?.[0] as string;
      const jwe = new URL(location).searchParams.get("request") as string;

      const { plaintext } = await jose.compactDecrypt(jwe, keys.rsaPrivateKey);
      const jws = new TextDecoder().decode(plaintext);

      const { payload } = await jose.jwtVerify(jws, keys.publicSigningKey, {
        issuer: "orchestrationAuth",
        audience: "https://frontend.example.com/",
      });

      expect(payload.rp_client_id).to.eq("test-rp-client-id");
      expect(payload.rp_sector_host).to.eq("test-rp-sector-host");
      expect(payload.requested_credential_strength).to.eq("Cl.Cm");
      expect(payload.authenticated).to.eq(true);
      expect(payload.channel).to.eq("web");
      expect(payload.redirect_uri).to.eq(
        "https://stub.example.com/orchestration-redirect",
      );
    });

    it("should include previous_session_id when a gs cookie is present", async () => {
      const result = await handler(
        postEvent("level=Cl&channel=web", {
          cookie: "gs=previous-session-id.previous-journey-id",
        }),
      );

      const location = result.multiValueHeaders?.Location?.[0] as string;
      const jwe = new URL(location).searchParams.get("request") as string;
      const { plaintext } = await jose.compactDecrypt(jwe, keys.rsaPrivateKey);
      const { payload } = await jose.jwtVerify(
        new TextDecoder().decode(plaintext),
        keys.publicSigningKey,
      );

      expect(payload.previous_session_id).to.eq("previous-session-id");
    });

    it("should omit channel and cookie_consent when set to none", async () => {
      const result = await handler(
        postEvent("level=Cl&channel=none&cookie-consent=none"),
      );

      const location = result.multiValueHeaders?.Location?.[0] as string;
      const jwe = new URL(location).searchParams.get("request") as string;
      const { plaintext } = await jose.compactDecrypt(jwe, keys.rsaPrivateKey);
      const { payload } = await jose.jwtVerify(
        new TextDecoder().decode(plaintext),
        keys.publicSigningKey,
      );

      expect(payload.channel).to.eq(undefined);
      expect(payload.cookie_consent).to.eq(undefined);
    });

    it("should throw when the body is missing required parameters", async () => {
      let threw = false;
      try {
        await handler(postEvent("channel=web"));
      } catch (error) {
        threw = true;
        expect((error as Error).message).to.contain("Unknown level");
      }
      expect(threw).to.eq(true);
    });
  });
});

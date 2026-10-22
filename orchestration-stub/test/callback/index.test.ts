import { expect } from "chai";
import { before, afterEach, describe, it } from "mocha";
import sinon from "sinon";
import type { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { buildEvent, setupHandlerEnv } from "../test-setup";

type Handler = (event: APIGatewayProxyEvent) => Promise<APIGatewayProxyResult>;

const okJson = (body: unknown): Response =>
  ({
    ok: true,
    status: 200,
    json: async () => body,
    text: async () => JSON.stringify(body),
  }) as Response;

const errorResponse = (status: number, message: string): Response =>
  ({
    ok: false,
    status,
    json: async () => ({ message }),
    text: async () => message,
  }) as Response;

describe("callback handler", () => {
  let handler: Handler;

  before(async () => {
    await setupHandlerEnv();
    ({ handler } = await import("../../src/callback/index"));
  });

  afterEach(() => {
    sinon.restore();
  });

  const callbackEvent = (
    query: Record<string, string> | null,
    cookie?: string,
  ) =>
    buildEvent({
      httpMethod: "GET",
      queryStringParameters: query,
      headers: cookie ? { cookie } : {},
    });

  it("should return 405 for a non-GET method", async () => {
    const result = await handler(
      buildEvent({ httpMethod: "POST", queryStringParameters: { code: "x" } }),
    );

    expect(result.statusCode).to.eq(405);
    expect(JSON.parse(result.body).message).to.eq("Method not allowed: POST");
  });

  it("should exchange the auth code and render user info on success", async () => {
    const fetchStub = sinon.stub(global, "fetch");
    fetchStub
      .onFirstCall()
      .resolves(okJson({ access_token: "access-token-123" }));
    fetchStub
      .onSecondCall()
      .resolves(okJson({ sub: "user-sub", email: "user@example.com" }));

    const result = await handler(
      callbackEvent(
        { code: "auth-code-abc", state: "session-id-1" },
        "gs=session-id-1.journey-id-1",
      ),
    );

    expect(result.statusCode).to.eq(200);
    expect(result.headers?.["Content-Type"]).to.eq("text/html");
    expect(result.body).to.contain("session-id-1");
    expect(result.body).to.contain("journey-id-1");
    expect(result.body).to.contain("access-token-123");
    expect(result.body).to.contain("user@example.com");
    // State matched, so no invalid-state error banner.
    expect(result.body).to.not.contain("Invalid state parameter");
  });

  it("should POST a client assertion to the token endpoint", async () => {
    const fetchStub = sinon.stub(global, "fetch");
    fetchStub.onFirstCall().resolves(okJson({ access_token: "tok" }));
    fetchStub.onSecondCall().resolves(okJson({ sub: "s" }));

    await handler(
      callbackEvent({ code: "the-code", state: "sid" }, "gs=sid.jid"),
    );

    const [tokenUrl, tokenInit] = fetchStub.firstCall.args;
    expect(tokenUrl.toString()).to.eq("https://backend.example.com/token");
    expect(tokenInit?.method).to.eq("POST");
    const sentBody = (tokenInit?.body as URLSearchParams).toString();
    expect(sentBody).to.contain("grant_type=authorization_code");
    expect(sentBody).to.contain("code=the-code");
    expect(sentBody).to.contain("client_id=orchestrationAuth");
  });

  it("should call the userinfo endpoint with the access token and session id", async () => {
    const fetchStub = sinon.stub(global, "fetch");
    fetchStub.onFirstCall().resolves(okJson({ access_token: "my-token" }));
    fetchStub.onSecondCall().resolves(okJson({ sub: "s" }));

    await handler(callbackEvent({ code: "c", state: "sid" }, "gs=sid.jid"));

    const [userInfoUrl, userInfoInit] = fetchStub.secondCall.args;
    expect(userInfoUrl.toString()).to.eq(
      "https://backend.example.com/userinfo",
    );
    const sentHeaders = userInfoInit?.headers as Record<string, string>;
    expect(sentHeaders["Authorization"]).to.eq("Bearer my-token");
    expect(sentHeaders["Session-Id"]).to.eq("sid");
  });

  it("should render the invalid-state banner when state does not match the session id", async () => {
    const fetchStub = sinon.stub(global, "fetch");
    fetchStub.onFirstCall().resolves(okJson({ access_token: "tok" }));
    fetchStub.onSecondCall().resolves(okJson({ sub: "s" }));

    const result = await handler(
      callbackEvent(
        { code: "c", state: "a-different-state" },
        "gs=actual-session-id.jid",
      ),
    );

    expect(result.statusCode).to.eq(200);
    expect(result.body).to.contain("Invalid state parameter");
  });

  it("should throw when there are no query string parameters", async () => {
    let threw = false;
    try {
      await handler(callbackEvent(null, "gs=sid.jid"));
    } catch (error) {
      threw = true;
      expect((error as Error).message).to.eq(
        "No queryStringParameters provided",
      );
    }
    expect(threw).to.eq(true);
  });

  it("should throw when the auth code is missing", async () => {
    let threw = false;
    try {
      await handler(callbackEvent({ state: "sid" }, "gs=sid.jid"));
    } catch (error) {
      threw = true;
      expect((error as Error).message).to.eq("No authCode provided");
    }
    expect(threw).to.eq(true);
  });

  it("should throw when the token endpoint returns a non-ok response", async () => {
    sinon
      .stub(global, "fetch")
      .resolves(errorResponse(400, "bad token request"));

    let threw = false;
    try {
      await handler(callbackEvent({ code: "c", state: "sid" }, "gs=sid.jid"));
    } catch (error) {
      threw = true;
      expect((error as Error).message).to.contain("Error while fetching token");
      expect((error as Error).message).to.contain("400");
    }
    expect(threw).to.eq(true);
  });

  it("should throw when the userinfo endpoint returns a non-ok response", async () => {
    const fetchStub = sinon.stub(global, "fetch");
    fetchStub.onFirstCall().resolves(okJson({ access_token: "tok" }));
    fetchStub.onSecondCall().resolves(errorResponse(401, "unauthorized"));

    let threw = false;
    try {
      await handler(callbackEvent({ code: "c", state: "sid" }, "gs=sid.jid"));
    } catch (error) {
      threw = true;
      expect((error as Error).message).to.contain(
        "Error while fetching user info",
      );
      expect((error as Error).message).to.contain("401");
    }
    expect(threw).to.eq(true);
  });
});

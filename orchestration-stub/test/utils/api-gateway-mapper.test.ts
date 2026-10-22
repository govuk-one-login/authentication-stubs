import { expect } from "chai";
import { describe, it, afterEach } from "mocha";
import sinon from "sinon";
import type { NextFunction, Request, Response } from "express";
import type { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { apiGatewayRoute } from "../../src/utils/api-gateway-mapper";

const next: NextFunction = () => {};

const buildRequest = (overrides: Partial<Request> = {}): Request =>
  ({
    body: "",
    headers: {},
    method: "GET",
    path: "/",
    query: {},
    ip: "127.0.0.1",
    ...overrides,
  }) as unknown as Request;

const buildResponse = () => {
  const res = {
    status: sinon.stub().returnsThis(),
    header: sinon.stub().returnsThis(),
    send: sinon.stub().returnsThis(),
  };
  return res as unknown as Response & typeof res;
};

describe("api-gateway-mapper.ts", () => {
  afterEach(() => {
    sinon.restore();
  });

  describe("apiGatewayRoute", () => {
    it("should map an express request into an API Gateway event", async () => {
      let captured: APIGatewayProxyEvent | undefined;
      const handler = sinon.spy(async (event: APIGatewayProxyEvent) => {
        captured = event;
        return { statusCode: 200, body: "ok" };
      });

      const req = buildRequest({
        body: "hello",
        method: "POST",
        path: "/orchestration-redirect",
        headers: { "content-type": "text/plain" },
        query: { foo: "bar" } as unknown as Request["query"],
      });

      await apiGatewayRoute(handler)(req, buildResponse(), next);

      expect(handler.calledOnce).to.eq(true);
      expect(captured?.httpMethod).to.eq("POST");
      expect(captured?.path).to.eq("/orchestration-redirect");
      expect(captured?.body).to.eq("hello");
      expect(captured?.headers["content-type"]).to.eq("text/plain");
      expect(captured?.queryStringParameters).to.deep.eq({ foo: "bar" });
      expect(captured?.isBase64Encoded).to.eq(false);
    });

    it("should split single- and multi-valued headers", async () => {
      let captured: APIGatewayProxyEvent | undefined;
      const handler = async (event: APIGatewayProxyEvent) => {
        captured = event;
        return { statusCode: 200, body: "" };
      };

      const req = buildRequest({
        headers: {
          single: "one",
          multi: ["a", "b"],
        } as unknown as Request["headers"],
      });

      await apiGatewayRoute(handler)(req, buildResponse(), next);

      expect(captured?.headers).to.deep.eq({ single: "one" });
      expect(captured?.multiValueHeaders).to.deep.eq({ multi: ["a", "b"] });
    });

    it("should write status, headers and body onto the response", async () => {
      const result: APIGatewayProxyResult = {
        statusCode: 302,
        headers: { Location: "https://example.com" },
        body: "redirecting",
      };
      const res = buildResponse();

      await apiGatewayRoute(async () => result)(buildRequest(), res, next);

      expect(res.status.calledWith(302)).to.eq(true);
      expect(res.header.calledWith("Location", "https://example.com")).to.eq(
        true,
      );
      expect(res.send.calledWith("redirecting")).to.eq(true);
    });

    it("should apply multiValueHeaders onto the response", async () => {
      const result: APIGatewayProxyResult = {
        statusCode: 200,
        multiValueHeaders: { "Set-Cookie": ["a=1", "b=2"] },
        body: "",
      };
      const res = buildResponse();

      await apiGatewayRoute(async () => result)(buildRequest(), res, next);

      expect(res.header.calledWith("Set-Cookie", ["a=1", "b=2"])).to.eq(true);
    });

    it("should decode a base64-encoded body before sending", async () => {
      const result: APIGatewayProxyResult = {
        statusCode: 200,
        body: Buffer.from("binary-content").toString("base64"),
        isBase64Encoded: true,
      };
      const res = buildResponse();

      await apiGatewayRoute(async () => result)(buildRequest(), res, next);

      const sent = res.send.firstCall.args[0] as Buffer;
      expect(Buffer.isBuffer(sent)).to.eq(true);
      expect(sent.toString()).to.eq("binary-content");
    });
  });
});

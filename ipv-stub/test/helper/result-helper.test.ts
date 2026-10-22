import { expect } from "chai";
import { describe, it } from "mocha";
import {
  CodedError,
  handleErrors,
  invalidAccessTokenResult,
  methodNotAllowedError,
  shouldObfuscate,
  successfulHtmlResult,
  successfulJsonResult,
  truncate,
} from "../../src/helper/result-helper";

describe("result-helper.ts", () => {
  describe("successfulHtmlResult", () => {
    it("should build a 200 HTML response and merge extra headers", () => {
      const result = successfulHtmlResult(200, "<p>hi</p>", {
        "Cache-Control": "no-store",
      });

      expect(result.statusCode).to.eq(200);
      expect(result.body).to.eq("<p>hi</p>");
      expect(result.headers?.["Content-Type"]).to.eq("text/html");
      expect(result.headers?.["Cache-Control"]).to.eq("no-store");
    });
  });

  describe("successfulJsonResult", () => {
    it("should build a JSON response with a stringified body", () => {
      const result = successfulJsonResult(302, { a: 1 }, { Location: "/x" });

      expect(result.statusCode).to.eq(302);
      expect(result.headers?.["Content-Type"]).to.eq("application/json");
      expect(result.headers?.Location).to.eq("/x");
      expect(JSON.parse(result.body)).to.deep.eq({ a: 1 });
    });
  });

  describe("invalidAccessTokenResult", () => {
    it("should return a 401 with a WWW-Authenticate header", () => {
      const result = invalidAccessTokenResult();

      expect(result.statusCode).to.eq(401);
      expect(result.headers?.["WWW-Authenticate"]).to.contain(
        'error="invalid_token"'
      );
    });
  });

  describe("methodNotAllowedError", () => {
    it("should return a 405 CodedError mentioning the method", () => {
      const err = methodNotAllowedError("PUT");

      expect(err).to.be.instanceOf(CodedError);
      expect(err.code).to.eq(405);
      expect(err.message).to.eq("Method PUT not allowed");
    });
  });

  describe("handleErrors", () => {
    it("should pass through a successful result", async () => {
      const result = await handleErrors(async () => ({
        statusCode: 200,
        body: "ok",
      }));

      expect(result.statusCode).to.eq(200);
      expect(result.body).to.eq("ok");
    });

    it("should map a CodedError to its status code and message", async () => {
      const result = await handleErrors(async () => {
        throw new CodedError(400, "bad request");
      });

      expect(result.statusCode).to.eq(400);
      expect(JSON.parse(result.body).message).to.eq("bad request");
    });

    it("should map a generic Error to a 500 with its message", async () => {
      const result = await handleErrors(async () => {
        throw new Error("boom");
      });

      expect(result.statusCode).to.eq(500);
      expect(JSON.parse(result.body).message).to.contain("boom");
    });

    it("should map a non-Error throwable to a 500", async () => {
      const result = await handleErrors(async () => {
        throw "string failure";
      });

      expect(result.statusCode).to.eq(500);
      expect(JSON.parse(result.body).message).to.contain("string failure");
    });
  });

  describe("shouldObfuscate", () => {
    it("should return true for sensitive parameter names", () => {
      expect(shouldObfuscate("code")).to.eq(true);
      expect(shouldObfuscate("jti")).to.eq(true);
      expect(shouldObfuscate("client_assertion")).to.eq(true);
    });

    it("should return false for non-sensitive parameter names", () => {
      expect(shouldObfuscate("client_id")).to.eq(false);
    });
  });

  describe("truncate", () => {
    it("should not obfuscate short values", () => {
      expect(truncate("12345678")).to.eq("12345678");
    });

    it("should obfuscate longer values keeping the ends", () => {
      expect(truncate("123456789")).to.eq("1234...6789");
    });
  });
});

import { expect } from "chai";
import { describe, it } from "mocha";
import * as jose from "jose";
import { processJoseError } from "../../src/helper/error-helper";
import { CodedError } from "../../src/helper/result-helper";

describe("error-helper.ts", () => {
  describe("processJoseError", () => {
    it("should rethrow a JOSE error as a 400 CodedError using its code", () => {
      const joseError = new jose.errors.JWEDecryptionFailed();

      try {
        processJoseError(joseError);
        expect.fail("expected processJoseError to throw");
      } catch (error) {
        expect(error).to.be.instanceOf(CodedError);
        expect((error as CodedError).code).to.eq(400);
        expect((error as CodedError).message).to.eq(joseError.code);
      }
    });

    it("should rethrow an unknown error as a 400 CodedError with a generic message", () => {
      try {
        processJoseError(new Error("some other failure"));
        expect.fail("expected processJoseError to throw");
      } catch (error) {
        expect(error).to.be.instanceOf(CodedError);
        expect((error as CodedError).code).to.eq(400);
        expect((error as CodedError).message).to.eq("Unknown error.");
      }
    });
  });
});
